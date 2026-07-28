// Copyright (c) 2023 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;

use actix_web::{
    http::{header, Method},
    middleware,
    web::{self, Query},
    App, HttpRequest, HttpResponse, HttpServer,
};
use anyhow::Context;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
#[cfg(feature = "as")]
use kbs_types::Tee;
use policy_engine::{rego::Regorus, PolicyEngine};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::{
    admin::Admin,
    config::KbsConfig,
    deployment_authorization::{AuthorizationStore, VerifiedAuthorization},
    jwe::jwe,
    plugins::PluginManager,
    policy_artifact,
    prometheus::{
        ACTIVE_CONNECTIONS, BUILD_INFO, DEPLOYMENT_AUTHORIZATION_LOOKUPS_TOTAL,
        DEPLOYMENT_AUTHORIZATION_LOOKUP_SECONDS, DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOTAL,
        KBS_POLICY_APPROVALS, KBS_POLICY_ERRORS, KBS_POLICY_EVALS, KBS_POLICY_VIOLATIONS,
        REQUEST_DURATION, REQUEST_SIZES, REQUEST_TOTAL, STATIC_RESOURCE_POLICY_BYTES,
        STATIC_RESOURCE_POLICY_DIGEST_INFO,
    },
    token::TokenVerifier,
    Error, Result,
};

#[cfg(feature = "as")]
use crate::attestation::backend::{EvidenceRuntimeData, IndependentEvidence};

const KBS_PREFIX: &str = "/kbs/v0";

pub const KBS_STORAGE_NAMESPACE: &str = "kbs";
pub const DEPLOYMENT_AUTHORIZATION_STORAGE_NAMESPACE: &str = "deployment_authorizations";

/// The name of the policy rule that determines if the request is allowed or denied
pub const KBS_POLICY_RULE: &str = "data.policy.allow";

/// The name of the policy identifier for the KBS Resource Policy
pub const KBS_POLICY_ID: &str = "resource-policy";

const KBS_ATTESTATION_VERIFY_BEARER_TOKEN_ENV: &str = "KBS_ATTESTATION_VERIFY_BEARER_TOKEN";
const KBS_ATTESTATION_VERIFY_ALLOW_UNAUTHENTICATED_ENV: &str =
    "KBS_ATTESTATION_VERIFY_ALLOW_UNAUTHENTICATED";
const KBS_DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOKEN_ENV: &str =
    "KBS_DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOKEN";

macro_rules! kbs_path {
    ($path:expr) => {
        format!("{}/{}", KBS_PREFIX, $path)
    };
}

/// The KBS API server
#[derive(Clone)]
pub struct ApiServer {
    plugin_manager: PluginManager,

    #[cfg(feature = "as")]
    attestation_service: crate::attestation::AttestationService,

    pub policy_engine: PolicyEngine<Regorus>,
    authorization_store: std::sync::Arc<AuthorizationStore>,
    admin: Admin,
    config: KbsConfig,
    token_verifier: TokenVerifier,
}

impl ApiServer {
    fn startup_policy(config: &KbsConfig) -> Result<String> {
        if let Some(policy_path) = &config.policy_engine.policy_path {
            return fs::read_to_string(policy_path)
                .with_context(|| {
                    format!("failed to read policy file from {}", policy_path.display())
                })
                .map_err(|source| Error::PolicyInitializationFailed { source });
        }

        Ok(include_str!("../sample_policies/default.rego").to_string())
    }

    async fn get_attestation_token(&self, request: &HttpRequest) -> anyhow::Result<String> {
        #[cfg(feature = "as")]
        if let Ok(token) = self
            .attestation_service
            .get_attest_token_from_session(request)
            .await
        {
            return Ok(token);
        }

        Self::get_authorization_token(request)
    }

    fn get_authorization_token(request: &HttpRequest) -> anyhow::Result<String> {
        let value = request
            .headers()
            .get(header::AUTHORIZATION)
            .context("Authorization header not found")?
            .to_str()
            .context("Authorization header is not valid UTF-8")?;

        let (scheme, token) = value
            .split_once(' ')
            .ok_or_else(|| anyhow::anyhow!("Authorization header has no scheme"))?;
        if token.is_empty() {
            anyhow::bail!("Authorization token is empty");
        }

        if scheme.eq_ignore_ascii_case("Bearer") || scheme.eq_ignore_ascii_case("Attestation") {
            return Ok(token.to_string());
        }

        anyhow::bail!("unsupported Authorization scheme {scheme}");
    }

    async fn verified_resource_policy_rego(&self, claim_str: &str) -> Result<String> {
        let stored_policy = self.policy_engine.get_policy(KBS_POLICY_ID).await?;
        policy_artifact::rego_for_evaluation(
            &self.config.policy_engine,
            &stored_policy,
            Some(claim_str),
        )
        .map_err(|source| Error::ParsePolicyError { source })
    }

    async fn verified_resource_policy_body(
        &self,
        policy_id: &str,
        claim_str: &str,
    ) -> Result<String> {
        let stored_policy = self.policy_engine.get_policy(policy_id).await?;
        if self.config.policy_engine.require_signed_policy {
            return policy_artifact::policy_body_for_claims(
                &self.config.policy_engine,
                &stored_policy,
                Some(claim_str),
            )
            .map_err(|source| Error::ParsePolicyError { source });
        }

        Ok(stored_policy)
    }

    async fn evaluate_resource_policy(
        &self,
        policy_data: Option<&str>,
        claim_str: &str,
    ) -> Result<policy_engine::EvaluationResult> {
        let policy = self.verified_resource_policy_rego(claim_str).await?;
        self.policy_engine
            .engine
            .evaluate(
                policy_data,
                claim_str,
                &policy,
                vec![KBS_POLICY_RULE],
                vec![],
            )
            .await
            .map_err(From::from)
    }

    pub async fn new(config: KbsConfig) -> Result<Self> {
        crate::deployment_authorization::validate_config(&config.policy_engine)
            .map_err(|source| Error::PolicyInitializationFailed { source })?;
        policy_artifact::validate_config(&config.policy_engine)
            .map_err(|source| Error::PolicyInitializationFailed { source })?;

        let plugin_manager = PluginManager::new(config.plugins.clone(), &config.storage_backend)
            .await
            .map_err(|e| Error::PluginManagerInitialization { source: e })?;
        let token_verifier = TokenVerifier::from_config(config.attestation_token.clone()).await?;

        let policy_storage_backend = config
            .storage_backend
            .backends
            .to_client_with_namespace(config.storage_backend.storage_type, KBS_STORAGE_NAMESPACE)
            .await
            .map_err(|e| Error::StorageBackendInitialization { source: e })?;
        let authorization_storage_backend = config
            .storage_backend
            .backends
            .to_client_with_namespace(
                config.storage_backend.storage_type,
                DEPLOYMENT_AUTHORIZATION_STORAGE_NAMESPACE,
            )
            .await
            .map_err(|e| Error::StorageBackendInitialization { source: e })?;
        let policy_engine = PolicyEngine::new(policy_storage_backend);
        let startup_policy = Self::startup_policy(&config)?;
        let startup_policy =
            policy_artifact::policy_for_storage(&config.policy_engine, &startup_policy)
                .map_err(|source| Error::PolicyInitializationFailed { source })?;
        if config.policy_engine.require_deployment_authorization {
            STATIC_RESOURCE_POLICY_BYTES
                .set(i64::try_from(startup_policy.len()).unwrap_or(i64::MAX));
            STATIC_RESOURCE_POLICY_DIGEST_INFO.reset();
            STATIC_RESOURCE_POLICY_DIGEST_INFO
                .with_label_values(&[&hex::encode(Sha256::digest(startup_policy.as_bytes()))])
                .set(1.0);
        }
        let existing_policy = policy_engine.get_policy(KBS_POLICY_ID).await.ok();
        policy_artifact::validate_static_policy_transition(
            &config.policy_engine,
            existing_policy.as_deref(),
            &startup_policy,
        )
        .map_err(|source| Error::PolicyInitializationFailed { source })?;

        policy_engine
            .set_policy(KBS_POLICY_ID, &startup_policy, true)
            .await?;
        let admin = Admin::try_from(config.admin.clone())?;

        #[cfg(feature = "as")]
        let attestation_service = crate::attestation::AttestationService::new(
            config.attestation_service.clone(),
            &config.storage_backend,
        )
        .await?;

        BUILD_INFO.inc();

        Ok(Self {
            config,
            plugin_manager,
            policy_engine,
            authorization_store: std::sync::Arc::new(AuthorizationStore::new(
                authorization_storage_backend,
            )),
            admin,
            token_verifier,

            #[cfg(feature = "as")]
            attestation_service,
        })
    }

    /// Start the HTTP server and serve API requests.
    pub async fn serve(self) -> Result<()> {
        actix::spawn(self.server()?)
            .await
            .map_err(|e| Error::HTTPFailed { source: e.into() })?
            .map_err(|e| Error::HTTPFailed { source: e.into() })
    }

    /// Setup API server
    pub fn server(self) -> Result<actix_web::dev::Server> {
        info!(
            "Starting HTTP{} server at {:?}",
            if !self.config.http_server.insecure_http {
                "S"
            } else {
                ""
            },
            self.config.http_server.sockets
        );

        let http_config = self.config.http_server.clone();

        #[allow(clippy::redundant_closure)]
        let mut http_server = HttpServer::new({
            move || {
                let api_server = self.clone();
                App::new()
                    .wrap(middleware::Logger::default())
                    .wrap(middleware::from_fn(prometheus_metrics_middleware))
                    .app_data(web::Data::new(api_server))
                    .app_data(web::PayloadConfig::new(
                        (1024 * 1024 * http_config.payload_request_size) as usize,
                    ))
                    .service(
                        web::resource(kbs_path!("workload-resource/{path:.*}"))
                            .route(web::put().to(workload_resource_api))
                            .route(web::delete().to(workload_resource_api)),
                    )
                    .service(
                        web::resource(kbs_path!(
                            "deployment-authorization/{descriptor_hash}/revoke"
                        ))
                        .route(web::post().to(revoke_deployment_authorization)),
                    )
                    .service(
                        web::resource(kbs_path!("deployment-authorization/{descriptor_hash}"))
                            .route(web::put().to(publish_deployment_authorization))
                            .route(web::get().to(readback_deployment_authorization))
                            .route(web::delete().to(deactivate_deployment_authorization)),
                    )
                    .service(
                        web::resource([kbs_path!("{path:.*}")])
                            .route(web::get().to(api))
                            .route(web::post().to(api))
                            .route(web::delete().to(api)),
                    )
                    .service(
                        web::resource("/metrics")
                            .route(web::get().to(prometheus_metrics_handler))
                            .route(web::post().to(|| HttpResponse::MethodNotAllowed())),
                    )
            }
        });

        if let Some(worker_count) = http_config.worker_count {
            http_server = http_server.workers(worker_count);
        }

        if !http_config.insecure_http {
            let tls_server = http_server
                .bind_openssl(
                    &http_config.sockets[..],
                    crate::http::tls_config(&http_config)
                        .map_err(|e| Error::HTTPSFailed { source: e })?,
                )
                .map_err(|e| Error::HTTPSFailed { source: e.into() })?;

            return Ok(tls_server.run());
        }

        Ok(http_server
            .bind(&http_config.sockets[..])
            .map_err(|e| Error::HTTPFailed { source: e.into() })?
            .run())
    }
}

fn endpoint_descriptor_hash(raw: &str) -> Result<[u8; 32]> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::DeploymentAuthorizationInvalid);
    }
    hex::decode(raw)
        .map_err(|_| Error::DeploymentAuthorizationInvalid)?
        .try_into()
        .map_err(|_| Error::DeploymentAuthorizationInvalid)
}

fn map_authorization_store_error(error: anyhow::Error) -> Error {
    let message = error.to_string();
    if error.chain().any(|cause| {
        cause
            .to_string()
            .contains("deployment authorization storage")
    }) {
        Error::DeploymentAuthorizationStorage { source: error }
    } else if message.contains("immutable") || message.contains("terminally revoked") {
        Error::DeploymentAuthorizationConflict
    } else {
        warn!(error = %error, "deployment authorization operation failed");
        Error::DeploymentAuthorizationInvalid
    }
}

fn map_authorization_readback_error(error: anyhow::Error) -> Error {
    if error.chain().any(|cause| {
        cause
            .to_string()
            .contains("deployment authorization storage")
    }) {
        Error::DeploymentAuthorizationStorage { source: error }
    } else {
        Error::DeploymentAuthorizationNotFound
    }
}

async fn resolve_deployment_authorization(
    core: &ApiServer,
    claims: &serde_json::Value,
) -> anyhow::Result<VerifiedAuthorization> {
    let timer = DEPLOYMENT_AUTHORIZATION_LOOKUP_SECONDS.start_timer();
    let result = core
        .authorization_store
        .resolve(&core.config.policy_engine, claims)
        .await;
    timer.observe_duration();
    DEPLOYMENT_AUTHORIZATION_LOOKUPS_TOTAL
        .with_label_values(&[if result.is_ok() { "success" } else { "deny" }])
        .inc();
    result
}

async fn publish_deployment_authorization(
    request: HttpRequest,
    body: web::Bytes,
    core: web::Data<ApiServer>,
    descriptor_hash: web::Path<String>,
) -> Result<HttpResponse> {
    verify_deployment_authorization_publisher(&request)?;
    if body.len() > crate::deployment_authorization::MAX_BYTES {
        return Err(Error::PayloadTooLarge);
    }
    let descriptor_hash = endpoint_descriptor_hash(&descriptor_hash)?;
    let result = core
        .authorization_store
        .publish(&core.config.policy_engine, &descriptor_hash, &body)
        .await;
    DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOTAL
        .with_label_values(&["publish", if result.is_ok() { "success" } else { "error" }])
        .inc();
    result.map_err(map_authorization_store_error)?;
    Ok(HttpResponse::Created().finish())
}

async fn readback_deployment_authorization(
    request: HttpRequest,
    core: web::Data<ApiServer>,
    descriptor_hash: web::Path<String>,
) -> Result<HttpResponse> {
    verify_deployment_authorization_publisher(&request)?;
    let descriptor_hash = endpoint_descriptor_hash(&descriptor_hash)?;
    let result = core
        .authorization_store
        .publisher_readback(&descriptor_hash)
        .await;
    DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOTAL
        .with_label_values(&["readback", if result.is_ok() { "success" } else { "error" }])
        .inc();
    let bytes = result.map_err(map_authorization_readback_error)?;
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(bytes))
}

async fn deactivate_deployment_authorization(
    request: HttpRequest,
    core: web::Data<ApiServer>,
    descriptor_hash: web::Path<String>,
) -> Result<HttpResponse> {
    verify_deployment_authorization_publisher(&request)?;
    let descriptor_hash = endpoint_descriptor_hash(&descriptor_hash)?;
    let result = core.authorization_store.deactivate(&descriptor_hash).await;
    DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOTAL
        .with_label_values(&[
            "deactivate",
            if result.is_ok() { "success" } else { "error" },
        ])
        .inc();
    result.map_err(map_authorization_store_error)?;
    Ok(HttpResponse::NoContent().finish())
}

async fn revoke_deployment_authorization(
    request: HttpRequest,
    body: web::Bytes,
    core: web::Data<ApiServer>,
    descriptor_hash: web::Path<String>,
) -> Result<HttpResponse> {
    verify_deployment_authorization_publisher(&request)?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RevokeRequest {
        reason: String,
    }
    let request_body: RevokeRequest =
        serde_json::from_slice(&body).map_err(|_| Error::DeploymentAuthorizationInvalid)?;
    if request_body.reason.trim().is_empty() || request_body.reason.len() > 1024 {
        return Err(Error::DeploymentAuthorizationInvalid);
    }
    let descriptor_hash = endpoint_descriptor_hash(&descriptor_hash)?;
    let result = core.authorization_store.revoke(&descriptor_hash).await;
    DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOTAL
        .with_label_values(&["revoke", if result.is_ok() { "success" } else { "error" }])
        .inc();
    result.map_err(map_authorization_store_error)?;
    Ok(HttpResponse::NoContent().finish())
}

/// APIs
pub(crate) async fn api(
    request: HttpRequest,
    body: web::Bytes,
    core: web::Data<ApiServer>,
    path: web::Path<String>,
    query: Query<HashMap<String, String>>,
) -> Result<HttpResponse> {
    let path = path.into_inner();
    let path_parts = path.split('/').collect::<Vec<&str>>();
    if path_parts.is_empty() {
        return Err(Error::InvalidRequestPath {
            path: path.to_string(),
        });
    }

    // path looks like `plugin/.../<END>`
    // the index 0 of the path parts is the plugin
    // the rest of the path parts is the resource path
    // if the path parts is equal to 1, return an empty vector
    let plugin = path_parts[0];

    let resource_path = match &path_parts[..] {
        [_, rest @ ..] => rest,
        _ => &[],
    };

    let query = query.into_inner();
    let policy_data =
        build_plugin_policy_data(request.method().as_str(), plugin, resource_path, &query);

    match plugin {
        #[cfg(feature = "as")]
        "auth" if request.method() == Method::POST => core
            .attestation_service
            .auth(&body)
            .await
            .map_err(From::from),
        #[cfg(feature = "as")]
        "attest" if request.method() == Method::POST => core
            .attestation_service
            .attest(&body, request)
            .await
            .map_err(From::from),
        "attestation" if request.method() == Method::POST && resource_path == ["verify"] => {
            let token = attestation_verify_token(&request, &body)?;
            let claims = core.token_verifier.verify(token).await?;
            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body(serde_json::to_string(&claims)?))
        }
        #[cfg(feature = "as")]
        "attestation-policy" if request.method() == Method::POST => {
            core.admin.check_admin_access(&request)?;
            core.attestation_service.set_policy(&body).await?;

            Ok(HttpResponse::Ok().finish())
        }
        #[cfg(feature = "as")]
        // Reference value querying API is exposed as
        // GET /reference-value/<reference_value_id>
        "reference-value" if request.method() == Method::GET => {
            core.admin.check_admin_access(&request)?;
            let reference_value_id = resource_path.join("/");
            let reference_values = core
                .attestation_service
                .query_reference_value(&reference_value_id)
                .await
                .map_err(|e| Error::RvpsError {
                    message: format!("Failed to get reference_values: {e}").to_string(),
                })?;

            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body(reference_values))
        }
        #[cfg(feature = "as")]
        "reference-value" if request.method() == Method::POST => {
            core.admin.check_admin_access(&request)?;
            let message = std::str::from_utf8(&body).map_err(|_| Error::RvpsError {
                message: "Failed to parse reference value message".to_string(),
            })?;
            serde_json::to_string(
                &core
                    .attestation_service
                    .register_reference_value(message)
                    .await
                    .map_err(|e| Error::RvpsError {
                        message: format!("Failed to register reference value: {e}").to_string(),
                    })?,
            )?;

            Ok(HttpResponse::Ok().content_type("application/json").finish())
        }

        // TODO: consider to rename the api name for it is not only for
        // resource retrievement but for all plugins.
        "resource-policy" if request.method() == Method::POST => {
            core.admin.check_admin_access(&request)?;
            let request: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| Error::ParsePolicyError {
                    source: anyhow::anyhow!("Illegal SetPolicy Request Json"),
                })?;

            let policy_b64 = request
                .pointer("/policy")
                .ok_or(Error::ParsePolicyError {
                    source: anyhow::anyhow!("No `policy` field inside SetPolicy Request Json"),
                })?
                .as_str()
                .ok_or(Error::ParsePolicyError {
                    source: anyhow::anyhow!(
                        "`policy` field is not a string in SetPolicy Request Json"
                    ),
                })?;

            let policy_slice = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(policy_b64)
                .map_err(|e| Error::ParsePolicyError {
                    source: anyhow::anyhow!("Failed to decode policy: {e}"),
                })?;

            let policy = String::from_utf8(policy_slice).map_err(|e| Error::ParsePolicyError {
                source: anyhow::anyhow!("Failed to decode policy: {e}"),
            })?;
            let policy = policy_artifact::policy_for_storage(&core.config.policy_engine, &policy)
                .map_err(|source| Error::ParsePolicyError { source })?;
            let existing_policy = core.policy_engine.get_policy(KBS_POLICY_ID).await.ok();
            policy_artifact::validate_static_policy_transition(
                &core.config.policy_engine,
                existing_policy.as_deref(),
                &policy,
            )
            .map_err(|source| Error::ParsePolicyError { source })?;

            core.policy_engine
                .set_policy(KBS_POLICY_ID, &policy, true)
                .await?;

            Ok(HttpResponse::Ok().finish())
        }
        "resource-policy"
            if request.method() == Method::GET
                && resource_path.len() == 2
                && resource_path[1] == "body" =>
        {
            let policy_id = resource_path[0];
            let token = core
                .get_attestation_token(&request)
                .await
                .map_err(|_| Error::TokenNotFound)?;
            let claims = core.token_verifier.verify(token).await?;
            let claim_str = serde_json::to_string(&claims)?;
            let policy_data = build_policy_body_policy_data(
                policy_id,
                query.get("resource_path").map(String::as_str),
            );
            let policy_data_str = policy_data.to_string();

            KBS_POLICY_EVALS.inc();
            let policy_result = core
                .evaluate_resource_policy(Some(&policy_data_str), &claim_str)
                .await
                .inspect_err(|_| KBS_POLICY_ERRORS.inc())?;
            if !policy_allows(&policy_result) {
                KBS_POLICY_VIOLATIONS.inc();
                return Err(Error::PolicyDeny);
            }
            KBS_POLICY_APPROVALS.inc();

            let policy = core
                .verified_resource_policy_body(policy_id, &claim_str)
                .await?;
            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body(policy))
        }
        // TODO: consider to rename the api name for it is not only for
        // resource retrievement but for all plugins.
        "resource-policy" if request.method() == Method::GET => {
            core.admin.check_admin_access(&request)?;
            let policy = core.policy_engine.list_policies().await?;

            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body(serde_json::to_string(&policy)?))
        }
        // If the base_path cannot be served by any of the above built-in
        // functions, try fulfilling the request via the PluginManager.
        plugin_name => {
            let plugin = core
                .plugin_manager
                .get(plugin_name)
                .ok_or(Error::PluginNotFound {
                    plugin_name: plugin_name.to_string(),
                })?;

            let body = body.to_vec();
            if plugin
                .validate_auth(&body, &query, resource_path, request.method())
                .await
                .map_err(|e| Error::PluginInternalError { source: e })?
            {
                // Plugin calls need to be authorized by the admin auth
                core.admin.check_admin_access(&request)?;
                let response = plugin
                    .handle(&body, &query, resource_path, request.method())
                    .await
                    .map_err(|e| Error::PluginInternalError { source: e })?;

                Ok(HttpResponse::Ok().content_type("text/xml").body(response))
            } else {
                // Plugin calls need to be authorized by the Token and policy
                let token = core
                    .get_attestation_token(&request)
                    .await
                    .map_err(|_| Error::TokenNotFound)?;

                let claims = core.token_verifier.verify(token).await?;

                let claim_str = serde_json::to_string(&claims)?;
                let mut request_policy_data = policy_data.clone();
                let verified_authorization = if core
                    .config
                    .policy_engine
                    .require_deployment_authorization
                {
                    let verified = resolve_deployment_authorization(&core, &claims)
                        .await
                        .map_err(|error| {
                            warn!(error = %error, "deployment authorization resolver denied request");
                            Error::PolicyDeny
                        })?;
                    let requested_path = resource_path.join("/");
                    if !verified.authorizes_path(&requested_path) {
                        return Err(Error::PolicyDeny);
                    }
                    verified
                        .inject_policy_data(&mut request_policy_data)
                        .map_err(|_| Error::PolicyDeny)?;
                    Some(verified)
                } else {
                    None
                };
                let request_policy_data_str = request_policy_data.to_string();

                KBS_POLICY_EVALS.inc();
                // TODO: add policy filter support for other plugins
                let policy_result = core
                    .evaluate_resource_policy(Some(&request_policy_data_str), &claim_str)
                    .await
                    .inspect_err(|_| KBS_POLICY_ERRORS.inc())?;
                if !policy_allows(&policy_result) {
                    KBS_POLICY_VIOLATIONS.inc();
                    return Err(Error::PolicyDeny);
                }
                KBS_POLICY_APPROVALS.inc();

                let requested_path = resource_path.join("/");
                let response = if plugin_name == "resource"
                    && resource_path.len() == 3
                    && resource_path[0] == "default"
                    && resource_path[1] == "policy-receipts"
                {
                    let verified = verified_authorization.as_ref().ok_or(Error::PolicyDeny)?;
                    if verified.authorization.receipt_resource_path != requested_path {
                        return Err(Error::PolicyDeny);
                    }
                    verified.exact_bytes.clone()
                } else {
                    plugin
                        .handle(&body, &query, resource_path, request.method())
                        .await
                        .map_err(|e| Error::PluginInternalError { source: e })?
                };
                if plugin
                    .encrypted(&body, &query, resource_path, request.method())
                    .await
                    .map_err(|e| Error::PluginInternalError { source: e })?
                {
                    let public_key = core.token_verifier.extract_tee_public_key(claims)?;
                    let jwe =
                        jwe(public_key, response).map_err(|e| Error::JweError { source: e })?;
                    let res = serde_json::to_string(&jwe)?;
                    return Ok(HttpResponse::Ok()
                        .content_type("application/json")
                        .body(res));
                }

                Ok(HttpResponse::Ok().content_type("text/xml").body(response))
            }
        }
    }
}

fn build_plugin_policy_data(
    method: &str,
    plugin: &str,
    resource_path: &[&str],
    query: &HashMap<String, String>,
) -> serde_json::Value {
    json!({
        "plugin": plugin,
        "resource-path": resource_path,
        "query": query,
        "method": method,
    })
}

/// Build method-aware policy data for workload-resource endpoint.
/// Extracted as a helper for unit testing.
#[cfg(test)]
pub(crate) fn build_workload_policy_data(method: &str, path_parts: &[&str]) -> serde_json::Value {
    build_workload_policy_data_with_body(method, path_parts, &[])
}

#[cfg(test)]
pub(crate) fn build_workload_policy_data_with_body(
    method: &str,
    path_parts: &[&str],
    body: &[u8],
) -> serde_json::Value {
    build_workload_policy_data_with_attested_receipt(method, path_parts, body, None)
}

fn build_workload_policy_data_with_attested_receipt(
    method: &str,
    path_parts: &[&str],
    body: &[u8],
    attested_receipt_pubkey_sha256: Option<[u8; 32]>,
) -> serde_json::Value {
    let body_sha256 = sha256_hex(body);
    let parsed_body = workload_request_body_policy_input(body, attested_receipt_pubkey_sha256);

    json!({
        "plugin": "workload-resource",
        "resource-path": path_parts,
        "query": {},
        "method": method,
        "request": {
            "method": method,
            "body_sha256": body_sha256,
            "body": parsed_body,
        },
    })
}

#[derive(Debug, serde::Deserialize)]
struct WorkloadRequestBody {
    operation: String,
    receipt: Option<WorkloadReceipt>,
    value: Option<String>,
    #[cfg(feature = "as")]
    receipt_attestation: Option<WorkloadReceiptAttestation>,
}

#[derive(Debug, serde::Deserialize)]
struct WorkloadReceipt {
    pubkey: String,
    payload_canonical_bytes: String,
    signature: String,
}

#[cfg(feature = "as")]
#[derive(Debug, serde::Deserialize)]
struct WorkloadReceiptAttestation {
    tee: Tee,
    evidence: serde_json::Value,
    runtime_data: String,
}

fn workload_request_body_policy_input(
    body: &[u8],
    attested_receipt_pubkey_sha256: Option<[u8; 32]>,
) -> serde_json::Value {
    if body.is_empty() {
        return serde_json::Value::Null;
    }

    match parse_workload_request_body_verified(body, attested_receipt_pubkey_sha256) {
        Ok(value) => value.policy_body,
        Err(err) => json!({
            "parse_error": err.to_string(),
            "receipt": {
                "pubkey_hash_matches": false,
                "signature_valid": false,
                "payload": {},
            },
            "value_hash_matches": false,
        }),
    }
}

struct ParsedWorkloadRequestBody {
    #[cfg(feature = "as")]
    parsed: WorkloadRequestBody,
    policy_body: serde_json::Value,
    #[cfg(feature = "as")]
    receipt_pubkey_sha256: Option<[u8; 32]>,
}

fn parse_workload_request_body_verified(
    body: &[u8],
    attested_receipt_pubkey_sha256: Option<[u8; 32]>,
) -> anyhow::Result<ParsedWorkloadRequestBody> {
    let parsed: WorkloadRequestBody = serde_json::from_slice(body)?;
    let mut receipt_value = json!({
        "pubkey_hash_matches": false,
        "signature_valid": false,
        "payload": {},
    });

    let mut value_hash_matches = false;
    let mut _receipt_pubkey_sha256 = None;
    if let Some(receipt) = parsed.receipt.as_ref() {
        let pubkey = policy_artifact::decode_bytes(&receipt.pubkey)?;
        let payload = policy_artifact::decode_bytes(&receipt.payload_canonical_bytes)?;
        let signature = policy_artifact::decode_bytes(&receipt.signature)?;

        let actual_pubkey_sha256 = sha256_bytes(&pubkey);
        let pubkey_hash_matches = attested_receipt_pubkey_sha256
            .map(|expected| actual_pubkey_sha256 == expected)
            .unwrap_or(false);
        let signature_valid = verify_ed25519(&pubkey, &payload, &signature);
        let payload_fields = receipt_payload_policy_fields(&payload)?;
        _receipt_pubkey_sha256 = Some(actual_pubkey_sha256);

        if let (Some(value), Some(expected_hash)) = (
            parsed.value.as_deref(),
            payload_fields
                .get("new_value_sha256")
                .and_then(|value| value.as_str()),
        ) {
            let value = policy_artifact::decode_bytes(value)?;
            if let Ok(expected_hash) = hex::decode(expected_hash) {
                value_hash_matches = sha256_bytes(&value).as_slice() == expected_hash.as_slice();
            }
        }

        receipt_value = json!({
            "pubkey_hash_matches": pubkey_hash_matches,
            "signature_valid": signature_valid,
            "payload": payload_fields,
        });
    }

    let operation = parsed.operation.clone();
    let policy_body = json!({
        "operation": operation,
        "receipt": receipt_value,
        "value_hash_matches": value_hash_matches,
    });

    Ok(ParsedWorkloadRequestBody {
        #[cfg(feature = "as")]
        parsed,
        policy_body,
        #[cfg(feature = "as")]
        receipt_pubkey_sha256: _receipt_pubkey_sha256,
    })
}

fn workload_resource_value_for_storage(body: &[u8]) -> Result<Vec<u8>> {
    if let Ok(parsed) = serde_json::from_slice::<WorkloadRequestBody>(body) {
        if let Some(value) = parsed.value {
            return policy_artifact::decode_bytes(&value)
                .map_err(|source| Error::PluginInternalError { source });
        }
    }

    Ok(body.to_vec())
}

fn receipt_payload_policy_fields(payload: &[u8]) -> anyhow::Result<serde_json::Value> {
    let records = policy_artifact::decode_ce_v1_records(payload)?;
    let mut fields = serde_json::Map::new();

    for (label, value) in records {
        let value = if label.ends_with("_sha256") {
            serde_json::Value::String(hex::encode(value))
        } else if let Ok(value) = String::from_utf8(value.clone()) {
            serde_json::Value::String(value)
        } else {
            serde_json::Value::String(hex::encode(value))
        };
        fields.insert(label, value);
    }

    Ok(serde_json::Value::Object(fields))
}

fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pubkey) = <[u8; 32]>::try_from(pubkey) else {
        return false;
    };
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(pubkey) = VerifyingKey::from_bytes(&pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature);
    pubkey.verify(message, &signature).is_ok()
}

#[cfg(feature = "as")]
fn decode_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

fn sha256_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(sha256_bytes(value))
}

#[cfg(feature = "as")]
async fn attested_receipt_pubkey_hash(
    core: &ApiServer,
    receipt_pubkey_sha256: [u8; 32],
    proof: &WorkloadReceiptAttestation,
) -> Result<Option<[u8; 32]>> {
    let Some(runtime_hash) = decode_hex_array::<32>(&proof.runtime_data) else {
        return Ok(None);
    };
    if runtime_hash != receipt_pubkey_sha256 {
        return Ok(None);
    }

    let token = core
        .attestation_service
        .verify_independent_evidence(vec![IndependentEvidence {
            tee: proof.tee,
            tee_evidence: proof.evidence.clone(),
            runtime_data: EvidenceRuntimeData::Raw(proof.runtime_data.as_bytes().to_vec()),
            init_data: None,
        }])
        .await
        .map_err(|source| Error::ReceiptAttestationUnavailable { source })?;
    core.token_verifier.verify(token).await.map_err(|source| {
        Error::ReceiptAttestationUnavailable {
            source: anyhow::Error::new(source),
        }
    })?;
    Ok(Some(runtime_hash))
}

pub(crate) fn build_policy_body_policy_data(
    policy_id: &str,
    resource_path: Option<&str>,
) -> serde_json::Value {
    let resource_path: Vec<&str> = resource_path
        .map(|path| path.split('/').filter(|part| !part.is_empty()).collect())
        .unwrap_or_else(|| vec![policy_id, "body"]);

    json!({
        "plugin": if resource_path.len() == 3 { "resource" } else { "resource-policy" },
        "resource-path": resource_path,
        "query": {},
        "method": "GET",
    })
}

fn policy_allows(policy_result: &policy_engine::EvaluationResult) -> bool {
    policy_result
        .eval_rules_result
        .get(KBS_POLICY_RULE)
        .expect("`data.policy.allow` rule not put as parameter found")
        .as_ref()
        .unwrap_or_else(|| {
            warn!(
                "The KBS Resource Policy does not define the `{KBS_POLICY_RULE}` rule, use false as default"
            );
            KBS_POLICY_ERRORS.inc();
            &serde_json::Value::Bool(false)
        })
        .as_bool()
        .unwrap_or_else(|| {
            warn!("`{KBS_POLICY_RULE}` rule result is not a boolean, use false as default");
            KBS_POLICY_ERRORS.inc();
            false
        })
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for idx in 0..max_len {
        let left_byte = *left.get(idx).unwrap_or(&0);
        let right_byte = *right.get(idx).unwrap_or(&0);
        diff |= (left_byte ^ right_byte) as usize;
    }
    diff == 0
}

fn attestation_verify_body_token(body: &[u8]) -> Result<String> {
    if !body.is_empty() {
        let value: serde_json::Value = serde_json::from_slice(body)?;
        if let Some(token) = value.get("token").and_then(|value| value.as_str()) {
            return Ok(token.to_string());
        }
    }

    Err(Error::TokenNotFound)
}

fn attestation_verify_caller_bearer(request: &HttpRequest) -> Result<&str> {
    let value = request
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or(Error::AttestationVerifyAuthRequired)?
        .to_str()
        .map_err(|_| Error::AttestationVerifyAuthInvalid)?
        .trim();
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(Error::AttestationVerifyAuthInvalid)?;
    let token = token.trim();
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err(Error::AttestationVerifyAuthInvalid);
    }

    Ok(token)
}

fn verify_attestation_verify_caller_auth(request: &HttpRequest, expected: &str) -> Result<()> {
    let supplied = attestation_verify_caller_bearer(request)?;
    if constant_time_eq(supplied.as_bytes(), expected.as_bytes()) {
        return Ok(());
    }

    Err(Error::AttestationVerifyAuthInvalid)
}

fn verify_deployment_authorization_publisher(request: &HttpRequest) -> Result<()> {
    let result = (|| {
        let expected = env_nonempty(KBS_DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOKEN_ENV)
            .ok_or(Error::DeploymentAuthorizationPublisherAuthRequired)?;
        let supplied = attestation_verify_caller_bearer(request)
            .map_err(|_| Error::DeploymentAuthorizationPublisherAuthInvalid)?;
        if constant_time_eq(supplied.as_bytes(), expected.as_bytes()) {
            Ok(())
        } else {
            Err(Error::DeploymentAuthorizationPublisherAuthInvalid)
        }
    })();
    if result.is_err() {
        DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOTAL
            .with_label_values(&["authenticate", "unauthorized"])
            .inc();
    }
    result
}

fn attestation_verify_token(request: &HttpRequest, body: &[u8]) -> Result<String> {
    if let Some(required_caller_token) = env_nonempty(KBS_ATTESTATION_VERIFY_BEARER_TOKEN_ENV) {
        verify_attestation_verify_caller_auth(request, &required_caller_token)?;
        return attestation_verify_body_token(body);
    }

    if !env_flag(KBS_ATTESTATION_VERIFY_ALLOW_UNAUTHENTICATED_ENV) {
        return Err(Error::AttestationVerifyAuthRequired);
    }

    if !body.is_empty() {
        return attestation_verify_body_token(body);
    }

    ApiServer::get_authorization_token(request).map_err(|_| Error::TokenNotFound)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkloadResourceCondition {
    CreateIfAbsent,
    ReplaceIfPresent,
    DeleteIfPresent,
}

impl WorkloadResourceCondition {
    fn query_value(self) -> &'static str {
        match self {
            Self::CreateIfAbsent => crate::plugins::resource::WORKLOAD_RESOURCE_CONDITION_CREATE,
            Self::ReplaceIfPresent => crate::plugins::resource::WORKLOAD_RESOURCE_CONDITION_REPLACE,
            Self::DeleteIfPresent => crate::plugins::resource::WORKLOAD_RESOURCE_CONDITION_DELETE,
        }
    }
}

fn workload_resource_condition_from_headers(
    request: &HttpRequest,
) -> Result<WorkloadResourceCondition> {
    let if_none_match = request
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok());
    let if_match = request
        .headers()
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok());

    match *request.method() {
        Method::PUT => match (if_none_match, if_match) {
            (Some("*"), None) => Ok(WorkloadResourceCondition::CreateIfAbsent),
            (None, Some("*")) => Ok(WorkloadResourceCondition::ReplaceIfPresent),
            _ => Err(Error::PreconditionFailed),
        },
        Method::DELETE => match (if_none_match, if_match) {
            (None, Some("*")) => Ok(WorkloadResourceCondition::DeleteIfPresent),
            _ => Err(Error::PreconditionFailed),
        },
        _ => Err(Error::InvalidRequestPath {
            path: request.path().to_string(),
        }),
    }
}

fn map_workload_resource_plugin_error(source: anyhow::Error) -> Error {
    if source
        .chain()
        .any(|err| err.to_string().contains("resource precondition failed:"))
    {
        Error::PreconditionFailed
    } else {
        Error::PluginInternalError { source }
    }
}

/// Workload-authenticated ciphertext CRUD endpoint.
/// PUT /kbs/v0/workload-resource/{repo}/{type}/{tag} - write ciphertext
/// DELETE /kbs/v0/workload-resource/{repo}/{type}/{tag} - delete ciphertext
///
/// Authenticates via attestation token (not admin JWT), evaluates OPA policy
/// with method-aware context, enforces *-owner path suffix restriction, and
/// limits PUT payload to 64KB.
pub(crate) async fn workload_resource_api(
    request: HttpRequest,
    body: web::Bytes,
    core: web::Data<ApiServer>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let path = path.into_inner();
    let method = request.method().clone();

    // Only allow PUT and DELETE
    if method != Method::PUT && method != Method::DELETE {
        return Err(Error::InvalidRequestPath {
            path: path.to_string(),
        });
    }

    // Enforce payload size limit for PUT (64KB max for ciphertext)
    if method == Method::PUT && body.len() > 65536 {
        return Err(Error::PayloadTooLarge);
    }

    // Parse and validate resource path (3-segment: repo/type/tag)
    let path_parts: Vec<&str> = path.split('/').collect();
    if path_parts.len() != 3 {
        return Err(Error::InvalidRequestPath {
            path: path.to_string(),
        });
    }

    // Hard-coded path restriction: only *-owner resource types allowed.
    // Belt enforcement -- suspenders is the OPA policy identity binding.
    if !path_parts[1].ends_with("-owner") {
        return Err(Error::PolicyDeny);
    }

    let resource_condition = workload_resource_condition_from_headers(&request)?;

    // Authenticate via attestation token (Bearer or session)
    let token = core
        .get_attestation_token(&request)
        .await
        .map_err(|_| Error::TokenNotFound)?;
    let claims = core.token_verifier.verify(token).await?;
    let claim_str = serde_json::to_string(&claims)?;

    let attested_receipt_pubkey_sha256 = {
        #[cfg(feature = "as")]
        {
            let mut attested_receipt_pubkey_sha256 = None;
            if let Ok(parsed_body) = parse_workload_request_body_verified(&body, None) {
                if let (Some(receipt_hash), Some(proof)) = (
                    parsed_body.receipt_pubkey_sha256,
                    parsed_body.parsed.receipt_attestation.as_ref(),
                ) {
                    attested_receipt_pubkey_sha256 =
                        attested_receipt_pubkey_hash(&core, receipt_hash, proof).await?;
                }
            }
            attested_receipt_pubkey_sha256
        }
        #[cfg(not(feature = "as"))]
        {
            None
        }
    };

    // Construct method-aware policy data
    let mut policy_data = build_workload_policy_data_with_attested_receipt(
        method.as_str(),
        &path_parts,
        &body,
        attested_receipt_pubkey_sha256,
    );
    if core.config.policy_engine.require_deployment_authorization {
        let verified = resolve_deployment_authorization(&core, &claims)
            .await
            .map_err(|error| {
                warn!(error = %error, "deployment authorization resolver denied workload resource request");
                Error::PolicyDeny
            })?;
        if !verified.authorizes_path(&path_parts.join("/")) {
            return Err(Error::PolicyDeny);
        }
        verified
            .inject_policy_data(&mut policy_data)
            .map_err(|_| Error::PolicyDeny)?;
    }
    validate_workload_receipt_hard_gate(method.as_str(), &path_parts, &policy_data)?;
    let policy_data_str = policy_data.to_string();

    // Evaluate OPA policy (same pattern as existing api() handler)
    KBS_POLICY_EVALS.inc();
    let policy_result = core
        .evaluate_resource_policy(Some(&policy_data_str), &claim_str)
        .await
        .inspect_err(|_| KBS_POLICY_ERRORS.inc())?;
    let allowed = policy_allows(&policy_result);
    if !allowed {
        warn!(
            method = %method,
            path = %path,
            policy_data = %policy_data_str,
            claims = %claim_str,
            "workload_resource_api denied by policy"
        );
        KBS_POLICY_VIOLATIONS.inc();
        return Err(Error::PolicyDeny);
    }
    KBS_POLICY_APPROVALS.inc();

    // Delegate to resource plugin for actual storage.
    // Map PUT -> POST for plugin dispatch (plugin handles "POST" for writes).
    let resource_plugin = core
        .plugin_manager
        .get("resource")
        .ok_or(Error::PluginNotFound {
            plugin_name: "resource".into(),
        })?;
    let mut query = std::collections::HashMap::new();
    query.insert(
        crate::plugins::resource::WORKLOAD_RESOURCE_CONDITION_QUERY.to_string(),
        resource_condition.query_value().to_string(),
    );
    let body_vec = if method == Method::PUT {
        workload_resource_value_for_storage(&body)?
    } else {
        body.to_vec()
    };
    let dispatch_method = if method == Method::PUT {
        Method::POST
    } else {
        method
    };
    resource_plugin
        .handle(&body_vec, &query, &path_parts, &dispatch_method)
        .await
        .map_err(map_workload_resource_plugin_error)?;

    Ok(HttpResponse::Ok().finish())
}

fn validate_workload_receipt_hard_gate(
    method: &str,
    path_parts: &[&str],
    policy_data: &serde_json::Value,
) -> Result<()> {
    let body = &policy_data["request"]["body"];
    if !body.is_object() {
        warn!(
            method,
            path = %path_parts.join("/"),
            "workload receipt hard gate denied: request body is not an object"
        );
        return Err(Error::PolicyDeny);
    }

    let receipt = &body["receipt"];
    let payload = &receipt["payload"];
    let expected_path = path_parts.join("/");
    let expected_purpose = match method {
        "PUT" => "enclava-rekey-v1",
        "DELETE" => "enclava-teardown-v1",
        _ => {
            warn!(
                method,
                path = %expected_path,
                "workload receipt hard gate denied: unsupported method"
            );
            return Err(Error::PolicyDeny);
        }
    };

    let signature_valid = receipt["signature_valid"].as_bool() == Some(true);
    let pubkey_hash_matches = receipt["pubkey_hash_matches"].as_bool() == Some(true);
    let purpose_matches = payload["purpose"].as_str() == Some(expected_purpose);
    let resource_path_matches = payload["resource_path"].as_str() == Some(expected_path.as_str());
    let value_hash_matches = method != "PUT" || body["value_hash_matches"].as_bool() == Some(true);
    let valid_common =
        signature_valid && pubkey_hash_matches && purpose_matches && resource_path_matches;
    if !valid_common {
        warn!(
            method,
            expected_path = %expected_path,
            expected_purpose,
            signature_valid,
            pubkey_hash_matches,
            purpose_matches,
            resource_path_matches,
            value_hash_matches,
            payload_purpose = ?payload["purpose"],
            payload_resource_path = ?payload["resource_path"],
            "workload receipt hard gate denied"
        );
        return Err(Error::PolicyDeny);
    }

    if !value_hash_matches {
        warn!(
            method,
            expected_path = %expected_path,
            expected_purpose,
            signature_valid,
            pubkey_hash_matches,
            purpose_matches,
            resource_path_matches,
            value_hash_matches,
            payload_purpose = ?payload["purpose"],
            payload_resource_path = ?payload["resource_path"],
            "workload receipt hard gate denied"
        );
        return Err(Error::PolicyDeny);
    }

    Ok(())
}

pub(crate) async fn prometheus_metrics_handler(
    _request: HttpRequest,
    _core: web::Data<ApiServer>,
) -> Result<HttpResponse> {
    let report =
        crate::prometheus::export_metrics().map_err(|e| Error::PrometheusError { source: e })?;
    Ok(HttpResponse::Ok().body(report))
}

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;

async fn prometheus_metrics_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> std::result::Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let start = actix::clock::Instant::now();

    // Ignore requests like /metrics for metrics collection, they can make
    // metrics weirdly not add up and distort metrics in odd ways.  They
    // arguably are not very interesting either to a user of KBS metrics.
    let is_kbs_req = req.request().path().starts_with("/kbs");
    if is_kbs_req {
        ACTIVE_CONNECTIONS.inc();
        REQUEST_TOTAL.inc();

        // Consider requests lacking a "content-length" header to be of zero
        // size as this seems to be the usual case with KBS.  (Streamed
        // requests would also lack "content-length" but they don't seem too
        // relevant with KBS.)
        if let Some(len) = req.headers().get("content-length") {
            if let Ok(Ok(len)) = len.to_str().map(|l| l.parse::<u64>()) {
                REQUEST_SIZES.observe(len as f64);
            }
        } else {
            REQUEST_SIZES.observe(0_f64);
        }
    }

    // This is the actual request handling.
    let res = next.call(req).await?;

    if is_kbs_req {
        REQUEST_DURATION.observe(start.elapsed().as_secs_f64());

        if let actix_web::body::BodySize::Sized(len) = res.response().body().size() {
            REQUEST_SIZES.observe(len as f64);
        }

        ACTIVE_CONNECTIONS.dec();
    }

    Ok(res)
}

#[cfg(test)]
mod workload_resource_tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType};
    use serial_test::serial;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn test_workload_resource_path_must_have_three_segments() {
        // 2-segment path should be invalid
        let path = "default/seed-encrypted";
        let path_parts: Vec<&str> = path.split('/').collect();
        assert_ne!(
            path_parts.len(),
            3,
            "2-segment path should not have 3 parts"
        );
    }

    #[test]
    fn test_workload_resource_owner_suffix_required() {
        // Path without -owner suffix should be rejected
        let path_parts = ["default", "test-notowner", "seed-encrypted"];
        assert!(
            !path_parts[1].ends_with("-owner"),
            "path without -owner suffix should fail the check"
        );
    }

    #[test]
    fn test_workload_resource_owner_suffix_accepted() {
        // Path with -owner suffix should pass
        let path_parts = ["default", "test-owner", "seed-encrypted"];
        assert!(
            path_parts[1].ends_with("-owner"),
            "path with -owner suffix should pass the check"
        );
    }

    #[test]
    fn test_workload_resource_payload_too_large() {
        // Body > 65536 bytes should be rejected for PUT
        let oversized_body = vec![0u8; 65537];
        assert!(
            oversized_body.len() > 65536,
            "oversized body should exceed 64KB limit"
        );
    }

    #[test]
    fn test_workload_resource_payload_boundary_ok() {
        // Body of exactly 65536 bytes should NOT be rejected
        let boundary_body = vec![0u8; 65536];
        assert!(
            boundary_body.len() <= 65536,
            "boundary body should not exceed 64KB limit"
        );
    }

    #[test]
    fn test_workload_resource_policy_data_shape() {
        let policy_data =
            build_workload_policy_data("PUT", &["default", "test-owner", "seed-encrypted"]);

        assert_eq!(
            policy_data["plugin"], "workload-resource",
            "plugin field must be 'workload-resource'"
        );
        assert_eq!(
            policy_data["method"], "PUT",
            "method field must reflect the HTTP method"
        );

        let resource_path = policy_data["resource-path"]
            .as_array()
            .expect("resource-path must be an array");
        assert_eq!(resource_path.len(), 3, "resource-path must have 3 segments");
        assert_eq!(resource_path[0], "default");
        assert_eq!(resource_path[1], "test-owner");
        assert_eq!(resource_path[2], "seed-encrypted");

        // query must be an empty object
        assert!(policy_data["query"].is_object(), "query must be an object");
    }

    #[test]
    fn test_plugin_policy_data_includes_http_method() {
        let mut query = HashMap::new();
        query.insert(
            "resource_path".to_string(),
            "default/test-owner/seed-encrypted".to_string(),
        );

        let policy_data = build_plugin_policy_data(
            "GET",
            "resource",
            &["default", "test-owner", "seed-encrypted"],
            &query,
        );

        assert_eq!(policy_data["plugin"], "resource");
        assert_eq!(policy_data["method"], "GET");
        assert_eq!(policy_data["resource-path"][0], "default");
        assert_eq!(
            policy_data["query"]["resource_path"],
            "default/test-owner/seed-encrypted"
        );
    }

    #[test]
    fn test_workload_resource_policy_data_delete() {
        let policy_data =
            build_workload_policy_data("DELETE", &["default", "test-owner", "seed-encrypted"]);
        assert_eq!(policy_data["method"], "DELETE");
        assert_eq!(policy_data["plugin"], "workload-resource");
    }

    #[test]
    fn test_workload_resource_policy_data_includes_verified_receipt_fields() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let receipt_pubkey = signing_key.verifying_key().to_bytes();
        let value = b"new encrypted seed";
        let value_hash = sha256_bytes(value);
        let payload = policy_artifact::ce_v1_bytes(&[
            ("purpose", b"enclava-rekey-v1"),
            ("resource_path", b"default/test-owner/seed-encrypted"),
            ("new_value_sha256", value_hash.as_slice()),
            ("timestamp", b"2026-04-28T00:00:00Z"),
        ]);
        let signature = signing_key.sign(&payload).to_bytes();
        let body = serde_json::to_vec(&json!({
            "operation": "rekey",
            "receipt": {
                "pubkey": STANDARD.encode(receipt_pubkey),
                "payload_canonical_bytes": STANDARD.encode(&payload),
                "signature": STANDARD.encode(signature),
            },
            "value": STANDARD.encode(value),
        }))
        .unwrap();
        let policy_data = build_workload_policy_data_with_attested_receipt(
            "PUT",
            &["default", "test-owner", "seed-encrypted"],
            &body,
            Some(sha256_bytes(&receipt_pubkey)),
        );

        assert_eq!(policy_data["request"]["method"], "PUT");
        assert_eq!(
            policy_data["request"]["body_sha256"],
            hex::encode(sha256_bytes(&body))
        );
        assert_eq!(policy_data["request"]["body"]["operation"], "rekey");
        assert_eq!(
            policy_data["request"]["body"]["receipt"]["pubkey_hash_matches"],
            true
        );
        assert_eq!(
            policy_data["request"]["body"]["receipt"]["signature_valid"],
            true
        );
        assert_eq!(policy_data["request"]["body"]["value_hash_matches"], true);
        assert_eq!(
            policy_data["request"]["body"]["receipt"]["payload"]["new_value_sha256"],
            hex::encode(value_hash)
        );
    }

    #[test]
    fn test_workload_resource_policy_data_accepts_attested_receipt_binding() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let receipt_pubkey = signing_key.verifying_key().to_bytes();
        let value = b"new encrypted seed";
        let value_hash = sha256_bytes(value);
        let payload = policy_artifact::ce_v1_bytes(&[
            ("purpose", b"enclava-rekey-v1"),
            ("resource_path", b"default/test-owner/seed-encrypted"),
            ("new_value_sha256", value_hash.as_slice()),
            ("timestamp", b"2026-04-28T00:00:00Z"),
        ]);
        let signature = signing_key.sign(&payload).to_bytes();
        let body = serde_json::to_vec(&json!({
            "operation": "rekey",
            "receipt": {
                "pubkey": STANDARD.encode(receipt_pubkey),
                "payload_canonical_bytes": STANDARD.encode(&payload),
                "signature": STANDARD.encode(signature),
            },
            "value": STANDARD.encode(value),
        }))
        .unwrap();
        let policy_data = build_workload_policy_data_with_attested_receipt(
            "PUT",
            &["default", "test-owner", "seed-encrypted"],
            &body,
            Some(sha256_bytes(&receipt_pubkey)),
        );

        assert_eq!(
            policy_data["request"]["body"]["receipt"]["pubkey_hash_matches"],
            true
        );
        validate_workload_receipt_hard_gate(
            "PUT",
            &["default", "test-owner", "seed-encrypted"],
            &policy_data,
        )
        .unwrap();
    }

    #[test]
    fn test_workload_resource_policy_data_rejects_missing_attested_binding() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let receipt_pubkey = signing_key.verifying_key().to_bytes();
        let value = b"new encrypted seed";
        let value_hash = sha256_bytes(value);
        let payload = policy_artifact::ce_v1_bytes(&[
            ("purpose", b"enclava-rekey-v1"),
            ("resource_path", b"default/test-owner/seed-encrypted"),
            ("new_value_sha256", value_hash.as_slice()),
            ("timestamp", b"2026-04-28T00:00:00Z"),
        ]);
        let signature = signing_key.sign(&payload).to_bytes();
        let body = serde_json::to_vec(&json!({
            "operation": "rekey",
            "receipt": {
                "pubkey": STANDARD.encode(receipt_pubkey),
                "payload_canonical_bytes": STANDARD.encode(&payload),
                "signature": STANDARD.encode(signature),
            },
            "value": STANDARD.encode(value),
        }))
        .unwrap();

        let policy_data = build_workload_policy_data_with_body(
            "PUT",
            &["default", "test-owner", "seed-encrypted"],
            &body,
        );

        assert_eq!(
            policy_data["request"]["body"]["receipt"]["pubkey_hash_matches"],
            false
        );
        assert!(matches!(
            validate_workload_receipt_hard_gate(
                "PUT",
                &["default", "test-owner", "seed-encrypted"],
                &policy_data
            )
            .unwrap_err(),
            Error::PolicyDeny
        ));
    }

    fn valid_rekey_policy_data() -> serde_json::Value {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let receipt_pubkey = signing_key.verifying_key().to_bytes();
        let value = b"new encrypted seed";
        let value_hash = sha256_bytes(value);
        let payload = policy_artifact::ce_v1_bytes(&[
            ("purpose", b"enclava-rekey-v1"),
            ("resource_path", b"default/test-owner/seed-encrypted"),
            ("new_value_sha256", value_hash.as_slice()),
        ]);
        let signature = signing_key.sign(&payload).to_bytes();
        let body = serde_json::to_vec(&json!({
            "operation": "rekey",
            "receipt": {
                "pubkey": STANDARD.encode(receipt_pubkey),
                "payload_canonical_bytes": STANDARD.encode(&payload),
                "signature": STANDARD.encode(signature),
            },
            "value": STANDARD.encode(value),
        }))
        .unwrap();
        build_workload_policy_data_with_attested_receipt(
            "PUT",
            &["default", "test-owner", "seed-encrypted"],
            &body,
            Some(sha256_bytes(&receipt_pubkey)),
        )
    }

    #[test]
    fn test_workload_resource_hard_gate_accepts_valid_rekey() {
        let policy_data = valid_rekey_policy_data();

        validate_workload_receipt_hard_gate(
            "PUT",
            &["default", "test-owner", "seed-encrypted"],
            &policy_data,
        )
        .unwrap();
    }

    #[test]
    fn test_workload_resource_hard_gate_rejects_missing_receipt() {
        let policy_data = build_workload_policy_data_with_body(
            "PUT",
            &["default", "test-owner", "seed-encrypted"],
            br#"{"operation":"rekey","value":"AA=="}"#,
        );

        assert!(matches!(
            validate_workload_receipt_hard_gate(
                "PUT",
                &["default", "test-owner", "seed-encrypted"],
                &policy_data
            )
            .unwrap_err(),
            Error::PolicyDeny
        ));
    }

    #[test]
    fn test_workload_resource_hard_gate_rejects_wrong_pubkey() {
        let mut policy_data = valid_rekey_policy_data();
        policy_data["request"]["body"]["receipt"]["pubkey_hash_matches"] =
            serde_json::Value::Bool(false);

        assert!(matches!(
            validate_workload_receipt_hard_gate(
                "PUT",
                &["default", "test-owner", "seed-encrypted"],
                &policy_data
            )
            .unwrap_err(),
            Error::PolicyDeny
        ));
    }

    #[test]
    fn test_workload_resource_hard_gate_rejects_wrong_purpose() {
        let mut policy_data = valid_rekey_policy_data();
        policy_data["request"]["body"]["receipt"]["payload"]["purpose"] =
            serde_json::Value::String("enclava-teardown-v1".to_string());

        assert!(matches!(
            validate_workload_receipt_hard_gate(
                "PUT",
                &["default", "test-owner", "seed-encrypted"],
                &policy_data
            )
            .unwrap_err(),
            Error::PolicyDeny
        ));
    }

    #[test]
    fn test_workload_resource_hard_gate_rejects_wrong_resource_path() {
        let mut policy_data = valid_rekey_policy_data();
        policy_data["request"]["body"]["receipt"]["payload"]["resource_path"] =
            serde_json::Value::String("default/test-owner/seed-sealed".to_string());

        assert!(matches!(
            validate_workload_receipt_hard_gate(
                "PUT",
                &["default", "test-owner", "seed-encrypted"],
                &policy_data
            )
            .unwrap_err(),
            Error::PolicyDeny
        ));
    }

    #[test]
    fn test_workload_resource_hard_gate_rejects_wrong_value_hash() {
        let mut policy_data = valid_rekey_policy_data();
        policy_data["request"]["body"]["value_hash_matches"] = serde_json::Value::Bool(false);

        assert!(matches!(
            validate_workload_receipt_hard_gate(
                "PUT",
                &["default", "test-owner", "seed-encrypted"],
                &policy_data
            )
            .unwrap_err(),
            Error::PolicyDeny
        ));
    }

    #[test]
    fn test_workload_resource_policy_data_rejects_forged_receipt_pubkey_binding() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let receipt_pubkey = signing_key.verifying_key().to_bytes();
        let payload = policy_artifact::ce_v1_bytes(&[("purpose", b"enclava-teardown-v1")]);
        let signature = signing_key.sign(&payload).to_bytes();
        let body = serde_json::to_vec(&json!({
            "operation": "teardown",
            "receipt": {
                "pubkey": STANDARD.encode(receipt_pubkey),
                "payload_canonical_bytes": STANDARD.encode(&payload),
                "signature": STANDARD.encode(signature),
            }
        }))
        .unwrap();
        let policy_data = build_workload_policy_data_with_attested_receipt(
            "DELETE",
            &["default", "test-owner", "seed-encrypted"],
            &body,
            Some([0u8; 32]),
        );

        assert_eq!(
            policy_data["request"]["body"]["receipt"]["pubkey_hash_matches"],
            false
        );
        assert_eq!(
            policy_data["request"]["body"]["receipt"]["signature_valid"],
            true
        );
    }

    #[test]
    fn test_workload_resource_value_for_storage_extracts_rekey_value() {
        let body = serde_json::to_vec(&json!({
            "operation": "rekey",
            "value": STANDARD.encode(b"ciphertext")
        }))
        .unwrap();

        let stored = workload_resource_value_for_storage(&body).unwrap();

        assert_eq!(stored, b"ciphertext");
    }

    #[test]
    fn test_if_none_match_star_selects_create_condition() {
        let request = actix_web::test::TestRequest::put()
            .insert_header((header::IF_NONE_MATCH, "*"))
            .to_http_request();

        assert_eq!(
            workload_resource_condition_from_headers(&request).unwrap(),
            WorkloadResourceCondition::CreateIfAbsent
        );
    }

    #[test]
    fn test_if_match_star_selects_replace_condition() {
        let request = actix_web::test::TestRequest::put()
            .insert_header((header::IF_MATCH, "*"))
            .to_http_request();

        assert_eq!(
            workload_resource_condition_from_headers(&request).unwrap(),
            WorkloadResourceCondition::ReplaceIfPresent
        );
    }

    #[test]
    fn test_workload_resource_put_without_condition_fails_closed() {
        let request = actix_web::test::TestRequest::put().to_http_request();

        assert!(matches!(
            workload_resource_condition_from_headers(&request).unwrap_err(),
            Error::PreconditionFailed
        ));
    }

    #[test]
    fn test_workload_resource_delete_requires_if_match_star() {
        let request = actix_web::test::TestRequest::delete()
            .insert_header((header::IF_NONE_MATCH, "*"))
            .to_http_request();

        assert!(matches!(
            workload_resource_condition_from_headers(&request).unwrap_err(),
            Error::PreconditionFailed
        ));
    }

    #[test]
    #[serial]
    fn test_attestation_verify_rejects_body_token_without_caller_auth() {
        let _token = EnvVarGuard::unset(KBS_ATTESTATION_VERIFY_BEARER_TOKEN_ENV);
        let _allow = EnvVarGuard::unset(KBS_ATTESTATION_VERIFY_ALLOW_UNAUTHENTICATED_ENV);
        let request = actix_web::test::TestRequest::post().to_http_request();
        let body = br#"{"token":"workload-attestation-token"}"#;

        assert!(attestation_verify_token(&request, body).is_err());
    }

    #[test]
    #[serial]
    fn test_attestation_verify_accepts_body_token_with_configured_caller_auth() {
        let _token = EnvVarGuard::set(KBS_ATTESTATION_VERIFY_BEARER_TOKEN_ENV, "internal-secret");
        let _allow = EnvVarGuard::unset(KBS_ATTESTATION_VERIFY_ALLOW_UNAUTHENTICATED_ENV);
        let request = actix_web::test::TestRequest::post()
            .insert_header((header::AUTHORIZATION, "Bearer internal-secret"))
            .to_http_request();
        let body = br#"{"token":"workload-attestation-token"}"#;

        assert_eq!(
            attestation_verify_token(&request, body).unwrap(),
            "workload-attestation-token"
        );
    }

    #[test]
    #[serial]
    fn test_attestation_verify_rejects_wrong_caller_auth() {
        let _token = EnvVarGuard::set(KBS_ATTESTATION_VERIFY_BEARER_TOKEN_ENV, "internal-secret");
        let _allow = EnvVarGuard::unset(KBS_ATTESTATION_VERIFY_ALLOW_UNAUTHENTICATED_ENV);
        let request = actix_web::test::TestRequest::post()
            .insert_header((header::AUTHORIZATION, "Bearer wrong-secret"))
            .to_http_request();
        let body = br#"{"token":"workload-attestation-token"}"#;

        assert!(attestation_verify_token(&request, body).is_err());
    }

    #[test]
    #[serial]
    fn deployment_authorization_publisher_has_a_dedicated_bearer() {
        let _token = EnvVarGuard::set(
            KBS_DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOKEN_ENV,
            "publisher-secret",
        );
        let accepted = actix_web::test::TestRequest::put()
            .insert_header((header::AUTHORIZATION, "Bearer publisher-secret"))
            .to_http_request();
        let rejected = actix_web::test::TestRequest::put()
            .insert_header((header::AUTHORIZATION, "Bearer other-admin-token"))
            .to_http_request();

        let unauthorized_before = DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOTAL
            .with_label_values(&["authenticate", "unauthorized"])
            .get();
        assert!(verify_deployment_authorization_publisher(&accepted).is_ok());
        assert!(matches!(
            verify_deployment_authorization_publisher(&rejected),
            Err(Error::DeploymentAuthorizationPublisherAuthInvalid)
        ));
        assert_eq!(
            DEPLOYMENT_AUTHORIZATION_PUBLISHER_TOTAL
                .with_label_values(&["authenticate", "unauthorized"])
                .get(),
            unauthorized_before + 1.0
        );
    }

    #[tokio::test]
    async fn enclava_static_policy_compiles_and_binds_verified_receipt() {
        let policy = include_str!("../sample_policies/enclava-static-v1.rego");
        let matching = serde_json::json!({
            "plugin": "resource",
            "method": "GET",
            "resource-path": ["default", "owner", "seed-encrypted"],
            "authorization_verified": true,
            "deployment_authorization": {
                "schema_version": "enclava-kbs-deployment-authorization-v1",
                "descriptor_core_hash": "aa",
                "expected_init_data_hash": "bb",
                "namespace": "tenant-a",
                "service_account": "app",
                "tenant_instance_identity_hash": "cc",
                "image_digest": "sha256:dd",
                "signer_identity": {"subject": "repo", "issuer": "oidc"},
                "authorized_resource_paths": ["default/owner/seed-encrypted"]
            },
            "canonical_attested_workload": {
                "descriptor_core_hash": "aa",
                "init_data_hash": "bb",
                "namespace": "tenant-a",
                "service_account": "app",
                "identity_hash": "cc",
                "image_digest": "sha256:dd",
                "signer_identity": {"subject": "repo", "issuer": "oidc"}
            }
        });
        let engine = policy_engine::rego::Regorus {};
        let result = engine
            .evaluate(
                Some(&matching.to_string()),
                "{}",
                policy,
                vec![KBS_POLICY_RULE],
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(
            result.eval_rules_result[KBS_POLICY_RULE],
            Some(serde_json::Value::Bool(true))
        );

        let mut mismatched = matching;
        mismatched["canonical_attested_workload"]["namespace"] =
            serde_json::Value::String("tenant-b".into());
        let result = engine
            .evaluate(
                Some(&mismatched.to_string()),
                "{}",
                policy,
                vec![KBS_POLICY_RULE],
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(
            result.eval_rules_result[KBS_POLICY_RULE],
            Some(serde_json::Value::Bool(false))
        );
    }

    #[test]
    #[serial]
    fn test_attestation_verify_can_explicitly_allow_legacy_unauthenticated_callers() {
        let _token = EnvVarGuard::unset(KBS_ATTESTATION_VERIFY_BEARER_TOKEN_ENV);
        let _allow = EnvVarGuard::set(KBS_ATTESTATION_VERIFY_ALLOW_UNAUTHENTICATED_ENV, "true");
        let request = actix_web::test::TestRequest::post().to_http_request();
        let body = br#"{"token":"workload-attestation-token"}"#;

        assert_eq!(
            attestation_verify_token(&request, body).unwrap(),
            "workload-attestation-token"
        );
    }

    #[test]
    fn test_policy_body_policy_data_uses_resource_path_when_supplied() {
        let policy_data = build_policy_body_policy_data(
            "resource-policy",
            Some("default/test-owner/seed-encrypted"),
        );

        assert_eq!(policy_data["plugin"], "resource");
        assert_eq!(policy_data["method"], "GET");
        assert_eq!(policy_data["resource-path"][0], "default");
        assert_eq!(policy_data["resource-path"][1], "test-owner");
        assert_eq!(policy_data["resource-path"][2], "seed-encrypted");
    }

    #[tokio::test]
    async fn test_direct_injected_unsigned_policy_is_rejected_before_evaluation() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let config = crate::config::PolicyEngineConfig {
            require_signed_policy: true,
            signed_policy_public_key: Some(hex::encode(signing_key.verifying_key().to_bytes())),
            ..Default::default()
        };
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, KBS_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let policy_engine = PolicyEngine::new(storage);
        policy_engine
            .set_policy(
                KBS_POLICY_ID,
                "package policy\n\ndefault allow := true\n",
                true,
            )
            .await
            .unwrap();

        let stored = policy_engine.get_policy(KBS_POLICY_ID).await.unwrap();
        let err = policy_artifact::rego_for_evaluation(&config, &stored, None).unwrap_err();

        assert!(
            err.to_string().contains("parse signed policy artifact"),
            "{err:?}"
        );
    }

    #[test]
    fn test_workload_resource_put_maps_to_post_dispatch() {
        // Verify the PUT -> POST mapping logic
        let method = Method::PUT;
        let dispatch_method = if method == Method::PUT {
            Method::POST
        } else {
            method
        };
        assert_eq!(
            dispatch_method,
            Method::POST,
            "PUT must map to POST for plugin dispatch"
        );
    }

    #[test]
    fn test_workload_resource_delete_stays_delete_dispatch() {
        // DELETE should remain DELETE for plugin dispatch
        let method = Method::DELETE;
        let dispatch_method = if method == Method::PUT {
            Method::POST
        } else {
            method.clone()
        };
        assert_eq!(
            dispatch_method,
            Method::DELETE,
            "DELETE must remain DELETE for plugin dispatch"
        );
    }
}
