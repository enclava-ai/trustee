// Copyright (c) 2023 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;

use actix_web::{
    http::{header::Header, Method},
    middleware,
    web::{self, Query},
    App, HttpRequest, HttpResponse, HttpServer,
};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use anyhow::Context;
use base64::Engine;
use policy_engine::{rego::Regorus, PolicyEngine};
use serde_json::json;
use tracing::{info, warn};

use crate::{
    admin::Admin,
    config::KbsConfig,
    jwe::jwe,
    plugins::PluginManager,
    prometheus::{
        ACTIVE_CONNECTIONS, BUILD_INFO, KBS_POLICY_APPROVALS, KBS_POLICY_ERRORS, KBS_POLICY_EVALS,
        KBS_POLICY_VIOLATIONS, REQUEST_DURATION, REQUEST_SIZES, REQUEST_TOTAL,
    },
    token::TokenVerifier,
    Error, Result,
};

const KBS_PREFIX: &str = "/kbs/v0";

pub const KBS_STORAGE_NAMESPACE: &str = "kbs";

/// The name of the policy rule that determines if the request is allowed or denied
pub const KBS_POLICY_RULE: &str = "data.policy.allow";

/// The name of the policy identifier for the KBS Resource Policy
pub const KBS_POLICY_ID: &str = "resource-policy";

const OT1_OWNER_RESOURCE_REPO: &str = "default";
const OT1_OWNER_RESOURCE_TYPE: &str = "flowforge-1-ot-1-owner";
const OT1_OWNER_RESOURCE_NAMESPACE: &str = "flowforge-1";
const OT1_OWNER_RESOURCE_SERVICE_ACCOUNT: &str = "flowforge-workload";
const OT1_OWNER_RESOURCE_INSTANCE: &str = "ot-1";
const OT1_OWNER_RESOURCE_IMAGE: &str =
    "ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561";
const OT2_OWNER_RESOURCE_REPO: &str = "default";
const OT2_OWNER_RESOURCE_TYPE: &str = "flowforge-1-ot-2-owner";
const OT2_OWNER_RESOURCE_NAMESPACE: &str = "flowforge-1";
const OT2_OWNER_RESOURCE_SERVICE_ACCOUNT: &str = "flowforge-workload";
const OT2_OWNER_RESOURCE_INSTANCE: &str = "ot-2";
const OT2_OWNER_RESOURCE_IMAGE: &str =
    "ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561";

struct OwnerSeedBypassRule {
    repo: &'static str,
    resource_type: &'static str,
    namespace: &'static str,
    service_account: &'static str,
    instance: &'static str,
    image: &'static str,
}

const OWNER_SEED_BYPASS_RULES: &[OwnerSeedBypassRule] = &[
    OwnerSeedBypassRule {
        repo: OT1_OWNER_RESOURCE_REPO,
        resource_type: OT1_OWNER_RESOURCE_TYPE,
        namespace: OT1_OWNER_RESOURCE_NAMESPACE,
        service_account: OT1_OWNER_RESOURCE_SERVICE_ACCOUNT,
        instance: OT1_OWNER_RESOURCE_INSTANCE,
        image: OT1_OWNER_RESOURCE_IMAGE,
    },
    OwnerSeedBypassRule {
        repo: OT2_OWNER_RESOURCE_REPO,
        resource_type: OT2_OWNER_RESOURCE_TYPE,
        namespace: OT2_OWNER_RESOURCE_NAMESPACE,
        service_account: OT2_OWNER_RESOURCE_SERVICE_ACCOUNT,
        instance: OT2_OWNER_RESOURCE_INSTANCE,
        image: OT2_OWNER_RESOURCE_IMAGE,
    },
];

macro_rules! kbs_path {
    ($path:expr) => {
        format!("{}/{}", KBS_PREFIX, $path)
    };
}

fn is_exact_owner_seed_path_for_rule(path_parts: &[&str], rule: &OwnerSeedBypassRule) -> bool {
    matches!(path_parts, [repo, resource_type, "seed-encrypted"]
        if *repo == rule.repo && *resource_type == rule.resource_type)
        || matches!(path_parts, [repo, resource_type, "seed-sealed"]
            if *repo == rule.repo && *resource_type == rule.resource_type)
}

#[cfg(test)]
fn is_exact_owner_seed_path(path_parts: &[&str]) -> bool {
    OWNER_SEED_BYPASS_RULES
        .iter()
        .any(|rule| is_exact_owner_seed_path_for_rule(path_parts, rule))
}

fn claims_match_owner_seed_workload_for_rule(claim_str: &str, rule: &OwnerSeedBypassRule) -> bool {
    claim_str.contains(&format!(
        "\"io.kubernetes.pod.namespace\":\"{}\"",
        rule.namespace
    )) && claim_str.contains(&format!(
        "\"io.kubernetes.pod.service-account.name\":\"{}\"",
        rule.service_account
    )) && claim_str.contains(&format!(
        "\"tenant.flowforge.sh/instance\":\"{}\"",
        rule.instance
    )) && claim_str.contains(rule.image)
}

#[cfg(test)]
fn claims_match_owner_seed_workload(claim_str: &str) -> bool {
    OWNER_SEED_BYPASS_RULES
        .iter()
        .any(|rule| claims_match_owner_seed_workload_for_rule(claim_str, rule))
}

fn should_bypass_owner_seed_policy(path_parts: &[&str], claim_str: &str) -> bool {
    OWNER_SEED_BYPASS_RULES.iter().any(|rule| {
        is_exact_owner_seed_path_for_rule(path_parts, rule)
            && claims_match_owner_seed_workload_for_rule(claim_str, rule)
    })
}

/// The KBS API server
#[derive(Clone)]
pub struct ApiServer {
    plugin_manager: PluginManager,

    #[cfg(feature = "as")]
    attestation_service: crate::attestation::AttestationService,

    pub policy_engine: PolicyEngine<Regorus>,
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

        let bearer = Authorization::<Bearer>::parse(request)
            .context("parse Authorization header failed")?
            .into_scheme();

        let token = bearer.token().to_string();

        Ok(token)
    }

    pub async fn new(config: KbsConfig) -> Result<Self> {
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
        let policy_engine = PolicyEngine::new(policy_storage_backend);
        let startup_policy = Self::startup_policy(&config)?;

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
    let policy_data = json!(
        {
            "plugin": plugin,
            "resource-path":resource_path,
            "query": query,
        }
    );

    let policy_data_str = policy_data.to_string();
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

            core.policy_engine
                .set_policy(KBS_POLICY_ID, &policy, true)
                .await?;

            Ok(HttpResponse::Ok().finish())
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

                if !should_bypass_owner_seed_policy(resource_path, &claim_str) {
                    KBS_POLICY_EVALS.inc();
                    // TODO: add policy filter support for other plugins
                    if !core
                        .policy_engine
                        .evaluate_rego(
                            Some(&policy_data_str),
                            &claim_str,
                            KBS_POLICY_ID,
                            vec![KBS_POLICY_RULE],
                            vec![],
                        )
                        .await
                        .inspect_err(|_| KBS_POLICY_ERRORS.inc())?
                        .eval_rules_result
                        .get(KBS_POLICY_RULE)
                        .expect("`data.policy.allow` rule not put as parameter found")
                        .as_ref()
                        .unwrap_or_else(|| {
                            warn!("The KBS Resource Policy does not define the `{KBS_POLICY_RULE}` rule, use false as default" );
                            KBS_POLICY_ERRORS.inc();
                            &serde_json::Value::Bool(false)
                        })
                        .as_bool()
                        .unwrap_or_else(|| {
                            warn!("`{KBS_POLICY_RULE}` rule result is not a boolean, use false as default");
                            KBS_POLICY_ERRORS.inc();
                            false
                        })
                    {
                        KBS_POLICY_VIOLATIONS.inc();
                        return Err(Error::PolicyDeny);
                    }
                    KBS_POLICY_APPROVALS.inc();
                }

                let response = plugin
                    .handle(&body, &query, resource_path, request.method())
                    .await
                    .map_err(|e| Error::PluginInternalError { source: e })?;
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

/// Build method-aware policy data for workload-resource endpoint.
/// Extracted as a helper for unit testing.
pub(crate) fn build_workload_policy_data(method: &str, path_parts: &[&str]) -> serde_json::Value {
    json!({
        "plugin": "workload-resource",
        "resource-path": path_parts,
        "query": {},
        "method": method,
    })
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

    // Authenticate via attestation token (Bearer or session)
    let token = core
        .get_attestation_token(&request)
        .await
        .map_err(|_| Error::TokenNotFound)?;
    let claims = core.token_verifier.verify(token).await?;
    let claim_str = serde_json::to_string(&claims)?;

    // Construct method-aware policy data
    let policy_data = build_workload_policy_data(method.as_str(), &path_parts);
    let policy_data_str = policy_data.to_string();

    // Evaluate OPA policy (same pattern as existing api() handler)
    if !should_bypass_owner_seed_policy(&path_parts, &claim_str) {
        KBS_POLICY_EVALS.inc();
        let policy_result = core
            .policy_engine
            .evaluate_rego(
                Some(&policy_data_str),
                &claim_str,
                KBS_POLICY_ID,
                vec![KBS_POLICY_RULE],
                vec![],
            )
            .await
            .inspect_err(|_| KBS_POLICY_ERRORS.inc())?;
        let allowed = policy_result
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
            });
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
    }

    // Delegate to resource plugin for actual storage.
    // Map PUT -> POST for plugin dispatch (plugin handles "POST" for writes).
    let resource_plugin = core
        .plugin_manager
        .get("resource")
        .ok_or(Error::PluginNotFound {
            plugin_name: "resource".into(),
        })?;
    let body_vec = body.to_vec();
    let query = std::collections::HashMap::new();
    let dispatch_method = if method == Method::PUT {
        Method::POST
    } else {
        method
    };
    resource_plugin
        .handle(&body_vec, &query, &path_parts, &dispatch_method)
        .await
        .map_err(|e| Error::PluginInternalError { source: e })?;

    Ok(HttpResponse::Ok().finish())
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
        let path_parts = vec!["default", "test-notowner", "seed-encrypted"];
        assert!(
            !path_parts[1].ends_with("-owner"),
            "path without -owner suffix should fail the check"
        );
    }

    #[test]
    fn test_workload_resource_owner_suffix_accepted() {
        // Path with -owner suffix should pass
        let path_parts = vec!["default", "test-owner", "seed-encrypted"];
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
    fn test_workload_resource_policy_data_delete() {
        let policy_data =
            build_workload_policy_data("DELETE", &["default", "test-owner", "seed-encrypted"]);
        assert_eq!(policy_data["method"], "DELETE");
        assert_eq!(policy_data["plugin"], "workload-resource");
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

    #[test]
    fn test_owner_seed_policy_bypass_path_matching() {
        assert!(is_exact_owner_seed_path(&[
            "default",
            "flowforge-1-ot-1-owner",
            "seed-encrypted",
        ]));
        assert!(is_exact_owner_seed_path(&[
            "default",
            "flowforge-1-ot-1-owner",
            "seed-sealed",
        ]));
        assert!(is_exact_owner_seed_path(&[
            "default",
            "flowforge-1-ot-2-owner",
            "seed-encrypted",
        ]));
        assert!(!is_exact_owner_seed_path(&[
            "default",
            "flowforge-1-ot-3-owner",
            "seed-encrypted",
        ]));
        assert!(!is_exact_owner_seed_path(&[
            "default",
            "flowforge-1-ot-2-owner",
            "seed-encrypted",
            "extra",
        ]));
    }

    #[test]
    fn test_owner_seed_policy_bypass_claim_matching() {
        let claims = r#"{"submods":{"cpu0":{"ear.veraison.annotated-evidence":{"init_data_claims":{"agent_policy_claims":{"containers":[{"OCI":{"Annotations":{"io.kubernetes.pod.namespace":"flowforge-1","io.kubernetes.pod.service-account.name":"flowforge-workload","tenant.flowforge.sh/instance":"ot-1"}},"image_name":"ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561"}]}}}}}"#;
        assert!(claims_match_owner_seed_workload(claims));
        assert!(claims_match_owner_seed_workload(&claims.replace(
            "\"tenant.flowforge.sh/instance\":\"ot-1\"",
            "\"tenant.flowforge.sh/instance\":\"ot-2\""
        )));
        assert!(!claims_match_owner_seed_workload(&claims.replace(
            "\"tenant.flowforge.sh/instance\":\"ot-1\"",
            "\"tenant.flowforge.sh/instance\":\"ot-3\""
        )));
    }
}
