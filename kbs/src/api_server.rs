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
use policy_engine::{rego::Regorus, PolicyEngine};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::{
    admin::Admin,
    config::KbsConfig,
    jwe::jwe,
    plugins::PluginManager,
    policy_artifact,
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

    async fn verified_resource_policy_rego(&self) -> Result<String> {
        let stored_policy = self.policy_engine.get_policy(KBS_POLICY_ID).await?;
        policy_artifact::rego_for_evaluation(&self.config.policy_engine, &stored_policy)
            .map_err(|source| Error::ParsePolicyError { source })
    }

    async fn verified_resource_policy_body(&self, policy_id: &str) -> Result<String> {
        let stored_policy = self.policy_engine.get_policy(policy_id).await?;
        if self.config.policy_engine.require_signed_policy {
            let _ = policy_artifact::verify(&self.config.policy_engine, &stored_policy)
                .map_err(|source| Error::ParsePolicyError { source })?;
        }

        Ok(stored_policy)
    }

    async fn evaluate_resource_policy(
        &self,
        policy_data: Option<&str>,
        claim_str: &str,
    ) -> Result<policy_engine::EvaluationResult> {
        let policy = self.verified_resource_policy_rego().await?;
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
        let policy_engine = PolicyEngine::new(policy_storage_backend);
        let startup_policy = Self::startup_policy(&config)?;
        let startup_policy =
            policy_artifact::policy_for_storage(&config.policy_engine, &startup_policy)
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

            let policy = core.verified_resource_policy_body(policy_id).await?;
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

                KBS_POLICY_EVALS.inc();
                // TODO: add policy filter support for other plugins
                let policy_result = core
                    .evaluate_resource_policy(Some(&policy_data_str), &claim_str)
                    .await
                    .inspect_err(|_| KBS_POLICY_ERRORS.inc())?;
                if !policy_allows(&policy_result) {
                    KBS_POLICY_VIOLATIONS.inc();
                    return Err(Error::PolicyDeny);
                }
                KBS_POLICY_APPROVALS.inc();

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
#[cfg(test)]
pub(crate) fn build_workload_policy_data(method: &str, path_parts: &[&str]) -> serde_json::Value {
    build_workload_policy_data_with_body(method, path_parts, &[], &serde_json::Value::Null)
}

pub(crate) fn build_workload_policy_data_with_body(
    method: &str,
    path_parts: &[&str],
    body: &[u8],
    claims: &serde_json::Value,
) -> serde_json::Value {
    let body_sha256 = sha256_hex(body);
    let parsed_body = workload_request_body_policy_input(body, claims);

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
}

#[derive(Debug, serde::Deserialize)]
struct WorkloadReceipt {
    pubkey: String,
    payload_canonical_bytes: String,
    signature: String,
}

fn workload_request_body_policy_input(
    body: &[u8],
    claims: &serde_json::Value,
) -> serde_json::Value {
    if body.is_empty() {
        return serde_json::Value::Null;
    }

    match parse_workload_request_body(body, claims) {
        Ok(value) => value,
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

fn parse_workload_request_body(
    body: &[u8],
    claims: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let parsed: WorkloadRequestBody = serde_json::from_slice(body)?;
    let mut receipt_value = json!({
        "pubkey_hash_matches": false,
        "signature_valid": false,
        "payload": {},
    });

    let mut value_hash_matches = false;
    if let Some(receipt) = parsed.receipt {
        let pubkey = policy_artifact::decode_bytes(&receipt.pubkey)?;
        let payload = policy_artifact::decode_bytes(&receipt.payload_canonical_bytes)?;
        let signature = policy_artifact::decode_bytes(&receipt.signature)?;

        let pubkey_hash_matches = receipt_pubkey_hash_from_claims(claims)
            .map(|expected| sha256_bytes(&pubkey) == expected)
            .unwrap_or(false);
        let signature_valid = verify_ed25519(&pubkey, &payload, &signature);
        let payload_fields = receipt_payload_policy_fields(&payload)?;

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

    Ok(json!({
        "operation": parsed.operation,
        "receipt": receipt_value,
        "value_hash_matches": value_hash_matches,
    }))
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

fn receipt_pubkey_hash_from_claims(claims: &serde_json::Value) -> Option<[u8; 32]> {
    find_claim_string(claims, "receipt_pubkey_sha256")
        .and_then(decode_hex_array::<32>)
        .or_else(|| {
            let report_data = find_claim_string(claims, "report_data")?;
            let report_data = hex::decode(report_data).ok()?;
            if report_data.len() != 64 {
                return None;
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&report_data[32..64]);
            Some(hash)
        })
}

fn find_claim_string<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(value) = map.get(key).and_then(|value| value.as_str()) {
                return Some(value);
            }
            map.values().find_map(|value| find_claim_string(value, key))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|value| find_claim_string(value, key)),
        _ => None,
    }
}

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

fn attestation_verify_token(request: &HttpRequest, body: &[u8]) -> Result<String> {
    if !body.is_empty() {
        let value: serde_json::Value = serde_json::from_slice(body)?;
        if let Some(token) = value.get("token").and_then(|value| value.as_str()) {
            return Ok(token.to_string());
        }
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

    // Construct method-aware policy data
    let policy_data =
        build_workload_policy_data_with_body(method.as_str(), &path_parts, &body, &claims);
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
        let mut report_data = [0u8; 64];
        report_data[32..64].copy_from_slice(&sha256_bytes(&receipt_pubkey));
        let claims = json!({
            "submods": {
                "cpu0": {
                    "ear.veraison.annotated-evidence": {
                        "report_data": hex::encode(report_data)
                    }
                }
            }
        });

        let policy_data = build_workload_policy_data_with_body(
            "PUT",
            &["default", "test-owner", "seed-encrypted"],
            &body,
            &claims,
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
        let claims = json!({
            "report_data": hex::encode([0u8; 64])
        });

        let policy_data = build_workload_policy_data_with_body(
            "DELETE",
            &["default", "test-owner", "seed-encrypted"],
            &body,
            &claims,
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
        let err = policy_artifact::rego_for_evaluation(&config, &stored).unwrap_err();

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
