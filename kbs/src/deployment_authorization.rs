use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use key_value_storage::{KeyValueStorageInstance, SetParameters, SetResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::PolicyEngineConfig;

pub const SCHEMA_V1: &str = "enclava-kbs-deployment-authorization-v1";
pub const MAX_BYTES: usize = 16 * 1024;

pub fn validate_config(config: &PolicyEngineConfig) -> Result<()> {
    if !config.require_deployment_authorization {
        return Ok(());
    }
    if config.deployment_authorization_public_keys.is_empty() {
        bail!("deployment authorization trust map is required");
    }
    for (key_id, key) in &config.deployment_authorization_public_keys {
        if key_id.is_empty() || key_id.len() > 255 {
            bail!("deployment authorization key id is invalid");
        }
        decode_key(key).context("parse deployment authorization trust key")?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentAuthorization {
    pub schema_version: String,
    pub authorization_id: Uuid,
    pub org_id: Uuid,
    pub app_id: Uuid,
    pub descriptor_deploy_id: Uuid,
    #[serde(with = "hex32")]
    pub descriptor_core_hash: [u8; 32],
    #[serde(with = "hex32")]
    pub expected_init_data_hash: [u8; 32],
    pub namespace: String,
    pub service_account: String,
    #[serde(with = "hex32")]
    pub tenant_instance_identity_hash: [u8; 32],
    pub org_owner_version: u64,
    #[serde(with = "hex32")]
    pub org_owner_pubkey_sha256: [u8; 32],
    pub image_digest: String,
    pub signer_identity: SignerIdentity,
    pub receipt_resource_path: String,
    pub authorized_resource_paths: Vec<String>,
    #[serde(with = "hex32")]
    pub rego_sha256: [u8; 32],
    #[serde(with = "hex32")]
    pub agent_policy_sha256: [u8; 32],
    #[serde(with = "hex32")]
    pub artifact_bundle_digest: [u8; 32],
    pub issuer_key_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature_alg: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignerIdentity {
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PublicationState {
    Active,
    Inactive,
    Tombstoned,
}

pub struct AuthorizationStore {
    storage: KeyValueStorageInstance,
}

impl AuthorizationStore {
    pub fn new(storage: KeyValueStorageInstance) -> Self {
        Self { storage }
    }

    async fn storage_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.storage
            .get(key)
            .await
            .context("deployment authorization storage read")
    }

    async fn storage_set(
        &self,
        key: &str,
        value: &[u8],
        parameters: SetParameters,
    ) -> Result<SetResult> {
        self.storage
            .set(key, value, parameters)
            .await
            .context("deployment authorization storage write")
    }

    pub async fn validate_storage(&self) -> Result<()> {
        let _ = self
            .storage_get("deployment-authorization/startup-probe")
            .await?;
        Ok(())
    }

    pub async fn publish(
        &self,
        config: &PolicyEngineConfig,
        descriptor_hash: &[u8; 32],
        exact_bytes: &[u8],
    ) -> Result<()> {
        let authorization = parse_and_verify(config, exact_bytes)?;
        if &authorization.descriptor_core_hash != descriptor_hash {
            bail!("authorization descriptor hash does not match endpoint");
        }
        if self.tombstoned(descriptor_hash).await? {
            bail!("deployment authorization is terminally revoked");
        }
        let key = body_key(descriptor_hash);
        match self
            .storage_set(&key, exact_bytes, SetParameters { overwrite: false })
            .await?
        {
            SetResult::Inserted => {}
            SetResult::AlreadyExists => {
                let existing = self
                    .storage_get(&key)
                    .await?
                    .context("authorization body disappeared after conflict")?;
                if existing != exact_bytes {
                    bail!("immutable deployment authorization conflict");
                }
            }
        }
        self.set_state(descriptor_hash, PublicationState::Active)
            .await
    }

    pub async fn publisher_readback(&self, descriptor_hash: &[u8; 32]) -> Result<Vec<u8>> {
        if self.state(descriptor_hash).await? != Some(PublicationState::Active)
            || self.tombstoned(descriptor_hash).await?
        {
            bail!("deployment authorization is not active");
        }
        self.storage_get(&body_key(descriptor_hash))
            .await?
            .context("deployment authorization body not found")
    }

    pub async fn deactivate(&self, descriptor_hash: &[u8; 32]) -> Result<()> {
        if self.tombstoned(descriptor_hash).await? {
            return Ok(());
        }
        if self
            .storage_get(&body_key(descriptor_hash))
            .await?
            .is_some()
        {
            self.set_state(descriptor_hash, PublicationState::Inactive)
                .await?;
        }
        Ok(())
    }

    pub async fn revoke(&self, descriptor_hash: &[u8; 32]) -> Result<()> {
        self.storage_set(
            &tombstone_key(descriptor_hash),
            b"enclava-kbs-authorization-tombstone-v1",
            SetParameters { overwrite: false },
        )
        .await?;
        self.set_state(descriptor_hash, PublicationState::Tombstoned)
            .await
    }

    pub async fn resolve(
        &self,
        config: &PolicyEngineConfig,
        claims: &Value,
    ) -> Result<VerifiedAuthorization> {
        let canonical_claims = CanonicalClaims::extract(claims)?;
        let descriptor_hash = canonical_claims.descriptor_core_hash;
        if self.tombstoned(&descriptor_hash).await?
            || self.state(&descriptor_hash).await? != Some(PublicationState::Active)
        {
            bail!("deployment authorization is inactive or revoked");
        }
        let exact_bytes = self
            .storage_get(&body_key(&descriptor_hash))
            .await?
            .context("deployment authorization not found")?;
        let authorization = parse_and_verify(config, &exact_bytes)?;
        verify_claim_bindings(&authorization, &canonical_claims)?;
        if self.tombstoned(&descriptor_hash).await?
            || self.state(&descriptor_hash).await? != Some(PublicationState::Active)
        {
            bail!("deployment authorization changed while being verified");
        }
        Ok(VerifiedAuthorization {
            authorization,
            exact_bytes,
            canonical_claims,
        })
    }

    async fn set_state(&self, hash: &[u8; 32], state: PublicationState) -> Result<()> {
        self.storage_set(
            &state_key(hash),
            &serde_json::to_vec(&state)?,
            SetParameters { overwrite: true },
        )
        .await?;
        Ok(())
    }

    async fn state(&self, hash: &[u8; 32]) -> Result<Option<PublicationState>> {
        self.storage_get(&state_key(hash))
            .await?
            .map(|bytes| serde_json::from_slice(&bytes).context("parse authorization state"))
            .transpose()
    }

    async fn tombstoned(&self, hash: &[u8; 32]) -> Result<bool> {
        Ok(self.storage_get(&tombstone_key(hash)).await?.is_some())
    }
}

pub struct VerifiedAuthorization {
    pub authorization: DeploymentAuthorization,
    pub exact_bytes: Vec<u8>,
    canonical_claims: CanonicalClaims,
}

impl VerifiedAuthorization {
    pub fn inject_policy_data(&self, data: &mut Value) -> Result<()> {
        let object = data
            .as_object_mut()
            .context("policy data must be a JSON object")?;
        object.insert("authorization_verified".into(), Value::Bool(true));
        object.insert(
            "deployment_authorization".into(),
            serde_json::to_value(&self.authorization)?,
        );
        object.insert(
            "canonical_attested_workload".into(),
            self.canonical_claims.policy_value(),
        );
        Ok(())
    }

    pub fn authorizes_path(&self, path: &str) -> bool {
        self.authorization
            .authorized_resource_paths
            .binary_search_by(|candidate| candidate.as_str().cmp(path))
            .is_ok()
    }
}

#[derive(Debug)]
struct CanonicalClaims {
    descriptor_core_hash: [u8; 32],
    init_data_hash: [u8; 32],
    namespace: String,
    service_account: String,
    identity_hash: [u8; 32],
    image_digest: String,
    signer_subject: String,
    signer_issuer: String,
}

impl CanonicalClaims {
    fn extract(value: &Value) -> Result<Self> {
        let evidence = value
            .pointer("/submods/cpu0/ear.veraison.annotated-evidence")
            .and_then(Value::as_object)
            .context("annotated CPU evidence is missing")?;
        let init_data_claims = evidence
            .get("init_data_claims")
            .and_then(Value::as_object)
            .context("verified init-data claims are missing")?;

        Ok(Self {
            descriptor_core_hash: required_hex_claim(init_data_claims, "descriptor_core_hash")?,
            init_data_hash: required_hex_claim(evidence, "init_data")?,
            namespace: required_string_claim(init_data_claims, "namespace")?.into(),
            service_account: required_string_claim(init_data_claims, "service_account")?.into(),
            identity_hash: required_hex_claim(init_data_claims, "identity_hash")?,
            image_digest: normalize_image_digest(required_string_claim(
                init_data_claims,
                "image_digest",
            )?)?,
            signer_subject: required_string_claim(init_data_claims, "signer_identity_subject")?
                .into(),
            signer_issuer: required_string_claim(init_data_claims, "signer_identity_issuer")?
                .into(),
        })
    }

    fn policy_value(&self) -> Value {
        json!({
            "descriptor_core_hash": hex::encode(self.descriptor_core_hash),
            "init_data_hash": hex::encode(self.init_data_hash),
            "namespace": self.namespace,
            "service_account": self.service_account,
            "identity_hash": hex::encode(self.identity_hash),
            "image_digest": self.image_digest,
            "signer_identity": {
                "subject": self.signer_subject,
                "issuer": self.signer_issuer,
            }
        })
    }
}

fn verify_claim_bindings(
    authorization: &DeploymentAuthorization,
    claims: &CanonicalClaims,
) -> Result<()> {
    if authorization.descriptor_core_hash != claims.descriptor_core_hash
        || authorization.expected_init_data_hash != claims.init_data_hash
        || authorization.namespace != claims.namespace
        || authorization.service_account != claims.service_account
        || authorization.tenant_instance_identity_hash != claims.identity_hash
        || authorization.image_digest != claims.image_digest
        || authorization.signer_identity.subject != claims.signer_subject
        || authorization.signer_identity.issuer != claims.signer_issuer
    {
        bail!("deployment authorization does not match attested claims");
    }
    Ok(())
}

pub fn parse_and_verify(
    config: &PolicyEngineConfig,
    exact_bytes: &[u8],
) -> Result<DeploymentAuthorization> {
    let result = parse_and_verify_inner(config, exact_bytes);
    crate::prometheus::DEPLOYMENT_AUTHORIZATION_VERIFY_TOTAL
        .with_label_values(&[if result.is_ok() { "success" } else { "deny" }])
        .inc();
    result
}

fn parse_and_verify_inner(
    config: &PolicyEngineConfig,
    exact_bytes: &[u8],
) -> Result<DeploymentAuthorization> {
    if exact_bytes.len() > MAX_BYTES {
        bail!("deployment authorization exceeds 16 KiB");
    }
    let authorization: DeploymentAuthorization =
        serde_json::from_slice(exact_bytes).context("parse deployment authorization")?;
    validate_contract(&authorization)?;
    let configured_key = config
        .deployment_authorization_public_keys
        .get(&authorization.issuer_key_id)
        .context("authorization issuer key id is not trusted")?;
    let key_bytes = decode_key(configured_key)?;
    let key = VerifyingKey::from_bytes(&key_bytes).context("parse authorization issuer key")?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(authorization.signature.as_bytes())
        .context("decode authorization signature")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("signature is {} bytes", bytes.len()))?;
    key.verify(
        &authorization_signing_bytes(&authorization),
        &Signature::from_bytes(&signature),
    )
    .context("verify deployment authorization signature")?;
    let now = Utc::now();
    if now < authorization.issued_at || authorization.expires_at.is_some_and(|expiry| now >= expiry)
    {
        bail!("deployment authorization is outside its validity window");
    }
    Ok(authorization)
}

fn validate_contract(value: &DeploymentAuthorization) -> Result<()> {
    if value.schema_version != SCHEMA_V1
        || value.signature_alg != "ed25519"
        || value.org_owner_version == 0
        || value.issuer_key_id.is_empty()
        || value.authorized_resource_paths.is_empty()
        || value.authorized_resource_paths.len() > 8
        || value
            .authorized_resource_paths
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || value
            .authorized_resource_paths
            .iter()
            .any(|path| !valid_resource_path(path))
        || value.receipt_resource_path != receipt_path(&value.descriptor_core_hash)
        || value
            .authorized_resource_paths
            .binary_search(&value.receipt_resource_path)
            .is_err()
        || value
            .expires_at
            .is_some_and(|expiry| expiry <= value.issued_at)
    {
        bail!("deployment authorization contract is invalid");
    }
    Ok(())
}

fn authorization_signing_bytes(value: &DeploymentAuthorization) -> Vec<u8> {
    let paths_hash = canonical_paths_hash(&value.authorized_resource_paths);
    let signer_hash = ce_v1_hash(&[
        ("subject", value.signer_identity.subject.as_bytes()),
        ("issuer", value.signer_identity.issuer.as_bytes()),
    ]);
    let owner_version = value.org_owner_version.to_be_bytes();
    let issued_at = normalized_timestamp(value.issued_at);
    let expires_at = value
        .expires_at
        .map(normalized_timestamp)
        .unwrap_or_default();
    ce_v1_bytes(&[
        ("purpose", SCHEMA_V1.as_bytes()),
        ("schema_version", value.schema_version.as_bytes()),
        ("authorization_id", value.authorization_id.as_bytes()),
        ("org_id", value.org_id.as_bytes()),
        ("app_id", value.app_id.as_bytes()),
        (
            "descriptor_deploy_id",
            value.descriptor_deploy_id.as_bytes(),
        ),
        ("descriptor_core_hash", &value.descriptor_core_hash),
        ("expected_init_data_hash", &value.expected_init_data_hash),
        ("namespace", value.namespace.as_bytes()),
        ("service_account", value.service_account.as_bytes()),
        (
            "tenant_instance_identity_hash",
            &value.tenant_instance_identity_hash,
        ),
        ("org_owner_version", &owner_version),
        ("org_owner_pubkey_sha256", &value.org_owner_pubkey_sha256),
        ("image_digest", value.image_digest.as_bytes()),
        ("signer_identity", &signer_hash),
        (
            "receipt_resource_path",
            value.receipt_resource_path.as_bytes(),
        ),
        ("authorized_resource_paths", &paths_hash),
        ("rego_sha256", &value.rego_sha256),
        ("agent_policy_sha256", &value.agent_policy_sha256),
        ("artifact_bundle_digest", &value.artifact_bundle_digest),
        ("issuer_key_id", value.issuer_key_id.as_bytes()),
        ("issued_at", issued_at.as_bytes()),
        ("expires_at", expires_at.as_bytes()),
        ("signature_alg", value.signature_alg.as_bytes()),
    ])
}

fn required_hex_claim(object: &serde_json::Map<String, Value>, key: &str) -> Result<[u8; 32]> {
    decode_lower_hex32(required_string_claim(object, key)?)
        .with_context(|| format!("invalid attestation claim {key}"))
}

fn required_string_claim<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("required attestation claim {key} is missing"))
}

fn normalize_image_digest(value: &str) -> Result<String> {
    let digest = value.rsplit_once('@').map_or(value, |(_, digest)| digest);
    if digest.len() != 71
        || !digest.starts_with("sha256:")
        || !digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("image digest claim is invalid");
    }
    Ok(digest.to_string())
}

fn valid_resource_path(value: &str) -> bool {
    if !value.is_ascii() || value.starts_with('/') || value.contains('%') || value.contains('\\') {
        return false;
    }
    let segments: Vec<_> = value.split('/').collect();
    segments.len() == 3
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && *segment != "."
                && *segment != ".."
                && !segment.starts_with('.')
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn body_key(hash: &[u8; 32]) -> String {
    format!("deployment-authorization/body/{}", hex::encode(hash))
}

fn state_key(hash: &[u8; 32]) -> String {
    format!("deployment-authorization/state/{}", hex::encode(hash))
}

fn tombstone_key(hash: &[u8; 32]) -> String {
    format!("deployment-authorization/tombstone/{}", hex::encode(hash))
}

fn receipt_path(hash: &[u8; 32]) -> String {
    format!("default/policy-receipts/{}", hex::encode(hash))
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    if let Ok(bytes) = hex::decode(value) {
        return bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| anyhow::anyhow!("key is {} bytes", bytes.len()));
    }
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .context("decode authorization public key")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("key is {} bytes", bytes.len()))
}

fn decode_lower_hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("claim must be lowercase hex");
    }
    Ok(hex::decode(value)?.try_into().expect("validated length"))
}

fn normalized_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

fn canonical_paths_hash(paths: &[String]) -> [u8; 32] {
    let records: Vec<(String, &[u8])> = paths
        .iter()
        .enumerate()
        .map(|(index, path)| (format!("path-{index}"), path.as_bytes()))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, path)| (label.as_str(), *path))
        .collect();
    ce_v1_hash(&refs)
}

fn ce_v1_bytes(records: &[(&str, &[u8])]) -> Vec<u8> {
    let total = records
        .iter()
        .map(|(label, value)| 2 + label.len() + 4 + value.len())
        .sum();
    let mut bytes = Vec::with_capacity(total);
    for (label, value) in records {
        bytes.extend_from_slice(&(label.len() as u16).to_be_bytes());
        bytes.extend_from_slice(label.as_bytes());
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    bytes
}

fn ce_v1_hash(records: &[(&str, &[u8])]) -> [u8; 32] {
    Sha256::digest(ce_v1_bytes(records)).into()
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error as _;
        let value = String::deserialize(deserializer)?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom("expected lowercase 32-byte hex"));
        }
        hex::decode(value)
            .map_err(D::Error::custom)?
            .try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use chrono::TimeZone as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use key_value_storage::memory::MemoryKeyValueStorage;

    use super::*;

    fn signed_fixture() -> (DeploymentAuthorization, Vec<u8>, PolicyEngineConfig, Value) {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let descriptor_hash = [0x11; 32];
        let receipt = receipt_path(&descriptor_hash);
        let mut authorization = DeploymentAuthorization {
            schema_version: SCHEMA_V1.into(),
            authorization_id: Uuid::from_u128(1),
            org_id: Uuid::from_u128(2),
            app_id: Uuid::from_u128(3),
            descriptor_deploy_id: Uuid::from_u128(4),
            descriptor_core_hash: descriptor_hash,
            expected_init_data_hash: [0x22; 32],
            namespace: "tenant-app".into(),
            service_account: "workload".into(),
            tenant_instance_identity_hash: [0x33; 32],
            org_owner_version: 1,
            org_owner_pubkey_sha256: [0x44; 32],
            image_digest: format!("sha256:{}", "55".repeat(32)),
            signer_identity: SignerIdentity {
                subject: "subject".into(),
                issuer: "issuer".into(),
            },
            receipt_resource_path: receipt.clone(),
            authorized_resource_paths: vec![
                "default/acme-owner/seed-encrypted".into(),
                "default/acme-owner/seed-sealed".into(),
                receipt,
            ],
            rego_sha256: [0x66; 32],
            agent_policy_sha256: [0x77; 32],
            artifact_bundle_digest: [0x88; 32],
            issuer_key_id: "platform-authorization-1".into(),
            issued_at: Utc.with_ymd_and_hms(2026, 1, 1, 1, 2, 3).unwrap(),
            expires_at: None,
            signature_alg: "ed25519".into(),
            signature: URL_SAFE_NO_PAD.encode([0u8; 64]),
        };
        authorization.signature = URL_SAFE_NO_PAD.encode(
            signing_key
                .sign(&authorization_signing_bytes(&authorization))
                .to_bytes(),
        );
        let bytes = serde_json::to_vec(&authorization).unwrap();
        let mut config = PolicyEngineConfig {
            require_deployment_authorization: true,
            deployment_authorization_public_keys: BTreeMap::from([(
                authorization.issuer_key_id.clone(),
                hex::encode(signing_key.verifying_key().to_bytes()),
            )]),
            ..Default::default()
        };
        // The fixture date is stable; keep it valid for the unit test without
        // weakening the production time check.
        config.require_signed_policy = false;
        let claims = json!({
            "submods": {
                "cpu0": {
                    "ear.veraison.annotated-evidence": {
                        "init_data": "22".repeat(32),
                        "init_data_claims": {
                            "descriptor_core_hash": "11".repeat(32),
                            "namespace": "tenant-app",
                            "service_account": "workload",
                            "identity_hash": "33".repeat(32),
                            "image_digest": format!("sha256:{}", "55".repeat(32)),
                            "signer_identity_subject": "subject",
                            "signer_identity_issuer": "issuer"
                        }
                    }
                }
            }
        });
        (authorization, bytes, config, claims)
    }

    #[tokio::test]
    async fn immutable_publish_resolve_deactivate_reactivate_and_tombstone() {
        let (authorization, bytes, config, claims) = signed_fixture();
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let store = AuthorizationStore::new(storage);

        store
            .publish(&config, &authorization.descriptor_core_hash, &bytes)
            .await
            .unwrap();
        assert_eq!(
            store
                .publisher_readback(&authorization.descriptor_core_hash)
                .await
                .unwrap(),
            bytes
        );
        let verified = store.resolve(&config, &claims).await.unwrap();
        assert!(verified.authorizes_path("default/acme-owner/seed-encrypted"));

        store
            .deactivate(&authorization.descriptor_core_hash)
            .await
            .unwrap();
        assert!(store.resolve(&config, &claims).await.is_err());
        store
            .publish(&config, &authorization.descriptor_core_hash, &bytes)
            .await
            .unwrap();
        assert!(store.resolve(&config, &claims).await.is_ok());

        store
            .revoke(&authorization.descriptor_core_hash)
            .await
            .unwrap();
        assert!(store
            .publish(&config, &authorization.descriptor_core_hash, &bytes)
            .await
            .is_err());
    }

    #[test]
    fn canonical_claims_use_only_verified_init_data_locations() {
        let (_, _, _, mut claims) = signed_fixture();
        claims["descriptor_core_hash"] = Value::String("99".repeat(32));
        claims["init_data_hash"] = Value::String("99".repeat(32));

        let extracted = CanonicalClaims::extract(&claims).unwrap();

        assert_eq!(extracted.descriptor_core_hash, [0x11; 32]);
        assert_eq!(extracted.init_data_hash, [0x22; 32]);
    }

    #[test]
    fn canonical_claims_reject_init_hash_from_init_data_claims() {
        let (_, _, _, mut claims) = signed_fixture();
        let evidence = claims
            .pointer_mut("/submods/cpu0/ear.veraison.annotated-evidence")
            .unwrap();
        evidence["init_data_claims"]["init_data_hash"] = Value::String("22".repeat(32));
        evidence.as_object_mut().unwrap().remove("init_data");

        assert!(CanonicalClaims::extract(&claims).is_err());
    }
}
