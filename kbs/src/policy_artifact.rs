// Copyright (c) 2026 by Enclava.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::PolicyEngineConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct SignedPolicyArtifact {
    pub metadata: PolicyMetadata,
    pub rego_text: String,
    #[serde(default)]
    pub rego_sha256: Option<String>,
    #[serde(default)]
    pub agent_policy_text: Option<String>,
    #[serde(default)]
    pub agent_policy_sha256: Option<String>,
    pub signature: String,
    #[serde(default)]
    pub verify_pubkey_b64: Option<String>,
    #[serde(default)]
    pub org_keyring: Option<OrgKeyringEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct SignedPolicyArtifactSet {
    #[serde(default)]
    pub schema_version: Option<String>,
    pub artifacts: Vec<SignedPolicyArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct PolicyMetadata {
    pub app_id: String,
    pub deploy_id: String,
    pub descriptor_core_hash: String,
    pub descriptor_signing_pubkey: String,
    pub platform_release_version: String,
    pub policy_template_id: String,
    pub policy_template_sha256: String,
    #[serde(default)]
    pub agent_policy_sha256: Option<String>,
    #[serde(default)]
    pub genpolicy_version_pin: Option<String>,
    pub signed_at: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct OrgKeyringEnvelope {
    pub keyring: OrgKeyring,
    #[serde(with = "hex_signature_array")]
    pub signature: [u8; 64],
    #[serde(with = "hex_bytes32_array")]
    pub signing_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct OrgKeyring {
    pub org_id: Uuid,
    pub version: u64,
    pub members: Vec<KeyringMember>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct KeyringMember {
    pub user_id: Uuid,
    #[serde(with = "hex_bytes32_array")]
    pub pubkey: [u8; 32],
    pub role: KeyringRole,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum KeyringRole {
    Owner,
    Admin,
    Deployer,
}

pub(crate) fn validate_config(config: &PolicyEngineConfig) -> Result<()> {
    if !config.require_signed_policy {
        return Ok(());
    }

    if config.signed_policy_public_key.is_none()
        && config.trusted_org_owner_public_keys.is_empty()
        && config.trusted_descriptor_public_keys.is_empty()
    {
        bail!(
            "signed_policy_public_key, trusted_org_owner_public_keys, or trusted_descriptor_public_keys is required when require_signed_policy is true"
        );
    }
    if let Some(public_key) = config.signed_policy_public_key.as_deref() {
        let _ = parse_verifying_key(public_key).context("parse signed_policy_public_key")?;
    }
    for public_key in &config.trusted_org_owner_public_keys {
        let _ = parse_verifying_key(public_key).context("parse trusted_org_owner_public_keys")?;
    }
    for public_key in &config.trusted_descriptor_public_keys {
        let _ = parse_verifying_key(public_key).context("parse trusted_descriptor_public_keys")?;
    }

    Ok(())
}

pub(crate) fn rego_for_evaluation(
    config: &PolicyEngineConfig,
    stored_policy: &str,
    claim_str: Option<&str>,
) -> Result<String> {
    if config.require_signed_policy {
        return select_verified_artifact(config, stored_policy, claim_str)
            .map(|artifact| artifact.rego_text);
    }

    Ok(stored_policy.to_string())
}

pub(crate) fn policy_body_for_claims(
    config: &PolicyEngineConfig,
    stored_policy: &str,
    claim_str: Option<&str>,
) -> Result<String> {
    if config.require_signed_policy {
        let artifact = select_verified_artifact(config, stored_policy, claim_str)?;
        return Ok(serde_json::to_string(&artifact)?);
    }

    Ok(stored_policy.to_string())
}

pub(crate) fn policy_for_storage(config: &PolicyEngineConfig, policy_body: &str) -> Result<String> {
    if config.require_signed_policy {
        verify_policy_body(config, policy_body)?;
    }

    Ok(policy_body.to_string())
}

pub(crate) fn verify(
    config: &PolicyEngineConfig,
    policy_body: &str,
) -> Result<SignedPolicyArtifact> {
    let artifact: SignedPolicyArtifact =
        serde_json::from_str(policy_body).context("parse signed policy artifact")?;
    verify_artifact(config, artifact)
}

fn verify_policy_body(config: &PolicyEngineConfig, policy_body: &str) -> Result<()> {
    if let Ok(set) = serde_json::from_str::<SignedPolicyArtifactSet>(policy_body) {
        if set.artifacts.is_empty() {
            bail!("signed policy artifact set is empty");
        }
        for artifact in set.artifacts {
            let _ = verify_artifact(config, artifact)?;
        }
        return Ok(());
    }

    let _ = verify(config, policy_body)?;
    Ok(())
}

fn select_verified_artifact(
    config: &PolicyEngineConfig,
    policy_body: &str,
    claim_str: Option<&str>,
) -> Result<SignedPolicyArtifact> {
    if let Ok(set) = serde_json::from_str::<SignedPolicyArtifactSet>(policy_body) {
        if set.artifacts.is_empty() {
            bail!("signed policy artifact set is empty");
        }
        let descriptor_core_hash = claim_str
            .and_then(extract_descriptor_core_hash)
            .context("descriptor_core_hash missing from attestation claims")?;
        for artifact in set.artifacts {
            let artifact = verify_artifact(config, artifact)?;
            if same_encoded_32(
                &artifact.metadata.descriptor_core_hash,
                &descriptor_core_hash,
            ) {
                return Ok(artifact);
            }
        }
        bail!("no signed policy artifact matches descriptor_core_hash");
    }

    verify(config, policy_body)
}

fn verify_artifact(
    config: &PolicyEngineConfig,
    artifact: SignedPolicyArtifact,
) -> Result<SignedPolicyArtifact> {
    let message = policy_artifact_message(&artifact)?;
    let signature = decode_fixed::<64>(&artifact.signature).context("decode policy signature")?;
    let signature = Signature::from_bytes(&signature);

    if let Some(public_key) = config.signed_policy_public_key.as_deref() {
        let key = parse_verifying_key(public_key)?;
        if key.verify(&message, &signature).is_ok() {
            return Ok(artifact);
        }
    }

    if !config.trusted_org_owner_public_keys.is_empty()
        && verify_customer_org_chain(config, &artifact, &message, &signature).is_ok()
    {
        return Ok(artifact);
    }

    if config
        .trusted_descriptor_public_keys
        .iter()
        .any(|trusted| same_public_key(trusted, &artifact.metadata.descriptor_signing_pubkey))
    {
        let descriptor_key = parse_verifying_key(&artifact.metadata.descriptor_signing_pubkey)
            .context("parse descriptor_signing_pubkey")?;
        if descriptor_key.verify(&message, &signature).is_ok() {
            return Ok(artifact);
        }
    }

    bail!("verify policy artifact signature with configured trust anchors")
}

fn verify_customer_org_chain(
    config: &PolicyEngineConfig,
    artifact: &SignedPolicyArtifact,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    let keyring = artifact
        .org_keyring
        .as_ref()
        .context("org_keyring missing from customer-signed policy artifact")?;
    let descriptor_pubkey = decode_fixed::<32>(&artifact.metadata.descriptor_signing_pubkey)
        .context("decode descriptor_signing_pubkey")?;
    if artifact
        .verify_pubkey_b64
        .as_deref()
        .is_some_and(|hint| !same_decoded_public_key(hint, &descriptor_pubkey))
    {
        bail!("artifact.verify_pubkey_b64 does not match descriptor_signing_pubkey");
    }

    let descriptor_key =
        VerifyingKey::from_bytes(&descriptor_pubkey).context("parse descriptor_signing_pubkey")?;
    descriptor_key
        .verify(message, signature)
        .context("policy artifact signature did not verify with descriptor_signing_pubkey")?;

    for trusted_owner in &config.trusted_org_owner_public_keys {
        let owner_key =
            parse_verifying_key(trusted_owner).context("parse trusted org owner key")?;
        if verify_org_keyring(keyring, &owner_key).is_ok()
            && keyring_authorizes_deployer(&keyring.keyring, &descriptor_pubkey)
        {
            return Ok(());
        }
    }

    bail!("descriptor_signing_pubkey is not authorized by a trusted org keyring")
}

fn verify_org_keyring(envelope: &OrgKeyringEnvelope, trusted_owner: &VerifyingKey) -> Result<()> {
    if envelope.signing_pubkey != trusted_owner.to_bytes() {
        bail!("org keyring signer does not match trusted owner pubkey");
    }
    let signature = Signature::from_bytes(&envelope.signature);
    trusted_owner
        .verify(&canonical_keyring_bytes(&envelope.keyring), &signature)
        .context("org keyring owner signature verification failed")?;
    if !envelope.keyring.members.iter().any(|member| {
        matches!(member.role, KeyringRole::Owner) && member.pubkey == trusted_owner.to_bytes()
    }) {
        bail!("org keyring does not contain trusted owner as owner member");
    }
    Ok(())
}

fn keyring_authorizes_deployer(keyring: &OrgKeyring, descriptor_pubkey: &[u8; 32]) -> bool {
    keyring.members.iter().any(|member| {
        member.pubkey == *descriptor_pubkey
            && matches!(
                member.role,
                KeyringRole::Owner | KeyringRole::Admin | KeyringRole::Deployer
            )
    })
}

fn extract_descriptor_core_hash(claim_str: &str) -> Option<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_str(claim_str).ok()?;
    extract_hex_claim(&value, "descriptor_core_hash")
}

fn extract_hex_claim(value: &serde_json::Value, key: &str) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(hash) = map
                .get(key)
                .and_then(serde_json::Value::as_str)
                .and_then(parse_hex32)
            {
                return Some(hash);
            }
            map.values()
                .find_map(|nested| extract_hex_claim(nested, key))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|nested| extract_hex_claim(nested, key)),
        _ => None,
    }
}

fn parse_hex32(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(trimmed).ok()
}

fn same_encoded_32(left: &str, right: &[u8]) -> bool {
    decode_fixed::<32>(left)
        .map(|left| left.as_slice() == right)
        .unwrap_or(false)
}

fn parse_verifying_key(public_key: &str) -> Result<VerifyingKey> {
    let key = decode_fixed::<32>(public_key).context("decode Ed25519 public key")?;
    VerifyingKey::from_bytes(&key).context("parse Ed25519 public key")
}

fn same_public_key(left: &str, right: &str) -> bool {
    let Ok(left) = decode_fixed::<32>(left) else {
        return false;
    };
    let Ok(right) = decode_fixed::<32>(right) else {
        return false;
    };
    left == right
}

fn same_decoded_public_key(encoded: &str, expected: &[u8; 32]) -> bool {
    decode_fixed::<32>(encoded)
        .map(|decoded| &decoded == expected)
        .unwrap_or(false)
}

fn decode_fixed<const N: usize>(input: &str) -> Result<[u8; N]> {
    for decoded in [
        URL_SAFE_NO_PAD.decode(input).ok(),
        STANDARD.decode(input).ok(),
        hex::decode(input).ok(),
    ]
    .into_iter()
    .flatten()
    {
        if decoded.len() == N {
            return decoded
                .try_into()
                .map_err(|bytes: Vec<u8>| anyhow!("expected {N} bytes, got {}", bytes.len()));
        }
    }

    bail!("expected {N} bytes encoded as hex or base64")
}

fn canonical_keyring_bytes(keyring: &OrgKeyring) -> Vec<u8> {
    let members_hash = canonical_members_hash(&keyring.members);
    let version = keyring.version.to_be_bytes();
    let updated = keyring.updated_at.to_rfc3339();
    ce_v1_bytes(&[
        ("purpose", b"enclava-org-keyring-v1"),
        ("org_id", keyring.org_id.as_bytes().as_slice()),
        ("version", &version),
        ("members", &members_hash),
        ("updated_at", updated.as_bytes()),
    ])
}

fn canonical_member_hash(member: &KeyringMember) -> [u8; 32] {
    let added = member.added_at.to_rfc3339();
    Sha256::digest(ce_v1_bytes(&[
        ("user_id", member.user_id.as_bytes().as_slice()),
        ("pubkey", &member.pubkey),
        ("role", keyring_role_str(&member.role).as_bytes()),
        ("added_at", added.as_bytes()),
    ]))
    .into()
}

fn canonical_members_hash(members: &[KeyringMember]) -> [u8; 32] {
    let mut sorted: Vec<&KeyringMember> = members.iter().collect();
    sorted.sort_by_key(|member| member.user_id);
    let records: Vec<(String, [u8; 32])> = sorted
        .iter()
        .map(|member| (member.user_id.to_string(), canonical_member_hash(member)))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, value)| (label.as_str(), value.as_slice()))
        .collect();
    Sha256::digest(ce_v1_bytes(&refs)).into()
}

fn keyring_role_str(role: &KeyringRole) -> &'static str {
    match role {
        KeyringRole::Owner => "owner",
        KeyringRole::Admin => "admin",
        KeyringRole::Deployer => "deployer",
    }
}

mod hex_bytes32_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        bytes.try_into().map_err(|_| D::Error::custom("len != 32"))
    }
}

mod hex_signature_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        bytes.try_into().map_err(|_| D::Error::custom("len != 64"))
    }
}

pub(crate) fn decode_bytes(input: &str) -> Result<Vec<u8>> {
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(input) {
        return Ok(bytes);
    }
    if let Ok(bytes) = STANDARD.decode(input) {
        return Ok(bytes);
    }
    hex::decode(input).context("input is neither base64 nor hex")
}

pub(crate) fn ce_v1_bytes(records: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (label, value) in records {
        out.extend_from_slice(&(label.len() as u16).to_be_bytes());
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

fn policy_artifact_message(artifact: &SignedPolicyArtifact) -> Result<Vec<u8>> {
    let metadata_hash = canonical_policy_metadata_hash(&artifact.metadata)?;
    let rego_hash: [u8; 32] = Sha256::digest(artifact.rego_text.as_bytes()).into();
    if let Some(expected) = artifact.rego_sha256.as_deref() {
        let expected = decode_fixed::<32>(expected).context("decode rego_sha256")?;
        if expected != rego_hash {
            bail!("rego_sha256 does not match rego_text");
        }
    }
    if let Some(agent_policy_text) = artifact.agent_policy_text.as_deref() {
        let actual: [u8; 32] = Sha256::digest(agent_policy_text.as_bytes()).into();
        let expected = artifact
            .agent_policy_sha256
            .as_deref()
            .or(artifact.metadata.agent_policy_sha256.as_deref())
            .ok_or_else(|| anyhow!("agent_policy_sha256 missing"))?;
        let expected = decode_fixed::<32>(expected).context("decode agent_policy_sha256")?;
        if expected != actual {
            bail!("agent_policy_sha256 does not match agent_policy_text");
        }
    }

    Ok(ce_v1_bytes(&[
        ("purpose", b"enclava-policy-artifact-v1"),
        ("metadata", metadata_hash.as_slice()),
        ("rego_sha256", rego_hash.as_slice()),
    ]))
}

fn canonical_policy_metadata_hash(metadata: &PolicyMetadata) -> Result<[u8; 32]> {
    let app_id = uuid::Uuid::parse_str(&metadata.app_id)
        .context("parse policy metadata app_id")?
        .into_bytes();
    let deploy_id = uuid::Uuid::parse_str(&metadata.deploy_id)
        .context("parse policy metadata deploy_id")?
        .into_bytes();
    let descriptor_core_hash = decode_fixed::<32>(&metadata.descriptor_core_hash)
        .context("decode descriptor_core_hash")?;
    let descriptor_signing_pubkey = decode_fixed::<32>(&metadata.descriptor_signing_pubkey)
        .context("decode descriptor_signing_pubkey")?;
    let policy_template_sha256 = decode_fixed::<32>(&metadata.policy_template_sha256)
        .context("decode policy_template_sha256")?;
    let agent_policy_sha256 = metadata
        .agent_policy_sha256
        .as_deref()
        .map(|value| decode_fixed::<32>(value).context("decode agent_policy_sha256"))
        .transpose()?;
    let genpolicy_version_pin = metadata.genpolicy_version_pin.as_deref().unwrap_or("");

    let mut records: Vec<(&str, &[u8])> = vec![
        ("app_id", app_id.as_slice()),
        ("deploy_id", deploy_id.as_slice()),
        ("descriptor_core_hash", descriptor_core_hash.as_slice()),
        (
            "descriptor_signing_pubkey",
            descriptor_signing_pubkey.as_slice(),
        ),
        (
            "platform_release_version",
            metadata.platform_release_version.as_bytes(),
        ),
        ("policy_template_id", metadata.policy_template_id.as_bytes()),
        ("policy_template_sha256", policy_template_sha256.as_slice()),
    ];
    if let Some(agent_policy_sha256) = agent_policy_sha256.as_ref() {
        records.push(("agent_policy_sha256", agent_policy_sha256.as_slice()));
        records.push(("genpolicy_version_pin", genpolicy_version_pin.as_bytes()));
    }
    records.push(("signed_at", metadata.signed_at.as_bytes()));
    records.push(("key_id", metadata.key_id.as_bytes()));

    Ok(Sha256::digest(ce_v1_bytes(&records)).into())
}

pub(crate) fn decode_ce_v1_records(input: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut offset = 0usize;
    let mut records = Vec::new();

    while offset < input.len() {
        if input.len() - offset < 2 {
            bail!("truncated CE-v1 label length");
        }
        let label_len = u16::from_be_bytes([input[offset], input[offset + 1]]) as usize;
        offset += 2;

        if input.len() - offset < label_len {
            bail!("truncated CE-v1 label");
        }
        let label = std::str::from_utf8(&input[offset..offset + label_len])
            .context("CE-v1 label is not UTF-8")?
            .to_string();
        offset += label_len;

        if input.len() - offset < 4 {
            bail!("truncated CE-v1 value length");
        }
        let value_len = u32::from_be_bytes([
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
        ]) as usize;
        offset += 4;

        if input.len() - offset < value_len {
            bail!("truncated CE-v1 value");
        }
        records.push((label, input[offset..offset + value_len].to_vec()));
        offset += value_len;
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_REGO: &str = "package policy\n\ndefault allow := false\nallow := true\n";

    fn metadata_for(rego: &str) -> PolicyMetadata {
        PolicyMetadata {
            app_id: "11111111-1111-1111-1111-111111111111".into(),
            deploy_id: "22222222-2222-2222-2222-222222222222".into(),
            descriptor_core_hash: "00".repeat(32),
            descriptor_signing_pubkey: "11".repeat(32),
            platform_release_version: "test".into(),
            policy_template_id: "resource-policy".into(),
            policy_template_sha256: hex::encode(Sha256::digest(rego.as_bytes())),
            agent_policy_sha256: None,
            genpolicy_version_pin: None,
            signed_at: "2026-04-28T00:00:00Z".into(),
            key_id: "test-key".into(),
        }
    }

    fn signed_policy(sk: &SigningKey, rego: &str) -> SignedPolicyArtifact {
        let mut artifact = SignedPolicyArtifact {
            metadata: metadata_for(rego),
            rego_text: rego.to_string(),
            rego_sha256: None,
            agent_policy_text: None,
            agent_policy_sha256: None,
            signature: String::new(),
            verify_pubkey_b64: None,
            org_keyring: None,
        };
        let message = policy_artifact_message(&artifact).unwrap();
        artifact.signature = hex::encode(sk.sign(&message).to_bytes());
        artifact
    }

    fn descriptor_signed_policy(sk: &SigningKey, rego: &str) -> SignedPolicyArtifact {
        let mut artifact = signed_policy(sk, rego);
        artifact.metadata.descriptor_signing_pubkey = hex::encode(sk.verifying_key().to_bytes());
        let message = policy_artifact_message(&artifact).unwrap();
        artifact.signature = hex::encode(sk.sign(&message).to_bytes());
        artifact
    }

    fn descriptor_signed_policy_for_hash(
        sk: &SigningKey,
        rego: &str,
        descriptor_core_hash: &str,
    ) -> SignedPolicyArtifact {
        let mut artifact = descriptor_signed_policy(sk, rego);
        artifact.metadata.descriptor_core_hash = descriptor_core_hash.to_string();
        let message = policy_artifact_message(&artifact).unwrap();
        artifact.signature = hex::encode(sk.sign(&message).to_bytes());
        artifact
    }

    fn signed_policy_config(pk: &VerifyingKey) -> PolicyEngineConfig {
        PolicyEngineConfig {
            require_signed_policy: true,
            signed_policy_public_key: Some(hex::encode(pk.to_bytes())),
            trusted_descriptor_public_keys: Vec::new(),
            ..Default::default()
        }
    }

    fn fixed_time() -> DateTime<Utc> {
        "2026-04-01T12:00:00Z".parse().unwrap()
    }

    fn keyring_envelope(owner: &SigningKey, deployer: &SigningKey) -> OrgKeyringEnvelope {
        let keyring = OrgKeyring {
            org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            version: 1,
            members: vec![
                KeyringMember {
                    user_id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
                    pubkey: owner.verifying_key().to_bytes(),
                    role: KeyringRole::Owner,
                    added_at: fixed_time(),
                },
                KeyringMember {
                    user_id: Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap(),
                    pubkey: deployer.verifying_key().to_bytes(),
                    role: KeyringRole::Deployer,
                    added_at: fixed_time(),
                },
            ],
            updated_at: fixed_time(),
        };
        OrgKeyringEnvelope {
            signature: owner.sign(&canonical_keyring_bytes(&keyring)).to_bytes(),
            signing_pubkey: owner.verifying_key().to_bytes(),
            keyring,
        }
    }

    #[test]
    fn valid_signed_policy_unwraps_to_rego() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let artifact = signed_policy(&sk, TEST_REGO);
        let body = serde_json::to_string(&artifact).unwrap();
        let config = signed_policy_config(&sk.verifying_key());

        let rego = rego_for_evaluation(&config, &body, None).unwrap();

        assert_eq!(rego, TEST_REGO);
    }

    #[test]
    fn descriptor_signed_policy_unwraps_without_platform_key() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let artifact = descriptor_signed_policy(&sk, TEST_REGO);
        let body = serde_json::to_string(&artifact).unwrap();
        let config = PolicyEngineConfig {
            require_signed_policy: true,
            signed_policy_public_key: None,
            trusted_descriptor_public_keys: vec![hex::encode(sk.verifying_key().to_bytes())],
            ..Default::default()
        };

        let rego = rego_for_evaluation(&config, &body, None).unwrap();

        assert_eq!(rego, TEST_REGO);
    }

    #[test]
    fn customer_org_owner_keyring_authorizes_descriptor_signed_policy() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let deployer = SigningKey::from_bytes(&[9u8; 32]);
        let mut artifact = descriptor_signed_policy(&deployer, TEST_REGO);
        artifact.verify_pubkey_b64 = Some(hex::encode(deployer.verifying_key().to_bytes()));
        artifact.org_keyring = Some(keyring_envelope(&owner, &deployer));
        let body = serde_json::to_string(&artifact).unwrap();
        let config = PolicyEngineConfig {
            require_signed_policy: true,
            signed_policy_public_key: None,
            trusted_org_owner_public_keys: vec![hex::encode(owner.verifying_key().to_bytes())],
            trusted_descriptor_public_keys: Vec::new(),
            ..Default::default()
        };

        let rego = rego_for_evaluation(&config, &body, None).unwrap();

        assert_eq!(rego, TEST_REGO);
    }

    #[test]
    fn customer_org_owner_keyring_rejects_untrusted_owner() {
        let owner = SigningKey::from_bytes(&[1u8; 32]);
        let wrong_owner = SigningKey::from_bytes(&[2u8; 32]);
        let deployer = SigningKey::from_bytes(&[9u8; 32]);
        let mut artifact = descriptor_signed_policy(&deployer, TEST_REGO);
        artifact.org_keyring = Some(keyring_envelope(&owner, &deployer));
        let body = serde_json::to_string(&artifact).unwrap();
        let config = PolicyEngineConfig {
            require_signed_policy: true,
            signed_policy_public_key: None,
            trusted_org_owner_public_keys: vec![hex::encode(
                wrong_owner.verifying_key().to_bytes(),
            )],
            trusted_descriptor_public_keys: Vec::new(),
            ..Default::default()
        };

        assert!(rego_for_evaluation(&config, &body, None).is_err());
    }

    #[test]
    fn descriptor_signed_policy_is_rejected_without_independent_trust_anchor() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let artifact = descriptor_signed_policy(&sk, TEST_REGO);
        let body = serde_json::to_string(&artifact).unwrap();
        let config = PolicyEngineConfig {
            require_signed_policy: true,
            signed_policy_public_key: None,
            trusted_descriptor_public_keys: Vec::new(),
            ..Default::default()
        };

        assert!(rego_for_evaluation(&config, &body, None).is_err());
    }

    #[test]
    fn unsigned_policy_is_rejected_when_required() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let config = signed_policy_config(&sk.verifying_key());

        let err = rego_for_evaluation(&config, TEST_REGO, None).unwrap_err();

        assert!(
            err.to_string().contains("parse signed policy artifact"),
            "{err:?}"
        );
    }

    #[test]
    fn tampered_policy_is_rejected_when_required() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut artifact = signed_policy(&sk, TEST_REGO);
        artifact.rego_text.push_str("\nallow := false\n");
        let body = serde_json::to_string(&artifact).unwrap();
        let config = signed_policy_config(&sk.verifying_key());

        let err = rego_for_evaluation(&config, &body, None).unwrap_err();

        assert!(
            err.to_string().contains("verify policy artifact signature"),
            "{err:?}"
        );
    }

    #[test]
    fn signed_policy_set_selects_artifact_matching_claim_descriptor_hash() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let old_hash = "11".repeat(32);
        let new_hash = "22".repeat(32);
        let old_rego = "package policy\n\ndefault allow := false\nallow if { input.old }\n";
        let new_rego = "package policy\n\ndefault allow := false\nallow if { input.new }\n";
        let old = descriptor_signed_policy_for_hash(&sk, old_rego, &old_hash);
        let new = descriptor_signed_policy_for_hash(&sk, new_rego, &new_hash);
        let body = serde_json::to_string(&SignedPolicyArtifactSet {
            schema_version: Some("enclava-signed-policy-set-v1".into()),
            artifacts: vec![old, new],
        })
        .unwrap();
        let config = PolicyEngineConfig {
            require_signed_policy: true,
            signed_policy_public_key: None,
            trusted_descriptor_public_keys: vec![hex::encode(sk.verifying_key().to_bytes())],
            ..Default::default()
        };
        let claims = serde_json::json!({
            "claims": {
                "init_data_claims": {
                    "descriptor_core_hash": new_hash
                }
            }
        })
        .to_string();

        let rego = rego_for_evaluation(&config, &body, Some(&claims)).unwrap();
        let selected_body = policy_body_for_claims(&config, &body, Some(&claims)).unwrap();
        let selected: SignedPolicyArtifact = serde_json::from_str(&selected_body).unwrap();

        assert_eq!(rego, new_rego);
        assert_eq!(selected.metadata.descriptor_core_hash, "22".repeat(32));
    }

    #[test]
    fn ce_v1_records_round_trip() {
        let encoded = ce_v1_bytes(&[
            ("purpose", b"enclava-rekey-v1"),
            ("resource_path", b"default/demo-owner/seed-encrypted"),
            ("new_value_sha256", &[1u8; 32]),
        ]);

        let decoded = decode_ce_v1_records(&encoded).unwrap();

        assert_eq!(decoded[0], ("purpose".into(), b"enclava-rekey-v1".to_vec()));
        assert_eq!(decoded[2], ("new_value_sha256".into(), vec![1u8; 32]));
    }
}
