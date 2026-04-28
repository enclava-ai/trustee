// Copyright (c) 2026 by Enclava.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::PolicyEngineConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct SignedPolicyArtifact {
    pub metadata: PolicyMetadata,
    pub rego_text: String,
    #[serde(default)]
    pub rego_sha256: Option<String>,
    pub signature: String,
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
    pub signed_at: String,
    pub key_id: String,
}

pub(crate) fn validate_config(config: &PolicyEngineConfig) -> Result<()> {
    if !config.require_signed_policy {
        return Ok(());
    }

    let public_key = config
        .signed_policy_public_key
        .as_deref()
        .ok_or_else(|| anyhow!("signed_policy_public_key is required"))?;
    let _ = parse_verifying_key(public_key).context("parse signed_policy_public_key")?;

    Ok(())
}

pub(crate) fn rego_for_evaluation(
    config: &PolicyEngineConfig,
    stored_policy: &str,
) -> Result<String> {
    if config.require_signed_policy {
        return verify(config, stored_policy).map(|artifact| artifact.rego_text);
    }

    Ok(stored_policy.to_string())
}

pub(crate) fn policy_for_storage(config: &PolicyEngineConfig, policy_body: &str) -> Result<String> {
    if config.require_signed_policy {
        let _ = verify(config, policy_body)?;
    }

    Ok(policy_body.to_string())
}

pub(crate) fn verify(
    config: &PolicyEngineConfig,
    policy_body: &str,
) -> Result<SignedPolicyArtifact> {
    let public_key = config
        .signed_policy_public_key
        .as_deref()
        .ok_or_else(|| anyhow!("signed_policy_public_key is required"))?;
    verify_with_public_key(policy_body, public_key)
}

fn verify_with_public_key(policy_body: &str, public_key: &str) -> Result<SignedPolicyArtifact> {
    let artifact: SignedPolicyArtifact =
        serde_json::from_str(policy_body).context("parse signed policy artifact")?;
    let key = parse_verifying_key(public_key)?;
    let message = policy_artifact_message(&artifact)?;
    let signature = decode_fixed::<64>(&artifact.signature).context("decode policy signature")?;
    let signature = Signature::from_bytes(&signature);

    key.verify(&message, &signature)
        .context("verify policy artifact signature")?;

    Ok(artifact)
}

fn parse_verifying_key(public_key: &str) -> Result<VerifyingKey> {
    let key = decode_fixed::<32>(public_key).context("decode Ed25519 public key")?;
    VerifyingKey::from_bytes(&key).context("parse Ed25519 public key")
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

    Ok(Sha256::digest(ce_v1_bytes(&[
        ("app_id", &app_id),
        ("deploy_id", &deploy_id),
        ("descriptor_core_hash", &descriptor_core_hash),
        ("descriptor_signing_pubkey", &descriptor_signing_pubkey),
        (
            "platform_release_version",
            metadata.platform_release_version.as_bytes(),
        ),
        ("policy_template_id", metadata.policy_template_id.as_bytes()),
        ("policy_template_sha256", &policy_template_sha256),
        ("signed_at", metadata.signed_at.as_bytes()),
        ("key_id", metadata.key_id.as_bytes()),
    ]))
    .into())
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
            app_id: "app".into(),
            deploy_id: "deploy".into(),
            descriptor_core_hash: "00".repeat(32),
            descriptor_signing_pubkey: "11".repeat(32),
            platform_release_version: "test".into(),
            policy_template_id: "resource-policy".into(),
            policy_template_sha256: hex::encode(Sha256::digest(rego.as_bytes())),
            signed_at: "2026-04-28T00:00:00Z".into(),
            key_id: "test-key".into(),
        }
    }

    fn signed_policy(sk: &SigningKey, rego: &str) -> SignedPolicyArtifact {
        let mut artifact = SignedPolicyArtifact {
            metadata: metadata_for(rego),
            rego_text: rego.to_string(),
            signature: String::new(),
        };
        let message = policy_artifact_message(&artifact).unwrap();
        artifact.signature = hex::encode(sk.sign(&message).to_bytes());
        artifact
    }

    fn signed_policy_config(pk: &VerifyingKey) -> PolicyEngineConfig {
        PolicyEngineConfig {
            require_signed_policy: true,
            signed_policy_public_key: Some(hex::encode(pk.to_bytes())),
            ..Default::default()
        }
    }

    #[test]
    fn valid_signed_policy_unwraps_to_rego() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let artifact = signed_policy(&sk, TEST_REGO);
        let body = serde_json::to_string(&artifact).unwrap();
        let config = signed_policy_config(&sk.verifying_key());

        let rego = rego_for_evaluation(&config, &body).unwrap();

        assert_eq!(rego, TEST_REGO);
    }

    #[test]
    fn unsigned_policy_is_rejected_when_required() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let config = signed_policy_config(&sk.verifying_key());

        let err = rego_for_evaluation(&config, TEST_REGO).unwrap_err();

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

        let err = rego_for_evaluation(&config, &body).unwrap_err();

        assert!(
            err.to_string().contains("verify policy artifact signature"),
            "{err:?}"
        );
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
