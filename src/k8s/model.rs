use std::collections::BTreeMap;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use k8s_openapi::api::core::v1::Secret;
use kube::core::DynamicObject;
use sha2::{Digest, Sha256};
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;

pub const SEALED_BY_ANNOTATION: &str = "sealedsecrets.bitnami.com/sealed-by";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Expired,
}

impl KeyStatus {
    pub fn badge(&self) -> &'static str {
        match self {
            KeyStatus::Active => "active",
            KeyStatus::Expired => "expired",
        }
    }
}

#[derive(Clone)]
pub struct SealingKey {
    pub name: String,
    pub status: KeyStatus,
    pub created_at: Option<String>,
    /// SHA-256 of raw tls.crt DER bytes, hex-encoded.
    /// Reserved for future ciphertext-fingerprint matching; not yet used at runtime.
    #[allow(dead_code)]
    pub fingerprint: Option<String>,
    pub rsa_private_key: Option<RsaPrivateKey>,
}

impl std::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealingKey")
            .field("name", &self.name)
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .field("fingerprint", &self.fingerprint)
            .field("rsa_private_key", &self.rsa_private_key.as_ref().map(|_| "<RSA key>"))
            .finish()
    }
}

impl SealingKey {
    pub fn from_secret(s: &Secret) -> Option<Self> {
        let name = s.metadata.name.clone()?;
        let labels = s.metadata.labels.as_ref();
        let status_val = labels
            .and_then(|l| l.get("sealedsecrets.bitnami.com/sealed-secrets-key"))
            .map(|v| v.as_str())
            .unwrap_or("expired");
        let status = if status_val == "active" { KeyStatus::Active } else { KeyStatus::Expired };
        let created_at = s
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| t.0.to_rfc3339());
        let fingerprint = s
            .data
            .as_ref()
            .and_then(|d| d.get("tls.crt"))
            .map(|bytes| {
                let hash = Sha256::digest(&bytes.0);
                hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
            });
        let rsa_private_key = s
            .data
            .as_ref()
            .and_then(|d| d.get("tls.key"))
            .and_then(|bytes| std::str::from_utf8(&bytes.0).ok())
            .and_then(|pem| {
                RsaPrivateKey::from_pkcs8_pem(pem)
                    .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
                    .ok()
            });
        Some(SealingKey { name, status, created_at, fingerprint, rsa_private_key })
    }
}

#[derive(Debug, Clone)]
pub struct SealedSecretItem {
    pub name: String,
    pub namespace: String,
    pub resolved_key: Option<String>,
    pub created_at: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    #[allow(dead_code)]
    pub encrypted_sample: Option<Vec<u8>>,
}

impl SealedSecretItem {
    pub fn from_dynamic(obj: &DynamicObject) -> Option<Self> {
        let name = obj.metadata.name.clone()?;
        let namespace = obj.metadata.namespace.clone().unwrap_or_default();
        let created_at = obj
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| t.0.to_rfc3339());
        let labels = obj
            .metadata
            .labels
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let annotations = obj
            .metadata
            .annotations
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();
        // All values share the same sealing key; pick any one — BTreeMap gives deterministic order.
        let encrypted_sample = obj
            .data
            .get("spec")
            .and_then(|s| s.get("encryptedData"))
            .and_then(|ed| ed.as_object())
            .and_then(|m| m.values().next())
            .and_then(|v| v.as_str())
            .and_then(|b64| B64.decode(b64).ok())
            .and_then(|bytes| {
                if bytes.len() < 2 {
                    return None;
                }
                let rsa_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
                if rsa_len == 0 || bytes.len() < 2 + rsa_len {
                    return None;
                }
                Some(bytes[2..2 + rsa_len].to_vec())
            });
        Some(SealedSecretItem { name, namespace, resolved_key: None, created_at, labels, annotations, encrypted_sample })
    }

    /// Human-readable age from created_at RFC-3339 string (e.g. "3d", "12h", "45m", "30s").
    pub fn age(&self) -> String {
        let ts = match &self.created_at {
            Some(s) => s,
            None => return "-".to_string(),
        };
        let parsed = match DateTime::parse_from_rfc3339(ts) {
            Ok(t) => t,
            Err(_) => return ts.clone(),
        };
        let secs = (Utc::now() - parsed.with_timezone(&Utc))
            .num_seconds()
            .max(0) as u64;
        match secs {
            s if s < 60 => format!("{s}s"),
            s if s < 3600 => format!("{}m", s / 60),
            s if s < 86400 => format!("{}h", s / 3600),
            s => format!("{}d", s / 86400),
        }
    }
}

/// Returns the key name this secret belongs to, or None for the unknown bucket.
///
/// Tier 1: `sealedsecrets.bitnami.com/sealed-by` annotation (direct match).
/// Tier 2: Most-recently-created key whose `created_at` <= secret's `created_at`.
pub fn key_name_for_sealed_secret(
    annotations: &BTreeMap<String, String>,
    keys: &[SealingKey],
    secret_created_at: Option<&str>,
) -> Option<String> {
    // Tier 1
    if let Some(name) = annotations.get(SEALED_BY_ANNOTATION) {
        return Some(name.clone());
    }
    // Tier 2
    if let Some(secret_ts) = secret_created_at {
        let mut best: Option<&SealingKey> = None;
        for key in keys {
            if let Some(key_ts) = &key.created_at {
                if key_ts.as_str() <= secret_ts {
                    let is_newer_best = best
                        .map(|b| b.created_at.as_deref().unwrap_or("") < key_ts.as_str())
                        .unwrap_or(true);
                    if is_newer_best {
                        best = Some(key);
                    }
                }
            }
        }
        return best.map(|k| k.name.clone());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_key(name: &str, created_at: &str) -> SealingKey {
        SealingKey {
            name: name.to_string(),
            status: KeyStatus::Active,
            created_at: Some(created_at.to_string()),
            fingerprint: None,
            rsa_private_key: None,
        }
    }

    #[test]
    fn annotation_match_returns_key_name() {
        let mut ann = BTreeMap::new();
        ann.insert(SEALED_BY_ANNOTATION.to_string(), "key-abc".to_string());
        let result = key_name_for_sealed_secret(&ann, &[], None);
        assert_eq!(result, Some("key-abc".to_string()));
    }

    #[test]
    fn annotation_takes_priority_over_timestamp() {
        let mut ann = BTreeMap::new();
        ann.insert(SEALED_BY_ANNOTATION.to_string(), "key-ann".to_string());
        let keys = vec![make_key("key-ts", "2024-01-01T00:00:00Z")];
        let result = key_name_for_sealed_secret(&ann, &keys, Some("2024-06-01T00:00:00Z"));
        assert_eq!(result, Some("key-ann".to_string()));
    }

    #[test]
    fn timestamp_fallback_picks_most_recent_key_before_secret() {
        let keys = vec![
            make_key("key-old", "2024-01-01T00:00:00Z"),
            make_key("key-new", "2024-06-01T00:00:00Z"),
        ];
        // secret created after key-new
        let result = key_name_for_sealed_secret(&BTreeMap::new(), &keys, Some("2024-09-01T00:00:00Z"));
        assert_eq!(result, Some("key-new".to_string()));
    }

    #[test]
    fn timestamp_fallback_picks_only_key_older_than_secret() {
        let keys = vec![
            make_key("key-old", "2024-01-01T00:00:00Z"),
            make_key("key-future", "2025-01-01T00:00:00Z"),
        ];
        // secret created between the two keys
        let result = key_name_for_sealed_secret(&BTreeMap::new(), &keys, Some("2024-06-01T00:00:00Z"));
        assert_eq!(result, Some("key-old".to_string()));
    }

    #[test]
    fn no_annotation_no_timestamp_returns_none() {
        let keys = vec![make_key("key-old", "2024-01-01T00:00:00Z")];
        let result = key_name_for_sealed_secret(&BTreeMap::new(), &keys, None);
        assert_eq!(result, None);
    }

    #[test]
    fn all_keys_newer_than_secret_returns_none() {
        let keys = vec![make_key("key-future", "2025-01-01T00:00:00Z")];
        let result = key_name_for_sealed_secret(&BTreeMap::new(), &keys, Some("2024-01-01T00:00:00Z"));
        assert_eq!(result, None);
    }

    #[test]
    fn key_status_badge() {
        assert_eq!(KeyStatus::Active.badge(), "active");
        assert_eq!(KeyStatus::Expired.badge(), "expired");
    }

    fn make_item_with_age(offset: Duration) -> SealedSecretItem {
        let ts = (Utc::now() - offset).to_rfc3339();
        SealedSecretItem {
            name: "x".into(), namespace: "y".into(), resolved_key: None,
            created_at: Some(ts),
            labels: BTreeMap::new(), annotations: BTreeMap::new(),
            encrypted_sample: None,
        }
    }

    #[test]
    fn age_formats_days() {
        let age = make_item_with_age(Duration::days(3)).age();
        assert!(age.ends_with('d'), "expected days, got: {age}");
    }

    #[test]
    fn age_formats_hours() {
        let age = make_item_with_age(Duration::hours(5)).age();
        assert!(age.ends_with('h'), "expected hours, got: {age}");
    }

    #[test]
    fn age_formats_minutes() {
        let age = make_item_with_age(Duration::minutes(30)).age();
        assert!(age.ends_with('m'), "expected minutes, got: {age}");
    }

    #[test]
    fn age_none_returns_dash() {
        let s = SealedSecretItem {
            name: "x".into(), namespace: "y".into(), resolved_key: None,
            created_at: None,
            labels: BTreeMap::new(), annotations: BTreeMap::new(),
            encrypted_sample: None,
        };
        assert_eq!(s.age(), "-");
    }

    #[test]
    fn from_dynamic_extracts_rsa_blob() {
        // Build a well-formed sealed-secrets ciphertext:
        // [u16 BE: 256] [256 bytes RSA blob] [28 bytes fake AES-GCM payload]
        let rsa_blob: Vec<u8> = (0u8..=255).collect(); // 256 distinct bytes
        let mut wire = Vec::new();
        wire.extend_from_slice(&(256u16).to_be_bytes());
        wire.extend_from_slice(&rsa_blob);
        wire.extend_from_slice(&[0xAAu8; 28]); // fake nonce + ciphertext

        let b64 = B64.encode(&wire);

        let obj = kube::core::DynamicObject {
            types: None,
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("my-secret".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({
                "spec": {
                    "encryptedData": {
                        "password": b64
                    }
                }
            }),
        };

        let item = SealedSecretItem::from_dynamic(&obj).unwrap();
        assert_eq!(item.encrypted_sample, Some(rsa_blob));
    }

    #[test]
    fn from_dynamic_missing_spec_gives_none_sample() {
        let obj = kube::core::DynamicObject {
            types: None,
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("my-secret".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let item = SealedSecretItem::from_dynamic(&obj).unwrap();
        assert!(item.encrypted_sample.is_none());
    }

    #[test]
    fn from_secret_parses_pkcs8_private_key() {
        use rsa::pkcs8::EncodePrivateKey;
        use rand::thread_rng;

        let key = RsaPrivateKey::new(&mut thread_rng(), 2048).unwrap();
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();

        let mut secret = k8s_openapi::api::core::v1::Secret::default();
        secret.metadata.name = Some("sealing-key-pkcs8".to_string());
        secret.metadata.labels = Some({
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "sealedsecrets.bitnami.com/sealed-secrets-key".to_string(),
                "active".to_string(),
            );
            m
        });
        secret.data = Some({
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "tls.key".to_string(),
                k8s_openapi::ByteString(pem.as_bytes().to_vec()),
            );
            m
        });

        let sk = SealingKey::from_secret(&secret).unwrap();
        assert!(sk.rsa_private_key.is_some(), "expected PKCS#8 key to parse");
    }

    #[test]
    fn from_secret_bad_tls_key_gives_none_rsa_key() {
        let mut secret = k8s_openapi::api::core::v1::Secret::default();
        secret.metadata.name = Some("sealing-key-bad".to_string());
        secret.metadata.labels = Some({
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "sealedsecrets.bitnami.com/sealed-secrets-key".to_string(),
                "active".to_string(),
            );
            m
        });
        secret.data = Some({
            let mut m = std::collections::BTreeMap::new();
            m.insert(
                "tls.key".to_string(),
                k8s_openapi::ByteString(b"not valid pem".to_vec()),
            );
            m
        });

        let sk = SealingKey::from_secret(&secret).unwrap();
        assert!(sk.rsa_private_key.is_none(), "bad PEM must not panic, must yield None");
        assert_eq!(sk.name, "sealing-key-bad");
        assert_eq!(sk.status, KeyStatus::Active);
    }
}
