use std::collections::BTreeMap;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use k8s_openapi::api::core::v1::Secret;
use kube::core::DynamicObject;
use sha2::{Digest, Sha256};
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::Oaep;


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


fn oaep_label(
    annotations: &BTreeMap<String, String>,
    namespace: &str,
    name: &str,
) -> String {
    if annotations
        .get("sealedsecrets.bitnami.com/cluster-wide")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        String::new()
    } else if annotations
        .get("sealedsecrets.bitnami.com/namespace-wide")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        namespace.to_string()
    } else {
        format!("{}/{}", namespace, name)
    }
}

pub fn resolve_key(
    annotations: &BTreeMap<String, String>,
    namespace: &str,
    name: &str,
    encrypted_sample: Option<&[u8]>,
    keys: &[SealingKey],
) -> Option<String> {
    let rsa_blob = encrypted_sample?;
    let label = oaep_label(annotations, namespace, name);

    for key in keys {
        if let Some(pk) = &key.rsa_private_key {
            let padding = Oaep::new_with_label::<Sha256, _>(label.as_str());
            if pk.decrypt(padding, rsa_blob).is_ok() {
                return Some(key.name.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

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

    // ── oaep_label ──────────────────────────────────────────────────────────────

    #[test]
    fn oaep_label_strict_scope() {
        let ann = BTreeMap::new();
        assert_eq!(oaep_label(&ann, "default", "my-secret"), "default/my-secret");
    }

    #[test]
    fn oaep_label_namespace_wide() {
        let mut ann = BTreeMap::new();
        ann.insert(
            "sealedsecrets.bitnami.com/namespace-wide".to_string(),
            "true".to_string(),
        );
        assert_eq!(oaep_label(&ann, "default", "my-secret"), "default");
    }

    #[test]
    fn oaep_label_cluster_wide() {
        let mut ann = BTreeMap::new();
        ann.insert(
            "sealedsecrets.bitnami.com/cluster-wide".to_string(),
            "true".to_string(),
        );
        assert_eq!(oaep_label(&ann, "default", "my-secret"), "");
    }

    // ── resolve_key ──────────────────────────────────────────────────────────────

    #[test]
    fn resolve_key_finds_correct_key() {
        use rand::thread_rng;
        use rsa::RsaPublicKey;

        let private_key = RsaPrivateKey::new(&mut thread_rng(), 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let session_key = [0xBBu8; 32];
        let label = "default/my-secret";
        let padding = Oaep::new_with_label::<Sha256, _>(label);
        let encrypted = public_key
            .encrypt(&mut thread_rng(), padding, &session_key)
            .unwrap();

        let sk = SealingKey {
            name: "sealing-key-1".to_string(),
            status: KeyStatus::Active,
            created_at: None,
            fingerprint: None,
            rsa_private_key: Some(private_key),
        };

        let ann = BTreeMap::new(); // strict scope → label "default/my-secret"
        let result = resolve_key(&ann, "default", "my-secret", Some(&encrypted), &[sk]);
        assert_eq!(result, Some("sealing-key-1".to_string()));
    }

    #[test]
    fn resolve_key_wrong_keys_return_none() {
        use rand::thread_rng;
        use rsa::RsaPublicKey;

        let key_a = RsaPrivateKey::new(&mut thread_rng(), 2048).unwrap();
        let key_b = RsaPrivateKey::new(&mut thread_rng(), 2048).unwrap();

        let padding = Oaep::new_with_label::<Sha256, _>("default/my-secret");
        let encrypted = RsaPublicKey::from(&key_a)
            .encrypt(&mut thread_rng(), padding, &[0u8; 32])
            .unwrap();

        let sk_b = SealingKey {
            name: "key-b".to_string(),
            status: KeyStatus::Active,
            created_at: None,
            fingerprint: None,
            rsa_private_key: Some(key_b),
        };

        let ann = BTreeMap::new();
        let result = resolve_key(&ann, "default", "my-secret", Some(&encrypted), &[sk_b]);
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_key_skips_keys_without_private_key() {
        use rand::thread_rng;
        use rsa::RsaPublicKey;

        let key = RsaPrivateKey::new(&mut thread_rng(), 2048).unwrap();
        let padding = Oaep::new_with_label::<Sha256, _>("default/my-secret");
        let encrypted = RsaPublicKey::from(&key)
            .encrypt(&mut thread_rng(), padding, &[0u8; 32])
            .unwrap();

        let sk = SealingKey {
            name: "key-no-priv".to_string(),
            status: KeyStatus::Active,
            created_at: None,
            fingerprint: None,
            rsa_private_key: None,
        };

        let ann = BTreeMap::new();
        let result = resolve_key(&ann, "default", "my-secret", Some(&encrypted), &[sk]);
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_key_none_sample_returns_none() {
        let sk = SealingKey {
            name: "any-key".to_string(),
            status: KeyStatus::Active,
            created_at: None,
            fingerprint: None,
            rsa_private_key: None,
        };
        let ann = BTreeMap::new();
        let result = resolve_key(&ann, "default", "my-secret", None, &[sk]);
        assert_eq!(result, None);
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
