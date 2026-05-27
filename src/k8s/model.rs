use std::collections::BTreeMap;
use k8s_openapi::api::core::v1::Secret;
use kube::core::DynamicObject;
use sha2::{Digest, Sha256};

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

#[derive(Debug, Clone)]
pub struct SealingKey {
    pub name: String,
    pub status: KeyStatus,
    pub created_at: Option<String>,
    /// SHA-256 of raw tls.crt DER bytes, hex-encoded (display only)
    pub fingerprint: Option<String>,
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
        Some(SealingKey { name, status, created_at, fingerprint })
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
        Some(SealedSecretItem {
            name,
            namespace,
            resolved_key: None,
            created_at,
            labels,
            annotations,
        })
    }

    /// Human-readable age from created_at RFC-3339 string.
    pub fn age(&self) -> String {
        self.created_at.as_deref().unwrap_or("-").to_string()
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

    fn make_key(name: &str, created_at: &str) -> SealingKey {
        SealingKey {
            name: name.to_string(),
            status: KeyStatus::Active,
            created_at: Some(created_at.to_string()),
            fingerprint: None,
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
}
