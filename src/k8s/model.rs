use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus { Active, Expired }

#[derive(Debug, Clone)]
pub struct SealingKey {
    pub name: String,
    pub status: KeyStatus,
    pub created_at: Option<String>,
    pub fingerprint: Option<String>,
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

pub const SEALED_BY_ANNOTATION: &str = "sealedsecrets.bitnami.com/sealed-by";

/// Returns the key name this secret belongs to, or None for unknown.
pub fn key_name_for_sealed_secret(
    annotations: &BTreeMap<String, String>,
    keys: &[SealingKey],
    secret_created_at: Option<&str>,
) -> Option<String> {
    // Tier 1: direct annotation
    if let Some(name) = annotations.get(SEALED_BY_ANNOTATION) {
        return Some(name.clone());
    }
    // Tier 2: timestamp correlation
    if let Some(secret_ts) = secret_created_at {
        let mut best: Option<&SealingKey> = None;
        for key in keys {
            if let Some(key_ts) = &key.created_at {
                if key_ts.as_str() <= secret_ts {
                    if best.map(|b| b.created_at.as_deref().unwrap_or("") < key_ts.as_str()).unwrap_or(true) {
                        best = Some(key);
                    }
                }
            }
        }
        return best.map(|k| k.name.clone());
    }
    None
}
