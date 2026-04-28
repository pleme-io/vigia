// JWKS fetch + cache for passaporte (Authentik) JWT verification.
//
// Authentik publishes its public keys at
// `<passaporte_url>/application/o/<slug>/jwks/`. We fetch on startup,
// refresh periodically, and key-rotation is automatic.

use anyhow::{anyhow, Context as _, Result};
use jsonwebtoken::{DecodingKey, jwk::JwkSet};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Deserialize)]
struct JwksDocument {
    keys: serde_json::Value,
}

/// In-memory JWKS cache. Refreshed periodically by a background task.
#[derive(Clone, Default)]
pub struct JwksCache {
    inner: Arc<RwLock<Option<JwkSet>>>,
}

impl JwksCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the cached JWKS document.
    pub async fn replace(&self, jwks: JwkSet) {
        let mut guard = self.inner.write().await;
        *guard = Some(jwks);
    }

    /// Look up a decoding key by `kid` claim in the JWT header.
    /// Returns Err if the JWKS is empty or the key isn't found.
    pub async fn key_for(&self, kid: &str) -> Result<DecodingKey> {
        let guard = self.inner.read().await;
        let jwks = guard.as_ref().ok_or_else(|| anyhow!("JWKS not yet fetched"))?;
        let jwk = jwks
            .find(kid)
            .ok_or_else(|| anyhow!("kid {kid} not in JWKS"))?;
        DecodingKey::from_jwk(jwk).context("decoding key from JWK")
    }
}

/// Fetch the JWKS document from passaporte and parse it.
pub async fn fetch(jwks_url: &str) -> Result<JwkSet> {
    let resp = reqwest::Client::new()
        .get(jwks_url)
        .send()
        .await
        .with_context(|| format!("GET {jwks_url}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("JWKS fetch returned {}", resp.status()));
    }
    let raw: JwksDocument = resp.json().await.context("parsing JWKS body")?;
    let jwks: JwkSet =
        serde_json::from_value(serde_json::json!({ "keys": raw.keys })).context("decoding JWKS")?;
    Ok(jwks)
}

/// Spawn a background task that refreshes the JWKS every `interval`.
pub fn spawn_refresher(cache: JwksCache, jwks_url: String, interval: std::time::Duration) {
    tokio::spawn(async move {
        loop {
            match fetch(&jwks_url).await {
                Ok(jwks) => {
                    let count = jwks.keys.len();
                    cache.replace(jwks).await;
                    tracing::info!(keys = count, jwks_url = %jwks_url, "JWKS refreshed");
                }
                Err(e) => {
                    tracing::warn!(error = %e, jwks_url = %jwks_url, "JWKS refresh failed");
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}
