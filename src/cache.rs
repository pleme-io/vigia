// Caches: (1) JWT verification → claims, (2) (user, cluster, service, verb)
// → Decision. Both bounded; both moka-backed.

use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Subset of the JWT claims vigia needs after verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedClaims {
    pub sub: String,
    pub email: Option<String>,
    pub exp: i64,
}

/// JWT-cache key is the raw token string (truncated for safety in
/// logs but used in full as the cache key).
pub type JwtCache = Cache<String, VerifiedClaims>;

/// Decision-cache key.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DecisionKey {
    pub user: String,
    pub cluster: String,
    pub service: String,
    pub verb: String,
}

#[derive(Debug, Clone)]
pub struct CachedDecision {
    pub allow: bool,
    pub reason: String,
}

pub type DecisionCache = Cache<DecisionKey, CachedDecision>;

#[must_use]
pub fn new_jwt_cache(max_entries: u64) -> JwtCache {
    Cache::builder()
        .max_capacity(max_entries)
        .time_to_live(Duration::from_secs(3600)) // upper bound; per-entry ttl set below
        .build()
}

#[must_use]
pub fn new_decision_cache(ttl: Duration) -> DecisionCache {
    Cache::builder()
        .max_capacity(8192)
        .time_to_live(ttl)
        .build()
}
