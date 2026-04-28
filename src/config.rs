// vigia config — typed, single source of truth.

use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
#[command(name = "vigia")]
#[command(about = "Per-cluster forward-auth for the saguão fleet", long_about = None)]
pub struct Config {
    /// Bind address for the auth-url subrequest target.
    #[arg(long, env = "VIGIA_ADDR", default_value = "0.0.0.0:9000")]
    pub addr: String,

    /// passaporte issuer URL (used to derive the JWKS endpoint).
    #[arg(long, env = "VIGIA_PASSAPORTE_URL", default_value = "https://auth.quero.cloud")]
    pub passaporte_url: String,

    /// crachá gRPC endpoint.
    #[arg(long, env = "VIGIA_CRACHA_URL", default_value = "http://cracha.quero.cloud:50051")]
    pub cracha_url: String,

    /// Cluster name vigia is running in (e.g., "rio").
    #[arg(long, env = "VIGIA_CLUSTER")]
    pub cluster: String,

    /// Location (e.g., "bristol").
    #[arg(long, env = "VIGIA_LOCATION")]
    pub location: String,

    /// Decision-cache TTL (seconds).
    #[arg(long, env = "VIGIA_DECISION_TTL_SECS", default_value_t = 300)]
    pub decision_ttl_secs: u64,

    /// JWT-cache size (LRU entries).
    #[arg(long, env = "VIGIA_JWT_CACHE_SIZE", default_value_t = 1024)]
    pub jwt_cache_size: u64,

    /// Stale-OK fallback (seconds). 0 = disabled.
    #[arg(long, env = "VIGIA_STALE_OK_SECS", default_value_t = 0)]
    pub stale_ok_secs: u64,

    /// OIDC audience claim required (typically the saguão fleet identifier).
    #[arg(long, env = "VIGIA_AUDIENCE", default_value = "saguao")]
    pub audience: String,
}

impl Config {
    #[must_use]
    pub fn decision_ttl(&self) -> Duration {
        Duration::from_secs(self.decision_ttl_secs)
    }

    /// Authentik's JWKS endpoint, derived from the passaporte URL.
    /// Authentik exposes JWKS at `/application/o/<slug>/jwks/`; the
    /// "saguao" application slug is the saguão convention.
    #[must_use]
    pub fn jwks_url(&self) -> String {
        format!(
            "{}/application/o/saguao/jwks/",
            self.passaporte_url.trim_end_matches('/')
        )
    }

    /// Authentik's authorization endpoint (where vigia redirects on 401).
    #[must_use]
    pub fn signin_url(&self, original_uri: &str) -> String {
        let encoded = urlencoding_encode(original_uri);
        format!(
            "{}/outpost.goauthentik.io/start?rd={}",
            self.passaporte_url.trim_end_matches('/'),
            encoded
        )
    }
}

/// Minimal urlencode for one query value. Avoids pulling in
/// percent-encoding crate for one use site.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_url_derived() {
        let c = Config {
            addr: "0.0.0.0:9000".into(),
            passaporte_url: "https://auth.quero.cloud".into(),
            cracha_url: "http://cracha.quero.cloud:50051".into(),
            cluster: "rio".into(),
            location: "bristol".into(),
            decision_ttl_secs: 300,
            jwt_cache_size: 1024,
            stale_ok_secs: 0,
            audience: "saguao".into(),
        };
        assert_eq!(
            c.jwks_url(),
            "https://auth.quero.cloud/application/o/saguao/jwks/"
        );
    }

    #[test]
    fn signin_url_encodes() {
        let c = Config {
            addr: "0.0.0.0:9000".into(),
            passaporte_url: "https://auth.quero.cloud/".into(), // trailing slash trimmed
            cracha_url: "http://cracha.quero.cloud:50051".into(),
            cluster: "rio".into(),
            location: "bristol".into(),
            decision_ttl_secs: 300,
            jwt_cache_size: 1024,
            stale_ok_secs: 0,
            audience: "saguao".into(),
        };
        let s = c.signin_url("https://vault.rio.bristol.quero.cloud/?x=1");
        assert!(s.starts_with("https://auth.quero.cloud/outpost.goauthentik.io/start?rd="));
        assert!(s.contains("https%3A%2F%2Fvault.rio.bristol.quero.cloud%2F%3Fx%3D1"));
    }
}
