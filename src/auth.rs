// The /auth handler — the load-bearing endpoint. nginx subrequests
// here for every gated request; we return 200 (allow), 401 (no/invalid
// token; redirect), or 403 (token valid but crachá denied).

use crate::cache::{
    new_decision_cache, new_jwt_cache, CachedDecision, DecisionCache, DecisionKey, JwtCache,
    VerifiedClaims,
};
use crate::config::Config;
use crate::hostname;
use crate::jwks::JwksCache;
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use cracha_core::Verb;
use jsonwebtoken::{decode, decode_header, Validation};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthState {
    pub config: Arc<Config>,
    pub jwks: JwksCache,
    pub jwt_cache: JwtCache,
    pub decision_cache: DecisionCache,
}

impl AuthState {
    #[must_use]
    pub fn new(config: Arc<Config>, jwks: JwksCache) -> Self {
        Self {
            jwt_cache: new_jwt_cache(config.jwt_cache_size),
            decision_cache: new_decision_cache(config.decision_ttl()),
            config,
            jwks,
        }
    }
}

/// JWT claims as Authentik issues them.
#[derive(Debug, Deserialize)]
struct AuthentikClaims {
    sub: String,
    email: Option<String>,
    exp: i64,
}

/// Headers nginx forwards via the auth-url subrequest.
const HEADER_ORIGINAL_URL: &str = "X-Original-URL";
const HEADER_ORIGINAL_METHOD: &str = "X-Original-Method";
const HEADER_AUTH_COOKIE: &str = "X-Saguao-Session";

pub async fn auth_handler(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
) -> Response {
    // 1. Parse the original URL → service target (app, cluster, location).
    let original_url = match headers
        .get(HEADER_ORIGINAL_URL)
        .and_then(|h| h.to_str().ok())
    {
        Some(u) => u,
        None => return (StatusCode::BAD_REQUEST, "missing X-Original-URL").into_response(),
    };

    let target = match hostname::parse_url(original_url) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, url = %original_url, "hostname parse failed");
            return (StatusCode::BAD_REQUEST, format!("hostname: {e}")).into_response();
        }
    };

    // Sanity: vigia should only be consulted for its own cluster's traffic.
    if target.cluster != state.config.cluster {
        tracing::warn!(
            requested = %target.cluster,
            configured = %state.config.cluster,
            "cluster mismatch — vigia configured for different cluster than request hostname"
        );
        // Still proceed; this is a config error not a security issue,
        // and crachá will catch any cross-cluster grant.
    }

    // 2. Map HTTP method → verb.
    let method = headers
        .get(HEADER_ORIGINAL_METHOD)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("GET");
    let verb = Verb::for_http_method(method);

    // 3. Read the session JWT from the saguão session cookie.
    let token = match extract_jwt(&headers) {
        Some(t) => t,
        None => return redirect_to_signin(&state.config, original_url),
    };

    // 4. Verify the JWT (with caching).
    let claims = match verify_jwt(&state, &token).await {
        Ok(c) => c,
        Err(e) => {
            tracing::info!(error = %e, "JWT verification failed");
            return redirect_to_signin(&state.config, original_url);
        }
    };

    // 5. Authorization decision (with caching).
    let key = DecisionKey {
        user: claims.sub.clone(),
        cluster: target.cluster.clone(),
        service: target.app.clone(),
        verb: verb_str(verb).into(),
    };

    let decision = if let Some(cached) = state.decision_cache.get(&key).await {
        cached
    } else {
        let fresh = call_cracha(&state, &claims.sub, &target, verb).await;
        state.decision_cache.insert(key, fresh.clone()).await;
        fresh
    };

    if decision.allow {
        // Forward identity headers downstream (Authentik convention).
        let mut response = (StatusCode::OK, "ok").into_response();
        let h = response.headers_mut();
        h.insert("X-Saguao-User", claims.sub.parse().unwrap_or_else(|_| "?".parse().unwrap()));
        if let Some(email) = claims.email {
            if let Ok(v) = email.parse() {
                h.insert("X-Saguao-Email", v);
            }
        }
        response
    } else {
        tracing::info!(user = %claims.sub, target = ?target, reason = %decision.reason, "denied");
        (StatusCode::FORBIDDEN, decision.reason).into_response()
    }
}

fn extract_jwt(headers: &HeaderMap) -> Option<String> {
    // Prefer the saguão session cookie; fall back to a Bearer header.
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
        if let Some(stripped) = auth.strip_prefix("Bearer ") {
            return Some(stripped.to_string());
        }
    }
    if let Some(cookies) = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()) {
        for c in cookies.split(';') {
            let c = c.trim();
            if let Some(stripped) = c.strip_prefix(&format!("{HEADER_AUTH_COOKIE}=")) {
                return Some(stripped.to_string());
            }
        }
    }
    None
}

fn redirect_to_signin(config: &Config, original_url: &str) -> Response {
    let url = config.signin_url(original_url);
    let header_value = HeaderValue::from_str(&url)
        .unwrap_or_else(|_| HeaderValue::from_static("/"));
    (
        StatusCode::UNAUTHORIZED,
        [(header::LOCATION, header_value)],
        "sign in required",
    )
        .into_response()
}

async fn verify_jwt(state: &AuthState, token: &str) -> anyhow::Result<VerifiedClaims> {
    if let Some(cached) = state.jwt_cache.get(token).await {
        return Ok(cached);
    }

    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("JWT has no kid"))?;
    let key = state.jwks.key_for(&kid).await?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[&state.config.audience]);

    let data = decode::<AuthentikClaims>(token, &key, &validation)?;
    let claims = VerifiedClaims {
        sub: data.claims.sub,
        email: data.claims.email,
        exp: data.claims.exp,
    };
    state.jwt_cache.insert(token.to_string(), claims.clone()).await;
    Ok(claims)
}

#[cfg(feature = "cracha-grpc")]
async fn call_cracha(
    state: &AuthState,
    user: &str,
    target: &hostname::ServiceTarget,
    verb: Verb,
) -> CachedDecision {
    use cracha_proto::{AuthorizeRequest, CrachaClient};
    let mut client = match CrachaClient::connect(state.config.cracha_url.clone()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "crachá unreachable; fail-closed");
            return CachedDecision {
                allow: false,
                reason: "crachá unreachable".into(),
            };
        }
    };
    let resp = client
        .authorize(AuthorizeRequest {
            user: user.into(),
            cluster: target.cluster.clone(),
            location: target.location.clone(),
            service: target.app.clone(),
            verb: verb_str(verb).into(),
        })
        .await;
    match resp {
        Ok(r) => {
            let r = r.into_inner();
            CachedDecision {
                allow: r.allow,
                reason: r.reason,
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "crachá Authorize failed");
            CachedDecision {
                allow: false,
                reason: format!("cracha error: {e}"),
            }
        }
    }
}

#[cfg(not(feature = "cracha-grpc"))]
async fn call_cracha(
    _state: &AuthState,
    _user: &str,
    _target: &hostname::ServiceTarget,
    _verb: Verb,
) -> CachedDecision {
    // Scaffold path: cracha-proto not enabled. Default-deny with a
    // diagnostic. Production deployments enable the feature.
    CachedDecision {
        allow: false,
        reason: "vigia built without cracha-grpc feature".into(),
    }
}

fn verb_str(v: Verb) -> &'static str {
    match v {
        Verb::Read => "read",
        Verb::Write => "write",
        Verb::Delete => "delete",
        Verb::Admin => "admin",
        Verb::All => "*",
    }
}
