// vigia — per-cluster forward-auth data plane for saguão.
//
// nginx forwards every gated request as an auth-url subrequest to
// /auth on this binary. /auth validates the JWT, queries crachá,
// and returns 200/401/403.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use clap::Parser;
use tracing::info;
use vigia::{
    auth::{auth_handler, AuthState},
    config::Config,
    jwks::{spawn_refresher, JwksCache},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = Arc::new(Config::parse());
    info!(
        cluster = %config.cluster,
        location = %config.location,
        passaporte = %config.passaporte_url,
        cracha = %config.cracha_url,
        "vigia starting"
    );

    let jwks = JwksCache::new();
    spawn_refresher(jwks.clone(), config.jwks_url(), Duration::from_secs(900));

    let auth_state = Arc::new(AuthState::new(config.clone(), jwks));

    let app = Router::new()
        .route("/auth", get(auth_handler))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(auth_state);

    let addr: std::net::SocketAddr = config.addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr = %addr, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(_state): State<Arc<AuthState>>) -> Response {
    // TODO: report unready until first JWKS fetch succeeds.
    (StatusCode::OK, "ready").into_response()
}

async fn metrics() -> Response {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    match encoder.encode_to_string(&metric_families) {
        Ok(body) => (StatusCode::OK, body).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
