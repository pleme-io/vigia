// vigia — per-cluster forward-auth library surface.
//
// Exposed primarily so unit tests can exercise the JWT + cache +
// authz-decision plumbing without spinning up an HTTP server.

pub mod auth;
pub mod cache;
pub mod config;
pub mod hostname;
pub mod jwks;
