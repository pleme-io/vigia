# vigia — repo-level agent instructions

> Brazilian-Portuguese for "sentinel." This repo implements **vigia**,
> the per-cluster forward-auth data plane of saguão.

## Frame

- [`pleme-io/theory/SAGUAO.md`](https://github.com/pleme-io/theory/blob/main/SAGUAO.md) §III.3 — what vigia *is*
- `blackmatter-pleme/skills/saguao/SKILL.md` — how to operate it
- The Compounding Directive in `pleme-io/CLAUDE.md`

## What this repo owns

- The Rust forward-auth HTTP service (axum)
- OIDC JWT validation against passaporte's JWKS (cached)
- gRPC client to crachá for authz decisions (cached, bounded TTL)
- The Helm chart `lareira-vigia` (one HelmRelease per cluster)
- Per-cluster decision metrics + audit log emission to the
  pleme-vector observability pipeline

## What this repo does NOT own

- **Identity** — passaporte issues the JWT. vigia validates, doesn't issue.
- **Authz policy** — crachá owns the decision. vigia caches and applies.
- **Routing** — nginx and the Cloudflare Tunnel handle HTTP routing. vigia is consulted via subrequest only.

## Conventions

- Single binary, single crate (substrate `rust-tool-release` shape).
- shikumi for config; ArcSwap hot-reload of config.
- kenshou for OIDC primitives (JWT verification, JWKS fetch, key rotation).
- tsunagu for service lifecycle (PID, sockets, health endpoints).
- tonic-built gRPC client to crachá; cached via moka.
- Axum router with three endpoints: `/auth` (the subrequest target),
  `/healthz`, `/metrics`.

## Pillar 1 reminder

Rust + tatara-lisp + Nix + YAML. **No shell.** Service lifecycle via
tsunagu macros; CLI via clap derive; config via shikumi.
