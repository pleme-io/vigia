# vigia — per-cluster forward-auth for the saguão fleet

> Brazilian-Portuguese for "sentinel." The figure standing at every door.

`vigia` is the **per-cluster forward-auth data plane** of the saguão
fleet identity + authz + portal architecture. One vigia instance runs
on every pleme-io homelab cluster; it sits behind ingress-nginx as
the auth-url subrequest target and gates every external request.

**Canonical architecture:** [`pleme-io/theory/SAGUAO.md`](https://github.com/pleme-io/theory/blob/main/SAGUAO.md) §III.3.

**Status:** scaffold. **Phase 7** of the saguão migration. Not yet
deployed. Phase-1 implementation of the same role is the **Authentik
embedded outpost** wired via the `pleme-lib.compliance.authn.oidc`
template helper — vigia replaces the outpost when the typed Rust
implementation ships and the helper grows a `provider: vigia`
branch.

## What it is

A small Rust HTTP service (axum) that:

1. Receives every request bound for a gated Ingress as a
   subrequest from nginx (`auth-url` annotation).
2. Validates the OIDC session JWT issued by **passaporte**
   (Authentik wrapped) against passaporte's JWKS (cached).
3. Calls **crachá**'s gRPC `Authorize(user, location, cluster,
   service, verb)` API to make the authz decision (cached for
   5min default).
4. Returns 200 (allow), 401 (no/invalid token; redirect to
   passaporte sign-in), or 403 (token valid but crachá denied).

## Why a typed Rust forward-auth (vs the Authentik outpost)

- **Typed end-to-end.** Shares the `cracha-core::AccessPolicy` types
  with crachá; no JSON-shape contract to maintain.
- **Caching control.** Per-`(user, service, verb)` cache with
  bounded TTL + manual flush on policy change; the outpost has
  coarser invalidation.
- **Pleme-io macros.** Built on shikumi (config), tsunagu (lifecycle),
  kenshou (OIDC primitives) — the same macro stack as the rest of
  the substrate.
- **No Authentik-version coupling.** When passaporte's Authentik
  upstream changes, the forward-auth contract here doesn't move
  in lock-step.

The data-plane role is *function*, not *implementation*. Phase 1
fills it with the outpost; Phase 7 fills it with vigia. Charts
that consume the role via `pleme-lib.compliance.authn.oidc` never
reference either implementation directly.

## Repo layout

```
vigia/
├── README.md                   (this file)
├── CLAUDE.md                   (per-repo agent instructions)
├── flake.nix                   (substrate rust-tool-release)
├── Cargo.toml
├── Cargo.lock                  (TBD — `cargo generate-lockfile`)
├── Cargo.nix                   (TBD — crate2nix)
├── .envrc / .gitignore
├── src/
│   └── main.rs                 (axum service)
└── charts/
    └── lareira-vigia/          (Helm chart)
```

## Bootstrap

```bash
nix develop
cargo generate-lockfile
nix run github:nix-community/crate2nix -- generate
cargo build
```

## Cross-references

- [`SAGUAO.md` §III.3](https://github.com/pleme-io/theory/blob/main/SAGUAO.md)
- `blackmatter-pleme/skills/saguao/SKILL.md`
- Companion repos: `pleme-io/passaporte` (identity), `pleme-io/cracha` (authz), `pleme-io/varanda` (PWA)

## License

MIT.
