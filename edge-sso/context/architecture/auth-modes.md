# Delivery Templates — Three Auth Modes

## Three templates on one axis

The axis that distinguishes the templates is **how the edge hands identity to the origin** — which maps directly to what the customer already runs.

| Template | Edge delivers to origin | Fits an origin that… |
|---|---|---|
| **gate-only** | nothing — just allow/deny | only needs "is this user authed?" (static sites, downloads, internal tools) |
| **cookie** | a verifiable JWT cookie the origin verifies itself | already verifies stateless JWTs |
| **header** | injects identity request headers (`x-sso-user` + per-claim `x-sso-*`); origin trusts the edge | has server-side sessions, or won't verify tokens |

> **Axis discipline:** templates split on identity-delivery ONLY.
> - **Provider** (Google / GitHub / SAML / future Microsoft, Facebook) is **runtime config**, not a template axis.
> - **Signing tier** (HS256 vs ES256+JWKS) is a config/hardening option inside the cookie/header variants, not a template.
> Letting either become a template axis causes a combinatorial explosion.

## How thin the differences actually are

- **auth-app** is the same across all three. It varies only by **token claim richness** (gate: `sub` only; cookie/header: `+email`, `+name`) and whether it exposes a JWKS route — both runtime config.
- **cdn-filter**: gate-only and cookie use the **identical** filter (no cookie → redirect; valid → allow). Only **header** adds one behavior: inject the `x-sso-*` identity headers upstream. Injection uses `add` for a new header and `set` to replace a client-supplied one (the CDN origin-fetch drops a `set` of a header that wasn't already present, so the API is chosen by the header's original presence — see the `put_user_header` comment in `core/filter/src/lib.rs`).

Three deployable artifacts, one shared core, one optional filter behavior (header injection), one config dimension (claims + JWKS). Adding a provider or upgrading the signing tier touches `core/` once and propagates to all three.

## Templates are thin presets

A `templates/<variant>/` directory is glue, not a reimplementation:

```tsx
// templates/cookie/auth-app/server.tsx — the variant is the only knob; JWKS
// route + ES256-vs-HS256 signing follow from it inside @sso/core.
import { createAuthApp } from "@sso/core";
const app = createAuthApp({ variant: "cookie" });
addEventListener("fetch", (e) => e.respondWith(app.fetch(e.request)));
```

```toml
# templates/header/cdn-filter/Cargo.toml — the filter is Rust; behaviour is
# selected by compile-time Cargo features on the shared core/filter crate.
# header  → strip-session-cookie + inject-user-header + alg-hs256
# gate    → strip-session-cookie + alg-hs256
# cookie  → alg-es256
sso-guard = { path = "../../../core/filter", default-features = false, features = ["strip-session-cookie", "inject-user-header", "alg-hs256"] }
```
