# Identity-Delivery Modes — the `SSO_VARIANT` Axis

## Three modes on one axis, one runtime env var

The axis that distinguishes the modes is **how the edge hands identity to the origin** — which maps directly to what the customer already runs. `SSO_VARIANT` selects it at runtime; it must be set to the same value on both the auth-app and the cdn-filter.

| `SSO_VARIANT` | Edge delivers to origin | Fits an origin that… |
|---|---|---|
| **gate-only** | nothing — just allow/deny | only needs "is this user authed?" (static sites, downloads, internal tools) |
| **cookie** | a verifiable JWT cookie the origin verifies itself | already verifies stateless JWTs |
| **header** | injects identity request headers (`x-sso-user` + per-claim `x-sso-*`); origin trusts the edge | has server-side sessions, or won't verify tokens |

> **Axis discipline:** `SSO_VARIANT` splits on identity-delivery ONLY.
> - **Provider** (Google / GitHub / SAML / Microsoft, Facebook) is **runtime config**, not part of this axis.
> - **Signing tier** (HS256 vs ES256+JWKS) follows from `SSO_VARIANT`, not a separate axis.
> Letting either become a separate axis causes a combinatorial explosion — this is exactly why the old three-*template* design (one build per axis value) was replaced with one runtime config value.

## How thin the differences actually are

- **auth-app** is the same binary for all three. It varies only by **token claim richness** (gate: `sub` only; cookie/header: `+email`, `+name`) and whether it exposes a JWKS route — both runtime config, resolved from `SSO_VARIANT` inside `createAuthApp`.
- **cdn-filter** is the same binary for all three. gate-only and cookie share the **identical** gate logic (no cookie → redirect; valid → allow). Only **header** adds one behavior: inject the `x-sso-*` identity headers upstream. Injection uses `add` for a new header and `set` to replace a client-supplied one (the CDN origin-fetch drops a `set` of a header that wasn't already present, so the API is chosen by the header's original presence — see the `put_user_header` comment in `cdn-filter/src/lib.rs`).

One auth-app binary, one cdn-filter binary, one optional filter behavior
(header injection) gated on `SSO_VARIANT`, one config dimension (claims +
JWKS) also gated on `SSO_VARIANT`. Adding a provider or upgrading the signing
tier touches each app once and applies to all three `SSO_VARIANT` values —
there's nothing to propagate to, since there's only one build of each.

## The variant is a runtime `if`, not a preset directory

```tsx
// auth-app/server.tsx — SSO_VARIANT is read from env (lazily, on first
// request — env vars aren't available during the build-time wizer snapshot).
// JWKS route + ES256-vs-HS256 signing follow from it inside createAuthApp.
const variant = getEnv("SSO_VARIANT"); // "gate-only" | "cookie" | "header"
const app = createAuthApp({ variant });
```

```rust
// cdn-filter/src/lib.rs — SSO_VARIANT picked once per request; fail-closed
// if unset or not one of the three values.
let variant = match env::var("SSO_VARIANT").ok().as_deref().and_then(Variant::parse) {
    Some(v) => v,
    None => return self.deny(..., "SSO_VARIANT not configured or invalid — refusing all sessions"),
};
// variant.expected_alg() / variant.strip_session_cookie() / variant.inject_user_header()
```

Before this became a runtime config value, each mode was a **separate Cargo
feature combination** compiled into a separate wasm binary (`alg-hs256` /
`alg-es256`, `strip-session-cookie`, `inject-user-header`), built from three
per-variant template directories over a shared `core/` package. See
`edge-sso/refactor.md` for the full before/after and why the merge was safe.
