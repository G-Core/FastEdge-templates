# Design Rationale

Why `totp-app` is built the way it is. This records the *current* design and the
reasoning behind it — not a change history.

## Components

- **`otp-app` — TypeScript + Hono HTTP app.** TOTP needs `crypto.subtle` HMAC,
  routing, and a hosted challenge/enrollment UI; the FastEdge JS HTTP-app runtime
  provides all three. A proxy-wasm filter alone (Rust/AS) cannot host the UI.
- **`otp-filter` — Rust proxy-wasm enforcement filter.** Runs in the CDN proxy in
  front of the customer's protected origin, verifies the `mfa_session` cookie on
  every request, and is **default-deny / fail-closed**. Enforcement lives in our
  code, not the customer's origin.

Both are deployed as FastEdge apps on the customer's CDN resource: the HTTP app on
the `AUTH_PREFIX` path rule, the filter in front of the protected paths.

## Storage — KV only, single-tenant

The TOTP seed lives in a **per-customer Gcore KV store**. One deployment serves one
customer, so the store holds only that customer's seeds in isolation — not a
multi-tenant honeypot. The app reads KV directly (`fastedge::kv`) and writes through
the Gcore KV REST API (`GCORE_API_TOKEN`), because the KV SDK is read-only.

Scope `GCORE_API_TOKEN` to the single store so a leak cannot reach other data. The
seed is **never exposed to the browser** — the runtime has no `crypto.subtle.encrypt`,
so a seed can't be sealed into a browser-visible token; it travels edge↔KV only and
is fetched at verify time (see `../architecture/flow.md` for the PoP reasoning).

## Trust handoff — signed ticket, no seed

The origin stays the source of truth for *who the user is*. After its password
check it signs a short-lived **handoff ticket** (HMAC over `HANDOFF_KEY`) carrying
`{ sub, next, exp }` and redirects the browser to the challenge page. The ticket
carries no seed and the origin can mint it itself — no "start" call to the edge.

## TOTP

RFC 6238 via `crypto.subtle` HMAC (SHA-1 default, configurable), base32 seed, RFC
4226 dynamic truncation, `±TOTP_DRIFT` step window, constant-time compare. SHA-1 is
the authenticator-app default. See `runtime-constraints.md`.

## Two enforcement profiles

- **Profile A (default, edge-enforced).** The Rust filter verifies the `mfa_session`
  cookie and gates protected paths. The origin runs **no MFA crypto** — `HANDOFF_KEY`
  is the only key it holds ("zero origin code").
- **Profile B (opt-in, origin-verified).** The edge mints a one-time **ES256** proof;
  the origin verifies it via the served **JWKS** endpoint (public key only — it
  cannot forge), then mints its own revocable, longer-lived session.

The trust anchor sets the session model: the edge `mfa_session` is stateless and
cross-PoP-unrevocable, so it stays short; a durable, revocable session belongs at
the origin, which has a database. Profile A is the easy-deploy headline; Profile B
is for customers wanting longer or origin-controlled sessions.

## Tokens, algorithms, TTLs

- **`mfa_session`** (edge HTTP app → filter): **HS256** over `MFA_SESSION_KEY`,
  `MFA_SESSION_TTL` = 8h absolute (non-sliding), host-only HttpOnly/Secure/SameSite=Lax
  cookie. Never crosses to the origin. 8h ≈ a workday; kept short because in Profile A
  it is the sole, unrevocable boundary.
- **Profile-B proof**: **ES256** over `MFA_PROOF_SIGNING_KEY`, `PROOF_TTL` ≈ 90s,
  single-use (`jti` + POP-local replay guard). Asymmetric so the origin holds only a
  public key. Delivered as a short-lived cookie, never in a URL.
- **Handoff ticket**: HS256 over `HANDOFF_KEY`. The edge requires `exp` and caps the
  absolute age (defence-in-depth).
- All verification pins its algorithm and rejects `none`/alg-switch — HS256 in the
  HTTP app and the Rust filter, ES256 for the proof.
- `iss`/`aud` are bound on `mfa_session` and the proof. The filter **fail-closes** if
  `MFA_AUDIENCE` is unset (it cannot otherwise know which tokens are its own); `iss`
  is checked only when set on both sides.

## Platform gotcha — JWKS fetch caching (Profile B)

An origin's `fetch()`/`createRemoteJWKSet()` call to `{AUTH_PREFIX}/.well-known/jwks.json`
from inside another FastEdge app can hit a cache layer internal to FastEdge's own
subrequest path — keyed by URL, invisible to the JWKS response's own `Cache-Control`
header, and **not cleared by a CDN "purge all"** on the resource. Observed while
building `private-shop`'s `mfa-verify` mode: after rotating `MFA_PROOF_SIGNING_KEY` /
`MFA_PROOF_PUBLIC_JWK`, the origin's `jwtVerify` kept failing with
`JWSSignatureVerificationFailed` against a stale key that neither the old nor the new
env value matched, on a specific edge node, even though direct `curl`s and the app's
own request-time env lookup both returned the correct key. The only fix that worked:
append a random query param to the JWKS URL on every fetch so the cache can't match
it against a previously-seen URL. If you build another origin that verifies this
JWKS endpoint, cache-bust the URL from the start rather than rediscovering this.

Enrollment renders the `otpauth://` URI to an inline `<svg>` with `uqr` (pure-JS /
SVG-string — no canvas or Node built-ins, which the runtime lacks). The URI embeds
the seed, so it is rendered **locally only and never sent to an external QR service**.

## Configurable mount path

The mount path is `AUTH_PREFIX` (default `/auth/totp`), read by both components. The
filter bypasses `{AUTH_PREFIX}` and `{AUTH_PREFIX}/…` plus `/health`; everything else
requires a valid session. Unauthenticated requests are redirected to `MFA_LOGIN_URL`
(a URL on the customer origin that starts the MFA flow), or get a 401 if it is unset
(useful for APIs). A customer who already owns `/auth/` can mount the app elsewhere
via their CDN path rule and set `AUTH_PREFIX` to match.

## Enrollment & recovery

Two enrollment paths write the seed to KV: **admin-provisioned**
(`POST {AUTH_PREFIX}/enroll`, gated by `ENROLL_API_KEY`) and **self-service first-login**
(`{AUTH_PREFIX}/activate`, on by default, gated by the handoff ticket). Self-service can
be turned off with `ALLOW_SELF_ENROLLMENT=false` for admin-provisioned deployments.

Identity proofing — confirming a human really is the account owner — is the **origin's**
responsibility, not the edge's (the edge holds no durable identity data). So account
recovery is delegated to the origin: a lost authenticator is re-provisioned by calling
`POST {AUTH_PREFIX}/enroll` with `force:true` behind the origin's own identity-proofing
flow. Backup codes are not issued, and there is no standalone enrollment UI beyond the
hosted `/activate` page. See `../security/threat-model.md` R5.
