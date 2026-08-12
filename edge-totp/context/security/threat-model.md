# Threat Model & Residual Risks

What `totp-app` defends against, how, and the risks it knowingly accepts because the
FastEdge platform can't do better. Read before touching the verify or enforcement
path.

## Trust model

- **Single-tenant**: one totp-app deployment = one customer. No multi-tenancy.
- Three actors: **Browser**, **Origin** (customer login — source of truth for *who*
  the user is), **Edge** (this app + its Rust enforcement filter — verifies the
  second factor).
- Realistic attacker for TOTP: **already holds the password** (phish / credential
  stuffing) and is trying to defeat the 6-digit factor. So they *can* drive the
  login flow and reach `/verify`.

## Protections in place

**Token & crypto integrity**
- Algorithms are **pinned**: `mfa_session` and the handoff ticket verify HS256 only;
  the Profile-B proof is ES256. The Rust filter rejects any non-HS256 token before
  touching the signature, so `none`/alg-switch is not reachable.
- Signature checks are constant-time (`verify_slice` in the filter, jose in the app).
  TOTP code comparison and the enroll API-key comparison use a constant-time helper.
- The Profile-B proof is **ES256/JWKS**: the origin holds only the public key and
  cannot forge proofs. Only `HANDOFF_KEY` is symmetric-shared with the origin (it is
  the legitimate ticket minter). `mfa_session` (HS256) stays edge-internal.

**Session / ticket handling**
- Handoff ticket **requires `exp`** and is rejected past an absolute max age; a ticket
  carrying a `seed` claim is rejected (prevents enroll-cookie/handoff confusion).
- The enroll cookie is **purpose-bound** (`purpose: "totp-enroll"`), so it can't be
  replayed through the handoff path even though it shares `HANDOFF_KEY`.
- The handoff ticket is **single-use**: on a successful `/verify` the ticket's
  fingerprint is recorded in `Cache` and a re-presented ticket is refused
  (`ticketFingerprint` + `Cache.exists`/`set` in `index.ts`). POP-local best-effort —
  see R2.
- `iss`/`aud` are bound on `mfa_session` and the proof. The proof is single-use
  (`jti` + replay guard), short-TTL, and delivered as a cookie — **never in a URL**.
- `mfa_session` is a host-only HttpOnly/Secure/SameSite=Lax cookie, 8h absolute.

**Verify path**
- **Replay guard** marks the consumed time-step atomically in `Cache` (incr-based, no
  TOCTOU window) so a code can't be reused within its validity window.
- **Brute-force guard** counts failures per user in `Cache`, locks over `MAX_ATTEMPTS`,
  and clears on a successful verify. (POP-local — see R2.)
- The seed is fetched from KV at verify time and **never exposed to the browser** (the
  runtime has no `crypto.subtle.encrypt`).

**Enforcement filter (`otp-filter`)**
- **Default-deny**: bypasses only `{AUTH_PREFIX}` paths and `/health`; everything else
  requires a valid `mfa_session`. Does not enumerate "protected" paths.
- **Fail-closed** on missing key / bad signature / expired token, and on an unset
  `MFA_AUDIENCE` (it refuses every session rather than trust a token it can't scope).
- **Traversal-safe bypass**: refuses to bypass paths containing `..`, `//`, `\`, or
  percent-encoded dots/slashes, so a path the origin would normalise (e.g.
  `{AUTH_PREFIX}/../admin`) cannot slip past the gate.
- Honours `nbf` when present; the unauthenticated redirect target is a **relative**
  path only (no attacker-controlled Host folded into `redirect=`).

**Hosted UI**
- All reflected values (branding, error codes) are HTML-escaped; `Referrer-Policy:
  no-referrer` and no third-party resources on the challenge/enroll pages limit
  ticket leakage and clickjacking surface.

## Residual risks we accept (platform-constrained)

`Cache` is POP-local with no cross-PoP view; KV is read-only from the app and
eventually consistent with no atomic counters. These cannot be fully closed on
FastEdge:

- **R1 — Cross-PoP single-use.** A captured proof or `mfa_session` can be replayed at
  a *different* PoP within its TTL; there is no global denylist. **Bound:** short TTLs,
  `aud`/`iss`/`jti` binding.
- **R2 — Cross-PoP brute force.** A distributed attacker who already holds the password
  can spread code guesses across PoPs to evade the per-PoP `Cache` cap. **Bound:**
  short single-use ticket + low per-ticket attempt cap + relogin-on-fail, delegating
  the global limit to the **origin's login rate-limiting**. Optional 7–8 digit codes
  multiply the keyspace 10–100×.
- **R3 — KV revocation lag.** A rotated/deprovisioned seed may still verify briefly at
  some PoPs (eventual consistency). Relevant to offboarding; accepted.
- **R4 — TOTP seeds are encrypted at rest in KV (`encoding: "masked"`).** Added to the
  Gcore KV write API specifically for this template, since the runtime has no
  `crypto.subtle.encrypt`/`decrypt`/`generateKey` and this app cannot seal the seed
  with a key it holds only at request time. Masking is a KV-store-level property: the
  seed is stored encrypted and the `fastedge::kv` read path (`readSeed` in
  `otp-app/src/seed/kv.ts`) decrypts it transparently for an authorized reader, so
  `/verify` still works unmodified. This closes the previous plaintext-at-rest gap (a KV
  data-browsing UI, logs, or backups no longer expose seeds), but does not remove the
  underlying trust boundary: anyone with the KV read grant this app holds, or an
  equivalent `GCORE_API_TOKEN`, can still reach the seed through that same authorized
  path and mint valid codes for every enrolled user. **You must still:** use a
  single-tenant, per-customer isolated KV store; scope `GCORE_API_TOKEN` to that one
  store; restrict and rotate KV access accordingly.
- **R5 — Enrollment & recovery trust (delegated to the origin).** First enrollment and
  account recovery are only as strong as the password until a second factor is bound
  (trust-on-first-use). totp-app deliberately does **not** perform identity proofing —
  that is the origin's job. Self-service `/activate` is **on by default** for easy
  deployment and inherits the password's trust level: an attacker who already holds the
  password for a not-yet-enrolled account can bind their own authenticator. **Bound:**
  for sensitive accounts, enroll proactively via `POST {AUTH_PREFIX}/enroll` (so there is
  no unenrolled-but-password-valid window), or set `ALLOW_SELF_ENROLLMENT=false` to
  disable `/activate` entirely. **Recovery:** a lost authenticator is re-provisioned by
  calling `POST {AUTH_PREFIX}/enroll` with `force:true` behind the origin's own
  identity-proofing flow (helpdesk, email re-verification, etc.). No backup codes are
  issued — recovery is the origin's responsibility.
