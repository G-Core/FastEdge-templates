# Flow — Enroll, Challenge, Verify

## Actors & shared keys

- **Browser** — the end user.
- **Origin** — the customer's existing site.
- **Edge** — `totp-app` (the HTTP app) plus `otp-filter` (the Rust enforcement filter).

Shared secrets (set as FastEdge secrets on the edge apps; matching values held by
the origin where noted):

- `HANDOFF_KEY` — HMAC key the **origin** uses to sign the short-lived handoff
  ticket and the **HTTP app** verifies. Proves "this user just passed the password
  step." The only key shared with the origin in Profile A.
- `MFA_SESSION_KEY` — HS256 key the **HTTP app** signs `mfa_session` with and the
  **Rust filter** verifies. Edge-internal; never shared with the origin.
- `MFA_PROOF_SIGNING_KEY` (**Profile B only**) — **ES256 private key** the HTTP app
  signs the one-time proof with; the **origin** verifies it via the served **JWKS**
  (public key only — it cannot forge).

## Enrollment (one-time, per user)

Two paths write a seed to KV:

- **Admin-provisioned** — `POST {AUTH_PREFIX}/enroll`, server-to-server, gated by
  `ENROLL_API_KEY` (constant-time compared). Generates a random base32 secret
  (`crypto.getRandomValues`), writes it to KV via the Gcore KV REST API, and returns
  `{ userId, otpauthUri, svgQr }`.
- **Self-service** — `GET {AUTH_PREFIX}/activate?t=<ticket>` shows a QR + confirmation
  form; the pending seed rides in a signed, short-lived `totp_enroll` cookie and is
  **only written to KV after the user confirms a code** (`POST {AUTH_PREFIX}/activate`).
  The challenge page redirects an unenrolled user here automatically.

QR is rendered server-side to an inline `<svg>` via `uqr`. The `otpauth://` URI
embeds the seed, so it is rendered **locally only — never sent to an external QR
service**.

## Challenge + verify (every login)

1. Browser submits username+password to **Origin**. Origin verifies the password
   (its existing logic). If the user has TOTP enrolled, it starts the challenge.
2. Origin signs a **handoff ticket** = HMAC(`HANDOFF_KEY`) over
   `{ sub: userId, next: <return URL>, iat, exp: now+TICKET_TTL }`, sets a short-lived
   `pre_mfa` marker bound to `sub`, and **303-redirects** the browser to
   `{AUTH_PREFIX}/challenge?t=<ticket>`. The ticket carries no seed.
3. **HTTP app** `GET {AUTH_PREFIX}/challenge?t=<ticket>`: verifies the ticket
   signature, `exp` (required), and absolute age, then renders the 6-digit entry page
   (form posts `t` + `code` to `/verify`).
4. Browser `POST {AUTH_PREFIX}/verify { t, code }`. The app:
   a. Verifies the ticket → `userId`, `next`.
   b. **Brute-force guard:** `Cache.incr("fail:"+userId)`; blocks over `MAX_ATTEMPTS`
      within a TTL window. The counter is cleared on a successful verify.
   c. **Fetches the seed** for `userId` from KV (`KvStore.open(KV_STORE_NAME)
      .get(KV_KEY_PREFIX+userId)`). See "Why fetch at verify time" below.
   d. **Verifies the code:** base32-decode seed → HMAC over the time-step counter
      (`floor(Date.now()/1000 / TOTP_PERIOD)`), checking `±TOTP_DRIFT` steps,
      constant-time compare.
   e. **Replay guard:** atomically marks the consumed time-step in `Cache`
      (`used:<userId>:<step>`, TTL ≈ the validity window) so a code can't be reused.
      POP-local — defence-in-depth, not a global guarantee.
   f. On success, mints the edge **`mfa_session`** = HS256(`MFA_SESSION_KEY`)
      `{ sub, amr:["otp"], iat, exp: now+MFA_SESSION_TTL, iss?, aud? }`, sets it as a
      host-only HttpOnly/Secure/SameSite=Lax cookie, and **303-redirects** to `next`
      (validated relative/same-host). **Profile B** additionally mints a one-time
      **ES256** proof `{ sub, amr:["otp"], iat, exp: now+PROOF_TTL, iss?, aud?, jti }`
      and delivers it as a short-lived cookie (never in a URL).
5. Enforcement depends on the profile:
   - **Profile A (default):** the **Rust filter** checks `mfa_session` on every request
     (default-deny, fail-closed) and lets the user through. The origin needs no MFA
     crypto — `HANDOFF_KEY` is the only key it holds.
   - **Profile B (opt-in):** the origin verifies the one-time ES256 proof via the
     served **JWKS** (public key only), confirms `sub` matches its `pre_mfa` user, and
     mints its **own revocable session** with whatever lifetime it chooses.

## Why fetch the seed at verify time (the PoP reasoning) — IMPORTANT

The seed must reach the verifier and must **never be exposed to the browser** (no
`crypto.subtle.encrypt`, so it can't be sealed into a browser-visible token).

Holding the seed in `Cache` between an origin-initiated start and a browser-initiated
verify does not work: `Cache` is **POP-local**, and the two calls usually hit
**different PoPs**. KV is the only cross-PoP store. So the app fetches the seed **at
verify time**, on the browser's PoP, via a KV read (globally replicated). The seed
travels edge↔KV only. `Cache` is used for replay/rate-limit as per-PoP
defence-in-depth.

## Deployment & cookies

Deploy the HTTP app as a CDN origin on `{AUTH_PREFIX}/*` of the customer's CDN
resource (path rule), so the challenge UI and the origin are the **same host** → the
`mfa_session` cookie is first-party host-only and `next` stays same-origin. Same-host
is required: the proof and session are consumed at the edge into a host-only cookie,
so there is no cross-host URL-token path.
