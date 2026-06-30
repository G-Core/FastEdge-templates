# Integration — Wiring TOTP into a Customer Login

This describes how a customer adds the TOTP second factor to a site that already
has its own username/password login. The origin keeps owning *who* the user is;
totp-app adds the second-factor step in front of it.

## The three changes a customer makes

Adding the TOTP second factor is **three small changes** on the origin side, all in
the auth layer — the rest of the site is untouched:

1. **Split login into password-then-OTP.** After the password check succeeds,
   instead of immediately minting the full origin session:
   - sign a **handoff ticket** = HMAC(`HANDOFF_KEY`) over
     `{ sub: userId, next, exp: now+TICKET_TTL }`;
   - set a short-lived **`pre_mfa`** cookie/marker so the origin remembers the
     password step passed (bind it to `sub`);
   - 303-redirect to `{AUTH_PREFIX}/challenge?t=<ticket>` (totp-app, same host
     via the CDN path rule).

2. **Finish login on return to `next` — pick a profile:**
   - **Profile A (default, zero origin code):** the Rust filter enforces the edge
     `mfa_session` (8h) on protected paths, so any request reaching the origin has
     passed MFA. The origin just re-identifies its `pre_mfa` user and mints its own
     session — **no proof verification, no crypto.** `HANDOFF_KEY` is the only key
     it holds.
   - **Profile B (opt-in, longer sessions):** the edge hands back a one-time **ES256**
     proof; the origin verifies it via totp-app's **JWKS** endpoint
     (`createRemoteJWKSet` — public key only, can't forge), checks `sub` matches
     `pre_mfa`, and mints its **own revocable session** with whatever lifetime it
     wants (safely longer than the 8h edge session).
   The proof is **never in a URL** — it is delivered as a short-lived cookie.

3. **Enroll users.** No origin endpoint needed: call
   `POST {AUTH_PREFIX}/enroll` (gated by `ENROLL_API_KEY`), which writes the seed to
   KV (via totp-app's `GCORE_API_TOKEN`); verify reads it from KV at challenge time.
   Users can also self-enroll on first login via `{AUTH_PREFIX}/activate` (on by
   default; set `ALLOW_SELF_ENROLLMENT=false` to require admin provisioning instead).
   **Recovery:** re-provision a lost authenticator by calling `/enroll` with
   `force:true` behind your own identity check. Self-service enrollment inherits the
   password's trust level — see [security/threat-model.md](security/threat-model.md) R5
   before relying on it for sensitive accounts.

Only the origin's auth module changes; the rest of the site stays as-is.

## Shared configuration (origin ⇄ edge)

| Key | Origin uses it to… | Edge uses it to… |
| --- | --- | --- |
| `HANDOFF_KEY` (HS256) | sign the handoff ticket | verify it on `/challenge` + `/verify` |
| **JWKS** (Profile B only) | verify the one-time ES256 proof via `createRemoteJWKSet` (**public key only**) | sign the proof (`MFA_PROOF_SIGNING_KEY`) + serve `{AUTH_PREFIX}/.well-known/jwks.json` |

> **Profile A shares only `HANDOFF_KEY`** — the origin holds no verification key at
> all; the Rust filter enforces `mfa_session` (HS256 `MFA_SESSION_KEY`, edge-internal).
> Profile B adds the JWKS public-key fetch. No symmetric secret crosses to the origin
> on the proof path.

Both apps live on the **same CDN host** (path rule `{AUTH_PREFIX}/*` → totp-app), so
the `mfa_session` cookie is first-party and host-only. Same-host is **required**: the
proof and session are consumed at the edge into a host-only cookie, so there is no
cross-host URL-token path.

## What the edge asserts — and what the origin still owns (read before shipping)

The edge proves **"a second factor succeeded"**, not **"this specific request is user X."**
Getting this boundary right is the difference between a real MFA gate and a bypassable one.

- **Identity stays the origin's job.** In **Profile A** the Rust filter only verifies
  that *a* valid `mfa_session` exists — it does not bind that session to the origin's
  password identity, and it deliberately does **not** forward the user id to the origin.
  That's correct here: the origin already authenticated the password and re-identifies
  its `pre_mfa` user when minting its session. Do **not** add an unsigned
  `x-mfa-user`-style header for the origin to trust — forwarded-identity headers are a
  recurring source of auth-bypass CVEs (e.g. oauth2-proxy header smuggling). If you need
  the *edge* to assert **which** user passed MFA, use **Profile B**: the ES256 proof
  carries `sub`, the origin verifies it via JWKS and checks it matches `pre_mfa`. This is
  the same signed-assertion pattern Cloudflare Access uses (`Cf-Access-Jwt-Assertion`),
  and the reason the proof is signed rather than a bare header.

- **Lock the origin to edge-only traffic (required).** Any edge gate — Profile A or B —
  is only meaningful if the origin **cannot be reached except through the CDN**. If the
  origin's IP is directly reachable, an attacker simply skips the edge and the
  `mfa_session`/filter never runs. Customers must restrict the origin to Gcore CDN
  ingress (IP allowlist / origin auth / tunnel). Profile B is more robust here because
  the origin *independently verifies* the signed proof rather than trusting that the
  request came through the gate — prefer it when the origin can't be fully locked down.

The env/secret list to configure both apps is in
[architecture/storage-and-secrets.md](architecture/storage-and-secrets.md).
