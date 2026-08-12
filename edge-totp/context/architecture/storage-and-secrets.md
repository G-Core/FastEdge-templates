# Storage & Secrets — Seed location, KV mode, config

## The only hard question: where is the TOTP seed at verify time?

TOTP is symmetric — the verifier must hold the same per-user seed to recompute the
code. That per-user durable state is the whole storage question.

**Storage model = KV only.** The seed lives in a **per-customer, single-tenant KV
store** (one deployment = one customer, so the store is isolated, not a multi-tenant
honeypot). Seeds are stored **encrypted at rest** (`encoding: "masked"`) and decrypted
transparently on read by the `fastedge::kv` SDK — but scope `GCORE_API_TOKEN` to the
single store and treat KV read access as equivalent to the seeds themselves, since that
same authorized path still reaches the plaintext seed (see `../security/threat-model.md`
R4).

### KV storage — the seed source

- **Reads** (verify time): `KvStore.open("TOTP_USER_SEEDS").get(KV_KEY_PREFIX+userId)`
  via the `fastedge::kv` SDK. `TOTP_USER_SEEDS` is a `store`-type template param — a
  fixed binding name, not a runtime value — linked to a physical KV store at deploy
  time via `storeRefs`/`kvStoreVars`. That link is what grants read access; it does not
  appear in `env`. Globally replicated, so PoP-safe.
- **Writes** (enrollment): the SDK is **read-only**, so the edge writes via the
  **Gcore KV REST API** using `GCORE_API_TOKEN`:
  `PUT /fastedge/v1/kv/{KV_STORE_ID}/data`, sent as `application/json` with a body of
  `[{ key: KV_KEY_PREFIX+userId, datatype: "kv", op: "add", payload: { value: <base32
  seed>, encoding: "masked" } }]` (see `otp-app/src/seed/kv.ts`).

> Why KV and not "hand the seed off at start": the seed must reach the verifier at
> the **browser's** PoP, and `Cache` is POP-local. KV is the only globally-replicated
> store, and the seed must never reach the browser (no `crypto.subtle.encrypt`). See
> `architecture/flow.md` "Why fetch the seed at verify time."

## Configuration

### Environment variables (`getEnv`, non-secret)

| Var | Default | Purpose |
| --- | --- | --- |
| `AUTH_PREFIX` | `/auth/totp` | Mount path for this app. Used by both the HTTP app (Hono base path, JWKS URL) and the Rust filter (bypass prefix). Set to match the CDN path rule. |
| `TOTP_ISSUER` | — | Issuer label in the `otpauth://` URI shown in the authenticator app |
| `TOTP_DIGITS` | `6` | Code length |
| `TOTP_PERIOD` | `30` | Time-step seconds |
| `TOTP_ALGORITHM` | `SHA1` | HMAC hash (SHA1 is the RFC 6238 default; authenticator apps assume it) |
| `TOTP_DRIFT` | `1` | Allowed ± time-steps for clock skew |
| `TICKET_TTL` | `90` | Handoff-ticket lifetime (s) — short, single-use. Set by the origin when it signs the ticket; the app independently requires `exp` and caps absolute age. |
| `PROOF_TTL` | `90` | Profile-B one-time proof lifetime (s); single-use |
| `MFA_SESSION_TTL` | `28800` | `mfa_session` lifetime (s) — **8h, absolute** (non-sliding) re-MFA interval |
| `ENROLL_TTL` | `600` | `totp_enroll` cookie lifetime (s) — window for the user to scan QR + confirm code |
| `MAX_ATTEMPTS` | `5` | Failed codes before lockout (per Cache window); cleared on success |
| `ALLOW_SELF_ENROLLMENT` | `true` | Whether unenrolled users may self-enroll on first login via `{AUTH_PREFIX}/activate`. Set `false` for admin-provisioned deployments — `/activate` returns 403 and `/challenge` refuses unenrolled users. See `../security/threat-model.md` R5. |
| `MFA_SESSION_COOKIE` | `mfa_session` | Edge session cookie the Rust filter checks (Profile A); host-only, no `Domain` |
| `MFA_PROOF_COOKIE` | `mfa_proof` | Name of the one-time ES256 proof cookie (Profile B) |
| `MFA_AUDIENCE` | — | `aud` claim embedded in `mfa_session` and the proof. **Required when the filter is deployed** (the filter fail-closes without it). Should be the CDN hostname (e.g. `https://app.example.com`). |
| `MFA_ISSUER` | — | `iss` claim embedded in `mfa_session` and the proof. Validated only when set on both sides. |
| `MFA_PROOF_PUBLIC_JWK` | — | Pre-computed public JWK JSON for the Profile-B JWKS endpoint. Generated offline (`exportKey` is unavailable in the runtime, so the public JWK is stored here rather than derived at runtime). |
| `KV_STORE_ID` | — | KV store numeric ID — used for writes via the Gcore KV REST API. Must point at the same store linked via `TOTP_USER_SEEDS` below. |
| `KV_KEY_PREFIX` | `totp:` | Prefix prepended to userId for KV keys. Default is `DEFAULT_KEY_PREFIX = "totp:"` (single source of truth in `seed/kv.ts`). Override to share one KV store across multiple apps without key collisions. |
| `GCORE_API_URL` | `https://api.gcore.com` | Gcore API base for KV writes |
| `TOTP_BRAND_NAME` | — | Appended to page `<title>` and used as logo `alt` text |
| `TOTP_BRAND_LOGO_URL` | — | URL of a logo image shown above the form (max 48 × 180 px) |
| `TOTP_BRAND_FAVICON_URL` | — | URL of a favicon injected as `<link rel="icon">` |
| `TOTP_BRAND_BUTTON_COLOR` | `#0066cc` | Button background + input focus-ring colour |
| `TOTP_BRAND_BUTTON_HOVER_COLOR` | — | Explicit hover background. If unset, `filter: brightness(0.88)` is applied instead. |

> The JWKS path is derived at runtime from `AUTH_PREFIX`
> (`{AUTH_PREFIX}/.well-known/jwks.json`) — there is no separate path env var.

### KV store binding (`fastedge::kv`, not `getEnv`)

| Param | Purpose |
| --- | --- |
| `TOTP_USER_SEEDS` | `store`-type param. Links the app to a physical KV store at deploy time (`storeRefs`/`kvStoreVars`), granting `KvStore.open("TOTP_USER_SEEDS")` read access. Not readable via `getEnv` — the binding name is fixed in code (`seed/kv.ts`), same as a `getSecret()` key. |

### Secrets (`getSecret`)

| Secret | Purpose |
| --- | --- |
| `HANDOFF_KEY` | HS256 key for the origin→edge handoff ticket (shared with origin) |
| `MFA_SESSION_KEY` | HS256 key for the `mfa_session` cookie (edge-internal: HTTP app signs ↔ Rust filter verifies) |
| `MFA_PROOF_SIGNING_KEY` | **ES256 private key (PKCS8)** — edge signs the Profile-B proof; origin verifies via JWKS. **Profile B only.** |
| `ENROLL_API_KEY` | Gates `POST /auth/totp/enroll` |
| `GCORE_API_TOKEN` | Token for KV seed writes via the Gcore API (scope to the single store) |

Use `dotenv` sync (the `manage`/`live-test` skills sync `fixtures/.env*` to the
deployed app) — see the FastEdge dotenv docs.

> **Profile-B keypair:** generate the ES256 keypair with
> `node otp-app/scripts/gen-ec-keypair.mjs` (add `--dotenv` for `.env`-ready
> lines). It prints `MFA_PROOF_SIGNING_KEY` (the PKCS#8 private key — set as a
> secret) and `MFA_PROOF_PUBLIC_JWK` (the public JWK — set as an env var, served
> at the JWKS endpoint). The public JWK is stored rather than derived at runtime
> because `exportKey` is unavailable in the FastEdge runtime.
