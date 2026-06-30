# TOTP MFA for FastEdge — Edge Two-Factor Login Enhancer

## Governance (REQUIRED)

Read `AGENTS.md` for company-wide agent rules. These are mandatory and override any conflicting behavior. Key rules: never go beyond the assigned task, never change code that was not asked to change, never "improve" or "optimize" without a clear request, always distinguish observations from action requests.

---

## Project Goal

A **sellable edge MFA bolt-on** for Gcore FastEdge — adds **TOTP (RFC 6238) two-factor authentication** in front of a customer's existing login, so they get a second factor *without building TOTP themselves*. The customer keeps their own login; our edge app handles the OTP challenge, verification, replay/rate-limiting, and hands back a signed proof their origin trusts.

The governing principle is **"issue centrally, verify everywhere"**: the durable seed lives in per-customer KV; the edge only ever *verifies* and issues short-lived signed assertions.

"Easy to deploy & configure" is the product promise: a FastEdge **HTTP app** the customer routes `/auth/totp/*` to via a CDN path rule, configured entirely through env vars + secrets.

> **Read `context/INDEX.md` first**, then `context/architecture/overview.md` and `context/design/decisions.md`. For how a customer wires TOTP into their login, see `context/integration.md`.

---

## Status — BOTH COMPONENTS BUILT

- **`otp-app` (TypeScript HTTP app)** — implemented and deployed. All routes live:
  challenge, verify, enroll, activate (self-service), logout, JWKS, health, KV seed.
- **`otp-filter` (Rust proxy-wasm)** — implemented: verifies `mfa_session`,
  default-deny, fail-closed, traversal-safe bypass.
- Design rationale is in `context/design/decisions.md`. Deployed app IDs/URLs are
  operational state and are kept out of this repo.

---

## Architecture Overview

A single FastEdge **HTTP app (TypeScript / Hono)** plus a **Rust proxy-wasm enforcement filter**, attached as a **CDN origin** on `/auth/totp/*` of the customer's existing CDN resource. Storage model is **KV-only**. Repo layout:

```
otp-app/    ← TypeScript HTTP app
  src/
  tests/
  package.json / tsconfig.json
otp-filter/ ← Rust proxy-wasm enforcement filter
  src/lib.rs
  Cargo.toml
package.json          ← workspace root; Rust build/test scripts here
pnpm-workspace.yaml   ← lists otp-app
```

```
Browser ── password login ──▶ Customer origin
                                   │ password OK; user has TOTP enrolled
                                   │ signs handoff ticket {userId,next,exp} (HANDOFF_KEY)
                                   ▼ 303 redirect
Browser ──▶ totp-app  GET /auth/totp/challenge?t=<ticket>   (hosted 6-digit UI)
Browser ──▶ totp-app  POST /auth/totp/verify {t, code}
                                   │ fetch seed for userId (KV read)
                                   │ verify TOTP (crypto.subtle HMAC) + replay/rate-limit (Cache)
                                   │ set mfa_session cookie (HS256 MFA_SESSION_KEY, 8h)
                                   │ [Profile B] also mint one-time ES256 proof for origin (JWKS)
                                   ▼ 303 redirect to next (same-host; no URL token)
Browser ──▶ Customer origin  (A default: Rust filter checks mfa_session, default-deny;
                              B opt-in: origin verifies ES256 proof via JWKS, mints own session)
```

The seed is fetched **at verify time** (not held between steps) because `Cache` is POP-local and the origin-initiated start and browser-initiated verify usually hit different PoPs. See `context/architecture/flow.md` for the full flow and why.

---

## Discovery Guide

**Read when working on:**

| Task | Read |
| --- | --- |
| **Orientation / what every file is (START HERE)** | `context/INDEX.md` |
| **What this is / product overview** | `context/architecture/overview.md` |
| **How it's built (design)** | `context/design/decisions.md` |
| The end-to-end challenge/verify flow + PoP reasoning | `context/architecture/flow.md` |
| Where secrets live, config/env/secrets, KV-mode + Gcore KV write API | `context/architecture/storage-and-secrets.md` |
| FastEdge JS runtime facts that constrain TOTP (crypto, KV, Cache) | `context/design/runtime-constraints.md` |
| How a customer wires TOTP into their login | `context/integration.md` |
| Build, test, and deploy | `README.md` |

---

## Key Constraints (TOTP-relevant — full detail in `context/design/runtime-constraints.md`)

- **TOTP = HMAC over a time-step.** `crypto.subtle` supports HMAC sign/verify (SHA-1/256/…) + raw key import — sufficient for RFC 6238. `Date.now()` is available in the app runtime.
- **No `crypto.subtle.encrypt`/`decrypt`/`generateKey`.** So a seed cannot be sealed into a browser-visible token; it must travel server-to-server only.
- **KV is read-only from the app** (`fastedge::kv`). Enrollment writes the seed through the **Gcore KV REST API** with a `GCORE_API_TOKEN` — `PUT /fastedge/v1/kv/{store_id}/data` (KV is the only seed store).
- **`Cache` is POP-local** and transient — fine for replay/rate-limit (defense-in-depth), not for cross-PoP seed handoff.
- **No shared state / no WebSocket** — request/response only; sessions are self-contained signed tokens.
- **HTTP App language**: TypeScript (Hono via `addEventListener("fetch", e => e.respondWith(app.fetch(e.request)))` — **not** `app.fire()`); StarlingMonkey runtime, no Node.js APIs.

---

## FastEdge Platform Quick Reference

- JS SDK: `@gcoredev/fastedge-sdk-js`; framework Hono wired via `addEventListener("fetch", e => e.respondWith(app.fetch(e.request)))` (**not** `app.fire()`, not `export default`)
- Secrets: `getSecret("KEY")` from `fastedge::secret` (request-time only)
- Env: `getEnv("KEY")` from `fastedge::env` (request-time only)
- KV (read): `KvStore.open("name").get(key)` from `fastedge::kv` → `ArrayBuffer | null`
- Cache: `Cache.incr/get/set` from `fastedge::cache` (POP-local, atomic counters, TTL)
- Outbound fetch: standard `fetch()` available (limited count per invocation)
- Deploy: HTTP app attached as CDN origin via a path rule (`/auth/totp/*`).
- **Build/scaffold/test/deploy via the `gcore-fastedge` plugin SKILLS** — they are the intelligence layer; the MCP server (Docker) is just their executor. Do **not** call MCP build tools or `./node_modules/.bin/fastedge-build` directly unless a skill reports its executor is down.
  - `/gcore-fastedge:scaffold` — create project files from blueprints (do **not** hand-author `package.json`/`tsconfig`/`Cargo.toml`).
  - `/gcore-fastedge:test` — TDD loop with `@gcoredev/fastedge-test`.
  - `/gcore-fastedge:deploy` — build + pre-deploy test gate + deploy.
  - `/gcore-fastedge:manage` / `:live-test` — env/secret sync + scenario tests against the deployed app.
  - `/gcore-fastedge:fastedge-docs` — authoritative SDK/runtime reference (often answers inline without a round-trip).
