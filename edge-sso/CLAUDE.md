# Multi-Provider SSO for FastEdge CDN Resources

## Governance (REQUIRED)

Read `AGENTS.md` for company-wide agent rules. These are mandatory and override any conflicting behavior. Key rules: never go beyond the assigned task, never change code that was not asked to change, never "improve" or "optimize" without a clear request, always distinguish observations from action requests.

---

## Project Goal

A **sellable edge SSO bolt-on** for Gcore FastEdge — an Identity-Aware Proxy (forward-auth) in the spirit of Cloudflare Access. A customer puts our apps in front of their existing site to add SSO (Google, GitHub, Microsoft, Facebook, and SAML) without rewriting their backend. Shipped as **three templates** on the identity-delivery axis — **gate-only** (allow/deny), **cookie** (verifiable JWT the origin checks), **header** (signed `x-sso-*` headers injected upstream) — over a shared `core/`.

> **Read `context/INDEX.md` first** — it is the discovery hub and current state. Then `context/architecture/overview.md` for the authoritative design (variants, repo structure, config model, signing strategy).

## Architecture Overview

> **Structure (as-built):** shared `core/` (`@sso/core` TS federation/session + `@sso/filter` Rust) consumed by thin `templates/<variant>/{auth-app,cdn-filter}` presets. All three variants (gate-only, cookie, header) are complete (see `context/development/testing.md` for the test suites). See `context/architecture/overview.md` for the authoritative design. The per-deployment view below still holds: each deployment is one auth-app + one filter.

Two FastEdge apps work together **per deployment**:

1. **CDN filter** (Proxy-WASM, Rust — `core/filter` → `templates/*/cdn-filter`) — sits in the CDN proxy layer, verifies the session JWT on every request, redirects unauthenticated users
2. **HTTP Auth App** (HTTP App, TypeScript/Hono — `core/federation` → `templates/*/auth-app`) — federates to the IdP (SAML / GitHub / Google), issues the session token

```
User → CDN App (check session cookie)
              ↓ unauthenticated
       HTTP Auth App /auth/login  →  IdP (Okta / Azure AD / etc.)
                                          ↓ (user authenticates)
       HTTP Auth App /auth/callback  ←  IdP POSTs SAMLResponse
              ↓ (validates SAML, issues signed token)
       Back to CDN resource (with session cookie set)
              ↓ authenticated
       CDN App passes through → origin
```

See `context/` for detailed documentation on each component and design decisions.

## Discovery Guide

**Read when working on:**

| Task | Read |
|---|---|
| **Start here — current state, file map** | `context/INDEX.md` |
| Product shape, variants, repo structure, token contract, signing strategy | `context/architecture/overview.md` |
| Three delivery templates (gate-only / cookie / header) | `context/architecture/auth-modes.md` |
| SAML-specific flow, XML/crypto, security checklist | `context/architecture/saml-flow.md` |
| Choosing a library for the auth app (WebCrypto vs Node APIs) | `context/architecture/runtime-constraints.md` |
| Security posture and known limitations (CHECK before touching auth/error/token/redirect) | `context/architecture/security.md` |
| How a customer wires login into their origin | `context/design/integration.md` |
| Run or extend the test suite (layout, scripts, shared patterns) | `context/development/testing.md` |
| Every configuration option (env vars + secrets, with cross-app callouts) | each template's `.env.example` |

## Key Constraints

- **No shared state**: FastEdge WASM instances are stateless per-request; sessions must be self-contained signed tokens
- **KV store is read-only** from apps — data written via Gcore portal/API only
- **CDN App language**: Rust (Proxy-WASM ABI)
- **HTTP App language**: JavaScript or TypeScript (recommended)
- **Execution limits**: 50ms (Basic plan), 200ms (Pro plan)
- **No Node.js APIs in HTTP App**: The JS runtime (StarlingMonkey) has no `node:crypto`, no `fs`, no Node compat layer. Standard SAML libraries (samlify, node-saml, boxyhq) will not work. Use the WebCrypto-native stack — see `context/architecture/runtime-constraints.md`.

## FastEdge Platform

- JS SDK: `@gcoredev/fastedge-sdk-js`
- Framework: Hono with `app.fire()` (not `export default`)
- Secrets: `getSecret("KEY")` from `fastedge::secret`
- KV: `KvStore.open("name")` from `fastedge::kv` (read-only from app)
- Outbound fetch: standard `fetch()` API available
