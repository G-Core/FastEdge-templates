# totp-app — Edge TOTP MFA for FastEdge

Adds a **TOTP (RFC 6238) two-factor step** in front of a website's existing login,
deployed at the edge on Gcore FastEdge. The site keeps its own password login;
this app hosts the 6-digit challenge, verifies the code (with replay and
brute-force protection), and hands back a signed assertion the origin trusts — so a
customer gets a second factor without building TOTP themselves.

## Components

| Component | Language | Role |
| --- | --- | --- |
| `otp-app/` | TypeScript + Hono (WASM) | HTTP app: challenge, verify, enroll, self-service activate, logout, JWKS, health. Signs the `mfa_session` cookie (HS256) and the optional ES256 proof. |
| `otp-filter/` | Rust (proxy-wasm) | CDN enforcement filter: verifies `mfa_session` on protected paths, **default-deny** and **fail-closed**. |

**Two enforcement profiles:** **A** (default) — the filter enforces, zero origin
code; **B** (opt-in) — the origin verifies a one-time ES256 proof via JWKS and mints
its own session.

## Build & test

From the repo root:

```bash
pnpm install
pnpm build        # build both wasm binaries into ./wasm
pnpm test         # run TS unit tests + Rust filter tests
```

Per-component scripts: `pnpm build:app` / `pnpm test:app` (otp-app),
`pnpm build:filter` / `pnpm test:filter` (otp-filter).

## Configure

Copy `otp-app/.env.example` and `otp-filter/.env.example` to `.env` and fill in real
values (`.env` is git-ignored). The full env/secret reference is in
[`context/architecture/storage-and-secrets.md`](context/architecture/storage-and-secrets.md).
For Profile B, generate the ES256 keypair with `node otp-app/scripts/gen-ec-keypair.mjs`.

## Deploy

Upload the compiled binaries to the Gcore portal under **FastEdge → Templates**:

- `wasm/totp-app.wasm` — as an **HTTP App** template
- `wasm/totp-filter.wasm` — as a **Proxy-WASM** template

Set the environment variables and secrets from your `.env` files on each template.

**CDN wiring:** attach `otp-app` as a CDN origin on the `{AUTH_PREFIX}/*` path rule
of the customer's CDN resource; attach `otp-filter` as the CDN proxy app in front
of the protected paths (bypassing `{AUTH_PREFIX}` + `/health`). The app and the
origin share the CDN host so `mfa_session` is first-party host-only.

## ⚠️ Security — read before deploying

This is an authentication gate; misconfiguration can make it bypassable. At minimum:

- **Lock the origin to edge-only traffic.** Any edge gate is meaningless if the
  origin is directly reachable — an attacker just skips the CDN. Restrict the origin
  to Gcore CDN ingress (IP allowlist / origin auth / tunnel).
- **Set `MFA_AUDIENCE`** on both apps when the filter is deployed. The filter
  **fail-closes** (refuses every session) if it is unset.
- **TOTP seeds are encrypted at rest in KV**, but still readable in plaintext through
  the same authorized path this app uses. Use a single-tenant, per-customer isolated
  KV store; scope `GCORE_API_TOKEN` to that one store and treat it as equivalent to
  every seed it can reach.
- **The edge `mfa_session` is short-lived (8h, non-sliding) and not cross-PoP
  revocable.** Understand the accepted residual risks before relying on it.
- **CDN logs include user identity.** The filter logs the session subject (`sub`)
  and request path on each authorized request. If `sub` contains PII, review your
  CDN log retention policy.

Full trust model, protections, and the residual risks knowingly accepted are in
[`context/security/threat-model.md`](context/security/threat-model.md), and the
customer-side wiring is in [`context/integration.md`](context/integration.md).

## Documentation

Start at [`context/INDEX.md`](context/INDEX.md).
