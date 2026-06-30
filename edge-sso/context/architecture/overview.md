# Architecture Overview — Edge SSO Bolt-On

## What this is

An **Identity-Aware Proxy (IAP) / forward-auth gateway** for the Gcore CDN edge, sold as a **bolt-on**: a customer puts our FastEdge apps in front of their existing site to add SSO / OAuth / SAML login **without rewriting their backend**.

The category benchmark is **Cloudflare Access** (Zero Trust): edge gates every request, federates unauthenticated users to an IdP, issues a signed cookie, and verifies it at the edge on subsequent requests. Open-source analogues: oauth2-proxy, Pomerium, Authelia, Google IAP, Ory Oathkeeper. The honest pitch is *"Cloudflare Access, native to Gcore FastEdge."*

## Two cooperating apps per deployment

Every variant is built from this pair:

| App | Runtime / language | Role |
|---|---|---|
| **auth-app** | HTTP-WASM, StarlingMonkey, TypeScript / Hono | Federation: provider login/callback (OAuth/OIDC/SAML), issues the signed session token |
| **cdn-filter** | proxy-WASM, Rust | Enforcement: verifies the token on every request, redirects unauthenticated users |

### Why two apps and not one

Recurring question: could the OAuth/redirect logic fold into the filter so customers deploy **one** app instead of two? **No — keep the split.**

**The platform forbids the collapse you'd actually want.** Federation (PKCE, signed state, code exchange, SAML XML/sig validation, `jose` token minting) needs WebCrypto + JS libraries, which only exist in the **HTTP-WASM / StarlingMonkey** runtime. The **proxy-WASM** filter (Rust) cannot run the federation dance. So you *cannot* move auth into the filter. The only real "single app" option is the inverse: delete the filter and make the **JS app an in-path reverse proxy** — wrong direction for a CDN product. It puts a heavyweight JS runtime + `fetch()`-to-origin in the data path of **every** request, burning the 50/200ms budget on the hot path and forfeiting edge-caching positioning. The proxy-WASM filter verifies inline, cheaply, on every request; JS runs only on the cold login path.

**The split is what the category does.** Cloudflare Access, Pomerium, oauth2-proxy, Authelia, Envoy ext_authz all separate *enforcement* from *federation*. Our filter runs **inline in the CDN proxy** (proxy-WASM), avoiding the per-request subrequest hop that draws the main latency complaint against forward-auth tools.

**The split also gives "just OAuth, enforce at origin" for free** — a customer who wants only federation deploys the auth-app alone and enforces on their own backend. Merging would destroy that composability.

## Repo structure — monorepo, `core/` + `templates/`

```
saml-app/
├── core/
│   ├── federation/               # TypeScript package (@sso/core) — runs in the auth-app
│   │   ├── providers/            # google, github, microsoft, facebook, saml/ (+ common.ts: PKCE, signed state)
│   │   ├── app.tsx               # createAuthApp — mounts the /auth/** Hono router
│   │   ├── chooser.tsx           # provider chooser (renders enabled providers dynamically)
│   │   └── config.ts             # runtime config resolution from env/secrets
│   ├── session/
│   │   └── token.ts              # mint/verify; HS256 (gate/header) and ES256 (cookie)
│   └── filter/                   # Rust filter lib
├── templates/
│   ├── gate-only/   { auth-app/ , cdn-filter/ }
│   ├── cookie/      { auth-app/ , cdn-filter/ }
│   └── header/      { auth-app/ , cdn-filter/ }
└── context/
```

### `core/` is two libraries, one per runtime

The auth-app (TS) and the filter (Rust) run in different runtimes and **cannot share source**:

1. **`core/federation/` + `core/session/`** — TypeScript package consumed by every template's auth-app. Mints the token. Future providers land here only — the filter is provider-agnostic.
2. **`core/filter/`** — Rust library consumed by every template's cdn-filter. Verifies the token, redirects, (header variant) injects.

They share only the **token contract** (below), implemented once on each side: TS mints, Rust verifies.

## Token contract

Standard JWT. **Algorithm is per-variant:** gate-only / header sign **HS256** with `SESSION_SECRET`; the **cookie** variant signs **ES256** with `SESSION_SIGNING_KEY` (a PKCS#8 EC private key) and publishes the public half via JWKS (see signing strategy below). Default cookie `sso_session` (configurable via `SESSION_COOKIE`).

```
header  = { alg: "HS256" | "ES256", typ: "JWT", kid? }
payload = { sub, iat, exp, aud, iss?, email?, name?, picture?, given_name?, family_name? }
```

- `aud` scopes a token to its deployment. It is **required and fail-closed**: the auth-app refuses to sign without `SSO_AUDIENCE`, and the filter rejects any token whose `aud` doesn't match — and refuses all sessions when `SSO_AUDIENCE` is unset. Distinct value per deployment = isolated sessions; the same value on two apps = sessions deliberately shared. `iss` is validated only when configured.
- Cookie: `sso_session`; `HttpOnly; Secure; SameSite=Lax`. Under single-domain routing **no `Domain=` is needed** — same-origin.
- The filter verifies signature + `exp` + `aud` (+ `iss` when set). It is **provider-agnostic** — it never learns which provider authenticated.

## Signing strategy & roadmap

**HS256 (shared secret) — gate-only / header.** Each customer deploys their **own** app pair per CDN resource — issuer + all verifiers belong to **one trust domain**, so a shared secret is the zero-friction choice. The filter verifies HS256 against `SESSION_SECRET`.

**ES256 + JWKS — cookie variant.** The cookie variant signs ES256 so the customer's public origin can verify via a published JWKS endpoint and never holds a forge-capable secret. The auth-app signs ES256 with `SESSION_SIGNING_KEY` (`core/session/token.ts` + `key.ts`) and serves the public JWK at `GET /auth/.well-known/jwks.json` (`core/federation/app.tsx`, cookie variant only, gated on `SESSION_PUBLIC_JWK`, public members only); the Rust filter is ES256-only and verifies against `SESSION_PUBLIC_JWK` (algorithm pinned at compile time). An origin verifies the cookie itself via `createRemoteJWKSet` against the JWKS URL.

**StarlingMonkey constraint (the reason for the offline-key design):** `crypto.subtle` supports ECDSA `sign`/`verify` but **not** `generateKey`/`exportKey` — so the keypair is generated offline (`scripts/gen-ec-keypair.mjs`), the private key stored as a PKCS#8 secret (`SESSION_SIGNING_KEY`), and the pre-computed public JWK served from `SESSION_PUBLIC_JWK`. `jose` handles the signing.

## Configuration model — env + secrets only (no KV)

**KV is explicitly NOT used for config** — too expensive per read. Config comes from:

- **Secrets** (`getSecret`) — credentials and signing keys: `*_CLIENT_SECRET`, `SESSION_SECRET`, `SESSION_SIGNING_KEY` (cookie), `IDP_CERT`.
- **Env vars** (`getEnv` / `fastedge::env`) — non-sensitive selectors: `SSO_PROVIDERS`, `SSO_CLAIMS`, `SSO_ISSUER`, `SSO_AUDIENCE`, `CANONICAL_HOST`, `SSO_ALLOWED_ORIGINS`, `SESSION_COOKIE`, `SESSION_PUBLIC_JWK` (cookie), per-provider `*_CLIENT_ID`/`*_REDIRECT_URI`, `MICROSOFT_TENANT`/`MICROSOFT_ALLOWED_TENANTS`, SAML `IDP_*`/`SP_*`, and `LOGIN_PAGE_*` branding.

> Each template's `.env.example` is the authoritative, exhaustive list of every option with inline guidance — including which keys must match between an auth-app and its CDN filter.

### Build-time vs runtime split

- **Build-time** (defines which template you are): variant (gate/cookie/header), header-injection on/off, JWKS on/off. Fixed per artifact.
- **Runtime** (set in the Gcore portal, no rebuild): providers, claims, credentials, redirect URL, cookie name, allowed redirect origins. The **same built WASM serves every consumer.**

### Provider enablement

A provider self-activates only if its secrets exist (`no GOOGLE_CLIENT_ID` → Google off). Override with an explicit `SSO_PROVIDERS="google,github"` allowlist. The chooser page and `/auth/providers` both derive from the same resolved set.

## Cross-domain — Option 3 (single domain via CDN-as-origin)

The CDN supports a **FastEdge HTTP app as an origin**. The CDN resource rule-set routes `/auth/**` to the auth-app as an origin — everything is on one domain.

```
cdn.example.com/auth/**      → CDN rule → auth-app (HTTP app) as origin
cdn.example.com/<everything> → cdn-filter checks cookie → customer origin
```

Consequences:
- Session cookie is plain same-origin — no `Domain=` juggling.
- **The filter MUST bypass `/auth/**`** — without the bypass the login flow redirect-loops.
- IdP callback/ACS URLs register against the single CDN domain.

### CANONICAL_HOST

The auth-app enforces a `CANONICAL_HOST` env var via middleware — any request arriving on the bare FastEdge origin URL (`*.fastedge.cdn.gc.onl`) is 301-redirected to the canonical domain. This prevents sessions being established on the wrong host and keeps IdP callback URLs pointing at a stable, customer-visible domain.

## Deployment model

A **per-CDN-resource template**, not multi-tenant SaaS. A consumer assigns an app pair to their own CDN resource and sets their own secrets. One customer may reuse the same app across several of their resources — still one trust domain. HS256 is acceptable today because there is no cross-tenant blast radius.

## Current state

All three templates are built and tested (unit, filter, and integration suites
green — see `development/testing.md`). The CDN filter is Rust (proxy-WASM); the
auth-app is TypeScript/Hono. ES256/JWKS for the cookie variant and required,
fail-closed audience binding are both in place. Known limitations (no token
revocation, SAML full-POST replay, no IdP Single Logout) are tracked in
`architecture/security.md`.
