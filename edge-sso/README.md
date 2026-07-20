# edge-sso — Multi-Provider SSO for FastEdge

Bolt-on Identity-Aware Proxy for Gcore FastEdge. Adds SSO (Google, GitHub, Microsoft, Facebook, SAML) to any existing site without changing the backend. Ships as three variants on the identity-delivery axis.

## How It Works

Two FastEdge apps work together per deployment:

1. **CDN filter** (Proxy-WASM, Rust) — sits in the CDN proxy layer, verifies the session token on every request, redirects unauthenticated users to the auth app
2. **Auth app** (HTTP app, TypeScript/Hono) — federates to the identity provider, issues a signed session token, sets it on the client

```
User → CDN resource (filter checks session token)
              ↓ no valid token
       Auth app /auth/login → Identity Provider
                                   ↓ (user authenticates)
       Auth app /auth/callback ← IdP response
              ↓ (validates, issues signed token)
       Back to CDN resource (token set) → origin
```

## Variants

Choose one variant per deployment based on how your origin needs to consume identity:

| Variant | Session delivery | Use when |
|---|---|---|
| **gate-only** | Allow/deny only — no identity forwarded | Origin needs no user context, just access control |
| **cookie** | Signed JWT in a cookie the origin can verify | Origin reads user identity from a verifiable token |
| **header** | Signed `x-sso-*` identity headers injected upstream | Origin trusts a header from the CDN layer |

Each variant is in `templates/<variant>/` and contains two deployable apps:

```
templates/
├── gate-only/
│   ├── auth-app/     ← deploy as HTTP App
│   └── cdn-filter/   ← deploy as CDN App (Proxy-WASM)
├── cookie/
│   ├── auth-app/
│   └── cdn-filter/
└── header/
    ├── auth-app/
    └── cdn-filter/
```

## Shared Core

`core/` contains the shared TypeScript federation and session logic consumed by all three auth-app variants. The Rust CDN filter is in `core/filter/` and compiled into each `cdn-filter` variant.

## Configuration

Each template's `.env.example` lists all supported environment variables and secrets. Key shared requirements across both apps in a deployment:

- `SESSION_SECRET` — shared signing secret (gate-only and header variants)
- `SESSION_SIGNING_KEY` (secret) + `SESSION_PUBLIC_JWK` (env var) — EC key pair (cookie variant)
- `SSO_AUDIENCE` — must match on both apps; the filter rejects tokens whose `aud` doesn't match
- `AUTH_PREFIX` — the path prefix reserved for auth routes (default: `/auth`)

See each template's `.env.example` for the full list including per-provider OAuth credentials and SAML IdP settings.

## Providers

| Provider | Type | Auth-app env vars |
|---|---|---|
| Google | OAuth 2.0 | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` |
| GitHub | OAuth 2.0 | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI` |
| Microsoft | OAuth 2.0 / OIDC | `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_REDIRECT_URI` |
| Facebook | OAuth 2.0 | `FACEBOOK_CLIENT_ID`, `FACEBOOK_CLIENT_SECRET`, `FACEBOOK_REDIRECT_URI` |
| SAML | SAML 2.0 | `IDP_SSO_URL`, `IDP_ENTITY_ID`, `IDP_CERT`, `SP_ENTITY_ID`, `SP_ACS_URL` |

## License

Apache-2.0. See `LICENSE`.
