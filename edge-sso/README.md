# edge-sso — Multi-Provider SSO for FastEdge

Bolt-on Identity-Aware Proxy for Gcore FastEdge. Adds SSO (Google, GitHub, Microsoft, Facebook, SAML) to any existing site without changing the backend. One app pair, configured per deployment via `SSO_VARIANT`.

## How It Works

Two FastEdge apps work together per deployment:

1. **CDN filter** (Proxy-WASM, Rust, `cdn-filter/`) — sits in the CDN proxy layer, verifies the session token on every request, redirects unauthenticated users to the auth app
2. **Auth app** (HTTP app, TypeScript/Hono, `auth-app/`) — federates to the identity provider, issues a signed session token, sets it on the client

```
User → CDN resource (filter checks session token)
              ↓ no valid token
       Auth app /auth/login → Identity Provider
                                   ↓ (user authenticates)
       Auth app /auth/callback ← IdP response
              ↓ (validates, issues signed token)
       Back to CDN resource (token set) → origin
```

```
edge-sso/
├── auth-app/     ← deploy as HTTP App
└── cdn-filter/   ← deploy as CDN App (Proxy-WASM)
```

## Variants

`SSO_VARIANT` selects how your origin consumes identity — set the **same**
value on both apps:

| `SSO_VARIANT` | Session delivery | Use when |
|---|---|---|
| **gate-only** | Allow/deny only — no identity forwarded | Origin needs no user context, just access control |
| **cookie** | Signed JWT in a cookie the origin can verify | Origin reads user identity from a verifiable token |
| **header** | Signed `x-sso-*` identity headers injected upstream | Origin trusts a header from the CDN layer |

## Configuration

Each app's `.env.example` lists all supported environment variables and secrets. Key shared requirements across both apps in a deployment:

- `SSO_VARIANT` — must match on both apps; selects the identity-delivery mode above
- `SESSION_SECRET` — shared signing secret (required in every variant for OAuth/SAML flow cookies; also signs the session token itself in gate-only/header)
- `SESSION_SIGNING_KEY` (secret) + `SESSION_PUBLIC_JWK` (env var) — EC key pair (cookie variant's session token)
- `SSO_AUDIENCE` — must match on both apps; the filter rejects tokens whose `aud` doesn't match
- `AUTH_PREFIX` — the path prefix reserved for auth routes (default: `/auth`)

See each app's `.env.example` for the full list including per-provider OAuth credentials and SAML IdP settings.

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
