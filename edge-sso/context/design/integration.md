# Integration Guide — how a customer wires login into their origin

> How a consumer of the bolt-on connects their existing site to the auth-app's login surface. See `architecture/overview.md` for the product shape and single-domain routing model.

## The surface the auth-app exposes

Under single-domain routing (Option 3), the CDN routes `/auth/**` to the auth-app as an origin, so everything below is on the **customer's own domain** (e.g. `https://shop.example.com/auth/...`). The filter bypasses `/auth/**`; everything else is gated.

| Route | Method | Purpose |
|---|---|---|
| `/auth/` (and `/auth`) | GET | **Hosted login page** — server-rendered, branded, provider buttons. Honours `?redirect=`. |
| `/auth/providers` | GET | **Provider data (JSON)** — the enabled provider set, for customer-built login UIs. Honours `?redirect=`. |
| `/auth/branding` | GET | **Branding config (JSON)** — current `LOGIN_PAGE_*` values, for custom pages that want consistent branding. |
| `/auth/login/google` | GET | Start Google OIDC. Honours `?redirect=`. |
| `/auth/login/github` | GET | Start GitHub OAuth. Honours `?redirect=`. |
| `/auth/login/microsoft` | GET | Start Microsoft OIDC. Honours `?redirect=`. |
| `/auth/login/facebook` | GET | Start Facebook OAuth. Honours `?redirect=`. |
| `/auth/login` | GET | Start SAML SSO. Honours `?redirect=`. |
| `/auth/logout` | GET | **Sign out** — clears `sso_session` (`Max-Age=0`), redirects to the validated `?redirect=` (defaults to `/`). Not gated by the filter. |

Each provider's OAuth/SAML callback lands on `/auth/callback/<provider>` (or `/auth/callback` for SAML) — these are used by the IdP, not called directly.

`?redirect=<url>` is the post-login destination. After successful federation the auth-app sets the `sso_session` cookie and 302s to that URL.

The **enabled provider set** is resolved at runtime from `SSO_PROVIDERS` ∩ providers-whose-creds-are-present. The hosted page and `/auth/providers` are driven by the same resolution (`selectProviders`) so they never disagree.

---

## Login page customization — three tiers

### Tier 1 — env var branding (recommended default)

The built-in hosted login page reads these env vars per-request. No code changes, no custom CSS required for basic branding.

| Env var | Default | Effect |
|---|---|---|
| `LOGIN_PAGE_TITLE` | `"Sign in"` | `<title>` and `<h1>` |
| `LOGIN_PAGE_SUBTITLE` | `"Choose a sign-in method"` | Subheading below the title |
| `LOGIN_PAGE_LOGO_URL` | — | Logo image above the title |
| `LOGIN_PAGE_FAVICON_URL` | — | Tab favicon |
| `LOGIN_PAGE_ACCENT_COLOR` | `#0066cc` | Button/focus-ring color (CSS `--lp-accent`) |
| `LOGIN_PAGE_BACKGROUND_COLOR` | `#f0f2f5` | Page background (CSS `--lp-bg`) |
| `LOGIN_PAGE_CSS_URL` | — | Customer stylesheet linked last — overrides any built-in style |
| `IDP_LABEL` | `"SSO"` | Display name for the SAML provider button |
| `IDP_ICON_URL` | — | Icon URL for the SAML provider button |

`LOGIN_PAGE_CSS_URL` is the deep-customization escape hatch — a `<link rel="stylesheet">` injected after built-in styles. The CSS variables `--lp-accent` and `--lp-bg` are intentional override points.

### Tier 2 — fully custom login page (`LOGIN_PAGE_URL`)

Set `LOGIN_PAGE_URL` on the **CDN filter** to redirect unauthenticated users to a page you own instead of the built-in one. That page calls `GET /auth/providers` for login URLs and, optionally, `GET /auth/branding` for consistent branding tokens.

```
LOGIN_PAGE_URL=https://shop.example.com/my-login
```

Your custom page handles the full UI; clicking a provider's button navigates to its `loginUrl` (relative, same-origin) which kicks off the standard federation flow. The default value of `LOGIN_PAGE_URL` is `/auth/` — set it only to opt out.

### Tier 3 — embed sign-in buttons on an existing page

**Static links (simplest):** hard-code the provider routes.
```html
<a href="/auth/login/google?redirect=/account">Sign in with Google</a>
<a href="/auth/login/github?redirect=/account">Sign in with GitHub</a>
<a href="/auth/login?redirect=/account">Single Sign-On</a>
```

**Dynamic widget:** fetch `/auth/providers` and render whatever is enabled.
```js
const { providers } = await fetch("/auth/providers?redirect=/account").then(r => r.json());
for (const p of providers) {
  const a = document.createElement("a");
  a.href = p.loginUrl;                  // relative, same-origin, redirect already encoded
  a.textContent = `Sign in with ${p.label}`;
  loginContainer.append(a);
}
```

Adding or removing a provider (a secret or `SSO_PROVIDERS` change in the portal) updates the widget with no code change on the customer's side.

---

## `GET /auth/providers` contract

```jsonc
// GET /auth/providers?redirect=/cart
{
  "providers": [
    { "id": "google", "label": "Google", "loginUrl": "/auth/login/google?redirect=%2Fcart" },
    { "id": "github", "label": "GitHub", "loginUrl": "/auth/login/github?redirect=%2Fcart" },
    { "id": "saml",   "label": "SSO",    "loginUrl": "/auth/login?redirect=%2Fcart" }
  ]
}
```

- `id` — stable identifier (also the value used in `SSO_PROVIDERS`).
- `label` — human label; SAML label is overridden by `IDP_LABEL`.
- `loginUrl` — relative path including the encoded `redirect`.
- Order is stable (registry order), not allowlist order.

## `GET /auth/branding` contract

```jsonc
{
  "title": "Sign in",
  "subtitle": "Choose a sign-in method",
  "logoUrl": "https://cdn.example.com/logo.png",
  "faviconUrl": null,
  "accentColor": "#e00",
  "backgroundColor": "#f0f2f5",
  "cssUrl": null
}
```

Returns the current `LOGIN_PAGE_*` env var values as a JSON object. Custom login pages (Tier 2) can `fetch("/auth/branding")` to auto-style themselves consistently without duplicating the env var set.

---

## Security — `?redirect=` validation

The `redirect` parameter is validated against `SSO_ALLOWED_ORIGINS`. Relative URLs (starting with `/`) are always permitted. Off-origin absolute URLs are silently dropped — the post-login redirect falls back to `/`. Set `SSO_ALLOWED_ORIGINS` to a comma-separated list of allowed origins (e.g. `https://shop.example.com`) to permit absolute redirects.
