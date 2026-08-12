# Security Posture & Known Limitations

What the edge-SSO bolt-on defends against, how, and the limitations that remain by
design or platform constraint. Read this before changing the auth flow, token
handling, error pages, or redirect handling.

## Trust model

The signing key is the root of trust. The auth-app mints a signed session token;
the CDN filter verifies it on every request. Only a holder of the signing
key/secret can mint a token the filter accepts. `aud` scopes a token to its
deployment on top of that; `iss` is an optional secondary check.

Each deployment should use **its own** signing key/secret **and** its own
`SSO_AUDIENCE`. Sharing either across deployments is only for deliberately shared
sessions (see "Audience binding").

---

## Protections in place

### Session token
- **Algorithm pinned per `SSO_VARIANT` at runtime.** cookie ⇒ ES256 only; gate-only
  / header ⇒ HS256 only. The filter looks up its alg from `SSO_VARIANT` before
  touching the token, so a token cannot choose its own algorithm (no HS256↔ES256
  confusion, even if a stray `SESSION_SECRET` is present in a cookie deployment).
  `SSO_VARIANT` itself is required and fail-closed — missing or invalid values
  refuse every session (same rationale as audience binding below).
- **Audience binding is required and fail-closed.** The filter rejects every
  session unless `SSO_AUDIENCE` is configured and equals the token's `aud`; the
  auth-app refuses to mint a token without `SSO_AUDIENCE`. This blocks
  cross-deployment token replay. `aud` matching is RFC 7519 membership-aware
  (string equal, or array containing the value). To share sessions across apps,
  set the **same** `SSO_AUDIENCE` on each; to isolate (default), give each its own.
- **Issuer validated when configured.** When `SSO_ISSUER` is set on both sides the
  filter requires a matching `iss`. Optional because the signing key already
  establishes issuer trust in this single-key model.
- **Expiry enforced** on both sign and verify.

### SAML
- **XML signature verified** against the IdP's X.509 certificate (RSASSA-PKCS1-v1_5
  / SHA-256).
- **Signature algorithm pinned to SHA-256.** A SHA-1 (or other legacy)
  `SignatureMethod`/`DigestMethod` is rejected before verification — no downgrade.
- **XML Signature Wrapping defended.** Exactly one `Signature` and exactly one
  `Assertion` are required; the signature's `Reference` is resolved to its target
  element and the `Assertion` must live inside that verified subtree; every claim
  is read from within that assertion (never globally).
- **XML comments stripped before processing** (CVE-2025-29775 / SAMLStorm).
- **Issuer, AudienceRestriction, and time windows validated** (`Conditions` and
  `SubjectConfirmationData`, ±30s skew). Time-window checks are enforced **only
  when the IdP supplies the bound** — a `NotBefore`/`NotOnOrAfter` that is absent
  is treated as "no bound", not as failure (see the limitation below).
- **Request binding.** Login mints an `AuthnRequest` ID carried in a signed
  `RelayState` (`requestId.tag`, HMAC, ≤80 bytes); the callback requires the
  assertion's signed `InResponseTo` to equal it. Rejects responses to requests we
  never issued and forged/altered `RelayState`.
- **Post-login redirect** is carried in the `saml_relay` cookie (`SameSite=None`
  so it survives the IdP's cross-site POST callback; HttpOnly, Secure, signed,
  300s) and re-validated against the redirect allowlist on read.

### OAuth / OIDC
- **PKCE (S256)** on every OAuth/OIDC provider.
- **CSRF protection** via a signed, short-lived state cookie plus a `state`
  round-trip checked at callback.
- **OIDC nonce binding** (Google, Microsoft): a nonce is sent in the auth request
  and required to match in the `id_token`.
- **GitHub email is verified** — the verified primary address from `/user/emails`
  is used, never the public profile field.
- **Microsoft tenant guardrail.** With a wildcard `MICROSOFT_TENANT`
  (`common`/`organizations`/`consumers`) any Microsoft tenant can sign in; set
  `MICROSOFT_ALLOWED_TENANTS` to restrict by the verified `tid`. A wildcard tenant
  with no allowlist logs a warning.

### Edge / app surface
- **Open-redirect allowlist.** `?redirect=` is validated against
  `SSO_ALLOWED_ORIGINS`; relative paths are allowed, off-origin absolutes are
  dropped to `/`. Protocol-relative and backslash bypasses (`/\evil.com`) are
  rejected.
- **Canonical host.** `CANONICAL_HOST` 301-redirects requests on other hosts,
  keeping sessions and IdP callbacks on one domain.
- **Generic error page.** Failures redirect to a static `/auth/error` that reflects
  no caller input; the real reason is logged server-side only.
- **Session cookie hygiene.** `HttpOnly; Secure; SameSite=Lax`. gate-only and header
  variants strip the session cookie before proxying upstream so the origin never
  sees the raw token.
- **Header variant anti-spoofing.** The filter clears any client-supplied `x-sso-*`
  header and injects only verified values. (Origin contract: the platform blanks a
  cleared header to empty rather than removing it, so the origin must treat an empty
  `x-sso-*` as absent.)
- **JWKS endpoint** serves only public JWK members — private key material pasted
  into `SESSION_PUBLIC_JWK` is stripped before it is published.

---

## Known limitations

- **No token revocation.** Sessions are stateless JWTs and KV is read-only, so there
  is no live denylist — a token is valid until `exp` regardless of logout or account
  suspension. Mitigation: keep `Max-Age` short (currently 86400). Instant revocation
  would require writable KV.
- **No IdP Single Logout.** `GET /auth/logout` clears the edge session cookie, but
  the IdP session survives — a user can silently re-authenticate while the IdP
  session is active. Full SLO would require a SAML `LogoutRequest` / OIDC
  `end_session_endpoint` call.
- **SAML replay of a captured full POST.** The request binding stops
  response/request substitution and forged `RelayState`, but `RelayState` travels in
  the same POST as the `SAMLResponse`, so capturing and re-submitting both still
  validates. True one-time-use requires recording consumed assertion/request IDs
  (a write; KV is read-only).
- **SAML assertions with no time bound never expire.** The `Conditions` and
  `SubjectConfirmationData` time windows are validated only when the IdP includes
  them; an assertion that omits both carries no upper time bound and is accepted
  indefinitely (until the request binding / signature checks reject it on other
  grounds). In practice every mainstream IdP (Okta, Azure AD, etc.) always emits
  `Conditions/NotOnOrAfter`, so this affects only non-conformant or misconfigured
  IdPs — but the SP does not currently *require* a bound to be present.
- **SAML: no AuthnRequest signing**, single IdP per deployment, manual IdP cert
  rotation (the cert is a static secret).

---

## Operational notes

- Use a distinct `SESSION_SECRET` / signing key **and** a distinct `SSO_AUDIENCE`
  per deployment unless you intend to share sessions.
- Set `MICROSOFT_TENANT` to your tenant (or `MICROSOFT_ALLOWED_TENANTS`) — do not
  ship a wildcard tenant unrestricted.
- Rotate any secret that was ever committed to or generated in the working tree
  before it goes to production.
