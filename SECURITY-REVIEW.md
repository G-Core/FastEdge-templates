---
doc_type: policy
audience: bot+human
lang: en
tags: ["security", "review", "pre-merge", "filters", "auth"]
last_modified: 2026-10-22T00:00:00Z
copyright: "© 2026 gcore.com"
---

# SECURITY REVIEW CHECKLIST

TL;DR: Every template here is built and published as a product and runs on
customer edge traffic. A defect merged here ships to customers. This is the
pre-merge security gate for any PR that touches template source.

## When this applies

Run this checklist on any PR that changes:

- a proxy-wasm filter (`*/src/lib.rs` under a `*-filter/` or `cdn-filter/` dir),
- an auth app or any request/response handling,
- token, cookie, header, redirect, or request-body logic.

**Agents:** when you add or modify any of the above, check the diff against every
applicable item below before proposing it. Then do the cross-template check (see
end). **Reviewers:** the PR is not approvable until each applicable item is
answered. **CI:** the security-review job runs this as advisory (see
`.github/workflows/`), it does not replace human review.

Each item also lists the canonical implementation already in the tree — reuse it,
do not reinvent it.

---

## 1. Path gating — auth bypass (filters)

**Invariant:** any filter that **exempts** a path from an auth/security check
(prefix match, allowlist, health check) MUST first reject paths that the CDN or
origin could normalize into a *different* resource. Fail closed — fall through to
the check — never fail open (`Action::Continue`).

- **Exempt only plain, unencoded ASCII paths.** Reject before exempting: any
  non-ASCII byte, any control/NUL byte, any `%` (all percent-encoding), `..`,
  `//`, and `\`. A finite blocklist of specific encodings (`%2e`, `%2f`, …) is
  not enough — it misses overlong UTF-8 (`%c0%ae`), unicode dot/slash, `%00`, and
  multi-encoding. Because the guard fails closed, the character-class predicate is
  enough and needs no path parser.
- **Why:** `request.path` reaching the filter is the raw, undecoded path
  (confirmed live). The CDN or origin may resolve `/auth/%2e%2e%2fadmin` into
  `/admin`, so a raw prefix match waves an unauthenticated request past the gate.
- **Canonical impl:** `has_suspicious_sequence()` in `edge-totp/otp-filter` and
  `edge-sso/cdn-filter`.
- **Check:** does every path exemption call the traversal guard first? Is there a
  test firing the encoded/traversal corpus and asserting the gated outcome?

## 2. Token / signature verification

- The verifier pins the algorithm; the token never selects it (no `alg: none`,
  no HS/ES confusion). **Canonical:** `expected_alg()` in `edge-sso/cdn-filter`.
- Header-supplied key references are not trusted: ignore or allowlist `kid`, and
  never fetch `jku` / `x5u` (SSRF + key-substitution). Keys come from configured
  secrets / a pinned JWKS, not from the token.
- Signature is verified before any claim is trusted.
- `exp` / `iat` enforced; `aud` / `iss` checked when configured.
- Secret/token comparisons are constant-time (no early-exit `==` on MACs/codes).
  **Canonical:** `safeEqual` in `edge-totp/otp-app`.

## 3. Injected / trusted headers

- Any header the origin trusts (e.g. `x-sso-*`) is cleared or overwritten from
  the verified value, never passed through from the client. A spoofed client copy
  must not survive the filter. **Canonical:** `put_user_header()` in
  `edge-sso/cdn-filter`.
- Values written into headers or a response status line are free of CR/LF and
  other control characters (header injection / response splitting) — never
  interpolate raw request input into a header value. The correct filter strips
  all C0/C1 control chars (via `char::is_control`, which also covers CR, LF, NUL,
  DEL and NEL/U+0085) plus the Unicode line/paragraph separators U+2028/U+2029.
  Do NOT restrict to printable ASCII: non-ASCII bytes cannot contain the `0x0A`/
  `0x0D` that split an HTTP/1.1 header, and an ASCII-only filter would corrupt
  legitimate international names/emails in identity headers. **Canonical:**
  `sanitize_header_value()` in `edge-sso/cdn-filter`.

## 4. Redirects

- `?redirect=` / return-URL targets are validated against an allowlist;
  relative-only by default. Reject protocol-relative (`//host`, `/\host`),
  off-origin absolutes, and IDN/punycode look-alikes. **Canonical:** open-redirect
  handling in `edge-sso` (`SSO_ALLOWED_ORIGINS`).

## 4a. Outbound fetch (SSRF)

- `fetch()` targets (IdP endpoints, JWKS, metadata URLs) come from configuration,
  not from request input or token contents. A URL derived from the request is
  allowlisted by host before it is fetched.

## 5. Cookies

- Session cookies carry `HttpOnly; Secure; SameSite`; prefer a `__Host-` name
  prefix for host-scoped session cookies.
- gate-only and header variants strip the session cookie before proxying so the
  origin never sees the raw token.

## 6. Request-body abuse (filters that parse bodies)

- Enforce limits: depth, value size, batch/array count, blocked fields.
  **Canonical:** `graphql-protection`.

## 7. Error handling / information disclosure

- Error responses reflect no caller input; the real reason is logged server-side
  only. **Canonical:** generic `/auth/error` in `edge-sso`.

## 8. Secrets / configuration

- Secrets come via `getSecret` / `secretRefs`, never from env *values*, logs, or
  committed files.
- Fail closed on a missing or invalid required setting (e.g. `SSO_VARIANT`).

---

## Cross-template rule (read this one)

These templates deliberately **share no code**. A security primitive implemented
in one template therefore does **not** protect the others. When you fix or harden
a security-relevant pattern in any template, check every other template with the
same attack surface and port the guard.

This checklist exists because a path-gating guard present in `edge-totp` — with an
inline comment describing the exact attack — never reached `edge-sso`, which
shipped the bypass. An invariant that lives only as a comment in a sibling file
does not transfer. Write it here, and add an executable test for it.

## Adding a new template

Add its attack surface to this checklist and add the relevant adversarial test
corpus (traversal paths, malformed tokens, spoofed headers, etc.) to its test
suite, so a regression fails CI rather than relying on this document being read.
