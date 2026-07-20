# Testing — layout, how to run, patterns

There is **no root test runner** — each package has its own scripts. Unit tests are
pure TypeScript (run under Node, no build). Integration, filter, and e2e tests run a
built WASM artifact, so the wasm must exist first.

## Inventory

| Package | Script | Covers | Count |
|---|---|---|---|
| `templates/cookie/auth-app` | `test:unit` | shared `@sso/core` — token (HS256+ES256), SAML response/XSW + weak-alg rejection, OAuth common, OIDC (Google/Microsoft incl. tenant allowlist), claims, redirect | **120** |
| `templates/cookie/auth-app` | `test` | integration (`app.test.ts`): SAML login/callback, redirect sanitization, logout, JWKS endpoint | — |
| `templates/cookie/auth-app` | `test:e2e` | e2e per OAuth provider (github, google, microsoft, facebook) against a local stub IdP | 4 |
| `templates/cookie/cdn-filter` | `test` | gate + ES256 + aud/iss + fail-closed audience + alg-pin | **21** |
| `templates/header/cdn-filter` | `test` | gate + header inject + cookie strip + aud/iss + fail-closed + per-claim + spoof-strip | **22** |
| `templates/{gate-only,header}/auth-app` | `test` | variant smoke (no JWKS route, boots, serves federation routes) | 3 each |

`gate-only/cdn-filter` is **build-only** (no test suite) — its filter logic is identical
to cookie's gate behaviour, exercised via the shared filter suite under both signing tiers.

## Running

Unit tests need no build:

```bash
pnpm -C templates/cookie/auth-app test:unit
```

Integration / filter / e2e need the wasm built first. Each `build` script emits the
variant-prefixed artifact name the matching test loads (e.g. `cookie-auth-app.wasm`,
`cookie_sso_guard.wasm`) — and the filter build copies the Cargo output into place — so
`build` then `test` works with no manual renaming:

```bash
# auth-app (TS): build emits ./wasm/<variant>-auth-app.wasm, which the test loads
pnpm -C templates/cookie/auth-app build && pnpm -C templates/cookie/auth-app test

# filter (Rust): build compiles + copies to ./wasm/<variant>_sso_guard.wasm
pnpm -C templates/cookie/cdn-filter build && pnpm -C templates/cookie/cdn-filter test
pnpm -C templates/header/cdn-filter build && pnpm -C templates/header/cdn-filter test
```

## Shared-suite patterns (DRY across variants)

- **Filter suite** — `templates/cookie/cdn-filter/tests/filter-suite.ts` is imported by the
  header filter test via relative path. Exports `runGateSuites` / `runEs256Suites` /
  `runStripSuites` / `runAudIssSuites` / `runFailClosedSuites`, the `GateSigningTier`
  abstraction (HS256 vs ES256), `FILTER_AUDIENCE` / `AUDIENCE_ENV`, and one `signJwt` helper
  every minter funnels through (don't reintroduce per-tier copies). Because audience is
  fail-closed, every suite that expects a token to be accepted sets `SSO_AUDIENCE` and mints
  tokens carrying that `aud`.
- **Variant smoke** — `templates/cookie/auth-app/tests/non-cookie-smoke.ts` is imported by the
  `gate-only` and `header` auth-app tests. Those two are **identical** at the auth-app level
  (HS256, no JWKS route), so they share one smoke suite. The only variant branch in the whole
  codebase is in `core/federation/app.tsx` (ES256 vs HS256 signing key; JWKS route mounted only
  for `cookie`).
- **e2e** — deterministic, **no live credentials**. Each spins up a local Node HTTP stub IdP
  (mocking the token endpoint, userinfo/JWKS, and minting a stub `id_token` where applicable).

## CI

Tests are wired into `.github/workflows/publish-edge-sso-templates.yml` and gate
deployment — a push to `edge-sso/**` will not reach the deploy steps unless all
test stages pass. Run order:

1. **Unit tests** — no wasm needed, runs immediately after install
2. **Build** — TS WASM + Rust CDN filters compiled
3. **Integration tests** — all three auth-app variants
4. **Filter tests** — cookie and header CDN filters
5. **E2E tests** — cookie auth-app against a local stub IdP
6. **Deploy** — only reached if all above pass

`pnpm -r test` is not used; the workflow calls per-package scripts explicitly
(see the workflow for the exact commands).

## Known gaps

- e2e covers the happy path per provider; failure-path e2e is not present (unit/integration
  cover much of it).
