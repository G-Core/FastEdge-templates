# Testing — layout, how to run, patterns

There is **no root test runner** — each package has its own scripts. Unit tests are
pure TypeScript (run under Node, no build). Integration, filter, and e2e tests run a
built WASM artifact, so the wasm must exist first. One wasm binary per app now covers
all three `SSO_VARIANT` values — tests exercise the variant axis by setting
`SSO_VARIANT` in each test's `.env`, not by building separate binaries.

## Inventory

| Package | Script | Covers | Count |
|---|---|---|---|
| `auth-app` | `test:unit` | federation/session code — token (HS256+ES256), SAML response/XSW + weak-alg rejection, OAuth common, OIDC (Google/Microsoft incl. tenant allowlist), claims, redirect | **131** |
| `auth-app` | `test` | integration (`app.test.ts`): SAML login/callback, redirect sanitization, logout, JWKS endpoint (all under `SSO_VARIANT=cookie`), plus gate-only/header variant smoke | **31** |
| `auth-app` | `test:e2e` | e2e per OAuth provider (github, google, microsoft, facebook) against a local stub IdP | 4 |
| `cdn-filter` | `test` | gate + ES256 + HS256 + aud/iss + fail-closed audience + fail-closed `SSO_VARIANT` + alg-pin + cookie-strip + header-inject + per-claim + spoof-strip, each run once per applicable `SSO_VARIANT` | **78** |

## Running

Unit tests need no build:

```bash
pnpm -C auth-app test:unit
```

Integration / filter / e2e need the wasm built first. Each `build` script emits the
artifact name the matching test loads (`auth-app.wasm`, `sso_guard.wasm`) — and the
filter build copies the Cargo output into place — so `build` then `test` works with
no manual renaming:

```bash
# auth-app (TS): build emits ./wasm/auth-app.wasm, which the test loads
pnpm -C auth-app build && pnpm -C auth-app test

# filter (Rust): build compiles + copies to ./wasm/sso_guard.wasm
pnpm -C cdn-filter build && pnpm -C cdn-filter test
```

## Shared-suite patterns (DRY across `SSO_VARIANT` values)

- **Filter suite** — `cdn-filter/tests/filter-suite.ts`, imported by
  `cdn-filter/tests/filter.test.ts`. Exports `runGateSuites` / `runEs256Suites` /
  `runStripSuites` / `runAudIssSuites` / `runFailClosedSuites` /
  `runVariantFailClosedSuite`, the `GateSigningTier` abstraction (HS256 vs ES256,
  each tagged with the `SSO_VARIANT` value it represents), `FILTER_AUDIENCE` /
  `AUDIENCE_ENV`, and one `signJwt` helper every minter funnels through (don't
  reintroduce per-tier copies). Because audience is fail-closed, every suite that
  expects a token to be accepted sets `SSO_AUDIENCE` (and now `SSO_VARIANT`) and
  mints tokens carrying that `aud`.
- **Variant smoke** — `auth-app/tests/non-cookie-smoke.ts`, imported by
  `app.test.ts` and run for both `gate-only` and `header`. Those two are
  **identical** at the auth-app level (HS256, no JWKS route), so they share one
  smoke suite. The only variant branch in the whole codebase is in
  `auth-app/federation/app.tsx` (ES256 vs HS256 signing key; JWKS route mounted
  only for `cookie`).
- **e2e** — deterministic, **no live credentials**. Each spins up a local Node HTTP stub IdP
  (mocking the token endpoint, userinfo/JWKS, and minting a stub `id_token` where applicable).
  Runs under `SSO_VARIANT=cookie`.

## CI

Tests are wired into `.github/workflows/test-edge-sso.yml` and gate deployment
(via the separate `publish-sso-auth.yml` / `publish-sso-filter.yml` workflows) —
a push to `edge-sso/**` will not reach the deploy steps unless all test stages
pass. Run order:

1. **Unit tests** — no wasm needed, runs immediately after install
2. **Build** — auth-app TS wasm + cdn-filter Rust wasm compiled (one binary each)
3. **Integration tests** — auth-app, covers all three `SSO_VARIANT` values
4. **Filter tests** — cdn-filter, covers all three `SSO_VARIANT` values
5. **E2E tests** — auth-app against a local stub IdP (`SSO_VARIANT=cookie`)
6. **Deploy** — separate workflows, only reached if all above pass

## Known gaps

- e2e covers the happy path per provider; failure-path e2e is not present (unit/integration
  cover much of it).
