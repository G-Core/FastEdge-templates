# Edge SSO Bolt-On — Context Index

**Product:** Identity-Aware Proxy (forward-auth) for Gcore FastEdge. A customer
deploys two FastEdge apps in front of their existing site to add SSO without
rewriting their backend. Providers: Google, GitHub, Microsoft, Facebook, and SAML.
One app pair (`auth-app/` + `cdn-filter/`), configured per deployment via
`SSO_VARIANT`: **gate-only**, **cookie**, or **header**.

**Current state:** Built and tested — unit, filter, and integration suites green
across all three `SSO_VARIANT` values against the same wasm binaries (see
`development/testing.md` for the inventory and how to run them). The CDN filter
is Rust (proxy-WASM); the auth-app is TypeScript/Hono on StarlingMonkey.
Session-token audience binding is required and fail-closed (see
`architecture/security.md`).

---

## What to read

| Task | Read |
|---|---|
| Understand the product, repo structure, token contract, config model | `architecture/overview.md` |
| The `SSO_VARIANT` axis (gate-only / cookie / header) | `architecture/auth-modes.md` |
| SAML protocol, XMLDSig, library stack | `architecture/saml-flow.md` |
| FastEdge JS runtime limits (why standard SAML libs don't work) | `architecture/runtime-constraints.md` |
| Security posture and known limitations | `architecture/security.md` |
| How a customer wires login into their origin | `design/integration.md` |
| Run or extend the test suite (layout, scripts, shared patterns) | `development/testing.md` |
| All configuration options (env vars + secrets) | each app's `.env.example` |

---

## File map

```
context/
├── INDEX.md                      ← this file
├── architecture/
│   ├── overview.md               ← what it is, two-app split, token, signing, config, deployment
│   ├── auth-modes.md             ← the SSO_VARIANT axis: gate-only / cookie / header
│   ├── saml-flow.md              ← SAML protocol, XMLDSig, library stack
│   ├── runtime-constraints.md   ← StarlingMonkey limits, WebCrypto availability table
│   └── security.md              ← security posture and known limitations
├── design/
│   └── integration.md           ← customer guide: routes, login page, /auth/providers API
└── development/
    └── testing.md               ← test layout, how to run, shared-suite patterns
```
