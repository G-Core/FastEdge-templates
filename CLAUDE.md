# FastEdge Templates

## What This Repo Is

Build and publish pipeline for Gcore FastEdge bolt-on application templates. Each
template is a standalone project that a developer can copy out and work with
independently — no shared dependencies, no workspace coupling between templates.

The repo is public. Consumers can read what each template does or copy a specific
template to adapt it to their needs.

## Templates

| Directory | What it is |
|---|---|
| `html2md/` | Proxy-WASM filter: converts HTML origin responses to Markdown on `Accept: text/markdown` |
| `edge-sso/` | Multi-provider SSO bolt-on (Google, GitHub, Microsoft, Facebook, SAML) — three delivery variants: gate-only, cookie, header |

## Repo Structure

```
FastEdge-templates/
├── AGENTS.md              ← company-wide agent rules (this file's sibling)
├── CLAUDE.md              ← this file
├── README.md              ← public-facing overview
├── LICENSE
├── assets/                ← shared marketing assets (deploy buttons, etc.)
├── .github/workflows/     ← CI/CD: builds and publishes all templates to Gcore portal
├── html2md/               ← standalone Rust/WASM template
└── edge-sso/              ← standalone mixed Rust+TypeScript SSO template
```

## Standalone Principle

Each template directory is fully self-contained:

- Its own build toolchain config (`.cargo/config.toml`, `package.json`, etc.)
- Its own lockfiles
- Its own `README.md` for public consumers
- Its own `CLAUDE.md` and `AGENTS.md` for developers and AI agents
- Its own `context/` folder with architecture and design docs

**Do not** add cross-template dependencies or shared root-level build config.

## Working in This Repo

**Determine scope first:**

| Task | Where to work | What to read first |
|---|---|---|
| CI/CD pipeline, root docs | Repo root | This file |
| Working on `html2md` | `html2md/` | `html2md/README.md` |
| Working on `edge-sso` | `edge-sso/` | `edge-sso/CLAUDE.md`, then `edge-sso/context/INDEX.md` |

When working inside a template, treat it as a standalone project. Read its own
`CLAUDE.md` (if present) before doing anything. The root context does not apply
to template internals.

## CI/CD

`.github/workflows/` at the repo root builds and publishes all templates to the
Gcore portal on `workflow_dispatch`. Each template's build steps are independent
within the single workflow.
