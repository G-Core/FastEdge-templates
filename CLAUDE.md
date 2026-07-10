# FastEdge Templates

## What This Repo Is

Build and publish pipeline for Gcore FastEdge bolt-on application templates. Each
template is a standalone project that a developer can copy out and work with
independently — no shared dependencies, no workspace coupling between templates.

The repo is public. Consumers can read what each template does or copy a specific
template to adapt it to their needs.

## Templates

| Directory         | What it is                                                                                   |
| ----------------- | -------------------------------------------------------------------------------------------- |
| `html2md/`        | Proxy-WASM filter: converts HTML origin responses to Markdown on `Accept: text/markdown`     |
| `harden-cookies/` | Proxy-WASM filter: hardens `Set-Cookie` headers with `Secure`, `HttpOnly`, `SameSite=Strict` |

## Repo Structure

```
FastEdge-templates/
├── AGENTS.md              ← repo-wide agent rules (this file's sibling)
├── CLAUDE.md              ← this file
├── README.md              ← public-facing overview
├── LICENSE
├── assets/                ← shared marketing assets (deploy buttons, etc.)
├── .github/workflows/     ← CI/CD: builds and publishes all templates to Gcore portal
├── html2md/               ← standalone Rust/WASM template
└── harden-cookies/        ← standalone Rust/WASM template
```

## Standalone Principle

Each template directory is fully self-contained:

- Its own build toolchain config (`.cargo/config.toml`)
- Its own lockfile (`Cargo.lock`)
- Its own `README.md` for public consumers
- Its own `registry.json` for the Gcore portal
- Its own `LICENSE`

**Do not** add cross-template dependencies or shared root-level build config.

## Working in This Repo

**Determine scope first:**

| Task                        | Where to work     | What to read first         |
| --------------------------- | ----------------- | -------------------------- |
| CI/CD pipeline, root docs   | Repo root         | This file                  |
| Working on `html2md`        | `html2md/`        | `html2md/README.md`        |
| Working on `harden-cookies` | `harden-cookies/` | `harden-cookies/README.md` |

When working inside a template, treat it as a standalone project. The root context
does not apply to template internals.

## CI/CD

`.github/workflows/` at the repo root builds and publishes all templates to the
Gcore portal on `workflow_dispatch`. Each template's build steps are independent
within the single workflow.
