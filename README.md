# FastEdge Templates

FastEdge application templates for [Gcore FastEdge](https://gcore.com/fastedge).

Each template is a standalone project you can deploy directly from the Gcore portal
or copy out and modify to suit your needs. Templates have no dependencies on each
other.

## Templates

### html2md

Proxy-WASM filter that converts HTML origin responses to Markdown when the client
sends `Accept: text/markdown`. Zero configuration — drop it in front of any
HTML-serving origin.

See [`html2md/README.md`](html2md/README.md) for details and the deploy button.

### edge-sso

Multi-provider SSO bolt-on — an Identity-Aware Proxy that adds login (Google,
GitHub, Microsoft, Facebook, SAML) to any existing site without changing the
backend. Comes in three delivery variants:

- **gate-only** — allow/deny at the edge
- **cookie** — issues a verifiable JWT the origin can inspect
- **header** — injects a signed `X-Forwarded-User` header upstream

See [`edge-sso/README.md`](edge-sso/README.md) for details.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
