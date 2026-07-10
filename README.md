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

### harden-cookies

Proxy-WASM filter that adds `Secure`, `HttpOnly`, and `SameSite=Strict` attributes
to targeted `Set-Cookie` response headers. Configured entirely through environment
variables — no code changes required.

See [`harden-cookies/README.md`](harden-cookies/README.md) for details and the deploy button.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
