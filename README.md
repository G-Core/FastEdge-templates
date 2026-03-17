# FastEdge Templates

FastEdge application templates.

## Included Template

### html2md

`html2md` is a `cdylib` Proxy-Wasm module for content negotiation from HTML to Markdown.

Behavior summary:

- Detects markdown intent from request `Accept: text/markdown`.
- Converts only `Content-Type: text/html` origin responses.
- Rewrites response body to Markdown using `htmd`.
- Updates response headers for transformed content.

See `html2md/README.md` for details.

## License

Apache-2.0. See `LICENSE`.
