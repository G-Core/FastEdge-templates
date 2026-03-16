# html2md FastEdge Template

Proxy-Wasm template that converts HTML origin responses to Markdown when the client requests `text/markdown`.

## What It Does

The filter runs in HTTP context and performs conversion only when all of the following are true:

- Request `Accept` header includes exactly `text/markdown` (ignoring parameters like `; charset=utf-8`).
- Origin response `Content-Type` is `text/html` (also parameter-tolerant).
- Full response body is available (`end_of_stream`).

When conversion is enabled, the filter:

- Adds request header `Convert: markdown` (conversion flag for correct caching)
- Removes request `Accept-Encoding` to avoid compressed origin payloads
- Removes response `Content-Length`
- Sets response `Content-Type: text/markdown`
- Sets response `Transfer-Encoding: Chunked`
- Converts response body
- Adds `Vary: Convert` to keep cache variants separated

## Error Handling

- Returns `400` if request path metadata cannot be decoded as UTF-8.
- Returns `500` if origin body is not valid UTF-8.

## Notes

- Conversion happens at end of stream, so large responses are processed after full body arrival.
- Non-HTML responses pass through unchanged.
