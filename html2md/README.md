# html2md FastEdge Template

Proxy-Wasm template that converts HTML origin responses to Markdown when the client requests `text/markdown`.

# <kbd>[**Deploy Now**](https://portal.gcore.com/fastedge/create-template-app/110)</kbd>

## What It Does

The filter runs in HTTP context and performs conversion only when all of the following are true:

- Request `Accept` header includes exactly `text/markdown` (ignoring parameters like `; charset=utf-8`).
- Origin response `Content-Type` includes `text/html`, and charset is either not specified or explicitly `utf-8`.
- Full response body is available (`end_of_stream`).

When conversion is enabled, the filter:

- Adds request header `Convert: markdown` (conversion flag for correct caching)
- Removes request `Accept-Encoding` to avoid compressed origin payloads
- Removes response `Content-Length`
- Sets response `Content-Type: text/markdown`
- Sets response `Transfer-Encoding: Chunked`
- Converts response body to Markdown at end of stream
- Adds `Vary: Convert` (merged with existing `Vary` if present)

## Error Handling

- Returns `500` if origin body is not valid UTF-8.
- Returns `500` if HTML to Markdown conversion fails.

## Notes

- Conversion happens at end of stream, so large responses are processed after full body arrival.
- Request path metadata is decoded lossily for logs; invalid UTF-8 in the path does not fail the request.
- Non-HTML responses pass through unchanged.
