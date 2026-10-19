# graphql-protection FastEdge Template

Proxy-Wasm template that inspects GraphQL requests at the edge and rejects abusive queries — excessive depth, oversized batches, huge string values, blocked fields (e.g. introspection) — before they reach the origin.

[![Deploy Now](../assets/button_deploy-now.png)](https://portal.gcore.com/fastedge/create-template-app/132)

## What It Does

The filter runs in HTTP request body context. For `POST` requests whose path matches `ENDPOINT` (see [Endpoint matching](#endpoint-matching)), it buffers the body, parses it as GraphQL and applies the configured checks. Other requests pass through untouched.

Supported request encodings (by `Content-Type`):

- `application/json` — single `{"query", "variables"}` object or a batch array of them
- `application/graphql` — raw query document
- `application/x-www-form-urlencoded` — `query` and optional `variables` form fields

Content types are matched case-insensitively. Any other content type on the endpoint is rejected with `400`.

`variables` sent as a JSON-encoded string (accepted by some GraphQL servers) are decoded before checking.

## Configuration

Behavior is controlled through environment variables. Every limit is optional; unset means not enforced.

| Variable | Description |
| --- | --- |
| `ENDPOINT` | Request path to inspect. Default `/graphql` (also used when set to an empty value). |
| `MAX_BODY_SIZE` | Maximum request body size in bytes. |
| `MAX_QUERY_DEPTH` | Maximum selection-set nesting depth (fragment spreads are followed, with a cycle guard). The same value caps how many times one field name may appear directly on a single selection level (see Notes). |
| `MAX_BATCH_SIZE` | Maximum number of operations in a JSON batch array. |
| `MAX_VALUE_SIZE` | Maximum size in bytes of any string literal field argument or string variable value (nested lists/objects included). |
| `BLOCKED_FIELDS` | Comma-separated field names rejected anywhere in the document, e.g. `__schema,__type`. Matched on the field name, so aliases do not bypass it. |
| `BLOCK_DEBUG` | When exactly `true`, rejects a literal field argument `debug: true` (not `debug: $var`) or a top-level variable `"debug": true`. |

## Responses

| Status | When |
| --- | --- |
| `400` | Body is not valid UTF-8 / JSON / GraphQL, `query` is missing, `variables` is not valid JSON, a form field is repeated, or the content type is unsupported. `X-Reject-Reason: Invalid GraphQL request`. |
| `403` | `MAX_BODY_SIZE` is exceeded (`X-Reject-Reason: Request body size exceeds limit`) or any other configured check fails (`X-Reject-Reason: GraphQL request blocked`). |

`X-Reject-Reason` is deliberately generic so it doesn't reveal the configured limits. The detailed reason is written to the app log.

## Endpoint matching

The CDN passes the request path to the filter un-normalised, with the query string attached. To stop variants from skipping inspection, both the request path and `ENDPOINT` are normalised before comparing: the query string is dropped, percent-encoding is decoded, anything after `;`, `?` or `#` within a segment is removed (`/api;v=1/graphql` → `/api/graphql`, `/x%3F/../graphql` → `/graphql`), `\` is treated as `/`, empty, `.` and `..` segments are resolved, a trailing slash is removed, and the result is lower-cased. So `/graphql?x=1`, `/graphql/`, `//graphql`, `/GraphQL`, `/%67raphql` and `/api/../graphql` are all inspected as `/graphql`.

This matches more broadly than most origins route. That is intentional: an extra match only means a request body gets inspected.

## Notes

- Only `POST` is inspected. GraphQL over `GET` (`?query=...`) is not checked.
- Repeated `query` or `variables` fields in a form body are rejected, since origins disagree on which one wins.
- Double percent-encoding (`%2567`) is decoded only once.
- The per-level field repetition cap counts each inline fragment separately and does not count fields reached through named fragment spreads, so repeats can be spread across fragments.
- `MAX_VALUE_SIZE` checks field arguments, variables and variable default values, not directive arguments (e.g. a string passed to a custom `@directive(...)`).

## Testing

Black-box tests drive the compiled wasm through [`@gcoredev/fastedge-test`](https://www.npmjs.com/package/@gcoredev/fastedge-test):

```bash
pnpm install
cargo build --release
pnpm test
```
