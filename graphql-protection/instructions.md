In CDN resource configuration assign the application to `On request body`.

Set `ENDPOINT` to the path of your GraphQL endpoint (default `/graphql`). Only `POST` requests to this path are inspected; everything else passes through. The path is matched after normalisation, so variants such as `/graphql?x=1`, `/graphql/` or `/GraphQL` are inspected too.

Enable the checks you need — any limit left unset is not enforced:

- `MAX_BODY_SIZE` — maximum request body size, in bytes
- `MAX_QUERY_DEPTH` — maximum query nesting depth (the same value also caps how many times one field may repeat directly on a single level; repeats inside separate fragments are counted separately)
- `MAX_BATCH_SIZE` — maximum number of queries in a JSON batch request
- `MAX_VALUE_SIZE` — maximum size, in bytes, of any string field argument or variable value
- `BLOCKED_FIELDS` — comma-separated field names to reject, e.g. `__schema,__type` to disable introspection
- `BLOCK_DEBUG` — set to `true` to reject a literal `debug: true` field argument or a top-level `"debug": true` variable

Supported request content types are `application/json` (single or batch), `application/graphql` and `application/x-www-form-urlencoded`. Requests with another content type, or that cannot be parsed, are rejected with `400`; requests that fail a check are rejected with `403`. The `X-Reject-Reason` response header gives a generic reason; the detailed reason is written to the application log.

Template source is available here: [FastEdge-templates/graphql-protection](https://github.com/G-Core/FastEdge-templates/tree/main/graphql-protection)
