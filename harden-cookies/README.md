# harden-cookies FastEdge Template

Proxy-Wasm template that hardens `Set-Cookie` response headers by adding security attributes (`Secure`, `HttpOnly`, `SameSite=Strict`) to targeted cookies.

[![Deploy Now](../assets/button_deploy-now.png)](https://portal.gcore.com/fastedge/create-template-app/184)

## What It Does

The filter runs in HTTP response context and rewrites `Set-Cookie` headers according to environment-variable configuration.

For each `Set-Cookie` header whose cookie name matches the configured target, it appends the enabled attributes:

- `Secure` — added only if not already present.
- `HttpOnly` — added only if not already present.
- `SameSite=Strict` — set unconditionally, overriding any existing `SameSite` value.

Only cookies whose name matches `COOKIE_NAME` are modified. All other `Set-Cookie` headers pass through unchanged.

## Configuration

Behavior is controlled through environment variables:

| Variable | Description |
| --- | --- |
| `COOKIE_NAME` | Name of the cookie to target. Use `*` to match every cookie. If unset, the filter does nothing. |
| `SECURE` | Add the `Secure` attribute when set to exactly `true`. |
| `HTTPONLY` | Add the `HttpOnly` attribute when set to exactly `true`. |
| `SAMESITE` | Set `SameSite=Strict` when set to exactly `true`. |

If `COOKIE_NAME` is unset, or none of `SECURE`, `HTTPONLY`, `SAMESITE` is `true`, responses pass through untouched.

## Notes

- Duplicate `Set-Cookie` headers are preserved: the host collapses them to one, so the filter clears the header and re-adds each cookie as its own occurrence.
- Empty segments (e.g. from a trailing `;`) are dropped when re-joining, so no stray separators are emitted.
- Headers are only rewritten when at least one cookie value actually changes.
