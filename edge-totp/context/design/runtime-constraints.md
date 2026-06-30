# Runtime Constraints — What the FastEdge JS runtime allows for TOTP

The HTTP-app JS runtime is **StarlingMonkey** (SpiderMonkey, WinterCG-style). NOT
Node.js — no `node:crypto`, `fs`, `process`, `require`; no WebSocket; no DOM.
Authoritative reference: the `gcore-fastedge:fastedge-docs` skill (`js-runtime` /
`sdk-reference-js`).

## Crypto — sufficient for TOTP

`crypto.subtle` capability matrix (the parts that matter here):

| Op | Supported |
| --- | --- |
| `digest` | SHA-1, SHA-256, SHA-384, SHA-512, MD5 |
| `sign` / `verify` | **HMAC**, RSASSA-PKCS1-v1_5, ECDSA |
| `importKey` | **raw (HMAC)**, JWK, SPKI, PKCS#8 |
| `getRandomValues`, `randomUUID` | ✓ |
| `encrypt` / `decrypt` / `generateKey` / `deriveKey` / `exportKey` | **NOT implemented** |

Implications:
- **TOTP works**: import the base32-decoded seed as a raw HMAC key, `sign` the
  8-byte big-endian time-step counter, apply RFC 4226 dynamic truncation, mod
  `10^digits`. Default hash SHA-1 (RFC 6238 / authenticator-app default).
- **The `mfa_session` and handoff ticket** are HS256 — `importKey(raw, HMAC SHA-256)`
  + `sign`/`verify`. The Profile-B proof is ES256 (`importKey(pkcs8, ECDSA P-256)`).
- **No `encrypt`** ⇒ a seed cannot be sealed into a browser-visible token. This is
  the root reason the seed travels **server-to-server only** and is fetched at
  verify time (see `architecture/flow.md`).
- `Date.now()` **is** available in the app runtime (used for the time-step and JWT
  `exp`).

There is **no base32 in the standard library** — implement RFC 4648 base32
decode/encode yourself (small helper). `atob`/`btoa`, `TextEncoder/Decoder` are
available.

## Storage primitives

- **`fastedge::kv`** (`KvStore.open(name).get(key) → ArrayBuffer | null`) is
  **read-only from the app**. Writes go through the Gcore KV REST API
  (`GCORE_API_TOKEN`). Globally replicated, eventual consistency.
- **`fastedge::cache`** (`Cache.incr/get/set/expire`, atomic counters, TTL) is
  **POP-local** and transient. Good for replay marks + brute-force counters; NOT a
  cross-PoP store and NOT durable.
- **`fastedge::secret`** (`getSecret`) and **`fastedge::env`** (`getEnv`) are
  **request-time only** — never call them at module top level (causes a 531).
  Always handle `null`.

## Platform limits (Basic / Pro)

- Execution time 50 ms / 200 ms; memory 128 MB / 256 MB.
- Outbound `fetch` 5 / 20 per invocation — KV seed reads/writes count against this;
  keep verify to a single outbound call.
- Request/response body 1 MB / 5 MB.

## Framework

Hono wired via the **service-worker pattern** —
`addEventListener("fetch", (e) => e.respondWith(app.fetch(e.request)))` — **not**
`app.fire()`, not `export default`, not `Deno.serve`. Incoming `request.headers` is
read-only.
