# FastEdge JS Runtime Constraints

## Runtime: StarlingMonkey

The FastEdge HTTP App JS SDK (`@gcoredev/fastedge-sdk-js`) is built on
[@bytecodealliance/StarlingMonkey](https://github.com/bytecodealliance/StarlingMonkey) —
a SpiderMonkey-based JS runtime targeting the WASI 0.2 Component Model.

It is a **strict WinterCG-style runtime**. It is NOT Node.js and has NO Node.js compatibility layer.

### What is available

- `fetch` (standard)
- `crypto.subtle` (Web Crypto API — partial, see below)
- `crypto.getRandomValues()`
- `TextEncoder` / `TextDecoder`
- `CompressionStream` / `DecompressionStream` (including `deflate-raw`)
- `URL`, `URLSearchParams`, `FormData`
- `WHATWG Streams`, `Blob`, structured clone, `btoa` / `atob`, `console`
- `@gcoredev/fastedge-sdk-js`: `getSecret()`, `KvStore`, outbound `fetch`

### What is NOT available

- `node:crypto` — not implemented, not polyfillable (see below)
- `node:fs`, `node:path`, `node:buffer`, `process`, `require`
- No Node.js compatibility flag (unlike Cloudflare Workers' `nodejs_compat`)

### `crypto.subtle` supported operations

| Operation | Algorithms |
|---|---|
| `digest()` | SHA-1, SHA-256, SHA-384, SHA-512, MD5 |
| `sign()` / `verify()` | RSASSA-PKCS1-v1_5, ECDSA, HMAC |
| `importKey()` | JWK, PKCS#8, SPKI, raw (HMAC) |
| `getRandomValues()` | ✓ |
| `encrypt()` / `decrypt()` | **Not implemented** |
| `generateKey()`, `deriveKey()`, `deriveBits()` | **Not implemented** |
| `exportKey()` | **Not implemented** |

The SAML-critical operations (SHA-256 digest, RSASSA-PKCS1-v1_5 verify, SPKI importKey) are all available.

---

## Why Standard SAML Libraries Don't Work

All mainstream SAML libraries for Node.js are **incompatible** with StarlingMonkey:

| Library | Blocker |
|---|---|
| `samlify` | Depends on `xml-crypto` (sync Node crypto) and `node-rsa` |
| `@node-saml/node-saml` | Deep Node.js `crypto` dependency |
| `@boxyhq/saml20` | `xml-crypto` + `node-forge`; CVE-2025-29775 affected |
| `passport-saml` | Node.js `crypto` |

The core issue is `xml-crypto`, which calls the **synchronous** Node.js crypto API (`crypto.createVerify()`, `crypto.createSign()`, `crypto.createHash()`). StarlingMonkey only has the **async** `crypto.subtle` API. This is a fundamental impedance mismatch — no bundler polyfill can bridge synchronous calls to async `Promise`-returning functions without rewriting the library itself.

### Why polyfilling node:crypto doesn't work

`esbuild-plugin-polyfill-node` can substitute `node:crypto` with `crypto-browserify`. However:

1. `crypto-browserify` implements `createSign` / `createVerify` synchronously using its own pure-JS RSA implementation — it does **not** delegate to `crypto.subtle`.
2. Even if it did, `crypto.subtle` is async — the sync/async mismatch remains.
3. No known successful deployment of samlify or xml-crypto in a StarlingMonkey environment exists.

---

## Security Note: CVE-2025-29775 (SAMLStorm)

All libraries depending on `xml-crypto < 6.0.1` are affected by SAMLStorm, a critical authentication bypass via XML comment injection in `DigestValue`. The implemented stack strips XML comments before processing — see `saml-flow.md` security checklist.

---

## Viable Stack for SAML SP in FastEdge

| Task | Package | Node deps? |
|---|---|---|
| XML parsing | `@xmldom/xmldom` | None — pure JS |
| XML Digital Signature (XMLDSig) | `xmldsigjs` | None — uses `crypto.subtle` |
| X.509 cert → CryptoKey | `@peculiar/x509` | None — uses `crypto.subtle` |
| Deflate (SAMLRequest encoding) | Native `CompressionStream("deflate-raw")` | None |

### Caveats and Known Workarounds

**`exportKey` not implemented — polyfill required**

`crypto.subtle.exportKey` is not implemented in StarlingMonkey. `xmldsigjs.Verify()` calls `reimportKey()` internally which calls `exportKey("spki", key)`. Without a polyfill this throws `Application.crypto.subtle.exportKey is not a function`.

**Fix in `auth-app/federation/saml/response.ts`:**
- Import the IdP public key through the **global `crypto.subtle.importKey("spki", ...)`** (not via `cert.publicKey.export()` which uses `@peculiar/webcrypto`'s engine)
- At module load, install a polyfill for `exportKey` that stores SPKI bytes in a WeakMap keyed by the CryptoKey, then returns them when `exportKey("spki", key)` is called
- Covered by `saml-response.test.ts` "StarlingMonkey polyfill" test case

**`@peculiar/x509` crypto engine mismatch**

`cert.publicKey.export()` uses `@peculiar/webcrypto` as its crypto provider, not the global `crypto`. Keys imported via `@peculiar/webcrypto` are not usable by `xmldsigjs`, which uses the global `crypto`. Fix: use `cert.publicKey.rawData` (DER-encoded SPKI `ArrayBuffer`) and import directly via `crypto.subtle.importKey`.

- `xmldsigjs` is battle-tested in this stack — verified against Okta SAML 2.0.
- `@peculiar/x509` documents `node >= 20` as a requirement but uses Web Crypto internally — it bundles fine.
- Bundle size limit: 10 MB WASM binary. Check with `fastedge-build` after adding dependencies.

### XMLDSig Verification Steps (manual reference)

If implementing manually instead of using `xmldsigjs`:

1. Parse SAMLResponse XML with `@xmldom/xmldom`
2. Locate `<ds:Signature>` inside the `<Assertion>`
3. Extract `<ds:SignedInfo>` and apply **Exclusive C14N** with enveloped-signature transform (remove the `<ds:Signature>` element before canonicalizing)
4. `crypto.subtle.digest("SHA-256", c14nBytes)` and compare to `<ds:DigestValue>`
5. `crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, publicKey, sigBytes, c14nSignedInfoBytes)`

Exclusive C14N is the hardest part to implement from scratch — prefer `xmldsigjs` to avoid this.

---

## SAMLRequest Encoding

Use native `CompressionStream("deflate-raw")` — available in StarlingMonkey:

```js
async function deflateRaw(str) {
  const encoded = new TextEncoder().encode(str);
  const cs = new CompressionStream("deflate-raw");
  const writer = cs.writable.getWriter();
  writer.write(encoded);
  writer.close();
  const chunks = [];
  const reader = cs.readable.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return btoa(String.fromCharCode(...out));
}
```

Or use `fflate` (`deflateRawSync`) as a synchronous alternative.
