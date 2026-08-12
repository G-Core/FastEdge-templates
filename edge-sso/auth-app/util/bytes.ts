/**
 * Encode a string to UTF-8 bytes.
 *
 * `TextEncoder` always produces an ArrayBuffer-backed Uint8Array, but its declared
 * return type (`Uint8Array`, i.e. `Uint8Array<ArrayBufferLike>` under TS 5.7+) is not
 * assignable to the WebCrypto / Streams `BufferSource` params, which expect an
 * ArrayBuffer-backed view. The cast is therefore safe, and keeps call sites clean.
 */
export function encodeUtf8(input: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(input) as Uint8Array<ArrayBuffer>;
}

/** Encode bytes as standard base64 (RFC 4648, with `+/` and `=` padding). */
export function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Decode standard base64 to bytes. Input must be valid base64 (padded). */
export function base64Decode(b64: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)) as Uint8Array<ArrayBuffer>;
}

/** Encode bytes as base64url (RFC 4648 §5: `-_`, no padding) — the JWT/JWS form. */
export function base64urlEncode(input: Uint8Array | ArrayBuffer): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  return base64Encode(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Decode base64url (re-pads internally). */
export function base64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return base64Decode(padded);
}
