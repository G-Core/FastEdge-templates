import { test } from "node:test";
import assert from "node:assert/strict";
import { base32Decode, base32Encode } from "../../src/lib/base32.js";

// RFC 4648 §10 test vectors
test("base32Decode: empty string", () => {
  assert.deepEqual(base32Decode(""), new Uint8Array(0));
});

test("base32Decode: 'MY======'  → 'f'", () => {
  assert.deepEqual(base32Decode("MY======"), new Uint8Array([0x66]));
});

test("base32Decode: 'MZXQ====' → 'fo'", () => {
  assert.deepEqual(base32Decode("MZXQ===="), new Uint8Array([0x66, 0x6f]));
});

test("base32Decode: 'MZXW6===' → 'foo'", () => {
  assert.deepEqual(base32Decode("MZXW6==="), new Uint8Array([0x66, 0x6f, 0x6f]));
});

test("base32Decode: 'MZXW6YQ=' → 'foob'", () => {
  assert.deepEqual(base32Decode("MZXW6YQ="), new Uint8Array([0x66, 0x6f, 0x6f, 0x62]));
});

test("base32Decode: 'MZXW6YTB' → 'fooba'", () => {
  assert.deepEqual(
    base32Decode("MZXW6YTB"),
    new Uint8Array([0x66, 0x6f, 0x6f, 0x62, 0x61]),
  );
});

test("base32Decode: RFC 6238 SHA1 seed (ASCII '12345678901234567890')", () => {
  const expected = new TextEncoder().encode("12345678901234567890");
  assert.deepEqual(base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), expected);
});

test("base32Decode: case-insensitive", () => {
  assert.deepEqual(base32Decode("mfrgg==="), base32Decode("MFRGG==="));
});

test("base32Decode: strips whitespace", () => {
  assert.deepEqual(base32Decode("MF RG G==="), base32Decode("MFRGG==="));
});

test("base32Decode: throws on invalid character", () => {
  assert.throws(() => base32Decode("MFRG1==="), /Invalid base32 character/);
});

test("base32Encode + base32Decode: roundtrip", () => {
  const input = new Uint8Array([0x00, 0xff, 0x10, 0xab, 0xcd, 0xef]);
  assert.deepEqual(base32Decode(base32Encode(input)), input);
});

test("base32Encode: all-zero bytes", () => {
  // 5 zero bytes → 8 'A' chars (5 * 8 bits = 40 bits = 8 * 5-bit groups, all zero)
  assert.equal(base32Encode(new Uint8Array(5)), "AAAAAAAA");
});
