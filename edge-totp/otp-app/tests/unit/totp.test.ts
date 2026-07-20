import { test } from "node:test";
import assert from "node:assert/strict";
import { generateCode, otpauthUri } from "../../src/lib/totp.js";

// RFC 6238 Appendix B test vectors.
// Seed: ASCII "12345678901234567890" = base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
// Algorithm: SHA1 (authenticator-app default), 8-digit, period=30, T0=0
const RFC_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

function counter(unixTime: number, period = 30): number {
  return Math.floor(unixTime / period);
}

test("RFC 6238 vector T=59 → 8-digit 94287082", async () => {
  const code = await generateCode(RFC_SEED, counter(59), 8);
  assert.equal(code, "94287082");
});

test("RFC 6238 vector T=1111111109 → 8-digit 07081804", async () => {
  const code = await generateCode(RFC_SEED, counter(1111111109), 8);
  assert.equal(code, "07081804");
});

test("RFC 6238 vector T=1234567890 → 8-digit 89005924", async () => {
  const code = await generateCode(RFC_SEED, counter(1234567890), 8);
  assert.equal(code, "89005924");
});

test("RFC 6238 vector T=2000000000 → 8-digit 69279037", async () => {
  const code = await generateCode(RFC_SEED, counter(2000000000), 8);
  assert.equal(code, "69279037");
});

// 6-digit = rightmost 6 of the 8-digit code
test("RFC 6238 vector T=59 → 6-digit 287082", async () => {
  const code = await generateCode(RFC_SEED, counter(59), 6);
  assert.equal(code, "287082");
});

test("RFC 6238 vector T=1111111109 → 6-digit 081804", async () => {
  const code = await generateCode(RFC_SEED, counter(1111111109), 6);
  assert.equal(code, "081804");
});

test("RFC 6238 vector T=1234567890 → 6-digit 005924", async () => {
  const code = await generateCode(RFC_SEED, counter(1234567890), 6);
  assert.equal(code, "005924");
});

test("RFC 6238 vector T=2000000000 → 6-digit 279037", async () => {
  const code = await generateCode(RFC_SEED, counter(2000000000), 6);
  assert.equal(code, "279037");
});

// Drift: same counter at adjacent step
test("adjacent counter produces a different code", async () => {
  const c = counter(1111111109);
  const a = await generateCode(RFC_SEED, c, 6);
  const b = await generateCode(RFC_SEED, c + 1, 6);
  assert.notEqual(a, b);
});

test("otpauthUri: produces correct scheme and query params", () => {
  const uri = otpauthUri("JBSWY3DPEHPK3PXP", "alice@example.com", "Acme", {
    digits: 6,
    period: 30,
    algorithm: "SHA1",
  });
  assert.ok(uri.startsWith("otpauth://totp/"), `unexpected scheme: ${uri}`);
  assert.ok(uri.includes("secret=JBSWY3DPEHPK3PXP"), `missing secret: ${uri}`);
  assert.ok(uri.includes("issuer=Acme"), `missing issuer: ${uri}`);
  assert.ok(uri.includes("digits=6"), `missing digits: ${uri}`);
  assert.ok(uri.includes("period=30"), `missing period: ${uri}`);
});
