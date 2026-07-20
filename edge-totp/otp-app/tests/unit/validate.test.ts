import { test } from "node:test";
import assert from "node:assert/strict";
import { validateInt, validateRedirect, parseBool } from "../../src/lib/validate.js";

test("validateRedirect: keeps a same-host relative path", () => {
  assert.equal(validateRedirect("/dashboard"), "/dashboard");
  assert.equal(validateRedirect("/"), "/");
  assert.equal(validateRedirect("/path?x=1#h"), "/path?x=1#h");
});

test("validateRedirect: rejects protocol-relative and backslash tricks", () => {
  assert.equal(validateRedirect("//evil.com"), "/");
  assert.equal(validateRedirect("/\\evil.com"), "/");
});

test("validateRedirect: rejects absolute URLs and non-paths", () => {
  assert.equal(validateRedirect("https://evil.com"), "/");
  assert.equal(validateRedirect("javascript:alert(1)"), "/");
  assert.equal(validateRedirect(""), "/");
});

test("validateInt: unset/empty falls back to default", () => {
  assert.equal(validateInt("X", undefined, 30), 30);
  assert.equal(validateInt("X", null, 30), 30);
  assert.equal(validateInt("X", "", 30), 30);
});

test("validateInt: parses a valid integer", () => {
  assert.equal(validateInt("X", "45", 30), 45);
});

test("validateInt: rejects non-integer (no silent parseInt coercion)", () => {
  // parseInt("6abc") would be 6 — we must reject it instead of hiding the typo.
  assert.throws(() => validateInt("TOTP_DIGITS", "6abc", 6), /must be an integer/);
  assert.throws(() => validateInt("TOTP_DRIFT", "abc", 1), /must be an integer/);
  assert.throws(() => validateInt("TOTP_PERIOD", "1.5", 30), /must be an integer/);
});

test("validateInt: enforces min bound", () => {
  assert.throws(() => validateInt("TOTP_DIGITS", "4", 6, { min: 6 }), /must be >= 6/);
});

test("validateInt: enforces max bound", () => {
  assert.throws(() => validateInt("TOTP_DIGITS", "9", 6, { min: 6, max: 8 }), /must be <= 8/);
});

test("validateInt: accepts values on the boundary", () => {
  assert.equal(validateInt("TOTP_DIGITS", "6", 6, { min: 6, max: 8 }), 6);
  assert.equal(validateInt("TOTP_DIGITS", "8", 6, { min: 6, max: 8 }), 8);
});

test("parseBool: unset/empty falls back to default", () => {
  assert.equal(parseBool(undefined, true), true);
  assert.equal(parseBool(null, true), true);
  assert.equal(parseBool("", false), false);
});

test("parseBool: recognises truthy and falsy spellings (case-insensitive)", () => {
  for (const v of ["true", "TRUE", "1", "yes", " Yes "]) assert.equal(parseBool(v, false), true);
  for (const v of ["false", "FALSE", "0", "no", " No "]) assert.equal(parseBool(v, true), false);
});

test("parseBool: unrecognised value falls back rather than guessing", () => {
  assert.equal(parseBool("maybe", true), true);
  assert.equal(parseBool("maybe", false), false);
});
