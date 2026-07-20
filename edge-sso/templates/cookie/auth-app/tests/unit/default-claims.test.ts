import { test } from "node:test";
import assert from "node:assert/strict";
import { parseDefaultClaims } from "@sso/core/session";

test("parseDefaultClaims: parses a valid comma-separated list", () => {
  assert.deepEqual(parseDefaultClaims("email,name"), ["email", "name"]);
});

test("parseDefaultClaims: parses all supported claim names", () => {
  assert.deepEqual(
    parseDefaultClaims("email,name,picture,given_name,family_name"),
    ["email", "name", "picture", "given_name", "family_name"],
  );
});

test("parseDefaultClaims: trims whitespace around entries", () => {
  assert.deepEqual(parseDefaultClaims("email , name "), ["email", "name"]);
});

test("parseDefaultClaims: silently drops unknown claim names", () => {
  assert.deepEqual(parseDefaultClaims("email,unknown,name"), ["email", "name"]);
});

test("parseDefaultClaims: returns empty array for null", () => {
  assert.deepEqual(parseDefaultClaims(null), []);
});

test("parseDefaultClaims: returns empty array for empty string", () => {
  assert.deepEqual(parseDefaultClaims(""), []);
});

test("parseDefaultClaims: returns empty array for all-unknown values", () => {
  assert.deepEqual(parseDefaultClaims("foo,bar"), []);
});

test("parseDefaultClaims: single valid claim", () => {
  assert.deepEqual(parseDefaultClaims("picture"), ["picture"]);
});
