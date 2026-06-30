import { test } from "node:test";
import assert from "node:assert/strict";
import {
  extractSamlClaims,
  parseSamlClaimMap,
} from "@sso/core/saml-claims";

// ---- extractSamlClaims ----

test("extractSamlClaims: resolves email from plain 'email' attribute", () => {
  const result = extractSamlClaims(
    { email: "user@example.com" },
    ["email"],
  );
  assert.deepEqual(result, { email: "user@example.com" });
});

test("extractSamlClaims: resolves email from Microsoft schema URL", () => {
  const result = extractSamlClaims(
    {
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
        "user@corp.com",
    },
    ["email"],
  );
  assert.deepEqual(result, { email: "user@corp.com" });
});

test("extractSamlClaims: resolves email from OID URN", () => {
  const result = extractSamlClaims(
    { "urn:oid:0.9.2342.19200300.100.1.3": "oid@example.com" },
    ["email"],
  );
  assert.deepEqual(result, { email: "oid@example.com" });
});

test("extractSamlClaims: custom claimMap takes precedence over defaults", () => {
  const result = extractSamlClaims(
    { email: "default@example.com", EmailAddress: "custom@example.com" },
    ["email"],
    { email: "EmailAddress" },
  );
  assert.deepEqual(result, { email: "custom@example.com" });
});

test("extractSamlClaims: falls through to defaults when custom attr is absent", () => {
  const result = extractSamlClaims(
    { email: "fallback@example.com" },
    ["email"],
    { email: "NonExistentAttr" },
  );
  assert.deepEqual(result, { email: "fallback@example.com" });
});

test("extractSamlClaims: omits claim when no attribute matches", () => {
  const result = extractSamlClaims({ unrelated: "value" }, ["email"]);
  assert.deepEqual(result, {});
  assert.equal("email" in result, false);
});

test("extractSamlClaims: picture is always omitted (no standard SAML attr)", () => {
  const result = extractSamlClaims(
    { picture: "https://example.com/photo.jpg" },
    ["picture"],
  );
  assert.deepEqual(result, {});
});

test("extractSamlClaims: multi-value attribute uses first value", () => {
  const result = extractSamlClaims(
    { email: ["first@example.com", "second@example.com"] },
    ["email"],
  );
  assert.deepEqual(result, { email: "first@example.com" });
});

test("extractSamlClaims: resolves multiple claims in one call", () => {
  const result = extractSamlClaims(
    { email: "user@example.com", displayName: "Alice Smith" },
    ["email", "name"],
  );
  assert.deepEqual(result, { email: "user@example.com", name: "Alice Smith" });
});

test("extractSamlClaims: empty requestedClaims returns empty object", () => {
  const result = extractSamlClaims({ email: "user@example.com" }, []);
  assert.deepEqual(result, {});
});

// ---- parseSamlClaimMap ----

test("parseSamlClaimMap: parses valid JSON object", () => {
  const result = parseSamlClaimMap(
    JSON.stringify({ email: "EmailAddress", name: "FullName" }),
  );
  assert.deepEqual(result, { email: "EmailAddress", name: "FullName" });
});

test("parseSamlClaimMap: ignores unknown keys", () => {
  const result = parseSamlClaimMap(
    JSON.stringify({ email: "EmailAddress", unknownClaim: "whatever" }),
  );
  assert.deepEqual(result, { email: "EmailAddress" });
});

test("parseSamlClaimMap: returns empty for null", () => {
  assert.deepEqual(parseSamlClaimMap(null), {});
});

test("parseSamlClaimMap: returns empty for empty string", () => {
  assert.deepEqual(parseSamlClaimMap(""), {});
});

test("parseSamlClaimMap: returns empty for invalid JSON", () => {
  assert.deepEqual(parseSamlClaimMap("{not-json}"), {});
});

test("parseSamlClaimMap: returns empty for JSON array", () => {
  assert.deepEqual(parseSamlClaimMap('["email"]'), {});
});
