import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseAllowlist,
  selectProviders,
  buildLoginUrl,
} from "@sso/core/providers/registry";

// Convenience: a hasCred predicate from a set of present credential keys.
function credsPresent(...keys: string[]): (k: string) => boolean {
  const set = new Set(keys);
  return (k) => set.has(k);
}

const ALL = ["GOOGLE_CLIENT_ID", "GITHUB_CLIENT_ID", "MICROSOFT_CLIENT_ID", "FACEBOOK_CLIENT_ID", "IDP_SSO_URL"];

test("parseAllowlist: splits, trims, lowercases, drops blanks", () => {
  assert.deepEqual(parseAllowlist(" Google , GITHUB ,, "), ["google", "github"]);
  assert.deepEqual(parseAllowlist(""), []);
  assert.deepEqual(parseAllowlist(null), []);
  assert.deepEqual(parseAllowlist(undefined), []);
});

test("selectProviders: no allowlist → every provider with creds present", () => {
  const r = selectProviders(null, credsPresent(...ALL));
  assert.deepEqual(
    r.map((p) => p.id),
    ["google", "github", "microsoft", "facebook", "saml"],
  );
});

test("selectProviders: a provider missing its creds is excluded", () => {
  const r = selectProviders(null, credsPresent("GOOGLE_CLIENT_ID"));
  assert.deepEqual(
    r.map((p) => p.id),
    ["google"],
  );
});

test("selectProviders: allowlist ∩ creds-present", () => {
  // allowlist asks for google+github+saml, but only github has creds
  const r = selectProviders("google,github,saml", credsPresent("GITHUB_CLIENT_ID"));
  assert.deepEqual(
    r.map((p) => p.id),
    ["github"],
  );
});

test("selectProviders: allowlist narrows even when more creds are present", () => {
  const r = selectProviders("github", credsPresent(...ALL));
  assert.deepEqual(
    r.map((p) => p.id),
    ["github"],
  );
});

test("selectProviders: unknown allowlist ids are ignored", () => {
  const r = selectProviders("linkedin,google", credsPresent(...ALL));
  assert.deepEqual(
    r.map((p) => p.id),
    ["google"],
  );
});

test("selectProviders: result order follows the registry, not the allowlist", () => {
  const r = selectProviders("saml,google", credsPresent(...ALL));
  assert.deepEqual(
    r.map((p) => p.id),
    ["google", "saml"],
  );
});

test("selectProviders: no creds at all → empty", () => {
  assert.deepEqual(selectProviders(null, credsPresent()), []);
  assert.deepEqual(selectProviders("google,github", credsPresent()), []);
});

test("selectProviders: resolved provider carries label + loginPath", () => {
  const [google] = selectProviders("google", credsPresent(...ALL));
  assert.equal(google.label, "Google");
  assert.equal(google.loginPath, "/auth/login/google");
});

test("buildLoginUrl: appends url-encoded redirect when present", () => {
  assert.equal(
    buildLoginUrl("/auth/login/google", "https://shop.example.com/cart?x=1"),
    "/auth/login/google?redirect=https%3A%2F%2Fshop.example.com%2Fcart%3Fx%3D1",
  );
});

test("buildLoginUrl: omits the query when no redirect is given", () => {
  assert.equal(buildLoginUrl("/auth/login"), "/auth/login");
  assert.equal(buildLoginUrl("/auth/login", undefined), "/auth/login");
});
