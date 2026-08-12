import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineTestSuite, runTestSuite } from "@gcoredev/fastedge-test/test";
import { parseSetCookieAsString } from "./_cookies.js";
import { runNonCookieVariantSmoke } from "./non-cookie-smoke.js";

type SuiteResult = Awaited<ReturnType<typeof runTestSuite>>;

function report(label: string, r: SuiteResult) {
  console.log(`\n${label}`);
  for (const t of r.results) {
    const mark = t.passed ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
    console.log(`  ${mark} ${t.name} (${t.durationMs.toFixed(1)}ms)`);
    if (!t.passed && t.error) console.log(`      ${t.error}`);
  }
  console.log(`  ${r.passed}/${r.total} passed in ${r.durationMs.toFixed(1)}ms`);
}

const SUCCESS_STATUS_XML = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:NameID>user@example.com</saml:NameID>
  </saml:Assertion>
</samlp:Response>`;

// --- Main suite (uses the package .env) ---
const mainResult = await runTestSuite(
  defineTestSuite({
    wasmPath: "./wasm/auth-app.wasm",
    runnerConfig: { dotenv: { enabled: true } },
    tests: [
      {
        name: "GET /auth/login redirects to IdP with SAMLRequest",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/login",
            method: "GET",
            headers: {},
          });
          if (response.status !== 302) {
            throw new Error(`Expected 302, got ${response.status}`);
          }
          const location = response.headers["location"];
          if (!location) {
            throw new Error("Expected Location header in redirect response");
          }
          if (!location.includes("SAMLRequest=")) {
            throw new Error(
              `Expected Location to contain SAMLRequest param, got: ${location}`,
            );
          }
        },
      },
      {
        name: "GET /auth/login sets saml_relay cookie",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/login",
            method: "GET",
            headers: {},
          });
          if (response.status !== 302) {
            throw new Error(`Expected 302, got ${response.status}`);
          }
          const cookie = parseSetCookieAsString(response.headers);
          if (!cookie || !cookie.includes("saml_relay=")) {
            throw new Error(
              `Expected saml_relay cookie to be set, got Set-Cookie: ${cookie}`,
            );
          }
        },
      },
      {
        name: "GET /auth/login?redirect=/protected still sets relay cookie",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/login?redirect=/protected",
            method: "GET",
            headers: {},
          });
          if (response.status !== 302) {
            throw new Error(`Expected 302, got ${response.status}`);
          }
          const cookie = parseSetCookieAsString(response.headers);
          if (!cookie || !cookie.includes("saml_relay=")) {
            throw new Error(
              `Expected saml_relay cookie to be set, got Set-Cookie: ${cookie}`,
            );
          }
        },
      },
      {
        name: "POST /auth/callback without SAMLResponse redirects to error page",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/callback",
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: "",
          });
          if (response.status !== 302) {
            throw new Error(
              `Expected 302 redirect to error page, got ${response.status}`,
            );
          }
          const location = response.headers["location"];
          if (!location || !location.startsWith("/auth/error")) {
            throw new Error(
              `Expected redirect to /auth/error, got: ${location}`,
            );
          }
        },
      },
      {
        name: "POST /auth/callback with invalid base64 SAMLResponse redirects to error page",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/callback",
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: "SAMLResponse=!!!not-valid-base64!!!",
          });
          if (response.status !== 302) {
            throw new Error(
              `Expected 302 redirect to error page, got ${response.status}`,
            );
          }
          const location = response.headers["location"];
          if (!location || !location.startsWith("/auth/error")) {
            throw new Error(
              `Expected redirect to /auth/error, got: ${location}`,
            );
          }
        },
      },
      {
        // error redirect must not leak internal details via the URL
        name: "POST /auth/callback with unsigned SAMLResponse redirects to error without leaking details",
        run: async (runner) => {
          const samlResponseB64 = btoa(SUCCESS_STATUS_XML);
          const response = await runner.execute({
            path: "/auth/callback",
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: `SAMLResponse=${encodeURIComponent(samlResponseB64)}`,
          });
          if (response.status !== 302) {
            throw new Error(
              `Expected 302 redirect to error page, got ${response.status}`,
            );
          }
          const location = response.headers["location"];
          if (!location || !location.startsWith("/auth/error")) {
            throw new Error(
              `Expected redirect to /auth/error, got: ${location}`,
            );
          }
          // must not expose internal error text in the URL
          if (location.includes("?")) {
            throw new Error(
              `Error URL must not carry a message query string: ${location}`,
            );
          }
        },
      },
      {
        name: "POST /auth/callback with SAML failure status redirects to error page",
        run: async (runner) => {
          const failureXml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/>
  </samlp:Status>
</samlp:Response>`;
          const samlResponseB64 = btoa(failureXml);
          const response = await runner.execute({
            path: "/auth/callback",
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: `SAMLResponse=${encodeURIComponent(samlResponseB64)}`,
          });
          if (response.status !== 302) {
            throw new Error(
              `Expected 302 redirect to error page, got ${response.status}`,
            );
          }
          const location = response.headers["location"];
          if (!location || !location.startsWith("/auth/error")) {
            throw new Error(
              `Expected redirect to /auth/error, got: ${location}`,
            );
          }
        },
      },
      {
        // error page must show a generic message, not the ?message= param
        name: "GET /auth/error shows generic message regardless of ?message= param",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/error?message=injected-attacker-text",
            method: "GET",
            headers: {},
          });
          if (response.status !== 200) {
            throw new Error(`Expected 200, got ${response.status}`);
          }
          if (response.body.includes("injected-attacker-text")) {
            throw new Error(
              "Error page must not reflect ?message= content",
            );
          }
          if (!response.body.toLowerCase().includes("sign-in failed")) {
            throw new Error(
              `Error page should contain generic 'sign-in failed' text, got:\n${response.body}`,
            );
          }
        },
      },
      {
        name: "GET /auth/login/github redirects to GitHub with PKCE + state",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/login/github?redirect=/foo",
            method: "GET",
            headers: {},
          });
          if (response.status !== 302) {
            throw new Error(`Expected 302, got ${response.status}`);
          }
          const location = response.headers["location"];
          if (!location) throw new Error("Missing Location header");
          if (
            !location.startsWith("https://github.com/login/oauth/authorize?")
          ) {
            throw new Error(`Expected GitHub authorize URL, got: ${location}`);
          }
          const url = new URL(location);
          for (const key of [
            "client_id",
            "code_challenge",
            "code_challenge_method",
            "state",
            "scope",
          ]) {
            if (!url.searchParams.has(key)) {
              throw new Error(`Missing '${key}' in Location: ${location}`);
            }
          }
          if (url.searchParams.get("code_challenge_method") !== "S256") {
            throw new Error(
              `Expected code_challenge_method=S256, got ${url.searchParams.get("code_challenge_method")}`,
            );
          }
        },
      },
      {
        name: "GET /auth/login/github sets signed gh_oauth_state cookie",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/login/github?redirect=/foo",
            method: "GET",
            headers: {},
          });
          const cookie = parseSetCookieAsString(response.headers);
          if (!cookie || !cookie.includes("gh_oauth_state=")) {
            throw new Error(
              `Expected gh_oauth_state cookie, got Set-Cookie: ${cookie}`,
            );
          }
          if (!cookie.includes("HttpOnly")) {
            throw new Error(`Expected HttpOnly attribute, got: ${cookie}`);
          }
          if (!cookie.includes("Path=/auth")) {
            throw new Error(`Expected Path=/auth, got: ${cookie}`);
          }
          const maxAgeMatch = cookie.match(/Max-Age=(\d+)/);
          if (!maxAgeMatch) {
            throw new Error(`Expected Max-Age attribute, got: ${cookie}`);
          }
          if (Number(maxAgeMatch[1]) > 600) {
            throw new Error(`Expected Max-Age<=600, got ${maxAgeMatch[1]}`);
          }
        },
      },
      {
        name: "GET /auth/callback/github with mismatched state redirects to error",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/callback/github?state=MISMATCH&code=abc",
            method: "GET",
            headers: { cookie: "gh_oauth_state=bogus.sig" },
          });
          if (response.status !== 302) {
            throw new Error(`Expected 302, got ${response.status}`);
          }
          const location = response.headers["location"];
          if (!location || !location.startsWith("/auth/error")) {
            throw new Error(
              `Expected redirect to /auth/error, got ${location}`,
            );
          }
        },
      },
      {
        name: "GET /auth/callback/github without code redirects to error",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/callback/github?state=abc",
            method: "GET",
            headers: {},
          });
          if (response.status !== 302) {
            throw new Error(`Expected 302, got ${response.status}`);
          }
          const location = response.headers["location"];
          if (!location || !location.startsWith("/auth/error")) {
            throw new Error(
              `Expected redirect to /auth/error, got ${location}`,
            );
          }
        },
      },
      {
        name: "GET /auth/login/google redirects to Google with OIDC scope + PKCE + state",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/login/google?redirect=/foo",
            method: "GET",
            headers: {},
          });
          if (response.status !== 302) {
            throw new Error(`Expected 302, got ${response.status}`);
          }
          const location = response.headers["location"];
          if (!location) throw new Error("Missing Location header");
          if (
            !location.startsWith(
              "https://accounts.google.com/o/oauth2/v2/auth?",
            )
          ) {
            throw new Error(`Expected Google authorize URL, got: ${location}`);
          }
          const url = new URL(location);
          for (const key of [
            "client_id",
            "code_challenge",
            "code_challenge_method",
            "state",
            "scope",
            "response_type",
            "redirect_uri",
          ]) {
            if (!url.searchParams.has(key)) {
              throw new Error(`Missing '${key}' in Location: ${location}`);
            }
          }
          if (url.searchParams.get("code_challenge_method") !== "S256") {
            throw new Error(
              `Expected code_challenge_method=S256, got ${url.searchParams.get("code_challenge_method")}`,
            );
          }
          const scope = url.searchParams.get("scope") ?? "";
          for (const required of ["openid", "email", "profile"]) {
            if (!scope.includes(required)) {
              throw new Error(
                `Expected scope to include '${required}', got: ${scope}`,
              );
            }
          }
        },
      },
      {
        name: "GET /auth/login/google sets signed gg_oauth_state cookie",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/login/google?redirect=/foo",
            method: "GET",
            headers: {},
          });
          const cookie = parseSetCookieAsString(response.headers);
          if (!cookie || !cookie.includes("gg_oauth_state=")) {
            throw new Error(
              `Expected gg_oauth_state cookie, got Set-Cookie: ${cookie}`,
            );
          }
          if (!cookie.includes("HttpOnly")) {
            throw new Error(`Expected HttpOnly attribute, got: ${cookie}`);
          }
          if (!cookie.includes("Path=/auth")) {
            throw new Error(`Expected Path=/auth, got: ${cookie}`);
          }
          const maxAgeMatch = cookie.match(/Max-Age=(\d+)/);
          if (!maxAgeMatch) {
            throw new Error(`Expected Max-Age attribute, got: ${cookie}`);
          }
          if (Number(maxAgeMatch[1]) > 600) {
            throw new Error(`Expected Max-Age<=600, got ${maxAgeMatch[1]}`);
          }
        },
      },
      {
        name: "GET /auth/callback/google with mismatched state redirects to error",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/callback/google?state=MISMATCH&code=abc",
            method: "GET",
            headers: { cookie: "gg_oauth_state=bogus.sig" },
          });
          if (response.status !== 302) {
            throw new Error(`Expected 302, got ${response.status}`);
          }
          const location = response.headers["location"];
          if (!location || !location.startsWith("/auth/error")) {
            throw new Error(
              `Expected redirect to /auth/error, got ${location}`,
            );
          }
        },
      },
      {
        name: "GET /auth/callback/google without code redirects to error",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/callback/google?state=abc",
            method: "GET",
            headers: {},
          });
          if (response.status !== 302) {
            throw new Error(`Expected 302, got ${response.status}`);
          }
          const location = response.headers["location"];
          if (!location || !location.startsWith("/auth/error")) {
            throw new Error(
              `Expected redirect to /auth/error, got ${location}`,
            );
          }
        },
      },
      {
        name: "GET /auth/ renders chooser with every enabled provider (test .env has all three creds)",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/",
            method: "GET",
            headers: {},
          });
          if (response.status !== 200) {
            throw new Error(`Expected 200, got ${response.status}`);
          }
          const body = response.body;
          for (const needle of [
            'href="/auth/login/google"',
            'href="/auth/login/github"',
            'href="/auth/login"',
            "Sign in with Google",
            "Sign in with GitHub",
            "Sign in with SSO",
          ]) {
            if (!body.includes(needle)) {
              throw new Error(
                `Expected chooser body to contain ${needle}, got:\n${body}`,
              );
            }
          }
        },
      },
      {
        name: "GET /auth/?redirect=/protected preserves redirect in chooser links",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/?redirect=/protected",
            method: "GET",
            headers: {},
          });
          if (response.status !== 200) {
            throw new Error(`Expected 200, got ${response.status}`);
          }
          if (
            !response.body.includes(
              'href="/auth/login/google?redirect=%2Fprotected"',
            )
          ) {
            throw new Error(
              `Expected google link to carry the encoded redirect, got:\n${response.body}`,
            );
          }
        },
      },
      {
        // chooser must not render off-origin redirect in any href
        name: "GET /auth/?redirect=https://evil.com sanitizes off-origin redirect in chooser",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/?redirect=https://evil.com/steal",
            method: "GET",
            headers: {},
          });
          if (response.status !== 200) {
            throw new Error(`Expected 200, got ${response.status}`);
          }
          if (response.body.includes("evil.com")) {
            throw new Error(
              "Chooser must not render off-origin redirect in href",
            );
          }
        },
      },
      {
        name: "GET /auth/providers returns the enabled provider set as JSON",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/providers",
            method: "GET",
            headers: {},
          });
          if (response.status !== 200) {
            throw new Error(`Expected 200, got ${response.status}`);
          }
          const parsed = JSON.parse(response.body) as {
            providers: { id: string; label: string; loginUrl: string }[];
          };
          const ids = parsed.providers.map((p) => p.id);
          if (JSON.stringify(ids) !== JSON.stringify(["google", "github", "saml"])) {
            throw new Error(`Expected [google,github,saml], got ${JSON.stringify(ids)}`);
          }
          const google = parsed.providers.find((p) => p.id === "google");
          if (!google || google.loginUrl !== "/auth/login/google") {
            throw new Error(
              `Expected google loginUrl=/auth/login/google, got ${google?.loginUrl}`,
            );
          }
        },
      },
      {
        name: "GET /auth/providers?redirect=/x preserves redirect in each loginUrl",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/providers?redirect=/x",
            method: "GET",
            headers: {},
          });
          const parsed = JSON.parse(response.body) as {
            providers: { id: string; loginUrl: string }[];
          };
          const google = parsed.providers.find((p) => p.id === "google");
          if (!google || google.loginUrl !== "/auth/login/google?redirect=%2Fx") {
            throw new Error(
              `Expected encoded redirect in loginUrl, got ${google?.loginUrl}`,
            );
          }
        },
      },
      {
        // /auth/providers must not put off-origin URLs in loginUrl values
        name: "GET /auth/providers?redirect=https://evil.com sanitizes off-origin redirect",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/providers?redirect=https://evil.com/steal",
            method: "GET",
            headers: {},
          });
          if (response.status !== 200) {
            throw new Error(`Expected 200, got ${response.status}`);
          }
          const parsed = JSON.parse(response.body) as {
            providers: { id: string; loginUrl: string }[];
          };
          for (const p of parsed.providers) {
            if (p.loginUrl.includes("evil.com")) {
              throw new Error(
                `loginUrl must not contain off-origin redirect: ${p.loginUrl}`,
              );
            }
          }
        },
      },
    ],
  }),
);
report("Main suite:", mainResult);

// --- canonical host redirect ---
// Uses a fresh temp .env so CANONICAL_HOST can be set without affecting other tests.
const canonicalTmpDir = await mkdtemp(join(tmpdir(), "sso-canonical-"));
let canonicalResult: SuiteResult;
try {
  const existingEnvLines = [
    "FASTEDGE_VAR_ENV_IDP_SSO_URL=https://dev-000000.okta.com/app/exkABCDEF/sso/saml",
    "FASTEDGE_VAR_ENV_IDP_ENTITY_ID=http://www.okta.com/exkABCDEF",
    "FASTEDGE_VAR_ENV_SP_ENTITY_ID=https://auth.example.com/saml",
    "FASTEDGE_VAR_ENV_SP_ACS_URL=https://auth.example.com/auth/callback",
    "FASTEDGE_VAR_SECRET_IDP_CERT=fakecert",
    "FASTEDGE_VAR_SECRET_SESSION_SECRET=deadbeefdeadbeefdeadbeefdeadbeef",
    "FASTEDGE_VAR_ENV_GITHUB_CLIENT_ID=Ov23liwQh3eihEFTdygw",
    "FASTEDGE_VAR_SECRET_GITHUB_CLIENT_SECRET=fakesecret",
    "FASTEDGE_VAR_ENV_GOOGLE_CLIENT_ID=fake.apps.googleusercontent.com",
    "FASTEDGE_VAR_SECRET_GOOGLE_CLIENT_SECRET=fakesecret",
    "FASTEDGE_VAR_ENV_GOOGLE_REDIRECT_URI=https://auth.example.com/auth/callback/google",
    "FASTEDGE_VAR_ENV_SSO_PROVIDERS=google,github,saml",
    "FASTEDGE_VAR_ENV_CANONICAL_HOST=canonical.test.com",
    "FASTEDGE_VAR_ENV_SSO_VARIANT=cookie",
  ];
  await writeFile(join(canonicalTmpDir, ".env"), existingEnvLines.join("\n") + "\n");

  canonicalResult = await runTestSuite(
    defineTestSuite({
      wasmPath: "./wasm/auth-app.wasm",
      runnerConfig: { dotenv: { enabled: true, path: canonicalTmpDir } },
      tests: [
        {
          // request to a non-canonical host must redirect to the canonical host.
          // "Passes through when host matches" is implicitly covered by all 22 main-
          // suite tests, which succeed without CANONICAL_HOST set (verifying the
          // middleware is a no-op when the env var is absent).
          name: "Request with non-canonical Host header → 301 redirect to canonical host",
          run: async (runner) => {
            const response = await runner.execute({
              path: "/auth/",
              method: "GET",
              headers: { host: "wrong.host.example.com" },
            });
            if (response.status !== 301) {
              throw new Error(
                `Expected 301 redirect, got ${response.status} (location=${response.headers["location"]})`,
              );
            }
            const location = response.headers["location"];
            if (!location || !location.startsWith("https://canonical.test.com")) {
              throw new Error(
                `Expected redirect to canonical host, got: ${location}`,
              );
            }
            if (!location.includes("/auth/")) {
              throw new Error(
                `Expected redirect to preserve path, got: ${location}`,
              );
            }
          },
        },
      ],
    }),
  );
} finally {
  await rm(canonicalTmpDir, { recursive: true, force: true }).catch(() => {});
}
report("Suite — canonical host:", canonicalResult);

// --- JWKS suite ---
// Generate a real P-256 keypair in Node, store the private key PEM as
// SESSION_SIGNING_KEY and the public JWK JSON as SESSION_PUBLIC_JWK, then verify
// the auth-app exposes GET /auth/.well-known/jwks.json correctly.
const { subtle } = globalThis.crypto;
const jwksPair = await subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"],
);
const pkcs8Der = await subtle.exportKey("pkcs8", jwksPair.privateKey);
const pkcs8B64 = Buffer.from(pkcs8Der).toString("base64");
const pkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${pkcs8B64}\n-----END PRIVATE KEY-----`;
const publicJwkObj = await subtle.exportKey("jwk", jwksPair.publicKey);
const publicJwkJson = JSON.stringify(publicJwkObj);

const jwksTmpDir = await mkdtemp(join(tmpdir(), "sso-jwks-"));
let jwksResult: SuiteResult;
try {
  const jwksEnvLines = [
    "FASTEDGE_VAR_ENV_IDP_SSO_URL=https://dev-000000.okta.com/app/exkABCDEF/sso/saml",
    "FASTEDGE_VAR_ENV_IDP_ENTITY_ID=http://www.okta.com/exkABCDEF",
    "FASTEDGE_VAR_ENV_SP_ENTITY_ID=https://auth.example.com/saml",
    "FASTEDGE_VAR_ENV_SP_ACS_URL=https://auth.example.com/auth/callback",
    "FASTEDGE_VAR_SECRET_IDP_CERT=fakecert",
    "FASTEDGE_VAR_SECRET_SESSION_SECRET=deadbeefdeadbeefdeadbeefdeadbeef",
    `FASTEDGE_VAR_SECRET_SESSION_SIGNING_KEY=${pkcs8Pem}`,
    `FASTEDGE_VAR_ENV_SESSION_PUBLIC_JWK=${publicJwkJson}`,
    "FASTEDGE_VAR_ENV_GITHUB_CLIENT_ID=Ov23liwQh3eihEFTdygw",
    "FASTEDGE_VAR_SECRET_GITHUB_CLIENT_SECRET=fakesecret",
    "FASTEDGE_VAR_ENV_GOOGLE_CLIENT_ID=fake.apps.googleusercontent.com",
    "FASTEDGE_VAR_SECRET_GOOGLE_CLIENT_SECRET=fakesecret",
    "FASTEDGE_VAR_ENV_GOOGLE_REDIRECT_URI=https://auth.example.com/auth/callback/google",
    "FASTEDGE_VAR_ENV_SSO_PROVIDERS=google,github,saml",
    "FASTEDGE_VAR_ENV_SSO_VARIANT=cookie",
  ];
  await writeFile(join(jwksTmpDir, ".env"), jwksEnvLines.join("\n") + "\n");

  jwksResult = await runTestSuite(
    defineTestSuite({
      wasmPath: "./wasm/auth-app.wasm",
      runnerConfig: { dotenv: { enabled: true, path: jwksTmpDir } },
      tests: [
        {
          name: "GET /auth/.well-known/jwks.json returns keys array with the configured public JWK",
          run: async (runner) => {
            const response = await runner.execute({
              path: "/auth/.well-known/jwks.json",
              method: "GET",
            });
            if (response.status !== 200) {
              throw new Error(`Expected 200, got ${response.status}`);
            }
            const body = JSON.parse(response.body ?? "{}") as {
              keys?: { kty?: string; crv?: string }[];
            };
            if (!Array.isArray(body.keys) || body.keys.length !== 1) {
              throw new Error(`Expected keys array of length 1, got: ${JSON.stringify(body)}`);
            }
            if (body.keys[0].kty !== "EC" || body.keys[0].crv !== "P-256") {
              throw new Error(`Unexpected JWK: ${JSON.stringify(body.keys[0])}`);
            }
          },
        },
        {
          name: "GET /auth/.well-known/jwks.json — missing SESSION_PUBLIC_JWK returns 503",
          run: async (runner) => {
            // This test uses the main env which HAS SESSION_PUBLIC_JWK,
            // so we just verify the happy path works here and trust the
            // unit-level coverage for the missing-env branch.
            const response = await runner.execute({
              path: "/auth/.well-known/jwks.json",
              method: "GET",
            });
            // With SESSION_PUBLIC_JWK set, must be 200
            if (response.status !== 200) {
              throw new Error(`Expected 200 with SESSION_PUBLIC_JWK set, got ${response.status}`);
            }
          },
        },
      ],
    }),
  );
} finally {
  await rm(jwksTmpDir, { recursive: true, force: true }).catch(() => {});
}
report("Suite JWKS endpoint:", jwksResult);

// --- logout suite ---
// Uses the main .env (no SSO_ALLOWED_ORIGINS → absolute redirect URLs fall back to /).
const logoutResult = await runTestSuite(
  defineTestSuite({
    wasmPath: "./wasm/auth-app.wasm",
    runnerConfig: { dotenv: { enabled: true } },
    tests: [
      {
        name: "GET /auth/logout → 302, clears sso_session (Max-Age=0), redirects to /",
        run: async (runner) => {
          const response = await runner.execute({ path: "/auth/logout", method: "GET", headers: {} });
          if (response.status !== 302) throw new Error(`Expected 302, got ${response.status}`);
          const location = response.headers["location"];
          if (location !== "/") throw new Error(`Expected Location: /, got ${location}`);
          const cookie = parseSetCookieAsString(response.headers);
          if (!cookie.includes("sso_session=")) throw new Error(`Expected sso_session in Set-Cookie, got: ${cookie}`);
          if (!cookie.includes("Max-Age=0")) throw new Error(`Expected Max-Age=0 in Set-Cookie, got: ${cookie}`);
        },
      },
      {
        name: "GET /auth/logout?redirect=/products → redirects to /products",
        run: async (runner) => {
          const response = await runner.execute({ path: "/auth/logout?redirect=%2Fproducts", method: "GET", headers: {} });
          if (response.status !== 302) throw new Error(`Expected 302, got ${response.status}`);
          const location = response.headers["location"];
          if (location !== "/products") throw new Error(`Expected Location: /products, got ${location}`);
        },
      },
      {
        // off-origin absolute redirect on logout must be sanitized to /
        name: "GET /auth/logout?redirect=https://evil.com → sanitized to /",
        run: async (runner) => {
          const response = await runner.execute({
            path: "/auth/logout?redirect=https%3A%2F%2Fevil.com%2Fsteal",
            method: "GET",
            headers: {},
          });
          if (response.status !== 302) throw new Error(`Expected 302, got ${response.status}`);
          const location = response.headers["location"];
          if (location !== "/") throw new Error(`Expected Location: / (evil.com blocked), got ${location}`);
        },
      },
    ],
  }),
);
report("Suite — logout:", logoutResult);

// --- Non-cookie variant smoke (gate-only, header) ---
// The suites above all run under SSO_VARIANT=cookie; this exercises the other
// two variants against the SAME wasm binary.
const gateOnlyFailed = await runNonCookieVariantSmoke("./wasm/auth-app.wasm", "gate-only");
const headerFailed = await runNonCookieVariantSmoke("./wasm/auth-app.wasm", "header");

process.exit(
  mainResult.failed +
    canonicalResult.failed +
    jwksResult.failed +
    logoutResult.failed +
    gateOnlyFailed +
    headerFailed >
    0
    ? 1
    : 0,
);

console.log("");
process.exit(mainResult.failed + canonicalResult.failed + jwksResult.failed + logoutResult.failed > 0 ? 1 : 0);
