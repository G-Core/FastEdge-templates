/**
 * Shared gate-behaviour acceptance suite for cdn-filter templates.
 *
 * cookie and gate-only use identical filter logic; this module lets both
 * (and the header variant) run the same gate assertions without duplication.
 * Import this from each template's filter.test.ts.
 */
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignJWT } from "jose";
import { exportJWK, importPKCS8 } from "jose";
import {
  defineTestSuite,
  runTestSuite,
  runFlow,
} from "@gcoredev/fastedge-test/test";

export const SESSION_SECRET =
  "test-session-secret-abcdefghijklmnopqrstuvwxyz0123456789";
export const CDN_URL = "https://cdn.example.com/resource?foo=bar";
export const EXPECTED_ENCODED_TARGET = encodeURIComponent(CDN_URL);
export const LOGIN_PAGE_URL = "https://cdn.example.com/auth/";
export const CUSTOM_COOKIE = "my_session";
export const CONFIGURED_PREFIX = `${LOGIN_PAGE_URL}?redirect=`;
export const DEFAULT_PREFIX = "/auth/?redirect=";
export const DEFAULT_COOKIE = "sso_session";
// Audience is required and fail-closed (the filter refuses every session when
// SSO_AUDIENCE is unset), so every suite that expects a token to be ACCEPTED
// configures this audience and mints tokens carrying it.
export const FILTER_AUDIENCE = "https://app.example.com";
export const AUDIENCE_ENV = `FASTEDGE_VAR_ENV_SSO_AUDIENCE=${FILTER_AUDIENCE}`;

function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** The key types jose's SignJWT.sign accepts — Uint8Array for HS256, a
 * CryptoKey for ES256. Derived from jose so it stays in sync with the version. */
type JwtSigningKey = Parameters<InstanceType<typeof SignJWT>["sign"]>[0];

/**
 * Single source of truth for minting test JWTs: assemble iat/exp + payload and
 * sign with the given key/alg. HS256 (shared secret) and ES256 (P-256 key)
 * differ only in those two arguments, so every minter — module helpers and
 * both signing tiers — funnels through here rather than copying the assembly.
 */
async function signJwt(
  key: JwtSigningKey,
  alg: "HS256" | "ES256",
  ttlSeconds: number,
  payload: Record<string, unknown>,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT(payload)
    .setProtectedHeader({ alg, typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(key);
}

export function makeJwt(ttlSeconds: number, sub = "user-123"): Promise<string> {
  return signJwt(bytes(SESSION_SECRET), "HS256", ttlSeconds, {
    sub,
    aud: FILTER_AUDIENCE,
  });
}

export function makeJwtWithClaims(
  ttlSeconds: number,
  claims: Record<string, unknown>,
  sub = "user-123",
): Promise<string> {
  return signJwt(bytes(SESSION_SECRET), "HS256", ttlSeconds, {
    sub,
    aud: FILTER_AUDIENCE,
    ...claims,
  });
}

export function tamperSignature(jwt: string): string {
  const parts = jwt.split(".");
  const sig = parts[2];
  const mid = Math.floor(sig.length / 2);
  const flipped =
    sig.slice(0, mid) + (sig[mid] === "A" ? "B" : "A") + sig.slice(mid + 1);
  return [parts[0], parts[1], flipped].join(".");
}

export interface SuiteResult {
  passed: number;
  total: number;
  failed: number;
  durationMs: number;
  results: { name: string; passed: boolean; error?: string; durationMs: number }[];
}

export function headerValue(v: string | string[] | undefined): string {
  return Array.isArray(v) ? (v[0] ?? "") : (v ?? "");
}

export function report(label: string, result: SuiteResult): void {
  console.log(`\n${label}`);
  for (const r of result.results) {
    const mark = r.passed ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
    console.log(`  ${mark} ${r.name} (${r.durationMs.toFixed(1)}ms)`);
    if (!r.passed && r.error) console.log(`      ${r.error}`);
  }
  console.log(
    `  ${result.passed}/${result.total} passed in ${result.durationMs.toFixed(1)}ms`,
  );
}

/**
 * A signing tier describes how a variant's filter verifies tokens: the .env
 * lines that supply its verification key, and a factory that mints a token the
 * filter will accept. Gate behaviour (cookie naming, redirect formatting,
 * /auth bypass, expired/tampered/malformed) is alg-agnostic, so the same gate
 * suite runs against any tier — HS256 for gate-only/header, ES256 for cookie
 * (which is now ES256-only).
 */
export interface GateSigningTier {
  keyEnv: string[];
  /** Mint a token signed by this tier's key. Optional `claims` carry extra
   * registered claims (e.g. aud/iss) for the enforcement suite. */
  makeJwt: (
    ttlSeconds: number,
    sub?: string,
    claims?: Record<string, unknown>,
  ) => Promise<string>;
}

/** Default HS256 tier — gate-only and header variants verify HS256 tokens. */
function hs256Tier(): GateSigningTier {
  return {
    keyEnv: [`FASTEDGE_VAR_SECRET_SESSION_SECRET=${SESSION_SECRET}`],
    makeJwt: (ttl, sub = "user-123", claims = {}) =>
      signJwt(bytes(SESSION_SECRET), "HS256", ttl, { sub, ...claims }),
  };
}

/**
 * ES256 tier for the cookie variant: generates a P-256 keypair, exposes the
 * public JWK as filter env, and mints ES256 tokens with the private key.
 */
export async function makeEs256Tier(): Promise<GateSigningTier> {
  const { subtle } = globalThis.crypto;
  const pair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const pkcs8Der = await subtle.exportKey("pkcs8", pair.privateKey);
  const pkcs8B64 = Buffer.from(pkcs8Der).toString("base64");
  const pkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${pkcs8B64}\n-----END PRIVATE KEY-----`;
  const publicJwkJson = JSON.stringify(
    await subtle.exportKey("jwk", pair.publicKey),
  );
  const privateKey = await importPKCS8(pkcs8Pem, "ES256");

  return {
    keyEnv: [`FASTEDGE_VAR_ENV_SESSION_PUBLIC_JWK=${publicJwkJson}`],
    makeJwt: (ttlSeconds, sub = "user-es256", claims = {}) =>
      signJwt(privateKey, "ES256", ttlSeconds, { sub, ...claims }),
  };
}

/**
 * Runs the two gate-behaviour suites (A: runtime config, B: defaults).
 * Returns { totalFailed, tempDirs } — callers must rm -rf the dirs when done.
 */
export async function runGateSuites(
  wasmPath: string,
  tier: GateSigningTier = hs256Tier(),
): Promise<{ totalFailed: number; tempDirs: string[] }> {
  const validJwt = await tier.makeJwt(3600, "user-123", { aud: FILTER_AUDIENCE });
  const expiredJwt = await tier.makeJwt(-3600, "user-123", { aud: FILTER_AUDIENCE });
  const tamperedJwt = tamperSignature(validJwt);
  // nbf an hour out, exp two hours out → only the nbf (not-yet-valid) check can reject it.
  const nowSec = Math.floor(Date.now() / 1000);
  const notYetValidJwt = await tier.makeJwt(7200, "user-123", {
    aud: FILTER_AUDIENCE,
    nbf: nowSec + 3600,
  });

  const cfgDir = await mkdtemp(join(tmpdir(), "sso-filter-cfg-"));
  await writeFile(
    join(cfgDir, ".env"),
    [
      ...tier.keyEnv,
      AUDIENCE_ENV,
      `FASTEDGE_VAR_ENV_LOGIN_PAGE_URL=${LOGIN_PAGE_URL}`,
      `FASTEDGE_VAR_ENV_SESSION_COOKIE=${CUSTOM_COOKIE}`,
      "",
    ].join("\n"),
  );

  const defDir = await mkdtemp(join(tmpdir(), "sso-filter-def-"));
  await writeFile(join(defDir, ".env"), [...tier.keyEnv, AUDIENCE_ENV, ""].join("\n"));

  let totalFailed = 0;

  const configured = (await runTestSuite(
    defineTestSuite({
      wasmPath,
      runnerConfig: { dotenv: { enabled: true, path: cfgDir } },
      tests: [
        {
          name: "valid session in custom cookie name → Continue",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: "built-in",
              requestHeaders: { cookie: `${CUSTOM_COOKIE}=${validJwt}` },
            });
            if (r.hookResults.onRequestHeaders.returnCode !== 0) {
              throw new Error(
                `expected Continue (returnCode=0), got ${r.hookResults.onRequestHeaders.returnCode}`,
              );
            }
            if (r.finalResponse.status === 302) {
              throw new Error(
                `expected no redirect, got 302 to ${r.finalResponse.headers["location"]}`,
              );
            }
          },
        },
        {
          name: "default cookie name is NOT honored when SESSION_COOKIE overrides it → 302",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${DEFAULT_COOKIE}=${validJwt}` },
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
          },
        },
        {
          name: "no cookie → 302 to configured LOGIN_PAGE_URL with encoded original URL",
          run: async (runner) => {
            const r = await runFlow(runner, { url: CDN_URL, requestHeaders: {} });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
            const loc = headerValue(r.finalResponse.headers["location"]);
            const expected = CONFIGURED_PREFIX + EXPECTED_ENCODED_TARGET;
            if (loc !== expected) {
              throw new Error(`expected Location='${expected}', got '${loc}'`);
            }
          },
        },
        {
          name: "/auth/** is bypassed (Continue) even with no cookie",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: "https://cdn.example.com/auth/login/github?redirect=%2Ffoo",
              requestHeaders: {},
            });
            if (r.hookResults.onRequestHeaders.returnCode !== 0) {
              throw new Error(
                `expected Continue for /auth/** bypass, got returnCode=${r.hookResults.onRequestHeaders.returnCode}`,
              );
            }
            if (r.finalResponse.status === 302) {
              throw new Error(
                `expected /auth/** to pass through, got 302 to ${r.finalResponse.headers["location"]}`,
              );
            }
          },
        },
        {
          name: "expired JWT → 302",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${CUSTOM_COOKIE}=${expiredJwt}` },
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
            const loc = headerValue(r.finalResponse.headers["location"]);
            if (!loc || !loc.startsWith(CONFIGURED_PREFIX)) {
              throw new Error(`expected redirect to chooser, got '${loc}'`);
            }
          },
        },
        {
          name: "tampered JWT signature → 302",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${CUSTOM_COOKIE}=${tamperedJwt}` },
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
          },
        },
        {
          name: "not-yet-valid JWT (nbf in future) → 302",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${CUSTOM_COOKIE}=${notYetValidJwt}` },
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
          },
        },
        {
          name: "malformed token (no dots) → 302",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${CUSTOM_COOKIE}=not-a-jwt` },
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
          },
        },
      ],
    }),
  )) as SuiteResult;
  report("Suite A — runtime config (LOGIN_PAGE_URL + SESSION_COOKIE):", configured);
  totalFailed += configured.failed;

  const defaults = (await runTestSuite(
    defineTestSuite({
      wasmPath,
      runnerConfig: { dotenv: { enabled: true, path: defDir } },
      tests: [
        {
          name: "valid session in default sso_session cookie → Continue",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: "built-in",
              requestHeaders: { cookie: `${DEFAULT_COOKIE}=${validJwt}` },
            });
            if (r.hookResults.onRequestHeaders.returnCode !== 0) {
              throw new Error(
                `expected Continue (returnCode=0), got ${r.hookResults.onRequestHeaders.returnCode}`,
              );
            }
          },
        },
        {
          name: "no cookie → 302 to default relative /auth/ chooser",
          run: async (runner) => {
            const r = await runFlow(runner, { url: CDN_URL, requestHeaders: {} });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
            const loc = headerValue(r.finalResponse.headers["location"]);
            const expected = DEFAULT_PREFIX + EXPECTED_ENCODED_TARGET;
            if (loc !== expected) {
              throw new Error(`expected Location='${expected}', got '${loc}'`);
            }
          },
        },
      ],
    }),
  )) as SuiteResult;
  report("Suite B — defaults:", defaults);
  totalFailed += defaults.failed;

  return { totalFailed, tempDirs: [cfgDir, defDir] };
}

/**
 * Runs the session-cookie stripping suite (gate-only and header variants).
 * The wasmPath must be a binary compiled with the `strip-session-cookie` feature.
 * Returns { totalFailed, tempDirs } — callers must rm -rf the dirs when done.
 */
export async function runStripSuites(
  wasmPath: string,
): Promise<{ totalFailed: number; tempDirs: string[] }> {
  const validJwt = await makeJwt(3600);

  const stripDir = await mkdtemp(join(tmpdir(), "sso-filter-strip-"));
  await writeFile(
    join(stripDir, ".env"),
    [
      `FASTEDGE_VAR_SECRET_SESSION_SECRET=${SESSION_SECRET}`,
      AUDIENCE_ENV,
      `FASTEDGE_VAR_ENV_SESSION_COOKIE=${DEFAULT_COOKIE}`,
      "",
    ].join("\n"),
  );

  let totalFailed = 0;

  const stripSuite = (await runTestSuite(
    defineTestSuite({
      wasmPath,
      runnerConfig: { dotenv: { enabled: true, path: stripDir } },
      tests: [
        {
          name: "strip: session cookie removed from forwarded request",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: {
                cookie: `${DEFAULT_COOKIE}=${validJwt}; other_cookie=keep-me`,
              },
            });
            if (r.hookResults.onRequestHeaders.returnCode !== 0) {
              throw new Error(
                `expected Continue, got returnCode=${r.hookResults.onRequestHeaders.returnCode}`,
              );
            }
            const outHeaders =
              r.hookResults.onRequestHeaders.output.request.headers;
            const cookieOut = headerValue(
              outHeaders["cookie"] as string | string[] | undefined,
            );
            if (cookieOut.includes(DEFAULT_COOKIE)) {
              throw new Error(
                `session cookie still present in forwarded request: '${cookieOut}'`,
              );
            }
            if (!cookieOut.includes("other_cookie=keep-me")) {
              throw new Error(
                `other cookies were stripped unexpectedly: '${cookieOut}'`,
              );
            }
          },
        },
        {
          name: "strip: sole session cookie removes Cookie header entirely",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${DEFAULT_COOKIE}=${validJwt}` },
            });
            if (r.hookResults.onRequestHeaders.returnCode !== 0) {
              throw new Error(
                `expected Continue, got returnCode=${r.hookResults.onRequestHeaders.returnCode}`,
              );
            }
            const outHeaders =
              r.hookResults.onRequestHeaders.output.request.headers;
            const cookieOut = outHeaders["cookie"];
            if (cookieOut !== undefined && cookieOut !== "") {
              throw new Error(
                `expected Cookie header to be absent, got: '${cookieOut}'`,
              );
            }
          },
        },
      ],
    }),
  )) as SuiteResult;
  report("Suite — cookie stripping:", stripSuite);
  totalFailed += stripSuite.failed;

  return { totalFailed, tempDirs: [stripDir] };
}

/**
 * Runs the ES256 signing-tier acceptance suite.
 * Returns { totalFailed, tempDirs } — callers must rm -rf the dirs when done.
 */
export async function runEs256Suites(
  wasmPath: string,
): Promise<{ totalFailed: number; tempDirs: string[] }> {
  // Generate a real P-256 keypair in Node for the test
  const { subtle } = globalThis.crypto;
  const pair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  // Export private key as PKCS8 PEM (for the auth-app — not needed by filter, but mirrors reality)
  const pkcs8Der = await subtle.exportKey("pkcs8", pair.privateKey);
  const pkcs8B64 = Buffer.from(pkcs8Der).toString("base64");
  const pkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${pkcs8B64}\n-----END PRIVATE KEY-----`;

  // Export public key as JWK JSON — stored as SESSION_PUBLIC_KEY in the filter env
  const publicJwkObj = await subtle.exportKey("jwk", pair.publicKey);
  const publicJwkJson = JSON.stringify(publicJwkObj);

  // Sign a JWT with ES256 using jose
  const privateKey = await importPKCS8(pkcs8Pem, "ES256");

  async function makeEs256Jwt(ttlSeconds: number, sub = "user-es256"): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return await new SignJWT({ sub, aud: FILTER_AUDIENCE })
      .setProtectedHeader({ alg: "ES256", typ: "JWT" })
      .setIssuedAt(now)
      .setExpirationTime(now + ttlSeconds)
      .sign(privateKey);
  }

  const validJwt = await makeEs256Jwt(3600);
  const expiredJwt = await makeEs256Jwt(-3600);

  // Generate a second keypair to produce a "wrong key" JWT
  const wrongPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const wrongPkcs8Der = await subtle.exportKey("pkcs8", wrongPair.privateKey);
  const wrongPkcs8B64 = Buffer.from(wrongPkcs8Der).toString("base64");
  const wrongPkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${wrongPkcs8B64}\n-----END PRIVATE KEY-----`;
  const wrongPrivateKey = await importPKCS8(wrongPkcs8Pem, "ES256");
  const wrongKeyJwt = await new SignJWT({ sub: "user-wrong" })
    .setProtectedHeader({ alg: "ES256", typ: "JWT" })
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
    .sign(wrongPrivateKey);

  const es256Dir = await mkdtemp(join(tmpdir(), "sso-filter-es256-"));
  await writeFile(
    join(es256Dir, ".env"),
    [
      `FASTEDGE_VAR_ENV_SESSION_PUBLIC_JWK=${publicJwkJson}`,
      AUDIENCE_ENV,
      `FASTEDGE_VAR_ENV_SESSION_COOKIE=${DEFAULT_COOKIE}`,
      "",
    ].join("\n"),
  );

  let totalFailed = 0;

  const es256Suite = (await runTestSuite(
    defineTestSuite({
      wasmPath,
      runnerConfig: { dotenv: { enabled: true, path: es256Dir } },
      tests: [
        {
          name: "ES256: valid token → Continue",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${DEFAULT_COOKIE}=${validJwt}` },
            });
            if (r.hookResults.onRequestHeaders.returnCode !== 0) {
              throw new Error(
                `expected Continue (returnCode=0), got ${r.hookResults.onRequestHeaders.returnCode}`,
              );
            }
            if (r.finalResponse.status === 302) {
              throw new Error(
                `expected no redirect, got 302 to ${r.finalResponse.headers["location"]}`,
              );
            }
          },
        },
        {
          name: "ES256: expired token → 302",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${DEFAULT_COOKIE}=${expiredJwt}` },
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
          },
        },
        {
          name: "ES256: token signed with wrong key → 302",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${DEFAULT_COOKIE}=${wrongKeyJwt}` },
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
          },
        },
        {
          name: "ES256: tampered signature → 302",
          run: async (runner) => {
            const tampered = tamperSignature(validJwt);
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${DEFAULT_COOKIE}=${tampered}` },
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
          },
        },
      ],
    }),
  )) as SuiteResult;
  report("Suite C — ES256 signing tier:", es256Suite);
  totalFailed += es256Suite.failed;

  return { totalFailed, tempDirs: [es256Dir] };
}

/**
 * Runs the aud/iss enforcement suite. When SSO_AUDIENCE / SSO_ISSUER are
 * configured, the filter must reject an otherwise-valid token whose `aud`/`iss`
 * don't match — this is what stops a token minted for one protected resource
 * from being replayed against another that shares the same signing key.
 *
 * The check lives in shared filter logic (runs after signature+exp verification,
 * independent of alg), so it is exercised against whichever signing tier the
 * caller passes — HS256 for gate-only/header, ES256 for cookie.
 * Returns { totalFailed, tempDirs } — callers must rm -rf the dirs when done.
 */
export async function runAudIssSuites(
  wasmPath: string,
  tier: GateSigningTier = hs256Tier(),
): Promise<{ totalFailed: number; tempDirs: string[] }> {
  const AUDIENCE = "https://app.example.com";
  const OTHER_AUDIENCE = "https://other.example.com";
  const ISSUER = "https://sso.example.com";
  const OTHER_ISSUER = "https://evil-idp.example.com";

  const match = await tier.makeJwt(3600, "user-123", { aud: AUDIENCE, iss: ISSUER });
  const wrongAud = await tier.makeJwt(3600, "user-123", { aud: OTHER_AUDIENCE, iss: ISSUER });
  const wrongIss = await tier.makeJwt(3600, "user-123", { aud: AUDIENCE, iss: OTHER_ISSUER });
  // aud may be an array per RFC 7519 — a match is membership, not equality.
  const arrayAud = await tier.makeJwt(3600, "user-123", {
    aud: [OTHER_AUDIENCE, AUDIENCE],
    iss: ISSUER,
  });
  // Token carries no aud at all while the filter requires one → reject.
  const noAud = await tier.makeJwt(3600, "user-123", { iss: ISSUER });

  const dir = await mkdtemp(join(tmpdir(), "sso-filter-audiss-"));
  await writeFile(
    join(dir, ".env"),
    [
      ...tier.keyEnv,
      `FASTEDGE_VAR_ENV_SESSION_COOKIE=${DEFAULT_COOKIE}`,
      `FASTEDGE_VAR_ENV_SSO_AUDIENCE=${AUDIENCE}`,
      `FASTEDGE_VAR_ENV_SSO_ISSUER=${ISSUER}`,
      "",
    ].join("\n"),
  );

  const cookie = (jwt: string) => ({ cookie: `${DEFAULT_COOKIE}=${jwt}` });

  let totalFailed = 0;
  const suite = (await runTestSuite(
    defineTestSuite({
      wasmPath,
      runnerConfig: { dotenv: { enabled: true, path: dir } },
      tests: [
        {
          name: "matching aud + iss → Continue",
          run: async (runner) => {
            const r = await runFlow(runner, { url: CDN_URL, requestHeaders: cookie(match) });
            if (r.hookResults.onRequestHeaders.returnCode !== 0) {
              throw new Error(
                `expected Continue (returnCode=0), got ${r.hookResults.onRequestHeaders.returnCode}`,
              );
            }
            if (r.finalResponse.status === 302) {
              throw new Error(
                `expected no redirect, got 302 to ${r.finalResponse.headers["location"]}`,
              );
            }
          },
        },
        {
          name: "aud mismatch → 302 (cross-resource replay blocked)",
          run: async (runner) => {
            const r = await runFlow(runner, { url: CDN_URL, requestHeaders: cookie(wrongAud) });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
          },
        },
        {
          name: "iss mismatch → 302",
          run: async (runner) => {
            const r = await runFlow(runner, { url: CDN_URL, requestHeaders: cookie(wrongIss) });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
          },
        },
        {
          name: "aud array containing configured value → Continue",
          run: async (runner) => {
            const r = await runFlow(runner, { url: CDN_URL, requestHeaders: cookie(arrayAud) });
            if (r.hookResults.onRequestHeaders.returnCode !== 0) {
              throw new Error(
                `expected Continue (returnCode=0), got ${r.hookResults.onRequestHeaders.returnCode}`,
              );
            }
          },
        },
        {
          name: "no aud claim while SSO_AUDIENCE configured → 302",
          run: async (runner) => {
            const r = await runFlow(runner, { url: CDN_URL, requestHeaders: cookie(noAud) });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
          },
        },
      ],
    }),
  )) as SuiteResult;
  report("Suite — aud/iss enforcement:", suite);
  totalFailed += suite.failed;

  return { totalFailed, tempDirs: [dir] };
}

/**
 * Runs the custom AUTH_PREFIX suite: verifies that the filter bypasses paths
 * under the configured prefix and that the old default /auth is no longer
 * bypassed, and that LOGIN_PAGE_URL derives from AUTH_PREFIX when unset.
 * Returns { totalFailed, tempDirs } — callers must rm -rf the dirs when done.
 */
export async function runCustomPrefixSuites(
  wasmPath: string,
  tier: GateSigningTier = hs256Tier(),
): Promise<{ totalFailed: number; tempDirs: string[] }> {
  const CUSTOM_PREFIX = "/sso-auth";
  const validJwt = await tier.makeJwt(3600, "user-123", { aud: FILTER_AUDIENCE });

  const prefixDir = await mkdtemp(join(tmpdir(), "sso-filter-prefix-"));
  await writeFile(
    join(prefixDir, ".env"),
    [
      ...tier.keyEnv,
      AUDIENCE_ENV,
      `FASTEDGE_VAR_ENV_AUTH_PREFIX=${CUSTOM_PREFIX}`,
      "",
    ].join("\n"),
  );

  let totalFailed = 0;

  const suite = (await runTestSuite(
    defineTestSuite({
      wasmPath,
      runnerConfig: { dotenv: { enabled: true, path: prefixDir } },
      tests: [
        {
          name: "custom AUTH_PREFIX path is bypassed (Continue) with no cookie",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: `https://cdn.example.com${CUSTOM_PREFIX}/callback`,
              requestHeaders: {},
            });
            if (r.hookResults.onRequestHeaders.returnCode !== 0) {
              throw new Error(
                `expected Continue for ${CUSTOM_PREFIX}/** bypass, got returnCode=${r.hookResults.onRequestHeaders.returnCode}`,
              );
            }
            if (r.finalResponse.status === 302) {
              throw new Error(
                `expected ${CUSTOM_PREFIX}/** to pass through, got 302 to ${r.finalResponse.headers["location"]}`,
              );
            }
          },
        },
        {
          name: "default /auth/** is NOT bypassed when AUTH_PREFIX overrides it → 302",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: "https://cdn.example.com/auth/callback",
              requestHeaders: {},
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(
                `expected 302 for /auth/** when AUTH_PREFIX=${CUSTOM_PREFIX}, got ${r.finalResponse.status}`,
              );
            }
          },
        },
        {
          name: "LOGIN_PAGE_URL defaults to AUTH_PREFIX/ when unset",
          run: async (runner) => {
            const r = await runFlow(runner, { url: CDN_URL, requestHeaders: {} });
            if (r.finalResponse.status !== 302) {
              throw new Error(`expected 302, got ${r.finalResponse.status}`);
            }
            const loc = headerValue(r.finalResponse.headers["location"]);
            const expected = `${CUSTOM_PREFIX}/?redirect=${EXPECTED_ENCODED_TARGET}`;
            if (loc !== expected) {
              throw new Error(`expected Location='${expected}', got '${loc}'`);
            }
          },
        },
        {
          name: "valid session token still accepted with custom AUTH_PREFIX",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${DEFAULT_COOKIE}=${validJwt}` },
            });
            if (r.hookResults.onRequestHeaders.returnCode !== 0) {
              throw new Error(
                `expected Continue, got returnCode=${r.hookResults.onRequestHeaders.returnCode}`,
              );
            }
            if (r.finalResponse.status === 302) {
              throw new Error(
                `expected no redirect, got 302 to ${r.finalResponse.headers["location"]}`,
              );
            }
          },
        },
      ],
    }),
  )) as SuiteResult;
  report(`Suite — custom AUTH_PREFIX (${CUSTOM_PREFIX}):`, suite);
  totalFailed += suite.failed;

  return { totalFailed, tempDirs: [prefixDir] };
}

/**
 * Fail-closed audience: a filter with NO SSO_AUDIENCE configured must refuse
 * every session — even a correctly-signed, unexpired, aud-bearing token — rather
 * than trust a token it can't scope to itself. Runs against any signing tier.
 * Returns { totalFailed, tempDirs } — callers must rm -rf the dirs when done.
 */
export async function runFailClosedSuites(
  wasmPath: string,
  tier: GateSigningTier = hs256Tier(),
): Promise<{ totalFailed: number; tempDirs: string[] }> {
  const validJwt = await tier.makeJwt(3600, "user-123", { aud: FILTER_AUDIENCE });

  const dir = await mkdtemp(join(tmpdir(), "sso-filter-failclosed-"));
  // Deliberately omit SSO_AUDIENCE — key + cookie only.
  await writeFile(
    join(dir, ".env"),
    [...tier.keyEnv, `FASTEDGE_VAR_ENV_SESSION_COOKIE=${DEFAULT_COOKIE}`, ""].join("\n"),
  );

  let totalFailed = 0;
  const suite = (await runTestSuite(
    defineTestSuite({
      wasmPath,
      runnerConfig: { dotenv: { enabled: true, path: dir } },
      tests: [
        {
          name: "valid token but SSO_AUDIENCE unset → 302 (fail-closed)",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${DEFAULT_COOKIE}=${validJwt}` },
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(
                `expected 302 (filter must refuse sessions with no SSO_AUDIENCE), got ${r.finalResponse.status}`,
              );
            }
          },
        },
      ],
    }),
  )) as SuiteResult;
  report("Suite — fail-closed audience:", suite);
  totalFailed += suite.failed;

  return { totalFailed, tempDirs: [dir] };
}
