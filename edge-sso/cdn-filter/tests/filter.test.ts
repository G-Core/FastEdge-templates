import { rm, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  runGateSuites,
  runStripSuites,
  runEs256Suites,
  runAudIssSuites,
  runFailClosedSuites,
  runVariantFailClosedSuite,
  runCustomPrefixSuites,
  hs256Tier,
  makeEs256Tier,
  makeJwt,
  makeJwtWithClaims,
  SESSION_SECRET,
  DEFAULT_COOKIE,
  CUSTOM_COOKIE,
  CDN_URL,
  FILTER_AUDIENCE,
  AUDIENCE_ENV,
  headerValue,
  report,
  type SuiteResult,
} from "./filter-suite.js";
import { defineTestSuite, runTestSuite, runFlow } from "@gcoredev/fastedge-test/test";

// One wasm binary now serves all three variants — SSO_VARIANT picks the
// behavior at runtime. Every suite below runs against this same binary.
const WASM = "./wasm/sso_guard.wasm";

const gateOnlyTier = hs256Tier("gate-only");
const headerTier = hs256Tier("header");
const es256Tier = await makeEs256Tier();

let totalFailed = 0;
const allTempDirs: string[] = [];

async function track(p: Promise<{ totalFailed: number; tempDirs: string[] }>) {
  const r = await p;
  totalFailed += r.totalFailed;
  allTempDirs.push(...r.tempDirs);
}

// --- Gate behaviour (cookie naming, redirects, /auth bypass, expiry/tamper) —
// alg-agnostic, run once per variant/tier. ---
await track(runGateSuites(WASM, gateOnlyTier));
await track(runGateSuites(WASM, headerTier));
await track(runGateSuites(WASM, es256Tier));

// --- ES256 signing tier acceptance (cookie only) ---
await track(runEs256Suites(WASM));

// --- Cookie stripping (gate-only + header strip; cookie must NOT) ---
await track(runStripSuites(WASM, "gate-only"));
await track(runStripSuites(WASM, "header"));

// --- aud/iss enforcement, once per variant/tier ---
await track(runAudIssSuites(WASM, gateOnlyTier));
await track(runAudIssSuites(WASM, headerTier));
await track(runAudIssSuites(WASM, es256Tier));

// --- Custom AUTH_PREFIX, once per variant/tier ---
await track(runCustomPrefixSuites(WASM, gateOnlyTier));
await track(runCustomPrefixSuites(WASM, headerTier));
await track(runCustomPrefixSuites(WASM, es256Tier));

// --- Fail-closed audience, once per variant/tier ---
await track(runFailClosedSuites(WASM, gateOnlyTier));
await track(runFailClosedSuites(WASM, headerTier));
await track(runFailClosedSuites(WASM, es256Tier));

// --- Fail-closed SSO_VARIANT (new behavior introduced by the merge) ---
await track(runVariantFailClosedSuite(WASM));

// --- Alg pinning: SSO_VARIANT=cookie must stay ES256-only even when
// SESSION_SECRET is also present in the environment — cross-contamination is
// plausible now that a single binary/portal template serves all variants. ---
{
  const hs256Token = await makeJwt(3600);
  const contaminatedDir = await mkdtemp(join(tmpdir(), "cookie-algpin-"));
  await writeFile(
    join(contaminatedDir, ".env"),
    [
      ...es256Tier.keyEnv,
      `FASTEDGE_VAR_SECRET_SESSION_SECRET=${SESSION_SECRET}`,
      AUDIENCE_ENV,
      `FASTEDGE_VAR_ENV_SESSION_COOKIE=${DEFAULT_COOKIE}`,
      "",
    ].join("\n"),
  );
  try {
    const algPin = (await runTestSuite(
      defineTestSuite({
        wasmPath: WASM,
        runnerConfig: { dotenv: { enabled: true, path: contaminatedDir } },
        tests: [
          {
            name: "SSO_VARIANT=cookie rejects a valid HS256 token even with SESSION_SECRET present → 302",
            run: async (runner) => {
              const r = await runFlow(runner, {
                url: CDN_URL,
                requestHeaders: { cookie: `${DEFAULT_COOKIE}=${hs256Token}` },
              });
              if (r.finalResponse.status !== 302) {
                throw new Error(
                  `expected 302 (HS256 rejected under SSO_VARIANT=cookie), got ${r.finalResponse.status}`,
                );
              }
            },
          },
          {
            name: "SSO_VARIANT=cookie still accepts a valid ES256 token alongside stray secret → Continue",
            run: async (runner) => {
              const es256Token = await es256Tier.makeJwt(3600, undefined, {
                aud: FILTER_AUDIENCE,
              });
              const r = await runFlow(runner, {
                url: CDN_URL,
                requestHeaders: { cookie: `${DEFAULT_COOKIE}=${es256Token}` },
              });
              if (r.hookResults.onRequestHeaders.returnCode !== 0) {
                throw new Error(
                  `expected Continue, got returnCode=${r.hookResults.onRequestHeaders.returnCode}`,
                );
              }
            },
          },
        ],
      }),
    )) as SuiteResult;
    report("Suite — alg pinning (cookie, ES256-only):", algPin);
    totalFailed += algPin.failed;
  } finally {
    await rm(contaminatedDir, { recursive: true, force: true }).catch(() => {});
  }
}

// --- Header variant: identity header injection ---
{
  const TEST_SUB = "user-123";
  const validJwt = await makeJwt(3600, TEST_SUB);
  const expiredJwt = await makeJwt(-3600);

  const cfgDir = await mkdtemp(join(tmpdir(), "header-inject-"));
  await writeFile(
    join(cfgDir, ".env"),
    [
      `FASTEDGE_VAR_SECRET_SESSION_SECRET=${SESSION_SECRET}`,
      AUDIENCE_ENV,
      `FASTEDGE_VAR_ENV_SESSION_COOKIE=${CUSTOM_COOKIE}`,
      "FASTEDGE_VAR_ENV_SSO_VARIANT=header",
      "",
    ].join("\n"),
  );

  try {
    const injection = (await runTestSuite(
      defineTestSuite({
        wasmPath: WASM,
        runnerConfig: { dotenv: { enabled: true, path: cfgDir } },
        tests: [
          {
            name: "valid JWT → X-SSO-User injected with correct sub",
            run: async (runner) => {
              const r = await runFlow(runner, {
                url: "built-in",
                requestHeaders: { cookie: `${CUSTOM_COOKIE}=${validJwt}` },
              });
              if (r.hookResults.onRequestHeaders.returnCode !== 0) {
                throw new Error(
                  `expected Continue, got returnCode=${r.hookResults.onRequestHeaders.returnCode}`,
                );
              }
              const outHeaders = r.hookResults.onRequestHeaders.output.request.headers;
              const injected = headerValue(
                outHeaders["x-sso-user"] as string | string[] | undefined,
              );
              if (injected !== TEST_SUB) {
                throw new Error(`expected X-SSO-User=${TEST_SUB}, got '${injected}'`);
              }
            },
          },
          {
            name: "expired JWT → 302, X-SSO-User not injected",
            run: async (runner) => {
              const r = await runFlow(runner, {
                url: CDN_URL,
                requestHeaders: { cookie: `${CUSTOM_COOKIE}=${expiredJwt}` },
              });
              if (r.finalResponse.status !== 302) {
                throw new Error(`expected 302, got ${r.finalResponse.status}`);
              }
              const outHeaders = r.hookResults.onRequestHeaders.output.request.headers;
              const injected = outHeaders["x-sso-user"];
              if (injected !== undefined && injected !== "") {
                throw new Error(`expected no X-SSO-User on rejection, got '${injected}'`);
              }
            },
          },
        ],
      }),
    )) as SuiteResult;
    report("Suite — header injection:", injection);
    totalFailed += injection.failed;
  } finally {
    await rm(cfgDir, { recursive: true, force: true }).catch(() => {});
  }
}

// --- Header variant: per-claim header injection ---
{
  const TEST_SUB = "user-123";
  const jwtWithClaims = await makeJwtWithClaims(3600, {
    email: "testuser@example.com",
    name: "Test User",
    picture: "https://example.com/avatar.jpg",
    given_name: "Test",
    family_name: "User",
  });
  const jwtSubOnly = await makeJwt(3600, TEST_SUB);

  const claimCfgDir = await mkdtemp(join(tmpdir(), "header-claims-"));
  await writeFile(
    join(claimCfgDir, ".env"),
    [
      `FASTEDGE_VAR_SECRET_SESSION_SECRET=${SESSION_SECRET}`,
      AUDIENCE_ENV,
      "FASTEDGE_VAR_ENV_SSO_VARIANT=header",
      "",
    ].join("\n"),
  );

  try {
    const claimSuite = (await runTestSuite(
      defineTestSuite({
        wasmPath: WASM,
        runnerConfig: { dotenv: { enabled: true, path: claimCfgDir } },
        tests: [
          {
            name: "JWT with identity claims → per-claim headers injected alongside X-SSO-User",
            run: async (runner) => {
              const r = await runFlow(runner, {
                url: "built-in",
                requestHeaders: { cookie: `sso_session=${jwtWithClaims}` },
              });
              if (r.hookResults.onRequestHeaders.returnCode !== 0) {
                throw new Error(
                  `expected Continue, got returnCode=${r.hookResults.onRequestHeaders.returnCode}`,
                );
              }
              const out = r.hookResults.onRequestHeaders.output.request.headers;
              const check = (header: string, expected: string) => {
                const got = headerValue(out[header] as string | string[] | undefined);
                if (got !== expected) {
                  throw new Error(`expected ${header}=${expected}, got '${got}'`);
                }
              };
              check("x-sso-user", "user-123");
              check("x-sso-email", "testuser@example.com");
              check("x-sso-name", "Test User");
              check("x-sso-picture", "https://example.com/avatar.jpg");
              check("x-sso-given-name", "Test");
              check("x-sso-family-name", "User");
            },
          },
          {
            name: "JWT with only sub → X-SSO-User injected, no per-claim headers",
            run: async (runner) => {
              const r = await runFlow(runner, {
                url: "built-in",
                requestHeaders: { cookie: `sso_session=${jwtSubOnly}` },
              });
              if (r.hookResults.onRequestHeaders.returnCode !== 0) {
                throw new Error(
                  `expected Continue, got returnCode=${r.hookResults.onRequestHeaders.returnCode}`,
                );
              }
              const out = r.hookResults.onRequestHeaders.output.request.headers;
              const sub = headerValue(out["x-sso-user"] as string | string[] | undefined);
              if (sub !== TEST_SUB) {
                throw new Error(`expected X-SSO-User=${TEST_SUB}, got '${sub}'`);
              }
              for (const h of ["x-sso-email", "x-sso-name", "x-sso-picture"]) {
                const v = out[h];
                if (v !== undefined && v !== "") {
                  throw new Error(`expected no ${h} for sub-only JWT, got '${v}'`);
                }
              }
            },
          },
        ],
      }),
    )) as SuiteResult;
    report("Suite — per-claim header injection:", claimSuite);
    totalFailed += claimSuite.failed;
  } finally {
    await rm(claimCfgDir, { recursive: true, force: true }).catch(() => {});
  }
}

// --- Header variant: spoofed X-SSO-* headers must be stripped, not passed through ---
{
  const TEST_SUB = "user-123";
  const jwtSubOnly = await makeJwt(3600, TEST_SUB);

  const spoofCfgDir = await mkdtemp(join(tmpdir(), "header-spoof-"));
  await writeFile(
    join(spoofCfgDir, ".env"),
    [
      `FASTEDGE_VAR_SECRET_SESSION_SECRET=${SESSION_SECRET}`,
      AUDIENCE_ENV,
      "FASTEDGE_VAR_ENV_SSO_VARIANT=header",
      "",
    ].join("\n"),
  );

  try {
    const spoofSuite = (await runTestSuite(
      defineTestSuite({
        wasmPath: WASM,
        runnerConfig: { dotenv: { enabled: true, path: spoofCfgDir } },
        tests: [
          {
            name: "spoofed X-SSO-User replaced by filter value, no duplicate",
            run: async (runner) => {
              const r = await runFlow(runner, {
                url: "built-in",
                requestHeaders: {
                  cookie: `sso_session=${jwtSubOnly}`,
                  "x-sso-user": "admin@corp.com",
                  "x-sso-email": "attacker@evil.com",
                },
              });
              if (r.hookResults.onRequestHeaders.returnCode !== 0) {
                throw new Error(
                  `expected Continue, got returnCode=${r.hookResults.onRequestHeaders.returnCode}`,
                );
              }
              const out = r.hookResults.onRequestHeaders.output.request.headers;
              const user = out["x-sso-user"];
              if (Array.isArray(user)) {
                throw new Error(
                  `expected single X-SSO-User, got duplicates: ${JSON.stringify(user)}`,
                );
              }
              if (user !== TEST_SUB) {
                throw new Error(`expected X-SSO-User=${TEST_SUB}, got '${user}'`);
              }
              const email = out["x-sso-email"];
              if (email !== undefined && email !== "") {
                throw new Error(
                  `expected spoofed X-SSO-Email to be stripped, got '${JSON.stringify(email)}'`,
                );
              }
            },
          },
        ],
      }),
    )) as SuiteResult;
    report("Suite — spoofed header stripping:", spoofSuite);
    totalFailed += spoofSuite.failed;
  } finally {
    await rm(spoofCfgDir, { recursive: true, force: true }).catch(() => {});
  }
}

// --- Regression guard specific to this merge: gate-only must NOT get header
// injection now that inject_user_header() is a runtime branch instead of a
// Cargo feature absent from the gate-only binary entirely. ---
{
  const jwt = await makeJwt(3600);
  const dir = await mkdtemp(join(tmpdir(), "gate-only-no-inject-"));
  await writeFile(
    join(dir, ".env"),
    [
      `FASTEDGE_VAR_SECRET_SESSION_SECRET=${SESSION_SECRET}`,
      AUDIENCE_ENV,
      "FASTEDGE_VAR_ENV_SSO_VARIANT=gate-only",
      "",
    ].join("\n"),
  );
  try {
    const suite = (await runTestSuite(
      defineTestSuite({
        wasmPath: WASM,
        runnerConfig: { dotenv: { enabled: true, path: dir } },
        tests: [
          {
            name: "gate-only: no x-sso-* headers injected",
            run: async (runner) => {
              const r = await runFlow(runner, {
                url: "built-in",
                requestHeaders: { cookie: `${DEFAULT_COOKIE}=${jwt}` },
              });
              const out = r.hookResults.onRequestHeaders.output.request.headers;
              if (out["x-sso-user"] !== undefined) {
                throw new Error(
                  `expected no x-sso-user injection for gate-only, got '${out["x-sso-user"]}'`,
                );
              }
            },
          },
        ],
      }),
    )) as SuiteResult;
    report("Suite — gate-only does not inject headers:", suite);
    totalFailed += suite.failed;
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

for (const dir of allTempDirs) {
  await rm(dir, { recursive: true, force: true }).catch(() => {});
}
console.log("");
process.exit(totalFailed > 0 ? 1 : 0);
