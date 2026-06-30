import { rm, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  runGateSuites,
  runStripSuites,
  runAudIssSuites,
  runFailClosedSuites,
  makeJwt,
  makeJwtWithClaims,
  SESSION_SECRET,
  CUSTOM_COOKIE,
  CDN_URL,
  AUDIENCE_ENV,
  headerValue,
  report,
  type SuiteResult,
} from "../../../cookie/cdn-filter/tests/filter-suite.js";
import { defineTestSuite, runTestSuite, runFlow } from "@gcoredev/fastedge-test/test";

const TEST_SUB = "user-123";

// --- Suite A + B: identical gate behaviour to cookie/gate-only ---
const { totalFailed: gateFailed, tempDirs } = await runGateSuites(
  "./wasm/headers_sso_guard.wasm",
);
for (const dir of tempDirs) {
  await rm(dir, { recursive: true, force: true }).catch(() => {});
}

// --- Suite C: header injection ---
const validJwt = await makeJwt(3600, TEST_SUB);
const expiredJwt = await makeJwt(-3600);

const cfgDir = await mkdtemp(join(tmpdir(), "header-inject-"));
await writeFile(
  join(cfgDir, ".env"),
  [
    `FASTEDGE_VAR_SECRET_SESSION_SECRET=${SESSION_SECRET}`,
    AUDIENCE_ENV,
    `FASTEDGE_VAR_ENV_SESSION_COOKIE=${CUSTOM_COOKIE}`,
    `FASTEDGE_VAR_ENV_INJECT_USER_HEADER=1`,
    "",
  ].join("\n"),
);

let injectFailed = 0;
try {
  const injection = (await runTestSuite(
    defineTestSuite({
      wasmPath: "./wasm/headers_sso_guard.wasm",
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
            const outHeaders =
              r.hookResults.onRequestHeaders.output.request.headers;
            const injected = headerValue(
              outHeaders["x-sso-user"] as string | string[] | undefined,
            );
            if (injected !== TEST_SUB) {
              throw new Error(
                `expected X-SSO-User=${TEST_SUB}, got '${injected}'`,
              );
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
            const outHeaders =
              r.hookResults.onRequestHeaders.output.request.headers;
            const injected = outHeaders["x-sso-user"];
            if (injected !== undefined && injected !== "") {
              throw new Error(
                `expected no X-SSO-User on rejection, got '${injected}'`,
              );
            }
          },
        },
      ],
    }),
  )) as SuiteResult;
  report("Suite C — header injection:", injection);
  injectFailed = injection.failed;
} finally {
  await rm(cfgDir, { recursive: true, force: true }).catch(() => {});
}

const { totalFailed: stripFailed, tempDirs: stripDirs } = await runStripSuites(
  "./wasm/headers_sso_guard.wasm",
);
for (const dir of stripDirs) {
  await rm(dir, { recursive: true, force: true }).catch(() => {});
}

// --- aud/iss enforcement — HS256 tier ---
const { totalFailed: audIssFailed, tempDirs: audIssDirs } =
  await runAudIssSuites("./wasm/headers_sso_guard.wasm");
for (const dir of audIssDirs) {
  await rm(dir, { recursive: true, force: true }).catch(() => {});
}

// --- fail-closed audience — HS256 tier ---
const { totalFailed: failClosedFailed, tempDirs: failClosedDirs } =
  await runFailClosedSuites("./wasm/headers_sso_guard.wasm");
for (const dir of failClosedDirs) {
  await rm(dir, { recursive: true, force: true }).catch(() => {});
}

// --- Suite D: per-claim header injection ---
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
    `FASTEDGE_VAR_ENV_INJECT_USER_HEADER=1`,
    "",
  ].join("\n"),
);

let claimFailed = 0;
try {
  const claimSuite = (await runTestSuite(
    defineTestSuite({
      wasmPath: "./wasm/headers_sso_guard.wasm",
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
  report("Suite D — per-claim header injection:", claimSuite);
  claimFailed = claimSuite.failed;
} finally {
  await rm(claimCfgDir, { recursive: true, force: true }).catch(() => {});
}

// --- Suite E: spoofed X-SSO-* headers are stripped ---
// A client attaches its own x-sso-* headers to escalate identity. The
// filter must remove every header it manages before injecting, so the origin
// sees ONLY filter-issued values — never the client's, even for claims absent
// from the token.
const spoofCfgDir = await mkdtemp(join(tmpdir(), "header-spoof-"));
await writeFile(
  join(spoofCfgDir, ".env"),
  [
    `FASTEDGE_VAR_SECRET_SESSION_SECRET=${SESSION_SECRET}`,
    AUDIENCE_ENV,
    `FASTEDGE_VAR_ENV_INJECT_USER_HEADER=1`,
    "",
  ].join("\n"),
);

let spoofFailed = 0;
try {
  const spoofSuite = (await runTestSuite(
    defineTestSuite({
      wasmPath: "./wasm/headers_sso_guard.wasm",
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
            // Must be a single value equal to the filter's — not an array that
            // still carries the attacker's "admin@corp.com".
            if (Array.isArray(user)) {
              throw new Error(
                `expected single X-SSO-User, got duplicates: ${JSON.stringify(user)}`,
              );
            }
            if (user !== TEST_SUB) {
              throw new Error(
                `expected X-SSO-User=${TEST_SUB}, got '${user}'`,
              );
            }
            // The token has no email claim, so the spoofed x-sso-email
            // must be cleared rather than passed through.
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
  report("Suite E — spoofed header stripping:", spoofSuite);
  spoofFailed = spoofSuite.failed;
} finally {
  await rm(spoofCfgDir, { recursive: true, force: true }).catch(() => {});
}

console.log("");
process.exit(
  gateFailed +
    injectFailed +
    stripFailed +
    claimFailed +
    spoofFailed +
    audIssFailed +
    failClosedFailed >
    0
    ? 1
    : 0,
);
