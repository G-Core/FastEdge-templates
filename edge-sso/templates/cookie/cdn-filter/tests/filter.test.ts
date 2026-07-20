import { rm, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  runGateSuites,
  runEs256Suites,
  runAudIssSuites,
  runFailClosedSuites,
  runCustomPrefixSuites,
  makeEs256Tier,
  makeJwt,
  SESSION_SECRET,
  DEFAULT_COOKIE,
  CDN_URL,
  FILTER_AUDIENCE,
  AUDIENCE_ENV,
  report,
  type SuiteResult,
} from "./filter-suite.js";
import { defineTestSuite, runTestSuite, runFlow } from "@gcoredev/fastedge-test/test";

// The cookie variant is ES256-only: gate behaviour is exercised with
// ES256 tokens, not HS256.
const es256Tier = await makeEs256Tier();
const gate = await runGateSuites("./wasm/cookie_sso_guard.wasm", es256Tier);
const es256 = await runEs256Suites("./wasm/cookie_sso_guard.wasm");
const audIss = await runAudIssSuites("./wasm/cookie_sso_guard.wasm", es256Tier);
const failClosed = await runFailClosedSuites("./wasm/cookie_sso_guard.wasm", es256Tier);
const customPrefix = await runCustomPrefixSuites("./wasm/cookie_sso_guard.wasm", es256Tier);

// --- Suite: alg pinning ---
// Even when SESSION_SECRET is present in the environment (cross-contamination
// during portal setup is plausible — it is the default secret name for the
// other two variants), the cookie filter must NOT verify an HS256 token. The
// HS256 path is not compiled into this variant at all.
const hs256Token = await makeJwt(3600);
const contaminatedDir = await mkdtemp(join(tmpdir(), "cookie-algpin-"));
await writeFile(
  join(contaminatedDir, ".env"),
  [
    // ES256 verification key (correct config for this variant)...
    ...es256Tier.keyEnv,
    // ...PLUS a stray HS256 secret that must NOT enable HS256 verification.
    `FASTEDGE_VAR_SECRET_SESSION_SECRET=${SESSION_SECRET}`,
    AUDIENCE_ENV,
    `FASTEDGE_VAR_ENV_SESSION_COOKIE=${DEFAULT_COOKIE}`,
    "",
  ].join("\n"),
);

let algPinFailed = 0;
try {
  const algPin = (await runTestSuite(
    defineTestSuite({
      wasmPath: "./wasm/cookie_sso_guard.wasm",
      runnerConfig: { dotenv: { enabled: true, path: contaminatedDir } },
      tests: [
        {
          name: "valid HS256 token rejected even with SESSION_SECRET present → 302",
          run: async (runner) => {
            const r = await runFlow(runner, {
              url: CDN_URL,
              requestHeaders: { cookie: `${DEFAULT_COOKIE}=${hs256Token}` },
            });
            if (r.finalResponse.status !== 302) {
              throw new Error(
                `expected 302 (HS256 rejected by ES256-only filter), got ${r.finalResponse.status}`,
              );
            }
          },
        },
        {
          name: "valid ES256 token still accepted alongside stray secret → Continue",
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
  report("Suite — alg pinning:", algPin);
  algPinFailed = algPin.failed;
} finally {
  await rm(contaminatedDir, { recursive: true, force: true }).catch(() => {});
}

for (const dir of [
  ...gate.tempDirs,
  ...es256.tempDirs,
  ...audIss.tempDirs,
  ...failClosed.tempDirs,
  ...customPrefix.tempDirs,
]) {
  await rm(dir, { recursive: true, force: true }).catch(() => {});
}
console.log("");
process.exit(
  gate.totalFailed +
    es256.totalFailed +
    audIss.totalFailed +
    failClosed.totalFailed +
    customPrefix.totalFailed +
    algPinFailed >
    0
    ? 1
    : 0,
);
