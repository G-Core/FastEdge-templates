/**
 * Shared smoke suite for the NON-cookie SSO_VARIANT values (gate-only, header).
 *
 * At the auth-app level these two variants are identical: they sign HS256 and —
 * the one behaviour that distinguishes them from the cookie variant — expose NO
 * JWKS route (`/auth/.well-known/jwks.json` is mounted only for `cookie`, see
 * `federation/app.tsx`). All federation / token / routing logic is shared code,
 * already covered by app.test.ts's SSO_VARIANT=cookie suites, so this asserts
 * only the variant-specific surface + that the built artifact boots under
 * each variant.
 */
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineTestSuite, runTestSuite } from "@gcoredev/fastedge-test/test";

export async function runNonCookieVariantSmoke(
  wasmPath: string,
  variant: "gate-only" | "header",
): Promise<number> {
  const dir = await mkdtemp(join(tmpdir(), `sso-smoke-${variant}-`));
  await writeFile(
    join(dir, ".env"),
    [
      "FASTEDGE_VAR_SECRET_SESSION_SECRET=smoke-test-secret",
      `FASTEDGE_VAR_ENV_SSO_VARIANT=${variant}`,
      "FASTEDGE_VAR_ENV_SSO_PROVIDERS=google,github",
      "FASTEDGE_VAR_ENV_GITHUB_CLIENT_ID=smoke-gh-client",
      "FASTEDGE_VAR_ENV_GOOGLE_CLIENT_ID=smoke-gg-client",
      "FASTEDGE_VAR_ENV_GOOGLE_REDIRECT_URI=https://auth.example.com/auth/callback/google",
      "",
    ].join("\n"),
  );

  let failed = 0;
  try {
    const result = await runTestSuite(
      defineTestSuite({
        wasmPath,
        runnerConfig: { dotenv: { enabled: true, path: dir } },
        tests: [
          {
            name: `${variant}: JWKS route is cookie-only → 404`,
            run: async (runner) => {
              const r = await runner.execute({
                path: "/auth/.well-known/jwks.json",
                method: "GET",
                headers: {},
              });
              if (r.status !== 404) {
                throw new Error(
                  `expected 404 (no JWKS route for the ${variant} variant), got ${r.status}`,
                );
              }
            },
          },
          {
            name: `${variant}: GET /auth/ chooser → 200`,
            run: async (runner) => {
              const r = await runner.execute({
                path: "/auth/",
                method: "GET",
                headers: {},
              });
              if (r.status !== 200) {
                throw new Error(`expected 200 from /auth/, got ${r.status}`);
              }
            },
          },
          {
            name: `${variant}: GET /auth/providers → 200 (federation mounted)`,
            run: async (runner) => {
              const r = await runner.execute({
                path: "/auth/providers",
                method: "GET",
                headers: {},
              });
              if (r.status !== 200) {
                throw new Error(
                  `expected 200 from /auth/providers, got ${r.status}`,
                );
              }
            },
          },
        ],
      }),
    );
    failed = result.failed;
    console.log(`\n${variant} auth-app — variant smoke:`);
    for (const t of result.results) {
      const mark = t.passed ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
      console.log(`  ${mark} ${t.name} (${t.durationMs.toFixed(1)}ms)`);
      if (!t.passed && t.error) console.log(`      ${t.error}`);
    }
    console.log(
      `  ${result.passed}/${result.total} passed in ${result.durationMs.toFixed(1)}ms\n`,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  return failed;
}
