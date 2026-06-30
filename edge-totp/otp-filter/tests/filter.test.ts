/**
 * Black-box acceptance suite for the Rust enforcement filter (otp-filter).
 *
 * It drives the *compiled wasm* through
 * @gcoredev/fastedge-test rather than unit-testing Rust functions, so it
 * exercises the artifact that actually ships — including the request lifecycle,
 * env/secret wiring, the deny()/redirect path, and the 401 fail-closed path
 * that pure-function tests can't reach.
 *
 * The filter is HS256-only (the edge-internal mfa_session). Tokens are minted
 * with jose to match what otp-app's signMfaSession produces.
 */
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignJWT } from "jose";
import {
  defineTestSuite,
  runTestSuite,
  runFlow,
} from "@gcoredev/fastedge-test/test";

const WASM = "target/wasm32-wasip1/release/totp_filter.wasm";

const SESSION_KEY = "test-mfa-session-secret-abcdefghijklmnop0123456789";
const AUDIENCE = "https://app.example.com";
const OTHER_AUDIENCE = "https://other.example.com";
const ISSUER = "https://totp.example.com";
const LOGIN_URL = "https://cdn.example.com/auth/totp/challenge";
const DEFAULT_COOKIE = "mfa_session";
// A protected resource (not under the auth prefix), with a query string so we
// can assert the redirect target is the *relative path* only.
const PROTECTED_URL = "https://cdn.example.com/private/resource?foo=bar";

function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

async function mint(
  ttlSeconds: number,
  claims: Record<string, unknown> = {},
  sub = "user-123",
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub, amr: ["otp"], ...claims })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(bytes(SESSION_KEY));
}

/**
 * Hand-craft a token whose header advertises a non-HS256 alg (alg-confusion /
 * "alg:none" probe). jose refuses to *mint* these, but an attacker would just
 * assemble the bytes — which is what we do here. The signature segment is
 * arbitrary; the filter must reject on the header alg before ever checking it.
 */
function craftWithAlg(alg: string): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const header = b64({ alg, typ: "JWT" });
  const payload = b64({ sub: "user-123", aud: AUDIENCE, exp: Math.floor(Date.now() / 1000) + 3600 });
  return `${header}.${payload}.`;
}

function tamper(jwt: string): string {
  const [h, p, sig] = jwt.split(".");
  const mid = Math.floor(sig.length / 2);
  const flipped = sig.slice(0, mid) + (sig[mid] === "A" ? "B" : "A") + sig.slice(mid + 1);
  return [h, p, flipped].join(".");
}

function headerValue(v: string | string[] | undefined): string {
  return Array.isArray(v) ? (v[0] ?? "") : (v ?? "");
}

interface SuiteResult {
  passed: number;
  total: number;
  failed: number;
  durationMs: number;
  results: { name: string; passed: boolean; error?: string; durationMs: number }[];
}

function report(label: string, result: SuiteResult): void {
  console.log(`\n${label}`);
  for (const r of result.results) {
    const mark = r.passed ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
    console.log(`  ${mark} ${r.name} (${r.durationMs.toFixed(1)}ms)`);
    if (!r.passed && r.error) console.log(`      ${r.error}`);
  }
  console.log(`  ${result.passed}/${result.total} passed in ${result.durationMs.toFixed(1)}ms`);
}

// Assertion helpers: the filter signals authorize via Action::Continue
// (returnCode 0) and deny via a synthesized response (302 redirect, or 401 when
// no MFA_LOGIN_URL is configured).
function assertContinue(r: Awaited<ReturnType<typeof runFlow>>): void {
  if (r.hookResults.onRequestHeaders.returnCode !== 0) {
    throw new Error(`expected Continue (returnCode=0), got ${r.hookResults.onRequestHeaders.returnCode}`);
  }
  if (r.finalResponse.status === 302 || r.finalResponse.status === 401) {
    throw new Error(`expected no deny, got ${r.finalResponse.status}`);
  }
}
function assertStatus(r: Awaited<ReturnType<typeof runFlow>>, status: number): void {
  if (r.finalResponse.status !== status) {
    throw new Error(`expected ${status}, got ${r.finalResponse.status}`);
  }
}

async function envDir(prefix: string, lines: string[]): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  await writeFile(join(dir, ".env"), [...lines, ""].join("\n"));
  return dir;
}

const SECRET_KEY_ENV = `FASTEDGE_VAR_SECRET_MFA_SESSION_KEY=${SESSION_KEY}`;
const cookie = (jwt: string) => ({ cookie: `${DEFAULT_COOKIE}=${jwt}` });

const tempDirs: string[] = [];
let totalFailed = 0;

async function suite(
  label: string,
  env: string[],
  tests: { name: string; run: (runner: Parameters<Parameters<typeof defineTestSuite>[0]["tests"][number]["run"]>[0]) => Promise<void> }[],
): Promise<void> {
  const dir = await envDir("otp-filter-", env);
  tempDirs.push(dir);
  const result = (await runTestSuite(
    defineTestSuite({
      wasmPath: WASM,
      runnerConfig: { dotenv: { enabled: true, path: dir } },
      tests,
    }),
  )) as SuiteResult;
  report(label, result);
  totalFailed += result.failed;
}

// Pre-mint tokens.
const validJwt = await mint(3600, { aud: AUDIENCE });
const expiredJwt = await mint(-3600, { aud: AUDIENCE });
const tamperedJwt = tamper(validJwt);
const wrongKeyJwt = await new SignJWT({ sub: "user-123", aud: AUDIENCE })
  .setProtectedHeader({ alg: "HS256", typ: "JWT" })
  .setIssuedAt(Math.floor(Date.now() / 1000))
  .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
  .sign(bytes("a-different-secret-key-that-should-not-verify"));
const nowSec = Math.floor(Date.now() / 1000);
const notYetValidJwt = await mint(7200, { aud: AUDIENCE, nbf: nowSec + 3600 });

// --- Gate behaviour (audience configured, redirect login configured) --------
await suite(
  "Gate — default config (MFA_AUDIENCE + MFA_LOGIN_URL set):",
  [SECRET_KEY_ENV, `FASTEDGE_VAR_ENV_MFA_AUDIENCE=${AUDIENCE}`, `FASTEDGE_VAR_ENV_MFA_LOGIN_URL=${LOGIN_URL}`],
  [
    {
      name: "valid mfa_session → Continue",
      run: async (runner) => assertContinue(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(validJwt) })),
    },
    {
      name: "no cookie → 302 to MFA_LOGIN_URL with relative-path redirect",
      run: async (runner) => {
        const r = await runFlow(runner, { url: PROTECTED_URL, requestHeaders: {} });
        assertStatus(r, 302);
        const loc = headerValue(r.finalResponse.headers["location"]);
        if (!loc.startsWith(`${LOGIN_URL}?redirect=`)) {
          throw new Error(`expected redirect to login, got '${loc}'`);
        }
        const target = decodeURIComponent(loc.split("redirect=")[1] ?? "");
        // must be the relative path only — never an absolute URL with host
        if (!target.startsWith("/private/resource")) {
          throw new Error(`expected relative path target, got '${target}'`);
        }
        if (target.includes("https://") || target.includes("cdn.example.com")) {
          throw new Error(`redirect target leaked absolute URL/host: '${target}'`);
        }
      },
    },
    { name: "expired token → 302", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(expiredJwt) }), 302) },
    { name: "tampered signature → 302", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(tamperedJwt) }), 302) },
    { name: "wrong signing key → 302", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(wrongKeyJwt) }), 302) },
    { name: "not-yet-valid (nbf in future) → 302", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(notYetValidJwt) }), 302) },
    { name: "malformed token (no dots) → 302", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: { cookie: `${DEFAULT_COOKIE}=not-a-jwt` } }), 302) },
    {
      name: "alg=none token → 302 (alg pinned to HS256)",
      run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(craftWithAlg("none")) }), 302),
    },
    {
      name: "alg=RS256 token → 302 (alg pinned, no alg-confusion)",
      run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(craftWithAlg("RS256")) }), 302),
    },
    // bypass paths must pass through even with no cookie
    { name: "/health bypassed → Continue", run: async (runner) => assertContinue(await runFlow(runner, { url: "https://cdn.example.com/health", requestHeaders: {} })) },
    { name: "/auth/totp/challenge bypassed → Continue", run: async (runner) => assertContinue(await runFlow(runner, { url: "https://cdn.example.com/auth/totp/challenge?t=abc", requestHeaders: {} })) },
    {
      name: "traversal /auth/totp/../admin is GATED despite prefix match → 302",
      run: async (runner) => assertStatus(await runFlow(runner, { url: "https://cdn.example.com/auth/totp/../admin", requestHeaders: {} }), 302),
    },
  ],
);

// --- 401 fail-closed when no MFA_LOGIN_URL is configured ---------------------
await suite(
  "Fail-closed — no MFA_LOGIN_URL (deny must be a hard 401, not a redirect):",
  [SECRET_KEY_ENV, `FASTEDGE_VAR_ENV_MFA_AUDIENCE=${AUDIENCE}`],
  [
    { name: "no cookie → 401 MFA required", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: {} }), 401) },
    { name: "valid token still → Continue", run: async (runner) => assertContinue(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(validJwt) })) },
  ],
);

// --- Fail-closed audience: MFA_AUDIENCE unset refuses every session ----------
await suite(
  "Fail-closed audience — MFA_AUDIENCE unset refuses even a valid token:",
  [SECRET_KEY_ENV, `FASTEDGE_VAR_ENV_MFA_LOGIN_URL=${LOGIN_URL}`],
  [
    { name: "valid token but MFA_AUDIENCE unset → 302 (refuse)", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(validJwt) }), 302) },
  ],
);

// --- aud / iss enforcement ---------------------------------------------------
await suite(
  "aud/iss enforcement (MFA_AUDIENCE + MFA_ISSUER set):",
  [SECRET_KEY_ENV, `FASTEDGE_VAR_ENV_MFA_AUDIENCE=${AUDIENCE}`, `FASTEDGE_VAR_ENV_MFA_ISSUER=${ISSUER}`, `FASTEDGE_VAR_ENV_MFA_LOGIN_URL=${LOGIN_URL}`],
  [
    { name: "matching aud + iss → Continue", run: async (runner) => assertContinue(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(await mint(3600, { aud: AUDIENCE, iss: ISSUER })) })) },
    { name: "aud mismatch → 302 (cross-resource replay blocked)", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(await mint(3600, { aud: OTHER_AUDIENCE, iss: ISSUER })) }), 302) },
    { name: "iss mismatch → 302", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(await mint(3600, { aud: AUDIENCE, iss: "https://evil.example.com" })) }), 302) },
    { name: "aud array containing configured value → Continue", run: async (runner) => assertContinue(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(await mint(3600, { aud: [OTHER_AUDIENCE, AUDIENCE], iss: ISSUER })) })) },
    { name: "no aud claim while MFA_AUDIENCE required → 302", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(await mint(3600, { iss: ISSUER })) }), 302) },
  ],
);

// --- Custom AUTH_PREFIX + custom cookie name --------------------------------
await suite(
  "Custom AUTH_PREFIX (/mfa) + custom MFA_SESSION_COOKIE:",
  [
    SECRET_KEY_ENV,
    `FASTEDGE_VAR_ENV_MFA_AUDIENCE=${AUDIENCE}`,
    `FASTEDGE_VAR_ENV_MFA_LOGIN_URL=${LOGIN_URL}`,
    `FASTEDGE_VAR_ENV_AUTH_PREFIX=/mfa`,
    `FASTEDGE_VAR_ENV_MFA_SESSION_COOKIE=my_mfa`,
  ],
  [
    { name: "custom /mfa/ path bypassed (Continue) with no cookie", run: async (runner) => assertContinue(await runFlow(runner, { url: "https://cdn.example.com/mfa/verify", requestHeaders: {} })) },
    { name: "old default /auth/totp/ NOT bypassed when AUTH_PREFIX overridden → 302", run: async (runner) => assertStatus(await runFlow(runner, { url: "https://cdn.example.com/auth/totp/challenge", requestHeaders: {} }), 302) },
    { name: "valid token in custom cookie name → Continue", run: async (runner) => assertContinue(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: { cookie: `my_mfa=${validJwt}` } })) },
    { name: "token in default cookie name NOT honoured when overridden → 302", run: async (runner) => assertStatus(await runFlow(runner, { url: PROTECTED_URL, requestHeaders: cookie(validJwt) }), 302) },
  ],
);

for (const dir of tempDirs) await rm(dir, { recursive: true, force: true }).catch(() => {});
console.log("");
process.exit(totalFailed > 0 ? 1 : 0);
