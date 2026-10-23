/**
 * Black-box acceptance suite for the graphql-protection filter.
 *
 * Drives the *compiled wasm* through @gcoredev/fastedge-test, so it exercises
 * the artifact that ships: the onRequestBody hook, env wiring, request.path
 * (which includes the query string, as in production) and the local 400/403
 * responses. Allowed requests go to the runner's built-in responder, so no
 * network is needed.
 */
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  defineTestSuite,
  runTestSuite,
  runFlow,
} from "@gcoredev/fastedge-test/test";

const WASM = "target/wasm32-wasip1/release/graphql_protection.wasm";
const ORIGIN = "http://fastedge-builtin.debug";
const JSON_CT = { "content-type": "application/json" };

type Runner = Parameters<Parameters<typeof defineTestSuite>[0]["tests"][number]["run"]>[0];
type Flow = Awaited<ReturnType<typeof runFlow>>;

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

function headerValue(v: string | string[] | undefined): string {
  return Array.isArray(v) ? (v[0] ?? "") : (v ?? "");
}

// The filter allows via Action::Continue (request reaches the built-in origin,
// 200) and blocks via a local response.
function assertAllowed(r: Flow): void {
  if (r.finalResponse.status !== 200) {
    throw new Error(`expected request to reach origin (200), got ${r.finalResponse.status}`);
  }
}
function assertStatus(r: Flow, status: number, reason?: string): void {
  if (r.finalResponse.status !== status) {
    throw new Error(`expected ${status}, got ${r.finalResponse.status}`);
  }
  if (reason !== undefined) {
    const got = headerValue(r.finalResponse.headers["x-reject-reason"]);
    if (got !== reason) throw new Error(`expected X-Reject-Reason '${reason}', got '${got}'`);
  }
}
const blocked = (r: Flow) => assertStatus(r, 403, "GraphQL request blocked");
const invalid = (r: Flow) => assertStatus(r, 400, "Invalid GraphQL request");

function post(runner: Runner, path: string, body: string, headers: Record<string, string> = JSON_CT): Promise<Flow> {
  return runFlow(runner, { url: `${ORIGIN}${path}`, method: "POST", requestHeaders: headers, requestBody: body });
}
const gql = (query: string, variables?: unknown) => JSON.stringify({ query, variables });
const FORM = { "content-type": "application/x-www-form-urlencoded" };

// GraphQL over GET: query/variables ride in the URL query string.
function get(runner: Runner, path: string): Promise<Flow> {
  return runFlow(runner, { url: `${ORIGIN}${path}`, method: "GET" });
}
function gqlGetPath(query: string, variables?: unknown): string {
  let p = `/graphql?query=${encodeURIComponent(query)}`;
  if (variables !== undefined) p += `&variables=${encodeURIComponent(JSON.stringify(variables))}`;
  return p;
}

const tempDirs: string[] = [];
let totalFailed = 0;

async function suite(label: string, env: string[], tests: { name: string; run: (runner: Runner) => Promise<void> }[]): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "graphql-protection-"));
  tempDirs.push(dir);
  await writeFile(join(dir, ".env"), [...env, ""].join("\n"));
  const result = (await runTestSuite(
    defineTestSuite({ wasmPath: WASM, runnerConfig: { dotenv: { enabled: true, path: dir } }, tests }),
  )) as SuiteResult;
  report(label, result);
  totalFailed += result.failed;
}

const OK = "{ user(id: 1) { name } }";
const INTROSPECTION = "{ __schema { types { name } } }";

await suite(
  "All checks enabled:",
  [
    "FASTEDGE_VAR_ENV_MAX_BODY_SIZE=2000",
    "FASTEDGE_VAR_ENV_MAX_QUERY_DEPTH=3",
    "FASTEDGE_VAR_ENV_MAX_BATCH_SIZE=2",
    "FASTEDGE_VAR_ENV_MAX_VALUE_SIZE=10",
    "FASTEDGE_VAR_ENV_BLOCKED_FIELDS=__schema,__type",
    "FASTEDGE_VAR_ENV_BLOCK_DEBUG=true",
  ],
  [
    { name: "valid query → allowed", run: async (r) => assertAllowed(await post(r, "/graphql", gql(OK))) },
    { name: "depth over limit → 403", run: async (r) => blocked(await post(r, "/graphql", gql("{ a { b { c { d } } } }"))) },
    { name: "depth via fragment spread → 403", run: async (r) => blocked(await post(r, "/graphql", gql("{ a { ...F } } fragment F on A { b { c { d } } }"))) },
    { name: "batch over limit → 403", run: async (r) => blocked(await post(r, "/graphql", JSON.stringify([{ query: OK }, { query: OK }, { query: OK }]))) },
    { name: "batch within limit → allowed", run: async (r) => assertAllowed(await post(r, "/graphql", JSON.stringify([{ query: OK }, { query: OK }]))) },
    { name: "long string argument → 403", run: async (r) => blocked(await post(r, "/graphql", gql('{ user(name: "aaaaaaaaaaaaaaaa") { id } }'))) },
    { name: "long nested variable → 403", run: async (r) => blocked(await post(r, "/graphql", gql(OK, { filter: { name: "aaaaaaaaaaaaaaaa" } }))) },
    { name: "blocked field (__schema) → 403", run: async (r) => blocked(await post(r, "/graphql", gql(INTROSPECTION))) },
    { name: "blocked field behind alias → 403", run: async (r) => blocked(await post(r, "/graphql", gql("{ s: __schema { types { name } } }"))) },
    { name: "oversized variable default value → 403", run: async (r) => blocked(await post(r, "/graphql", gql('query Q($s: String = "aaaaaaaaaaaaaaaa") { user(name: $s) { id } }'))) },
    {
      // Each fragment spreads the next twice: 2^40 walks without memoisation.
      name: "shared fragment chain completes quickly → allowed",
      run: async (r) => {
        const n = 40;
        const frags = Array.from({ length: n }, (_, i) => `fragment F${i} on Query { ...F${i + 1} ...F${i + 1} }`).join(" ");
        const start = Date.now();
        assertAllowed(await post(r, "/graphql", gql(`{ ...F0 } ${frags} fragment F${n} on Query { ok }`)));
        if (Date.now() - start > 2000) throw new Error(`took ${Date.now() - start}ms`);
      },
    },
    { name: "debug: true argument → 403", run: async (r) => blocked(await post(r, "/graphql", gql("{ user(id: 1, debug: true) { name } }"))) },
    { name: "debug variable → 403", run: async (r) => blocked(await post(r, "/graphql", gql(OK, { debug: true }))) },
    { name: "debug in JSON-string-encoded variables → 403", run: async (r) => blocked(await post(r, "/graphql", JSON.stringify({ query: OK, variables: '{"debug":true}' }))) },
    { name: "body over MAX_BODY_SIZE → 403", run: async (r) => assertStatus(await post(r, "/graphql", gql(OK, { pad: "x".repeat(2500) })), 403) },
    { name: "invalid JSON → 400", run: async (r) => invalid(await post(r, "/graphql", "{not json")) },
    { name: "invalid GraphQL → 400", run: async (r) => invalid(await post(r, "/graphql", gql("{ user("))) },
    { name: "unsupported content type → 400", run: async (r) => invalid(await post(r, "/graphql", gql(OK), { "content-type": "text/plain" })) },
    { name: "uppercase content type still inspected → 403", run: async (r) => blocked(await post(r, "/graphql", gql(INTROSPECTION), { "content-type": "Application/JSON" })) },
    { name: "application/graphql body → 403 on introspection", run: async (r) => blocked(await post(r, "/graphql", INTROSPECTION, { "content-type": "application/graphql" })) },
    { name: "form body valid → allowed", run: async (r) => assertAllowed(await post(r, "/graphql", `query=${encodeURIComponent(OK)}`, FORM)) },
    { name: "form body introspection → 403", run: async (r) => blocked(await post(r, "/graphql", `query=${encodeURIComponent(INTROSPECTION)}`, FORM)) },
    { name: "form invalid variables JSON → 400", run: async (r) => invalid(await post(r, "/graphql", `query=${encodeURIComponent(OK)}&variables=%7Bdebug`, FORM)) },
    {
      name: "form duplicate query key → 400",
      run: async (r) => invalid(await post(r, "/graphql", `query=${encodeURIComponent(OK)}&query=${encodeURIComponent(INTROSPECTION)}`, FORM)),
    },
    // Path variants the CDN passes through un-normalised: all must be inspected.
    // Includes double-encoded `..` (%252e%252e): a single decode leaves %2e%2e,
    // which an origin re-decodes to `..` and resolves to /graphql.
    ...["/graphql?x=1", "/graphql/", "//graphql", "/GraphQL", "/%67raphql", "/api/../graphql", "/graphql;jsessionid=1", "/graphql%3Bjsessionid=1", "/graphql%3Fx", "/x%3F/../graphql", "/x%23/../graphql", "/./graphql", "/%252e%252e/graphql", "/foo/%252e%252e/graphql"].map((p) => ({
      name: `path variant ${p} → inspected (403)`,
      run: async (r: Runner) => blocked(await post(r, p, gql(INTROSPECTION))),
    })),
    { name: "other path → not inspected", run: async (r) => assertAllowed(await post(r, "/other", gql(INTROSPECTION))) },
    { name: "/graphql-v2 → not inspected", run: async (r) => assertAllowed(await post(r, "/graphql-v2", gql(INTROSPECTION))) },
    // GraphQL over GET: the query rides in the URL query string, which the body
    // hook never sees. These must be inspected, not waved through.
    { name: "GET introspection → 403", run: async (r) => blocked(await get(r, gqlGetPath(INTROSPECTION))) },
    { name: "GET depth over limit → 403", run: async (r) => blocked(await get(r, gqlGetPath("{ a { b { c { d } } } }"))) },
    { name: "GET blocked field via variables debug → 403", run: async (r) => blocked(await get(r, gqlGetPath("{ user(id: 1, debug: true) { name } }"))) },
    { name: "GET valid query → allowed", run: async (r) => assertAllowed(await get(r, gqlGetPath(OK))) },
    { name: "GET without query param (GraphiQL) → allowed", run: async (r) => assertAllowed(await get(r, "/graphql")) },
    { name: "GET duplicate query key → 400", run: async (r) => invalid(await get(r, `/graphql?query=${encodeURIComponent(OK)}&query=${encodeURIComponent(INTROSPECTION)}`)) },
    { name: "GET query over MAX_BODY_SIZE → 403", run: async (r) => assertStatus(await get(r, gqlGetPath(`{ user(name: "${"a".repeat(2500)}") { id } }`)), 403) },
    { name: "GET oversized non-query param still capped → 403", run: async (r) => assertStatus(await get(r, `/graphql?pad=${"a".repeat(2500)}`), 403) },
    // A literal `?` inside the query string must not hide params from inspection.
    { name: "GET query behind a literal ? → 403", run: async (r) => blocked(await get(r, `/graphql?pad=?&query=${encodeURIComponent(INTROSPECTION)}`)) },
    // Encoded `?` delimiter: no literal `?`, but a re-decoding origin would run it.
    { name: "GET query behind encoded ? (%3F) → 403", run: async (r) => blocked(await get(r, `/graphql%3Fquery=${encodeURIComponent(INTROSPECTION)}`)) },
    { name: "GET query behind double-encoded ? (%253F) → 403", run: async (r) => blocked(await get(r, `/graphql%253Fquery=${encodeURIComponent(INTROSPECTION)}`)) },
    // Legit query whose value contains an encoded `&` must NOT be mis-split → allowed.
    { name: "GET query with encoded & in a value → allowed", run: async (r) => assertAllowed(await get(r, gqlGetPath('{ user(x: "a&b") { id } }'))) },
    { name: "GET oversized param behind a literal ? → 403", run: async (r) => assertStatus(await get(r, `/graphql?z=?&pad=${"a".repeat(2500)}`), 403) },
    { name: "GET other path → not inspected", run: async (r) => assertAllowed(await get(r, `/other?query=${encodeURIComponent(INTROSPECTION)}`)) },
    { name: "GET path variant //graphql → inspected (403)", run: async (r) => blocked(await get(r, `//graphql?query=${encodeURIComponent(INTROSPECTION)}`)) },
    // Non-GET, non-POST methods that carry a GraphQL body must also be inspected.
    { name: "PUT introspection body → 403", run: async (r) => blocked(await runFlow(r, { url: `${ORIGIN}/graphql`, method: "PUT", requestHeaders: JSON_CT, requestBody: gql(INTROSPECTION) })) },
    { name: "PATCH introspection body → 403", run: async (r) => blocked(await runFlow(r, { url: `${ORIGIN}/graphql`, method: "PATCH", requestHeaders: JSON_CT, requestBody: gql(INTROSPECTION) })) },
    { name: "OPTIONS preflight (no body) → allowed", run: async (r) => assertAllowed(await runFlow(r, { url: `${ORIGIN}/graphql`, method: "OPTIONS" })) },
  ],
);

await suite("No limits configured (defaults):", [], [
  { name: "introspection allowed when BLOCKED_FIELDS unset", run: async (r) => assertAllowed(await post(r, "/graphql", gql(INTROSPECTION))) },
  { name: "deep query allowed when MAX_QUERY_DEPTH unset", run: async (r) => assertAllowed(await post(r, "/graphql", gql("{ a { b { c { d { e } } } } }"))) },
  { name: "unparseable body still → 400", run: async (r) => invalid(await post(r, "/graphql", "{not json")) },
]);

await suite("Custom ENDPOINT=/api/gql:", ["FASTEDGE_VAR_ENV_ENDPOINT=/api/gql", "FASTEDGE_VAR_ENV_BLOCKED_FIELDS=__schema"], [
  { name: "custom endpoint inspected → 403", run: async (r) => blocked(await post(r, "/api/gql", gql(INTROSPECTION))) },
  { name: "per-segment ;params /api;v=1/gql → inspected (403)", run: async (r) => blocked(await post(r, "/api;v=1/gql", gql(INTROSPECTION))) },
  { name: "default /graphql not inspected", run: async (r) => assertAllowed(await post(r, "/graphql", gql(INTROSPECTION))) },
]);

await suite("Blank ENDPOINT falls back to /graphql:", ["FASTEDGE_VAR_ENV_ENDPOINT=", "FASTEDGE_VAR_ENV_BLOCKED_FIELDS=__schema"], [
  { name: "/graphql inspected → 403", run: async (r) => blocked(await post(r, "/graphql", gql(INTROSPECTION))) },
]);

for (const dir of tempDirs) await rm(dir, { recursive: true, force: true }).catch(() => {});
console.log("");
process.exit(totalFailed > 0 ? 1 : 0);
