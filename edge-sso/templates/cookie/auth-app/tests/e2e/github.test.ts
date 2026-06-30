import { createServer } from "node:http";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, exportPKCS8 } from "jose";
import {
  defineTestSuite,
  runTestSuite,
} from "@gcoredev/fastedge-test/test";
import { parseSetCookieAsString } from "../_cookies.js";

interface StubServer {
  port: number;
  stop: () => Promise<void>;
  lastTokenBody: () => string | null;
  userFetches: () => number;
  emailFetches: () => number;
}

async function startStubServer(): Promise<StubServer> {
  let lastTokenBody: string | null = null;
  let userFetches = 0;
  let emailFetches = 0;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      if (
        req.url === "/login/oauth/access_token" &&
        req.method === "POST"
      ) {
        lastTokenBody = body;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "fake-access-token",
            token_type: "bearer",
          }),
        );
        return;
      }
      if (req.url === "/user" && req.method === "GET") {
        userFetches++;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            id: 12345,
            login: "testuser",
            name: "Test User",
            // the profile `email` field is public/unverified and must NOT be
            // trusted. A different value here proves the session email comes from
            // the verified /user/emails endpoint below, not this field.
            email: "unverified-profile@example.com",
            avatar_url: "https://example.com/avatar.jpg",
          }),
        );
        return;
      }
      if (req.url === "/user/emails" && req.method === "GET") {
        emailFetches++;
        res.writeHead(200, { "content-type": "application/json" });
        // the verified primary address is the only one the provider trusts.
        res.end(
          JSON.stringify([
            { email: "unverified@example.com", primary: false, verified: false },
            { email: "testuser@example.com", primary: true, verified: true },
          ]),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });
  });
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("Stub server failed to bind");
  }
  return {
    port: addr.port,
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
    lastTokenBody: () => lastTokenBody,
    userFetches: () => userFetches,
    emailFetches: () => emailFetches,
  };
}

async function main() {
  const { privateKey: signingKey } = await generateKeyPair("ES256", { extractable: true });
  // Strip PEM headers and newlines — importPrivateKeyPkcs8 handles raw base64 DER,
  // and dotenv does not expand \n escapes in unquoted values.
  const signingKeyB64 = (await exportPKCS8(signingKey))
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");

  const stub = await startStubServer();
  const tmpDir = await mkdtemp(join(tmpdir(), "sso-e2e-"));
  const envContent =
    [
      "FASTEDGE_VAR_ENV_IDP_SSO_URL=https://idp.example.com/sso",
      "FASTEDGE_VAR_ENV_IDP_ENTITY_ID=https://idp.example.com",
      "FASTEDGE_VAR_SECRET_IDP_CERT=-----BEGIN CERTIFICATE-----\\nfake\\n-----END CERTIFICATE-----",
      "FASTEDGE_VAR_ENV_SP_ENTITY_ID=https://auth.example.com",
      "FASTEDGE_VAR_ENV_SP_ACS_URL=https://auth.example.com/auth/callback",
      "FASTEDGE_VAR_SECRET_SESSION_SECRET=e2e-test-session-secret",
      `FASTEDGE_VAR_SECRET_SESSION_SIGNING_KEY=${signingKeyB64}`,
      "FASTEDGE_VAR_ENV_GITHUB_CLIENT_ID=test-client-id",
      "FASTEDGE_VAR_SECRET_GITHUB_CLIENT_SECRET=test-client-secret",
      `FASTEDGE_VAR_ENV_GITHUB_OAUTH_BASE_URL=http://127.0.0.1:${stub.port}`,
      `FASTEDGE_VAR_ENV_GITHUB_API_BASE_URL=http://127.0.0.1:${stub.port}`,
      "FASTEDGE_VAR_ENV_SSO_ISSUER=https://auth.example.com",
      "FASTEDGE_VAR_ENV_SSO_AUDIENCE=https://app.example.com",
      "FASTEDGE_VAR_ENV_SSO_CLAIMS=email,name,picture",
    ].join("\n") + "\n";
  await writeFile(join(tmpDir, ".env"), envContent);

  let failed = 0;
  try {
    const result = await runTestSuite(
      defineTestSuite({
        wasmPath: "./wasm/cookie-auth-app.wasm",
        runnerConfig: { dotenv: { enabled: true, path: tmpDir } },
        tests: [
          {
            name: "github e2e: happy path sets sso_session with github id and redirects to original url",
            run: async (runner) => {
              const loginRes = await runner.execute({
                path: "/auth/login/github?redirect=/foo",
                method: "GET",
                headers: {},
              });
              if (loginRes.status !== 302) {
                throw new Error(
                  `login status was ${loginRes.status}, location=${loginRes.headers["location"]}`,
                );
              }
              const location = loginRes.headers["location"];
              if (!location) {
                throw new Error("login response missing Location header");
              }
              const authorizeUrl = new URL(location);
              const state = authorizeUrl.searchParams.get("state");
              if (!state) {
                throw new Error("authorize URL missing state param");
              }
              const setCookie = parseSetCookieAsString(loginRes.headers);
              if (!setCookie) {
                throw new Error("login response missing Set-Cookie");
              }
              const stateCookieMatch = setCookie.match(
                /gh_oauth_state=([^;]+)/,
              );
              if (!stateCookieMatch) {
                throw new Error(
                  `gh_oauth_state cookie not found in: ${setCookie}`,
                );
              }

              const cbRes = await runner.execute({
                path: `/auth/callback/github?state=${encodeURIComponent(state)}&code=fake-code`,
                method: "GET",
                headers: { cookie: `gh_oauth_state=${stateCookieMatch[1]}` },
              });
              if (cbRes.status !== 302) {
                throw new Error(
                  `callback status was ${cbRes.status}, location=${cbRes.headers["location"]}`,
                );
              }
              if (cbRes.headers["location"] !== "/foo") {
                throw new Error(
                  `expected redirect to /foo, got ${cbRes.headers["location"]}`,
                );
              }

              const cbSetCookie = parseSetCookieAsString(cbRes.headers);
              if (!cbSetCookie) {
                throw new Error("callback response missing Set-Cookie");
              }
              const sessionMatch = cbSetCookie.match(
                /sso_session=([^;]+)/,
              );
              if (!sessionMatch) {
                throw new Error(
                  `sso_session cookie not found in: ${cbSetCookie}`,
                );
              }
              // JWT format: header.payload.signature — take [1] for payload
              const payloadB64 = sessionMatch[1].split(".")[1];
              const payloadJson = Buffer.from(
                payloadB64,
                "base64url",
              ).toString("utf8");
              const payload = JSON.parse(payloadJson) as {
                sub: string;
                iat: number;
                exp: number;
                iss?: string;
                aud?: string;
                email?: string;
                name?: string;
                picture?: string;
              };
              if (payload.sub !== "12345") {
                throw new Error(
                  `session.sub should be github user id, got ${payload.sub}`,
                );
              }
              // Identity claims
              if (payload.email !== "testuser@example.com") {
                throw new Error(
                  `session.email should be testuser@example.com, got ${payload.email}`,
                );
              }
              if (payload.name !== "Test User") {
                throw new Error(
                  `session.name should be "Test User", got ${payload.name}`,
                );
              }
              if (payload.picture !== "https://example.com/avatar.jpg") {
                throw new Error(
                  `session.picture should be the avatar_url, got ${payload.picture}`,
                );
              }
              // iss and aud must be present in the token
              if (payload.iss !== "https://auth.example.com") {
                throw new Error(
                  `session.iss should be https://auth.example.com, got ${payload.iss}`,
                );
              }
              if (payload.aud !== "https://app.example.com") {
                throw new Error(
                  `session.aud should be https://app.example.com, got ${payload.aud}`,
                );
              }

              const tokenBody = stub.lastTokenBody();
              if (!tokenBody) {
                throw new Error("stub did not receive a token request");
              }
              if (!/code_verifier=/.test(tokenBody)) {
                throw new Error(
                  `token body should include code_verifier, got: ${tokenBody}`,
                );
              }
              if (!/code=fake-code/.test(tokenBody)) {
                throw new Error(
                  `token body should include code=fake-code, got: ${tokenBody}`,
                );
              }
              if (stub.userFetches() !== 1) {
                throw new Error(
                  `expected exactly 1 /user fetch, got ${stub.userFetches()}`,
                );
              }
              // the email claim must come from the verified /user/emails
              // endpoint (fetched once), not the unverified profile field.
              if (stub.emailFetches() !== 1) {
                throw new Error(
                  `expected exactly 1 /user/emails fetch, got ${stub.emailFetches()}`,
                );
              }
            },
          },
        ],
      }),
    );
    failed = result.failed;
    for (const r of result.results) {
      const mark = r.passed ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
      console.log(`  ${mark} ${r.name} (${r.durationMs.toFixed(1)}ms)`);
      if (!r.passed && r.error) {
        console.log(`      ${r.error}`);
      }
    }
    console.log(
      `\n  ${result.passed}/${result.total} passed in ${result.durationMs.toFixed(1)}ms\n`,
    );
  } finally {
    await stub.stop();
    await rm(tmpDir, { recursive: true, force: true });
  }
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
