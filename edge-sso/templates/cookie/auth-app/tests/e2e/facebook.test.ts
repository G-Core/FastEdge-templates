import { createServer } from "node:http";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, exportPKCS8 } from "jose";
import { parseSetCookieAsString } from "../_cookies.js";
import {
  defineTestSuite,
  runTestSuite,
} from "@gcoredev/fastedge-test/test";

const FACEBOOK_USER_ID = "fb-user-12345678";
const FACEBOOK_CLIENT_ID = "test-facebook-app-id";
const API_VERSION = "v21.0";

interface StubServer {
  port: number;
  stop: () => Promise<void>;
  lastTokenBody: () => string | null;
  userFetches: () => number;
}

async function startStubServer(): Promise<StubServer> {
  let lastTokenBody: string | null = null;
  let userFetches = 0;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      if (
        req.url === `/${API_VERSION}/oauth/access_token` &&
        req.method === "POST"
      ) {
        lastTokenBody = body;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: "fake-fb-access-token",
            token_type: "bearer",
          }),
        );
        return;
      }
      // Match /v21.0/me?fields=... regardless of query string
      if (req.url?.startsWith(`/${API_VERSION}/me`) && req.method === "GET") {
        userFetches++;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            id: FACEBOOK_USER_ID,
            name: "FB Test User",
            email: "fbuser@example.com",
            picture: {
              data: {
                url: "https://example.com/fb-photo.jpg",
                is_silhouette: false,
              },
            },
          }),
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
  };
}

async function main() {
  const { privateKey: signingKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  const signingKeyB64 = (await exportPKCS8(signingKey))
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");

  const stub = await startStubServer();
  const tmpDir = await mkdtemp(join(tmpdir(), "sso-e2e-facebook-"));
  const envContent =
    [
      "FASTEDGE_VAR_ENV_IDP_SSO_URL=https://idp.example.com/sso",
      "FASTEDGE_VAR_ENV_IDP_ENTITY_ID=https://idp.example.com",
      "FASTEDGE_VAR_SECRET_IDP_CERT=-----BEGIN CERTIFICATE-----\\nfake\\n-----END CERTIFICATE-----",
      "FASTEDGE_VAR_ENV_SP_ENTITY_ID=https://auth.example.com",
      "FASTEDGE_VAR_ENV_SP_ACS_URL=https://auth.example.com/auth/callback",
      "FASTEDGE_VAR_SECRET_SESSION_SECRET=e2e-test-session-secret",
      `FASTEDGE_VAR_SECRET_SESSION_SIGNING_KEY=${signingKeyB64}`,
      `FASTEDGE_VAR_ENV_FACEBOOK_CLIENT_ID=${FACEBOOK_CLIENT_ID}`,
      "FASTEDGE_VAR_SECRET_FACEBOOK_CLIENT_SECRET=test-facebook-secret",
      "FASTEDGE_VAR_ENV_FACEBOOK_REDIRECT_URI=https://auth.example.com/auth/callback/facebook",
      `FASTEDGE_VAR_ENV_FACEBOOK_API_BASE_URL=http://127.0.0.1:${stub.port}`,
      `FASTEDGE_VAR_ENV_FACEBOOK_API_VERSION=${API_VERSION}`,
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
            name: "facebook e2e: happy path sets sso_session with facebook user id and redirects to original url",
            run: async (runner) => {
              const loginRes = await runner.execute({
                path: "/auth/login/facebook?redirect=/foo",
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
              // Facebook is OAuth2-only — no nonce (that's OIDC-specific)
              if (authorizeUrl.searchParams.has("nonce")) {
                throw new Error("authorize URL should not have nonce param (Facebook is not OIDC)");
              }
              const codeChallenge = authorizeUrl.searchParams.get("code_challenge");
              if (!codeChallenge) {
                throw new Error("authorize URL missing code_challenge param (PKCE)");
              }
              const setCookie = parseSetCookieAsString(loginRes.headers);
              if (!setCookie) {
                throw new Error("login response missing Set-Cookie");
              }
              const stateCookieMatch = setCookie.match(/fb_oauth_state=([^;]+)/);
              if (!stateCookieMatch) {
                throw new Error(
                  `fb_oauth_state cookie not found in: ${setCookie}`,
                );
              }

              const cbRes = await runner.execute({
                path: `/auth/callback/facebook?state=${encodeURIComponent(state)}&code=fake-code`,
                method: "GET",
                headers: { cookie: `fb_oauth_state=${stateCookieMatch[1]}` },
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
              const sessionMatch = cbSetCookie.match(/sso_session=([^;]+)/);
              if (!sessionMatch) {
                throw new Error(
                  `sso_session cookie not found in: ${cbSetCookie}`,
                );
              }
              const payloadB64 = sessionMatch[1].split(".")[1];
              const payloadJson = Buffer.from(payloadB64, "base64url").toString(
                "utf8",
              );
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
              if (payload.sub !== FACEBOOK_USER_ID) {
                throw new Error(
                  `session.sub should be ${FACEBOOK_USER_ID}, got ${payload.sub}`,
                );
              }
              if (payload.email !== "fbuser@example.com") {
                throw new Error(
                  `session.email should be fbuser@example.com, got ${payload.email}`,
                );
              }
              if (payload.name !== "FB Test User") {
                throw new Error(
                  `session.name should be "FB Test User", got ${payload.name}`,
                );
              }
              if (payload.picture !== "https://example.com/fb-photo.jpg") {
                throw new Error(
                  `session.picture should be the Facebook photo URL, got ${payload.picture}`,
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

              // Token exchange should use form-urlencoded with PKCE verifier
              const tokenBody = stub.lastTokenBody();
              if (!tokenBody) {
                throw new Error("stub did not receive a token request");
              }
              if (!tokenBody.includes("code=fake-code")) {
                throw new Error(
                  `token body should include code=fake-code, got: ${tokenBody}`,
                );
              }
              if (!tokenBody.includes("code_verifier=")) {
                throw new Error(
                  `token body should include code_verifier (PKCE), got: ${tokenBody}`,
                );
              }
              if (!tokenBody.includes("grant_type=authorization_code")) {
                throw new Error(
                  `token body should include grant_type=authorization_code, got: ${tokenBody}`,
                );
              }
              if (stub.userFetches() < 1) {
                throw new Error(
                  `expected >=1 /me fetch, got ${stub.userFetches()}`,
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
