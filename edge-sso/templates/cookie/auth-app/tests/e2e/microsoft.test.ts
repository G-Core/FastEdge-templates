import { createServer } from "node:http";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SignJWT,
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  type JWK,
} from "jose";
import { parseSetCookieAsString } from "../_cookies.js";
import {
  defineTestSuite,
  runTestSuite,
} from "@gcoredev/fastedge-test/test";

const MICROSOFT_SUB = "ms-user-sub-abcdef-12345";
const MICROSOFT_CLIENT_ID = "test-microsoft-client-id";
const MICROSOFT_TENANT = "common";
// The tid embedded in the stub id_token — represents the actual tenant when common is used
const SIGNING_TENANT = "stub-tenant-id-98765";

interface StubServer {
  port: number;
  stop: () => Promise<void>;
  lastTokenBody: () => string | null;
  jwksFetches: () => number;
  setIdToken: (token: string) => void;
}

async function startStubServer(jwks: { keys: JWK[] }): Promise<StubServer> {
  let lastTokenBody: string | null = null;
  let jwksFetches = 0;
  let idToken: string | null = null;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      // Match both single-tenant (/tenant-id/...) and multi-tenant (/common/...) paths
      if (req.url?.endsWith("/oauth2/v2.0/token") && req.method === "POST") {
        lastTokenBody = body;
        if (!idToken) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "id_token not set by test" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            id_token: idToken,
            access_token: "fake-access-token",
            token_type: "Bearer",
            expires_in: 3600,
          }),
        );
        return;
      }
      if (req.url?.endsWith("/discovery/v2.0/keys") && req.method === "GET") {
        jwksFetches++;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(jwks));
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
    jwksFetches: () => jwksFetches,
    setIdToken: (token: string) => {
      idToken = token;
    },
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

  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = (await exportJWK(publicKey)) as JWK;
  publicJwk.kid = "stub-ms-kid-1";
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";
  const jwks = { keys: [publicJwk] };

  // mint on demand with the nonce from the auth request, as a real IdP would.
  // tid is SIGNING_TENANT; iss is derived from it (multi-tenant common flow).
  const mintIdToken = (nonce: string) =>
    new SignJWT({
      sub: MICROSOFT_SUB,
      email: "msuser@example.com",
      // The app forwards a Microsoft email only when it is marked verified via
      // xms_edov (email domain owner verified). A real verified-email happy path
      // emits this; the mock must too, or verifiedEmail() correctly drops it.
      xms_edov: true,
      name: "MS Test User",
      tid: SIGNING_TENANT,
      nonce,
    })
      .setProtectedHeader({ alg: "RS256", kid: "stub-ms-kid-1" })
      .setIssuer(`https://login.microsoftonline.com/${SIGNING_TENANT}/v2.0`)
      .setAudience(MICROSOFT_CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);

  const stub = await startStubServer(jwks);
  const tmpDir = await mkdtemp(join(tmpdir(), "sso-e2e-microsoft-"));
  const envContent =
    [
      "FASTEDGE_VAR_ENV_IDP_SSO_URL=https://idp.example.com/sso",
      "FASTEDGE_VAR_ENV_IDP_ENTITY_ID=https://idp.example.com",
      "FASTEDGE_VAR_SECRET_IDP_CERT=-----BEGIN CERTIFICATE-----\\nfake\\n-----END CERTIFICATE-----",
      "FASTEDGE_VAR_ENV_SP_ENTITY_ID=https://auth.example.com",
      "FASTEDGE_VAR_ENV_SP_ACS_URL=https://auth.example.com/auth/callback",
      "FASTEDGE_VAR_SECRET_SESSION_SECRET=e2e-test-session-secret",
      `FASTEDGE_VAR_SECRET_SESSION_SIGNING_KEY=${signingKeyB64}`,
      `FASTEDGE_VAR_ENV_MICROSOFT_CLIENT_ID=${MICROSOFT_CLIENT_ID}`,
      "FASTEDGE_VAR_SECRET_MICROSOFT_CLIENT_SECRET=test-microsoft-secret",
      "FASTEDGE_VAR_ENV_MICROSOFT_REDIRECT_URI=https://auth.example.com/auth/callback/microsoft",
      `FASTEDGE_VAR_ENV_MICROSOFT_OAUTH_BASE_URL=http://127.0.0.1:${stub.port}`,
      `FASTEDGE_VAR_ENV_MICROSOFT_TENANT=${MICROSOFT_TENANT}`,
      "FASTEDGE_VAR_ENV_SSO_ISSUER=https://auth.example.com",
      "FASTEDGE_VAR_ENV_SSO_AUDIENCE=https://app.example.com",
      "FASTEDGE_VAR_ENV_SSO_CLAIMS=email,name",
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
            name: "microsoft e2e: happy path sets sso_session with microsoft sub and redirects to original url",
            run: async (runner) => {
              const loginRes = await runner.execute({
                path: "/auth/login/microsoft?redirect=/foo",
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
              // capture the nonce and mint the stub token with it
              const nonce = authorizeUrl.searchParams.get("nonce");
              if (!nonce) {
                throw new Error("authorize URL missing nonce param");
              }
              stub.setIdToken(await mintIdToken(nonce));
              const setCookie = parseSetCookieAsString(loginRes.headers);
              if (!setCookie) {
                throw new Error("login response missing Set-Cookie");
              }
              const stateCookieMatch = setCookie.match(/ms_oauth_state=([^;]+)/);
              if (!stateCookieMatch) {
                throw new Error(
                  `ms_oauth_state cookie not found in: ${setCookie}`,
                );
              }

              const cbRes = await runner.execute({
                path: `/auth/callback/microsoft?state=${encodeURIComponent(state)}&code=fake-code`,
                method: "GET",
                headers: { cookie: `ms_oauth_state=${stateCookieMatch[1]}` },
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
              };
              if (payload.sub !== MICROSOFT_SUB) {
                throw new Error(
                  `session.sub should be ${MICROSOFT_SUB}, got ${payload.sub}`,
                );
              }
              if (payload.email !== "msuser@example.com") {
                throw new Error(
                  `session.email should be msuser@example.com, got ${payload.email}`,
                );
              }
              if (payload.name !== "MS Test User") {
                throw new Error(
                  `session.name should be "MS Test User", got ${payload.name}`,
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

              // Assert token exchange used form-urlencoded (not JSON body)
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
                  `token body should include code_verifier, got: ${tokenBody}`,
                );
              }
              if (!tokenBody.includes("grant_type=authorization_code")) {
                throw new Error(
                  `token body should include grant_type=authorization_code, got: ${tokenBody}`,
                );
              }
              if (stub.jwksFetches() < 1) {
                throw new Error(
                  `expected >=1 JWKS fetch, got ${stub.jwksFetches()}`,
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
