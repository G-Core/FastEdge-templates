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

const GOOGLE_SUB = "google-user-sub-12345";
const GOOGLE_CLIENT_ID = "test-google-client.apps.googleusercontent.com";

interface StubServer {
  port: number;
  stop: () => Promise<void>;
  lastTokenBody: () => string | null;
  jwksFetches: () => number;
  setIdToken: (token: string) => void;
}

async function startStubServer(
  jwks: { keys: JWK[] },
): Promise<StubServer> {
  let lastTokenBody: string | null = null;
  let jwksFetches = 0;
  // Set by the test once login reveals the nonce: the id_token must echo
  // the auth request's nonce, which isn't known until the login step has run.
  let idToken: string | null = null;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      if (req.url === "/token" && req.method === "POST") {
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
            access_token: "fake-access",
            token_type: "Bearer",
            expires_in: 3600,
          }),
        );
        return;
      }
      if (req.url === "/jwks" && req.method === "GET") {
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
  const { privateKey: signingKey } = await generateKeyPair("ES256", { extractable: true });
  const signingKeyB64 = (await exportPKCS8(signingKey))
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");

  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = (await exportJWK(publicKey)) as JWK;
  publicJwk.kid = "stub-kid-1";
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";
  const jwks = { keys: [publicJwk] };

  // the id_token must echo the `nonce` from the auth request, which is only
  // generated when the login step runs — so mint it on demand with that nonce.
  const mintIdToken = (nonce: string) =>
    new SignJWT({
      sub: GOOGLE_SUB,
      email: "test@example.com",
      email_verified: true,
      name: "Test User",
      picture: "https://example.com/photo.jpg",
      nonce,
    })
      .setProtectedHeader({ alg: "RS256", kid: "stub-kid-1" })
      .setIssuer("https://accounts.google.com")
      .setAudience(GOOGLE_CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);

  const stub = await startStubServer(jwks);
  const tmpDir = await mkdtemp(join(tmpdir(), "sso-e2e-google-"));
  const envContent =
    [
      "FASTEDGE_VAR_ENV_IDP_SSO_URL=https://idp.example.com/sso",
      "FASTEDGE_VAR_ENV_IDP_ENTITY_ID=https://idp.example.com",
      "FASTEDGE_VAR_SECRET_IDP_CERT=-----BEGIN CERTIFICATE-----\\nfake\\n-----END CERTIFICATE-----",
      "FASTEDGE_VAR_ENV_SP_ENTITY_ID=https://auth.example.com",
      "FASTEDGE_VAR_ENV_SP_ACS_URL=https://auth.example.com/auth/callback",
      "FASTEDGE_VAR_SECRET_SESSION_SECRET=e2e-test-session-secret",
      `FASTEDGE_VAR_SECRET_SESSION_SIGNING_KEY=${signingKeyB64}`,
      `FASTEDGE_VAR_ENV_GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}`,
      "FASTEDGE_VAR_SECRET_GOOGLE_CLIENT_SECRET=test-google-secret",
      "FASTEDGE_VAR_ENV_GOOGLE_REDIRECT_URI=https://auth.example.com/auth/callback/google",
      `FASTEDGE_VAR_ENV_GOOGLE_OAUTH_BASE_URL=http://127.0.0.1:${stub.port}`,
      `FASTEDGE_VAR_ENV_GOOGLE_JWKS_URL=http://127.0.0.1:${stub.port}/jwks`,
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
            name: "google e2e: happy path sets sso_session with google sub and redirects to original url",
            run: async (runner) => {
              const loginRes = await runner.execute({
                path: "/auth/login/google?redirect=/foo",
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
              // capture the nonce the provider put in the auth request and
              // mint the stub's id_token to echo it, as a real IdP would.
              const nonce = authorizeUrl.searchParams.get("nonce");
              if (!nonce) {
                throw new Error("authorize URL missing nonce param");
              }
              stub.setIdToken(await mintIdToken(nonce));
              const setCookie = parseSetCookieAsString(loginRes.headers);
              if (!setCookie) {
                throw new Error("login response missing Set-Cookie");
              }
              const stateCookieMatch = setCookie.match(
                /gg_oauth_state=([^;]+)/,
              );
              if (!stateCookieMatch) {
                throw new Error(
                  `gg_oauth_state cookie not found in: ${setCookie}`,
                );
              }

              const cbRes = await runner.execute({
                path: `/auth/callback/google?state=${encodeURIComponent(state)}&code=fake-code`,
                method: "GET",
                headers: { cookie: `gg_oauth_state=${stateCookieMatch[1]}` },
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
              if (payload.sub !== GOOGLE_SUB) {
                throw new Error(
                  `session.sub should be google sub (${GOOGLE_SUB}), got ${payload.sub}`,
                );
              }
              // Identity claims
              if (payload.email !== "test@example.com") {
                throw new Error(
                  `session.email should be test@example.com, got ${payload.email}`,
                );
              }
              if (payload.name !== "Test User") {
                throw new Error(
                  `session.name should be "Test User", got ${payload.name}`,
                );
              }
              if (payload.picture !== "https://example.com/photo.jpg") {
                throw new Error(
                  `session.picture should be the Google picture URL, got ${payload.picture}`,
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
              // Unlike GitHub (form-urlencoded via URLSearchParams), the Google
              // provider intentionally sends a JSON body — see the workaround
              // comment in providers/google.ts (FastEdge strips the
              // form-urlencoded Content-Type, so Google's gateway defaults to
              // JSON parsing). Assert against the parsed JSON, not a
              // form-encoded `key=value` shape.
              let parsedTokenBody: Record<string, unknown>;
              try {
                parsedTokenBody = JSON.parse(tokenBody);
              } catch {
                throw new Error(
                  `token body should be JSON, got: ${tokenBody}`,
                );
              }
              if (!parsedTokenBody.code_verifier) {
                throw new Error(
                  `token body should include code_verifier, got: ${tokenBody}`,
                );
              }
              if (parsedTokenBody.code !== "fake-code") {
                throw new Error(
                  `token body should include code=fake-code, got: ${tokenBody}`,
                );
              }
              if (parsedTokenBody.grant_type !== "authorization_code") {
                throw new Error(
                  `token body should include grant_type=authorization_code, got: ${tokenBody}`,
                );
              }
              if (stub.jwksFetches() < 1) {
                throw new Error(
                  `expected >=1 /jwks fetch, got ${stub.jwksFetches()}`,
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
