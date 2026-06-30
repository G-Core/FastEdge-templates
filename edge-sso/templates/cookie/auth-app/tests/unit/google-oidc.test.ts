import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SignJWT,
  exportJWK,
  generateKeyPair,
  createLocalJWKSet,
  type JWK,
  type JWTPayload,
} from "jose";
import { verifyGoogleIdToken } from "@sso/core/providers/google-oidc";

const AUDIENCE = "test-client-id.apps.googleusercontent.com";

interface Fixture {
  privateKey: CryptoKey;
  jwks: ReturnType<typeof createLocalJWKSet>;
  kid: string;
}

async function makeFixture(): Promise<Fixture> {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = (await exportJWK(publicKey)) as JWK;
  jwk.kid = "test-kid-1";
  jwk.use = "sig";
  jwk.alg = "RS256";
  return {
    privateKey: privateKey as CryptoKey,
    jwks: createLocalJWKSet({ keys: [jwk] }),
    kid: "test-kid-1",
  };
}

async function makeIdToken(
  fx: Fixture,
  opts: {
    sub?: string;
    iss?: string;
    aud?: string | string[];
    exp?: string | number;
    iat?: number;
    nonce?: string;
  } = {},
): Promise<string> {
  const payload: JWTPayload = { sub: opts.sub ?? "google-user-123" };
  if (opts.nonce !== undefined) payload.nonce = opts.nonce;
  const builder = new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: fx.kid })
    .setIssuer(opts.iss ?? "https://accounts.google.com")
    .setAudience(opts.aud ?? AUDIENCE)
    .setIssuedAt(opts.iat)
    .setExpirationTime(opts.exp ?? "1h");
  return builder.sign(fx.privateKey);
}

test("verifyGoogleIdToken: accepts valid signed JWT with correct iss/aud/exp", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx);
  const claims: JWTPayload = await verifyGoogleIdToken(token, fx.jwks, AUDIENCE);
  assert.equal(claims.sub, "google-user-123");
});

test("verifyGoogleIdToken: rejects tampered signature", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx);
  const parts = token.split(".");
  const sig = parts[2];
  // Flip a char mid-signature (the last base64url char may only hold padding bits).
  const midIdx = Math.floor(sig.length / 2);
  const tamperedSig =
    sig.slice(0, midIdx) +
    (sig[midIdx] === "A" ? "B" : "A") +
    sig.slice(midIdx + 1);
  const tampered = [parts[0], parts[1], tamperedSig].join(".");
  await assert.rejects(verifyGoogleIdToken(tampered, fx.jwks, AUDIENCE));
});

test("verifyGoogleIdToken: rejects wrong issuer", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { iss: "https://evil.example.com" });
  await assert.rejects(verifyGoogleIdToken(token, fx.jwks, AUDIENCE));
});

test("verifyGoogleIdToken: rejects wrong audience", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { aud: "wrong-client-id" });
  await assert.rejects(verifyGoogleIdToken(token, fx.jwks, AUDIENCE));
});

test("verifyGoogleIdToken: rejects expired token", async () => {
  const fx = await makeFixture();
  const nowSec = Math.floor(Date.now() / 1000);
  const token = await makeIdToken(fx, {
    iat: nowSec - 7200,
    exp: nowSec - 3600,
  });
  await assert.rejects(verifyGoogleIdToken(token, fx.jwks, AUDIENCE));
});

test("verifyGoogleIdToken: accepts 'accounts.google.com' issuer (Google emits both forms)", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { iss: "accounts.google.com" });
  const claims = await verifyGoogleIdToken(token, fx.jwks, AUDIENCE);
  assert.equal(claims.sub, "google-user-123");
});

// nonce binding
test("verifyGoogleIdToken: accepts matching nonce", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { nonce: "n-abc123" });
  const claims = await verifyGoogleIdToken(token, fx.jwks, AUDIENCE, "n-abc123");
  assert.equal(claims.sub, "google-user-123");
});

test("verifyGoogleIdToken: rejects mismatched nonce", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { nonce: "n-abc123" });
  await assert.rejects(
    verifyGoogleIdToken(token, fx.jwks, AUDIENCE, "n-different"),
    /nonce mismatch/i,
  );
});

test("verifyGoogleIdToken: rejects missing nonce when one is expected", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx); // no nonce in token
  await assert.rejects(
    verifyGoogleIdToken(token, fx.jwks, AUDIENCE, "n-expected"),
    /nonce mismatch/i,
  );
});

test("verifyGoogleIdToken: no nonce check when none expected", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { nonce: "n-abc123" });
  const claims = await verifyGoogleIdToken(token, fx.jwks, AUDIENCE);
  assert.equal(claims.sub, "google-user-123");
});
