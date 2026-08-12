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
import { verifyMicrosoftIdToken } from "../../federation/providers/microsoft-oidc.js";

const AUDIENCE = "test-microsoft-client-id";
const TENANT = "test-tenant-abcdef-1234";
const TENANT_ISSUER = `https://login.microsoftonline.com/${TENANT}/v2.0`;

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
    tid?: string;
  } = {},
): Promise<string> {
  const payload: JWTPayload = {
    sub: opts.sub ?? "ms-user-sub-123",
  };
  // Only set tid when specified — lets us test the missing-tid case
  if (opts.tid !== undefined) payload.tid = opts.tid;
  if (opts.nonce !== undefined) payload.nonce = opts.nonce;
  const builder = new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: fx.kid })
    .setIssuer(opts.iss ?? TENANT_ISSUER)
    .setAudience(opts.aud ?? AUDIENCE)
    .setIssuedAt(opts.iat)
    .setExpirationTime(opts.exp ?? "1h");
  return builder.sign(fx.privateKey);
}

// Single-tenant tests

test("verifyMicrosoftIdToken: accepts valid signed JWT for single tenant", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT });
  const claims = await verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, TENANT);
  assert.equal(claims.sub, "ms-user-sub-123");
});

test("verifyMicrosoftIdToken: rejects tampered signature", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT });
  const parts = token.split(".");
  const sig = parts[2];
  const midIdx = Math.floor(sig.length / 2);
  const tamperedSig =
    sig.slice(0, midIdx) +
    (sig[midIdx] === "A" ? "B" : "A") +
    sig.slice(midIdx + 1);
  const tampered = [parts[0], parts[1], tamperedSig].join(".");
  await assert.rejects(verifyMicrosoftIdToken(tampered, fx.jwks, AUDIENCE, TENANT));
});

test("verifyMicrosoftIdToken: rejects wrong issuer", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, {
    tid: TENANT,
    iss: "https://evil.example.com",
  });
  await assert.rejects(verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, TENANT));
});

test("verifyMicrosoftIdToken: rejects wrong audience", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT, aud: "wrong-client" });
  await assert.rejects(verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, TENANT));
});

test("verifyMicrosoftIdToken: rejects expired token", async () => {
  const fx = await makeFixture();
  const nowSec = Math.floor(Date.now() / 1000);
  const token = await makeIdToken(fx, {
    tid: TENANT,
    iat: nowSec - 7200,
    exp: nowSec - 3600,
  });
  await assert.rejects(verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, TENANT));
});

// Nonce tests

test("verifyMicrosoftIdToken: accepts matching nonce", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT, nonce: "n-abc123" });
  const claims = await verifyMicrosoftIdToken(
    token,
    fx.jwks,
    AUDIENCE,
    TENANT,
    "n-abc123",
  );
  assert.equal(claims.sub, "ms-user-sub-123");
});

test("verifyMicrosoftIdToken: rejects mismatched nonce", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT, nonce: "n-abc123" });
  await assert.rejects(
    verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, TENANT, "n-different"),
    /nonce mismatch/i,
  );
});

test("verifyMicrosoftIdToken: rejects missing nonce when one is expected", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT }); // no nonce in token
  await assert.rejects(
    verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, TENANT, "n-expected"),
    /nonce mismatch/i,
  );
});

test("verifyMicrosoftIdToken: no nonce check when none expected", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT, nonce: "n-abc123" });
  const claims = await verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, TENANT);
  assert.equal(claims.sub, "ms-user-sub-123");
});

// Multi-tenant tests

test("verifyMicrosoftIdToken: multi-tenant (common) derives issuer from tid claim", async () => {
  const fx = await makeFixture();
  // Token has tid = TENANT, iss = TENANT_ISSUER — both match when derived from tid
  const token = await makeIdToken(fx, { tid: TENANT });
  const claims = await verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, "common");
  assert.equal(claims.sub, "ms-user-sub-123");
});

test("verifyMicrosoftIdToken: multi-tenant (organizations) derives issuer from tid claim", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT });
  const claims = await verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, "organizations");
  assert.equal(claims.sub, "ms-user-sub-123");
});

test("verifyMicrosoftIdToken: multi-tenant rejects token with missing tid", async () => {
  const fx = await makeFixture();
  // No tid= in opts, so makeIdToken omits it from the payload
  const token = await makeIdToken(fx); // tid omitted
  await assert.rejects(
    verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, "common"),
    /tid claim/i,
  );
});

test("verifyMicrosoftIdToken: multi-tenant rejects token whose issuer does not match derived tenant", async () => {
  const fx = await makeFixture();
  // tid claims one tenant, iss claims a different one — signature is valid but issuer mismatch
  const token = await makeIdToken(fx, {
    tid: TENANT,
    iss: "https://login.microsoftonline.com/different-tenant-id/v2.0",
  });
  await assert.rejects(verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, "common"));
});

// Tenant allowlist (guardrail against the wide-open "common" default)

test("verifyMicrosoftIdToken: accepts token whose tid is in the allowlist", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT });
  const claims = await verifyMicrosoftIdToken(
    token,
    fx.jwks,
    AUDIENCE,
    "common",
    undefined,
    [TENANT, "another-tenant"],
  );
  assert.equal(claims.sub, "ms-user-sub-123");
});

test("verifyMicrosoftIdToken: rejects token whose tid is not in the allowlist", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT });
  await assert.rejects(
    verifyMicrosoftIdToken(token, fx.jwks, AUDIENCE, "common", undefined, [
      "only-this-other-tenant",
    ]),
    /not in MICROSOFT_ALLOWED_TENANTS/i,
  );
});

test("verifyMicrosoftIdToken: empty allowlist disables the tenant check", async () => {
  const fx = await makeFixture();
  const token = await makeIdToken(fx, { tid: TENANT });
  const claims = await verifyMicrosoftIdToken(
    token,
    fx.jwks,
    AUDIENCE,
    "common",
    undefined,
    [],
  );
  assert.equal(claims.sub, "ms-user-sub-123");
});
