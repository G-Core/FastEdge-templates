import { test } from "node:test";
import assert from "node:assert/strict";
import {
  verifyHandoffTicket,
  signMfaSession,
  signProof,
  buildJwks,
  importEs256PrivateKey,
  signEnrollCookie,
  verifyEnrollCookie,
  ticketFingerprint,
} from "../../src/lib/jwt.js";
import { SignJWT } from "jose";

const SECRET = "test-handoff-secret-32-bytes-long!";

function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

async function mintHandoffTicket(
  sub: string,
  next: string,
  secret: string,
  ttl = 90,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub, next })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .sign(encodeUtf8(secret));
}

// --- Handoff ticket ---

test("verifyHandoffTicket: valid token returns claims", async () => {
  const token = await mintHandoffTicket("user1", "/dashboard", SECRET);
  const claims = await verifyHandoffTicket(token, SECRET);
  assert.equal(claims?.sub, "user1");
  assert.equal(claims?.next, "/dashboard");
});

test("verifyHandoffTicket: wrong secret returns null", async () => {
  const token = await mintHandoffTicket("user1", "/dashboard", SECRET);
  const claims = await verifyHandoffTicket(token, "wrong-secret");
  assert.equal(claims, null);
});

test("verifyHandoffTicket: expired token returns null", async () => {
  const token = await mintHandoffTicket("user1", "/dashboard", SECRET, -10);
  const claims = await verifyHandoffTicket(token, SECRET);
  assert.equal(claims, null);
});

test("verifyHandoffTicket: missing next claim returns null", async () => {
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ sub: "user1" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(now)
    .setExpirationTime(now + 90)
    .sign(encodeUtf8(SECRET));
  const claims = await verifyHandoffTicket(token, SECRET);
  assert.equal(claims, null);
});

test("verifyHandoffTicket: ticket without exp returns null", async () => {
  const token = await new SignJWT({ sub: "user1", next: "/dashboard" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .sign(encodeUtf8(SECRET));
  assert.equal(await verifyHandoffTicket(token, SECRET), null);
});

test("verifyHandoffTicket: ticket older than maxTokenAge returns null", async () => {
  // iat 20 min ago but exp still in the future — only the maxTokenAge cap rejects it.
  const old = Math.floor(Date.now() / 1000) - 20 * 60;
  const token = await new SignJWT({ sub: "user1", next: "/dashboard" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(old)
    .setExpirationTime(old + 60 * 60)
    .sign(encodeUtf8(SECRET));
  assert.equal(await verifyHandoffTicket(token, SECRET), null);
});

test("verifyHandoffTicket: token carrying a seed claim returns null", async () => {
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ sub: "user1", next: "/", seed: "JBSWY3DP" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(now)
    .setExpirationTime(now + 90)
    .sign(encodeUtf8(SECRET));
  assert.equal(await verifyHandoffTicket(token, SECRET), null);
});

// --- enroll cookie (purpose binding) ---

test("signEnrollCookie + verifyEnrollCookie: roundtrip", async () => {
  const token = await signEnrollCookie("user1", "JBSWY3DP", "/dash", SECRET, 600);
  const claims = await verifyEnrollCookie(token, SECRET);
  assert.equal(claims?.sub, "user1");
  assert.equal(claims?.seed, "JBSWY3DP");
  assert.equal(claims?.next, "/dash");
});

test("verifyEnrollCookie: token without enroll purpose returns null", async () => {
  // A handoff-shaped token that happens to carry a seed must not pass as an enroll cookie.
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ sub: "user1", next: "/", seed: "JBSWY3DP" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(now)
    .setExpirationTime(now + 600)
    .sign(encodeUtf8(SECRET));
  assert.equal(await verifyEnrollCookie(token, SECRET), null);
});

// --- mfa_session (verified in production by the Rust filter, not in TS) ---

test("signMfaSession: emits HS256 token with sub/amr/exp/aud/iss", async () => {
  const token = await signMfaSession("alice", SECRET, 3600, {
    iss: "totp-app",
    aud: "myapp",
  });
  const [headerB64, payloadB64] = token.split(".");
  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
  assert.equal(header.alg, "HS256");
  assert.equal(payload.sub, "alice");
  assert.deepEqual(payload.amr, ["otp"]);
  assert.equal(payload.iss, "totp-app");
  assert.equal(payload.aud, "myapp");
  assert.ok(payload.exp > payload.iat);
});

// --- ticketFingerprint (single-use ticket key derivation) ---

test("ticketFingerprint: stable for the same token", async () => {
  const token = await mintHandoffTicket("user1", "/dashboard", SECRET);
  assert.equal(await ticketFingerprint(token), await ticketFingerprint(token));
});

test("ticketFingerprint: differs for distinct tokens", async () => {
  const a = await mintHandoffTicket("user1", "/dashboard", SECRET);
  const b = await mintHandoffTicket("user2", "/dashboard", SECRET);
  assert.notEqual(await ticketFingerprint(a), await ticketFingerprint(b));
});

test("ticketFingerprint: bounded-length lowercase hex", async () => {
  const token = await mintHandoffTicket("user1", "/dashboard", SECRET);
  const fp = await ticketFingerprint(token);
  assert.equal(fp.length, 32);
  assert.match(fp, /^[0-9a-f]+$/);
});

// --- buildJwks ---

test("buildJwks: wraps parsed JWK in keys array", () => {
  const jwk = { kty: "EC", crv: "P-256", x: "abc", y: "def", use: "sig" };
  const result = buildJwks(JSON.stringify(jwk));
  assert.deepEqual(result, { keys: [jwk] });
});

test("buildJwks: throws on invalid JSON", () => {
  assert.throws(() => buildJwks("not json"), /SyntaxError|Unexpected/);
});

// --- ES256 proof (requires an actual keypair) ---

test("signProof: produces a JWT signed with ES256", async () => {
  // Generate a test keypair using the Web Crypto API (Node has this)
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  const token = await signProof("bob", keyPair.privateKey, 90, "jti-abc", {
    iss: "totp-app",
    aud: "myapp",
  });

  // Decode header to confirm ES256 alg
  const [headerB64] = token.split(".");
  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
  assert.equal(header.alg, "ES256");

  // Decode payload to confirm claims
  const [, payloadB64] = token.split(".");
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
  assert.equal(payload.sub, "bob");
  assert.equal(payload.jti, "jti-abc");
  assert.deepEqual(payload.amr, ["otp"]);
});

test("importEs256PrivateKey: accepts PKCS8 PEM from gen-ec-keypair.mjs format", async () => {
  // Generate + export a key pair to produce a real PKCS8 PEM for testing
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const pkcs8Der = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const b64 = Buffer.from(pkcs8Der).toString("base64");
  const lines = b64.match(/.{1,64}/g)!.join("\n");
  const pem = `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----`;

  // importEs256PrivateKey must accept this PEM without throwing
  const imported = await importEs256PrivateKey(pem);
  assert.equal(typeof imported, "object");
});
