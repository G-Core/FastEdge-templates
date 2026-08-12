import { test } from "node:test";
import assert from "node:assert/strict";
import {
  signToken,
  verifyToken,
  importPrivateKeyPkcs8,
  signRequestBinding,
  verifyRequestBinding,
} from "../../session/token.js";

function decodePayload(jwt: string): Record<string, unknown> {
  const payloadB64 = jwt.split(".")[1];
  return JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
}

test("signToken: payload has sub, iat, exp", async () => {
  const jwt = await signToken("user-1", "secret", 3600);
  const p = decodePayload(jwt);
  assert.equal(p.sub, "user-1");
  assert.equal(typeof p.iat, "number");
  assert.equal(typeof p.exp, "number");
  assert.equal((p.exp as number) - (p.iat as number), 3600);
});

test("signToken: omits iss and aud when not provided", async () => {
  const jwt = await signToken("user-1", "secret", 3600);
  const p = decodePayload(jwt);
  assert.equal(p.iss, undefined);
  assert.equal(p.aud, undefined);
});

test("signToken: includes iss when provided", async () => {
  const jwt = await signToken("user-1", "secret", 3600, {
    iss: "https://auth.example.com",
  });
  const p = decodePayload(jwt);
  assert.equal(p.iss, "https://auth.example.com");
});

test("signToken: includes aud when provided", async () => {
  const jwt = await signToken("user-1", "secret", 3600, {
    aud: "https://app.example.com",
  });
  const p = decodePayload(jwt);
  assert.equal(p.aud, "https://app.example.com");
});

test("signToken: includes both iss and aud when provided", async () => {
  const jwt = await signToken("user-1", "secret", 3600, {
    iss: "https://auth.example.com",
    aud: "https://app.example.com",
  });
  const p = decodePayload(jwt);
  assert.equal(p.iss, "https://auth.example.com");
  assert.equal(p.aud, "https://app.example.com");
});

test("signToken: empty string options are omitted", async () => {
  const jwt = await signToken("user-1", "secret", 3600, { iss: "", aud: "" });
  const p = decodePayload(jwt);
  assert.equal(p.iss, undefined);
  assert.equal(p.aud, undefined);
});

async function generateTestKeyPair(): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  pkcs8Pem: string;
}> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const pkcs8Der = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  const b64 = Buffer.from(pkcs8Der).toString("base64");
  const pem = `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----`;
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, pkcs8Pem: pem };
}

test("signToken ES256: header has alg ES256", async () => {
  const { privateKey } = await generateTestKeyPair();
  const jwt = await signToken("user-1", privateKey, 3600);
  const header = JSON.parse(
    Buffer.from(jwt.split(".")[0], "base64url").toString(),
  );
  assert.equal(header.alg, "ES256");
});

test("signToken ES256: payload has sub, iat, exp", async () => {
  const { privateKey } = await generateTestKeyPair();
  const jwt = await signToken("user-1", privateKey, 3600);
  const p = decodePayload(jwt);
  assert.equal(p.sub, "user-1");
  assert.equal(typeof p.iat, "number");
  assert.equal(typeof p.exp, "number");
  assert.equal((p.exp as number) - (p.iat as number), 3600);
});

test("verifyToken ES256: accepts valid token signed with matching key", async () => {
  const { privateKey, publicKey } = await generateTestKeyPair();
  const jwt = await signToken("user-2", privateKey, 3600);
  const result = await verifyToken(jwt, publicKey);
  assert.ok(result !== null);
  assert.equal(result!.sub, "user-2");
});

test("verifyToken ES256: rejects token signed with a different key", async () => {
  const { privateKey } = await generateTestKeyPair();
  const { publicKey: wrongPublicKey } = await generateTestKeyPair();
  const jwt = await signToken("user-3", privateKey, 3600);
  const result = await verifyToken(jwt, wrongPublicKey);
  assert.equal(result, null);
});

test("importPrivateKeyPkcs8: returns a usable signing key", async () => {
  const { pkcs8Pem, publicKey } = await generateTestKeyPair();
  const importedKey = await importPrivateKeyPkcs8(pkcs8Pem);
  const jwt = await signToken("user-4", importedKey, 3600);
  const result = await verifyToken(jwt, publicKey);
  assert.ok(result !== null);
  assert.equal(result!.sub, "user-4");
});

test("signToken: includes identity claims in payload when provided", async () => {
  const jwt = await signToken("user-1", "secret", 3600, {
    claims: { email: "user@example.com", name: "Test User", picture: "https://example.com/pic.jpg" },
  });
  const p = decodePayload(jwt);
  assert.equal(p.email, "user@example.com");
  assert.equal(p.name, "Test User");
  assert.equal(p.picture, "https://example.com/pic.jpg");
});

test("signToken: omits identity claims when not provided", async () => {
  const jwt = await signToken("user-1", "secret", 3600);
  const p = decodePayload(jwt);
  assert.equal(p.email, undefined);
  assert.equal(p.name, undefined);
  assert.equal(p.picture, undefined);
});

test("signToken: empty claims object results in no extra payload fields", async () => {
  const jwt = await signToken("user-1", "secret", 3600, { claims: {} });
  const p = decodePayload(jwt);
  assert.equal(p.email, undefined);
  assert.equal(p.name, undefined);
});

test("verifyToken: returns identity claims present in token payload", async () => {
  const jwt = await signToken("user-1", "secret", 3600, {
    claims: { email: "user@example.com", name: "Test User" },
  });
  const result = await verifyToken(jwt, "secret");
  assert.ok(result !== null);
  assert.equal(result!.email, "user@example.com");
  assert.equal(result!.name, "Test User");
  assert.equal(result!.picture, undefined);
});

test("verifyToken: returned object contains only known fields (no arbitrary JWT claims)", async () => {
  const jwt = await signToken("user-1", "secret", 3600, {
    claims: { email: "user@example.com" },
  });
  const result = await verifyToken(jwt, "secret");
  assert.ok(result !== null);
  const allowedKeys = new Set(["sub", "iat", "exp", "email", "name", "picture", "given_name", "family_name"]);
  for (const key of Object.keys(result!)) {
    assert.ok(allowedKeys.has(key), `unexpected key in verifyToken result: ${key}`);
  }
});

// ---- SAML AuthnRequest binding ----

test("signRequestBinding/verifyRequestBinding: round-trips the request id", async () => {
  const rid = "_0123456789abcdef0123456789abcdef";
  const relay = await signRequestBinding(rid, "secret");
  assert.equal(await verifyRequestBinding(relay, "secret"), rid);
});

test("signRequestBinding: fits within the SAML 80-byte RelayState limit", async () => {
  const rid = "_0123456789abcdef0123456789abcdef";
  const relay = await signRequestBinding(rid, "secret");
  assert.ok(relay.length <= 80, `RelayState too long: ${relay.length} bytes`);
});

test("verifyRequestBinding: rejects a tampered request id", async () => {
  const rid = "_0123456789abcdef0123456789abcdef";
  const relay = await signRequestBinding(rid, "secret");
  // swap the id while keeping the original tag
  const tag = relay.slice(relay.lastIndexOf(".") + 1);
  const forged = `_ffffffffffffffffffffffffffffffff.${tag}`;
  assert.equal(await verifyRequestBinding(forged, "secret"), null);
});

test("verifyRequestBinding: rejects a wrong-secret tag", async () => {
  const rid = "_0123456789abcdef0123456789abcdef";
  const relay = await signRequestBinding(rid, "secret");
  assert.equal(await verifyRequestBinding(relay, "other-secret"), null);
});

test("verifyRequestBinding: rejects malformed values", async () => {
  assert.equal(await verifyRequestBinding("no-dot", "secret"), null);
  assert.equal(await verifyRequestBinding(".onlytag", "secret"), null);
  assert.equal(await verifyRequestBinding("onlyid.", "secret"), null);
  assert.equal(await verifyRequestBinding("", "secret"), null);
});
