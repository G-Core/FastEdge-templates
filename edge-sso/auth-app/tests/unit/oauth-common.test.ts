import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generatePkcePair,
  signOAuthState,
  verifyOAuthState,
  verifiedEmail,
} from "../../federation/providers/common.js";

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

test("generatePkcePair: verifier matches [A-Za-z0-9-._~]{43,128}", async () => {
  const { codeVerifier } = await generatePkcePair();
  assert.match(codeVerifier, /^[A-Za-z0-9\-._~]{43,128}$/);
});

test("generatePkcePair: challenge equals base64url(SHA-256(verifier))", async () => {
  const { codeVerifier, codeChallenge } = await generatePkcePair();
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  );
  const expected = base64url(new Uint8Array(digest));
  assert.equal(codeChallenge, expected);
});

test("generatePkcePair: successive calls return different values", async () => {
  const a = await generatePkcePair();
  const b = await generatePkcePair();
  assert.notEqual(a.codeVerifier, b.codeVerifier);
  assert.notEqual(a.codeChallenge, b.codeChallenge);
});

test("signOAuthState + verifyOAuthState: roundtrip", async () => {
  const input = { state: "abc", codeVerifier: "verifier123", redirect: "/foo" };
  const signed = await signOAuthState(input, "secret", 600);
  const verified = await verifyOAuthState(signed, "secret");
  assert.deepEqual(verified, input);
});

test("signOAuthState + verifyOAuthState: roundtrips the OIDC nonce", async () => {
  const input = {
    state: "abc",
    codeVerifier: "verifier123",
    redirect: "/foo",
    nonce: "n-xyz789",
  };
  const signed = await signOAuthState(input, "secret", 600);
  const verified = await verifyOAuthState(signed, "secret");
  assert.deepEqual(verified, input);
});

test("verifyOAuthState: tampered payload fails", async () => {
  const input = { state: "abc", codeVerifier: "verifier123", redirect: "/foo" };
  const signed = await signOAuthState(input, "secret", 600);
  const [payload, sig] = signed.split(".");
  const tampered = payload.slice(0, -2) + "XX" + "." + sig;
  const verified = await verifyOAuthState(tampered, "secret");
  assert.equal(verified, null);
});

test("verifyOAuthState: wrong secret fails", async () => {
  const input = { state: "abc", codeVerifier: "verifier123", redirect: "/foo" };
  const signed = await signOAuthState(input, "secret-one", 600);
  const verified = await verifyOAuthState(signed, "secret-two");
  assert.equal(verified, null);
});

test("verifyOAuthState: expired cookie fails", async () => {
  const input = { state: "abc", codeVerifier: "verifier123", redirect: "/foo" };
  const signed = await signOAuthState(input, "secret", -10);
  const verified = await verifyOAuthState(signed, "secret");
  assert.equal(verified, null);
});

// verifiedEmail — only forward an email the issuer marked verified.

test("verifiedEmail: Google email_verified=true → returns email", () => {
  const r = verifiedEmail({ email: "a@b.com", email_verified: true }, "email_verified");
  assert.equal(r, "a@b.com");
});

test("verifiedEmail: email_verified=false → undefined", () => {
  const r = verifiedEmail({ email: "a@b.com", email_verified: false }, "email_verified");
  assert.equal(r, undefined);
});

test("verifiedEmail: verification flag absent → undefined", () => {
  const r = verifiedEmail({ email: "a@b.com" }, "email_verified");
  assert.equal(r, undefined);
});

test("verifiedEmail: verified but email missing → undefined", () => {
  const r = verifiedEmail({ email_verified: true }, "email_verified");
  assert.equal(r, undefined);
});

test("verifiedEmail: Microsoft xms_edov=true → returns email", () => {
  const r = verifiedEmail({ email: "a@b.com", xms_edov: true }, "xms_edov");
  assert.equal(r, "a@b.com");
});

test('verifiedEmail: xms_edov string "true" (Microsoft serialization) → returns email', () => {
  const r = verifiedEmail({ email: "a@b.com", xms_edov: "true" }, "xms_edov");
  assert.equal(r, "a@b.com");
});

test("verifiedEmail: xms_edov absent → undefined (unverified Microsoft email dropped)", () => {
  const r = verifiedEmail({ email: "a@b.com" }, "xms_edov");
  assert.equal(r, undefined);
});
