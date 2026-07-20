#!/usr/bin/env node
/**
 * Generates a P-256 ECDSA keypair for ES256 session JWT signing.
 *
 * Output:
 *   SESSION_SIGNING_KEY  — private key as PKCS#8 PEM  → FastEdge secret
 *   SESSION_PUBLIC_JWK   — public key as JWK JSON      → FastEdge env var (filter + auth-app JWKS endpoint)
 *
 * Usage:
 *   node scripts/gen-ec-keypair.mjs
 *   node scripts/gen-ec-keypair.mjs --dotenv   # emi .env-compatible lines
 */

const { subtle } = globalThis.crypto;

const pair = await subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"],
);

const pkcs8Der = await subtle.exportKey("pkcs8", pair.privateKey);
const pkcs8B64 = Buffer.from(pkcs8Der).toString("base64");
const pemLines = pkcs8B64.match(/.{1,64}/g).join("\n");
const pkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${pemLines}\n-----END PRIVATE KEY-----`;

const publicJwk = await subtle.exportKey("jwk", pair.publicKey);
// Remove key_ops / ext — not needed by the filter or JWKS consumers
delete publicJwk.key_ops;
delete publicJwk.ext;
const publicJwkJson = JSON.stringify(publicJwk);

const dotenv = process.argv.includes("--dotenv");

if (dotenv) {
  // Single-line PEM (newlines replaced with \n literal) for dotenv. Keys are
  // prefixed the way the templates' .env files and test runners expect them.
  const pemOneLine = pkcs8Pem.replace(/\n/g, "\\n");
  console.log(`FASTEDGE_VAR_SECRET_SESSION_SIGNING_KEY=${pemOneLine}`);
  console.log(`FASTEDGE_VAR_ENV_SESSION_PUBLIC_JWK=${publicJwkJson}`);
} else {
  console.log(
    "# ── SESSION_SIGNING_KEY (FastEdge secret — private, keep secure) ──",
  );
  console.log(pkcs8Pem);
  console.log();
  console.log(
    "# ── SESSION_PUBLIC_JWK (FastEdge env var — filter + auth-app JWKS endpoint) ──",
  );
  console.log(publicJwkJson);
}
