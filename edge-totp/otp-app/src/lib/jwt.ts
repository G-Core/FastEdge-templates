import { SignJWT, jwtVerify } from "jose";

function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export async function importEs256PrivateKey(pem: string): Promise<CryptoKey> {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}

// --- Handoff ticket (HS256, signed by origin, verified by edge) ---

export interface HandoffClaims {
  sub: string;
  next: string;
}

export async function verifyHandoffTicket(
  token: string,
  secret: string,
  opts: { iss?: string; aud?: string } = {},
): Promise<HandoffClaims | null> {
  try {
    const { payload } = await jwtVerify(token, encodeUtf8(secret), {
      algorithms: ["HS256"],
      // A handoff ticket MUST carry exp. jose validates exp only when present,
      // so without this an origin that forgets to set exp would mint a ticket
      // that never expires and can be replayed indefinitely (it rides in the
      // URL). Require it and cap the absolute age as defence-in-depth.
      requiredClaims: ["exp"],
      maxTokenAge: "10 minutes",
      ...(opts.iss ? { issuer: opts.iss } : {}),
      ...(opts.aud ? { audience: opts.aud } : {}),
    });
    // A handoff ticket is minted by the origin and never carries a seed. Reject
    // any token that does — it would be an enroll cookie (same key, overlapping
    // claims) being replayed through the handoff path.
    if (typeof payload.sub !== "string" || typeof payload["next"] !== "string") {
      return null;
    }
    if ("seed" in payload) return null;
    return { sub: payload.sub, next: payload["next"] as string };
  } catch {
    return null;
  }
}

/**
 * Stable, unguessable fingerprint of a handoff ticket, derived from its
 * signature segment. Used as a Cache key to enforce single-use: the signature
 * is unique per minted ticket, so two distinct tickets never collide and the
 * same ticket always maps to the same key. We hash it (rather than use the raw
 * signature) to keep the cache key short and bounded.
 */
export async function ticketFingerprint(token: string): Promise<string> {
  const sig = token.slice(token.lastIndexOf(".") + 1);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(sig),
  );
  const bytes = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex.slice(0, 32);
}

// --- mfa_session (HS256, edge-internal: HTTP app ↔ Rust filter) ---

export async function signMfaSession(
  sub: string,
  secret: string,
  ttlSeconds: number,
  opts: { iss?: string; aud?: string } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  let builder = new SignJWT({ sub, amr: ["otp"] })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds);
  if (opts.iss) builder = builder.setIssuer(opts.iss);
  if (opts.aud) builder = builder.setAudience(opts.aud);
  return builder.sign(encodeUtf8(secret));
}

// mfa_session is verified in production by the Rust filter (otp-filter), not
// here — the app only signs it. No TS verifier is kept to avoid a second,
// untested verification path drifting from the filter's.

// --- ES256 one-time proof + JWKS (Profile B) ---

export async function signProof(
  sub: string,
  privateKey: CryptoKey,
  ttlSeconds: number,
  jti: string,
  opts: { iss?: string; aud?: string } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  let builder = new SignJWT({ sub, amr: ["otp"], jti })
    .setProtectedHeader({ alg: "ES256", typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds);
  if (opts.iss) builder = builder.setIssuer(opts.iss);
  if (opts.aud) builder = builder.setAudience(opts.aud);
  return builder.sign(privateKey);
}

// --- Enrollment cookie (HS256, short-lived, carries pending seed + next) ---
// Written during GET /activate (before KV write); verified during POST /activate.
// Avoids persisting an unconfirmed seed to KV — the seed is only written after
// the user proves they scanned correctly.

export interface EnrollClaims {
  sub: string;
  seed: string;
  next: string;
}

// The enroll cookie shares HANDOFF_KEY with the handoff ticket and has
// overlapping claims. A `purpose` marker (asserted on verify, and rejected on
// the handoff path) makes the two token types non-interchangeable.
const ENROLL_PURPOSE = "totp-enroll";

export async function signEnrollCookie(
  sub: string,
  seed: string,
  next: string,
  secret: string,
  ttlSeconds: number,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub, seed, next, purpose: ENROLL_PURPOSE })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(encodeUtf8(secret));
}

export async function verifyEnrollCookie(
  token: string,
  secret: string,
): Promise<EnrollClaims | null> {
  try {
    const { payload } = await jwtVerify(token, encodeUtf8(secret), {
      algorithms: ["HS256"],
    });
    if (payload["purpose"] !== ENROLL_PURPOSE) return null;
    if (
      typeof payload.sub !== "string" ||
      typeof payload["seed"] !== "string" ||
      typeof payload["next"] !== "string"
    ) return null;
    return {
      sub: payload.sub,
      seed: payload["seed"] as string,
      next: payload["next"] as string,
    };
  } catch {
    return null;
  }
}

// --- JWKS ---

/**
 * Build the JWKS response body from the pre-computed public JWK env var.
 * exportKey is unavailable in the FastEdge runtime — the keypair is generated
 * offline (scripts/gen-ec-keypair.mjs) and the public JWK stored in
 * MFA_PROOF_PUBLIC_JWK (see storage-and-secrets.md).
 */
export function buildJwks(publicJwkJson: string): { keys: unknown[] } {
  const parsed = JSON.parse(publicJwkJson);
  return { keys: [parsed] };
}
