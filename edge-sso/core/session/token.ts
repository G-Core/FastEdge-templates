import { SignJWT, jwtVerify } from "jose";
import { base64Decode, base64urlEncode, encodeUtf8 } from "../util/bytes";

export type ClaimName = "email" | "name" | "picture" | "given_name" | "family_name";
export type IdentityClaims = Partial<Record<ClaimName, string>>;

/** All recognised ClaimName values — used to filter unknown keys from JWT payloads. */
export const CLAIM_NAMES: ClaimName[] = [
  "email",
  "name",
  "picture",
  "given_name",
  "family_name",
];

/**
 * Parse a comma-separated `SSO_CLAIMS` string (e.g. "email,name") into a
 * validated `ClaimName[]`. Unknown values are silently dropped.
 */
export function parseDefaultClaims(raw: string | null): ClaimName[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s): s is ClaimName => (CLAIM_NAMES as string[]).includes(s));
}

export interface SignTokenOptions {
  /** Issuer claim (`iss`). Omitted from token when empty or absent. */
  iss?: string;
  /** Audience claim (`aud`). Omitted from token when empty or absent. */
  aud?: string;
  /** Optional identity claims to embed in the token (email, name, picture, etc.). */
  claims?: IdentityClaims;
}

export async function importPrivateKeyPkcs8(pem: string): Promise<CryptoKey> {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const der = base64Decode(b64);
  return crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}

export async function signToken(
  sub: string,
  key: string | CryptoKey,
  ttlSeconds = 86400,
  options: SignTokenOptions = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const isAsymmetric = key instanceof CryptoKey;
  let builder = new SignJWT({ sub, ...(options.claims ?? {}) })
    .setProtectedHeader({ alg: isAsymmetric ? "ES256" : "HS256", typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds);
  if (options.iss) builder = builder.setIssuer(options.iss);
  if (options.aud) builder = builder.setAudience(options.aud);
  return await builder.sign(isAsymmetric ? key : encodeUtf8(key));
}

export async function verifyToken(
  token: string,
  key: string | CryptoKey,
): Promise<({ sub: string; exp: number; iat: number } & IdentityClaims) | null> {
  try {
    const isAsymmetric = key instanceof CryptoKey;
    const { payload } = await jwtVerify(
      token,
      isAsymmetric ? key : encodeUtf8(key),
      { algorithms: [isAsymmetric ? "ES256" : "HS256"] },
    );
    if (
      typeof payload.sub !== "string" ||
      typeof payload.exp !== "number" ||
      typeof payload.iat !== "number"
    ) {
      return null;
    }
    const identityClaims: IdentityClaims = {};
    for (const claim of CLAIM_NAMES) {
      if (typeof payload[claim] === "string") {
        identityClaims[claim] = payload[claim] as string;
      }
    }
    return { sub: payload.sub, exp: payload.exp, iat: payload.iat, ...identityClaims };
  } catch {
    return null;
  }
}

export async function signRelayCookie(
  redirectUrl: string,
  secret: string,
  ttlSeconds = 300,
): Promise<string> {
  return signToken(redirectUrl, secret, ttlSeconds);
}

export async function verifyRelayCookie(
  value: string,
  secret: string,
): Promise<string | null> {
  const claims = await verifyToken(value, secret);
  return claims ? claims.sub : null;
}

// --- SAML AuthnRequest binding -------------------------------------------
//
// Carried in `RelayState`, which the IdP echoes back on the callback POST (a
// cross-site POST where SameSite=Lax cookies are NOT sent — so the cookie
// cannot carry this). SAML caps RelayState at 80 bytes, so this is a compact
// `requestId.tag` rather than a JWT: `tag` is a truncated HMAC over the request
// id, proving WE minted it. The callback then requires the response's signed
// `InResponseTo` to equal this request id.

async function hmacSha256(secret: string, message: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    encodeUtf8(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, encodeUtf8(message));
  return new Uint8Array(sig);
}

/** Constant-time string compare (equal-length, ASCII). */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Produce the `RelayState` value binding a SAML login to `requestId`.
 * Format `requestId.tag` (≤80 bytes for a standard `_<32 hex>` id).
 */
export async function signRequestBinding(
  requestId: string,
  secret: string,
): Promise<string> {
  const mac = await hmacSha256(secret, requestId);
  return `${requestId}.${base64urlEncode(mac.slice(0, 16))}`;
}

/**
 * Verify a `RelayState` binding and return the bound `requestId`, or `null` if
 * the value is malformed or the tag does not verify.
 */
export async function verifyRequestBinding(
  relayState: string,
  secret: string,
): Promise<string | null> {
  const dot = relayState.lastIndexOf(".");
  if (dot <= 0 || dot === relayState.length - 1) return null;
  const requestId = relayState.slice(0, dot);
  const tag = relayState.slice(dot + 1);
  const expected = base64urlEncode((await hmacSha256(secret, requestId)).slice(0, 16));
  return timingSafeEqual(tag, expected) ? requestId : null;
}
