import { base64urlDecode, base64urlEncode, encodeUtf8 } from "../../util/bytes";

async function importHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encodeUtf8(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
}

export async function generatePkcePair(): Promise<PkcePair> {
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const codeVerifier = base64urlEncode(random);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encodeUtf8(codeVerifier),
  );
  const codeChallenge = base64urlEncode(digest);
  return { codeVerifier, codeChallenge };
}

export function generateOAuthState(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

export interface OAuthStatePayload {
  state: string;
  codeVerifier: string;
  redirect: string;
  /** OIDC nonce, bound into the id_token (Google). Absent for plain OAuth (GitHub). */
  nonce?: string;
}

interface SignedOAuthState extends OAuthStatePayload {
  iat: number;
  exp: number;
}

export async function signOAuthState(
  input: OAuthStatePayload,
  secret: string,
  ttlSeconds: number,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const full: SignedOAuthState = { ...input, iat: now, exp: now + ttlSeconds };
  const jsonBytes = new TextEncoder().encode(JSON.stringify(full));
  const payload = base64urlEncode(jsonBytes);
  const key = await importHmacKey(secret);
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    encodeUtf8(payload),
  );
  return `${payload}.${base64urlEncode(sig)}`;
}

export async function verifyOAuthState(
  signed: string,
  secret: string,
): Promise<OAuthStatePayload | null> {
  const parts = signed.split(".");
  if (parts.length !== 2) return null;
  const [payload, signature] = parts;
  const key = await importHmacKey(secret);
  const sigBytes = base64urlDecode(signature);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    sigBytes.buffer as ArrayBuffer,
    encodeUtf8(payload),
  );
  if (!valid) return null;
  try {
    const decoded = JSON.parse(
      new TextDecoder().decode(base64urlDecode(payload)),
    ) as SignedOAuthState;
    if (Math.floor(Date.now() / 1000) > decoded.exp) return null;
    const result: OAuthStatePayload = {
      state: decoded.state,
      codeVerifier: decoded.codeVerifier,
      redirect: decoded.redirect,
    };
    if (decoded.nonce !== undefined) result.nonce = decoded.nonce;
    return result;
  } catch {
    return null;
  }
}

/**
 * Decide whether an OIDC `email` claim is trustworthy enough to forward. An
 * unverified address could be one the user doesn't control, and the header
 * variant injects it for the origin to trust — so we require the issuer's
 * verification flag. Google sets `email_verified`; Microsoft sets `xms_edov`
 * (email domain owner verified, sometimes serialized as the string "true").
 * Returns the email only when the flag is set and `email` is a string.
 */
export function verifiedEmail(
  claims: Record<string, unknown>,
  verifiedFlag: "email_verified" | "xms_edov",
): string | undefined {
  const flag = claims[verifiedFlag];
  const isVerified = flag === true || flag === "true";
  return isVerified && typeof claims.email === "string"
    ? (claims.email as string)
    : undefined;
}
