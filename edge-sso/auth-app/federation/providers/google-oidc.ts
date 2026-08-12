import { jwtVerify } from "jose";
import type { JWTPayload } from "jose";

type KeyInput = Parameters<typeof jwtVerify>[1];

const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

export async function verifyGoogleIdToken(
  idToken: string,
  jwks: KeyInput,
  audience: string,
  expectedNonce?: string,
): Promise<JWTPayload> {
  const { payload } = await jwtVerify(idToken, jwks, {
    audience,
    issuer: GOOGLE_ISSUERS,
    algorithms: ["RS256"],
  });
  // Bind the id_token to this login. The nonce we sent in the auth request
  // is echoed into the id_token; requiring it to match closes token-substitution
  // edge cases (a stolen/replayed id_token minted for a different login attempt).
  if (expectedNonce !== undefined && payload.nonce !== expectedNonce) {
    throw new Error("id_token nonce mismatch");
  }
  return payload;
}
