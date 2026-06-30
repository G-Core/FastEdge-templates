import { getSecret } from "fastedge::secret";
import { importPrivateKeyPkcs8 } from "./token.js";

export async function requireEs256SigningKey(): Promise<CryptoKey> {
  const pem = getSecret("SESSION_SIGNING_KEY");
  if (!pem) {
    throw new Error(
      "SESSION_SIGNING_KEY secret is required for the cookie variant — run scripts/gen-ec-keypair.mjs to generate a keypair",
    );
  }
  return importPrivateKeyPkcs8(pem);
}

export async function requireHs256Secret(): Promise<string> {
  const secret = getSecret("SESSION_SECRET");
  if (!secret) {
    throw new Error("SESSION_SECRET secret is required");
  }
  return secret;
}
