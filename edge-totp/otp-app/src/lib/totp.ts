import { base32Decode, base32Encode } from "./base32.js";
import { timingSafeEqual } from "./safeEqual.js";

export interface TotpOptions {
  digits?: number;
  period?: number;
  algorithm?: string;
  drift?: number;
}

function webCryptoHash(algorithm: string): string {
  switch (algorithm.toUpperCase()) {
    case "SHA256": return "SHA-256";
    case "SHA512": return "SHA-512";
    default: return "SHA-1"; // SHA1 is the RFC 6238 / authenticator-app default
  }
}

async function importSeed(seedBytes: Uint8Array, algorithm: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    seedBytes as unknown as ArrayBuffer,
    { name: "HMAC", hash: webCryptoHash(algorithm) },
    false,
    ["sign"],
  );
}

/**
 * Generate a TOTP code for a given seed and counter value.
 * Exported for testing against known RFC 6238 vectors.
 */
export async function generateCode(
  seed: string,
  counter: number,
  digits = 6,
  algorithm = "SHA1",
): Promise<string> {
  const key = await importSeed(base32Decode(seed), algorithm);

  // 8-byte big-endian counter (RFC 4226 §5.3)
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);

  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));

  // RFC 4226 dynamic truncation
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(code % 10 ** digits).padStart(digits, "0");
}

/**
 * Find the absolute step counter that matches code (within the drift window).
 * Returns the matching step, or null. Used by the verify handler so it can
 * record the exact step for POP-local replay guarding.
 */
export async function findMatchingStep(
  code: string,
  seed: string,
  opts: TotpOptions = {},
): Promise<number | null> {
  const digits = opts.digits ?? 6;
  const period = opts.period ?? 30;
  const algorithm = opts.algorithm ?? "SHA1";
  const drift = opts.drift ?? 1;

  const normalised = code.replace(/\s/g, "");
  if (normalised.length !== digits) return null;

  const counter = Math.floor(Date.now() / 1000 / period);

  for (let step = -drift; step <= drift; step++) {
    const expected = await generateCode(seed, counter + step, digits, algorithm);
    if (timingSafeEqual(normalised, expected)) return counter + step;
  }

  return null;
}

export async function generateSecret(): Promise<string> {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

export function otpauthUri(
  secret: string,
  account: string,
  issuer: string,
  opts: { digits?: number; period?: number; algorithm?: string } = {},
): string {
  const params = new URLSearchParams({
    secret,
    issuer,
    digits: String(opts.digits ?? 6),
    period: String(opts.period ?? 30),
    algorithm: opts.algorithm ?? "SHA1",
  });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?${params}`;
}
