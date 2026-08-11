import { getEnv } from "fastedge::env";
import { getSecret } from "fastedge::secret";
import { DEFAULT_KEY_PREFIX } from "./seed/kv.js";
import { validateInt, parseBool } from "./lib/validate.js";

export interface Config {
  authPrefix: string;
  issuer: string;
  digits: number;
  period: number;
  algorithm: string;
  drift: number;
  ticketTtl: number;
  proofTtl: number;
  mfaSessionTtl: number;
  enrollTtl: number;
  maxAttempts: number;
  allowSelfEnrollment: boolean;
  mfaSessionCookie: string;
  mfaProofCookie: string;
  mfaAudience: string | null;
  mfaIssuer: string | null;
  kvStoreId: string | null;
  kvKeyPrefix: string;
  gcoreApiUrl: string;
  brandName: string | null;
  brandLogoUrl: string | null;
  brandFaviconUrl: string | null;
  brandButtonColor: string | null;
  brandButtonHoverColor: string | null;
}

export interface Secrets {
  handoffKey: string | null;
  mfaSessionKey: string | null;
  mfaProofSigningKey: string | null;
  enrollApiKey: string | null;
  gcoreApiToken: string | null;
}

/**
 * Parse an integer env var, applying `fallback` when unset/empty and rejecting
 * anything that is not a whole number within [min, max]. We fail loudly rather
 * than let `parseInt` silently coerce: `parseInt("6abc")` is 6 (hides a typo)
 * and `parseInt("abc")` is NaN (turns into a confusing run-time misbehaviour —
 * e.g. drift=NaN makes the verify loop never run and every code "fails"). A
 * misconfigured edge app should surface the bad value, not degrade quietly.
 */
function intEnv(
  name: string,
  fallback: number,
  bounds: { min?: number; max?: number } = {},
): number {
  return validateInt(name, getEnv(name), fallback, bounds);
}

export function loadConfig(): Config {
  const authPrefix = (getEnv("AUTH_PREFIX") ?? "/auth/totp").replace(/\/$/, "");
  return {
    authPrefix,
    issuer: getEnv("TOTP_ISSUER") ?? "TOTP",
    digits: intEnv("TOTP_DIGITS", 6, { min: 6, max: 8 }),
    period: intEnv("TOTP_PERIOD", 30, { min: 1, max: 300 }),
    algorithm: getEnv("TOTP_ALGORITHM") ?? "SHA1",
    drift: intEnv("TOTP_DRIFT", 1, { min: 0, max: 10 }),
    ticketTtl: intEnv("TICKET_TTL", 90, { min: 1 }),
    proofTtl: intEnv("PROOF_TTL", 90, { min: 1 }),
    mfaSessionTtl: intEnv("MFA_SESSION_TTL", 28800, { min: 1 }),
    enrollTtl: intEnv("ENROLL_TTL", 600, { min: 1 }),
    maxAttempts: intEnv("MAX_ATTEMPTS", 5, { min: 1 }),
    allowSelfEnrollment: parseBool(getEnv("ALLOW_SELF_ENROLLMENT"), true),
    mfaSessionCookie: getEnv("MFA_SESSION_COOKIE") ?? "mfa_session",
    mfaProofCookie: getEnv("MFA_PROOF_COOKIE") ?? "mfa_proof",
    mfaAudience: getEnv("MFA_AUDIENCE") ?? null,
    mfaIssuer: getEnv("MFA_ISSUER") ?? null,
    kvStoreId: getEnv("KV_STORE_ID"),
    kvKeyPrefix: getEnv("KV_KEY_PREFIX") ?? DEFAULT_KEY_PREFIX,
    gcoreApiUrl: getEnv("GCORE_API_URL") ?? "https://api.gcore.com",
    brandName: getEnv("TOTP_BRAND_NAME") ?? null,
    brandLogoUrl: getEnv("TOTP_BRAND_LOGO_URL") ?? null,
    brandFaviconUrl: getEnv("TOTP_BRAND_FAVICON_URL") ?? null,
    brandButtonColor: getEnv("TOTP_BRAND_BUTTON_COLOR") ?? null,
    brandButtonHoverColor: getEnv("TOTP_BRAND_BUTTON_HOVER_COLOR") ?? null,
  };
}

export function loadSecrets(): Secrets {
  return {
    handoffKey: getSecret("HANDOFF_KEY"),
    mfaSessionKey: getSecret("MFA_SESSION_KEY"),
    mfaProofSigningKey: getSecret("MFA_PROOF_SIGNING_KEY"),
    enrollApiKey: getSecret("ENROLL_API_KEY"),
    gcoreApiToken: getSecret("GCORE_API_TOKEN"),
  };
}
