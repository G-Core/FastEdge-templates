import { CLAIM_NAMES, type ClaimName, type IdentityClaims } from "../../session/token.js";
import type { SamlAttributes } from "./response.js";

/**
 * Built-in fallback chains for common IdP attribute naming conventions.
 * Covers Okta, Azure AD SAML, Shibboleth/eduGAIN (OID URNs), and plain
 * attribute names. `picture` has no standard SAML equivalent — always empty.
 */
const SAML_ATTR_DEFAULTS: Record<ClaimName, string[]> = {
  email: [
    "email",
    "mail",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
  ],
  name: [
    "displayName",
    "cn",
    "name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "urn:oid:2.5.4.3",
  ],
  given_name: [
    "givenName",
    "firstName",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    "urn:oid:2.5.4.42",
  ],
  family_name: [
    "sn",
    "surname",
    "lastName",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    "urn:oid:2.5.4.4",
  ],
  picture: [],
};

/**
 * Parse the `SAML_CLAIM_MAP` env var value (JSON object mapping ClaimName →
 * SAML attribute name). Unknown keys and non-string values are silently dropped.
 * Returns an empty object for null/empty/invalid input.
 */
export function parseSamlClaimMap(
  raw: string | null,
): Partial<Record<ClaimName, string>> {
  if (!raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
      return {};
    const result: Partial<Record<ClaimName, string>> = {};
    for (const key of CLAIM_NAMES) {
      const val = (parsed as Record<string, unknown>)[key];
      if (typeof val === "string") result[key] = val;
    }
    return result;
  } catch {
    return {};
  }
}

function firstValue(v: string | string[]): string {
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Extract identity claims from a SAML attribute map.
 *
 * For each requested claim the lookup order is:
 *   1. Custom attribute name from `claimMap` (from `SAML_CLAIM_MAP` env var)
 *   2. Built-in fallback chain (`SAML_ATTR_DEFAULTS`)
 *
 * Claims that cannot be resolved are omitted from the result (never null).
 */
export function extractSamlClaims(
  attributes: SamlAttributes,
  requestedClaims: ClaimName[],
  claimMap: Partial<Record<ClaimName, string>> = {},
): IdentityClaims {
  const result: IdentityClaims = {};
  for (const claim of requestedClaims) {
    // Custom mapping takes precedence
    const customAttr = claimMap[claim];
    if (customAttr !== undefined) {
      const val = attributes[customAttr];
      if (val !== undefined) {
        result[claim] = firstValue(val);
        continue;
      }
    }
    // Fall through to built-in defaults
    for (const attr of SAML_ATTR_DEFAULTS[claim]) {
      const val = attributes[attr];
      if (val !== undefined) {
        result[claim] = firstValue(val);
        break;
      }
    }
  }
  return result;
}
