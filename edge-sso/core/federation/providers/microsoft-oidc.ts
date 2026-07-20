import { jwtVerify, decodeJwt } from "jose";
import type { JWTPayload } from "jose";

type KeyInput = Parameters<typeof jwtVerify>[1];

const TENANT_WILDCARDS = new Set(["common", "organizations", "consumers"]);

function buildIssuer(tenantId: string): string {
  return `https://login.microsoftonline.com/${tenantId}/v2.0`;
}

/**
 * Verify a Microsoft identity platform id_token.
 *
 * Multi-tenant apps (tenant = "common"/"organizations"/"consumers"): the token's
 * `tid` claim carries the signing tenant; we derive the expected issuer from it.
 * The signature check that follows cryptographically binds the issuer to the key,
 * so reading `tid` before verification does not introduce a security gap.
 *
 * Single-tenant: the issuer is computed from the configured tenant directly.
 */
export async function verifyMicrosoftIdToken(
  idToken: string,
  jwks: KeyInput,
  audience: string,
  tenant: string,
  expectedNonce?: string,
  allowedTenants?: string[],
): Promise<JWTPayload> {
  let issuer: string;
  if (TENANT_WILDCARDS.has(tenant)) {
    const decoded = decodeJwt(idToken);
    const tid = decoded.tid;
    if (typeof tid !== "string" || !tid) {
      throw new Error(
        "id_token missing tid claim (required for multi-tenant issuer validation)",
      );
    }
    issuer = buildIssuer(tid);
  } else {
    issuer = buildIssuer(tenant);
  }

  const { payload } = await jwtVerify(idToken, jwks, {
    audience,
    issuer,
    algorithms: ["RS256"],
  });

  // Bind the id_token to this login attempt (same pattern as Google).
  if (expectedNonce !== undefined && payload.nonce !== expectedNonce) {
    throw new Error("id_token nonce mismatch");
  }

  // Tenant guardrail: with a wildcard MICROSOFT_TENANT (common/organizations/
  // consumers) the signature only proves the token came from *some* Microsoft
  // tenant — by itself it lets any Microsoft account anywhere sign in. When the
  // operator supplies an allowlist, require the verified `tid` to be in it so a
  // deployment can be restricted to its own tenant(s).
  if (allowedTenants && allowedTenants.length > 0) {
    const tid = typeof payload.tid === "string" ? payload.tid : "";
    if (!allowedTenants.includes(tid)) {
      throw new Error(
        `id_token tenant '${tid || "<none>"}' is not in MICROSOFT_ALLOWED_TENANTS`,
      );
    }
  }
  return payload;
}
