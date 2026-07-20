import type { Context } from "hono";
import { getEnv } from "fastedge::env";
import { createRemoteJWKSet } from "jose";
import {
  generateOAuthState,
  generatePkcePair,
  signOAuthState,
  verifyOAuthState,
  verifiedEmail,
} from "./common.js";
import { verifyMicrosoftIdToken } from "./microsoft-oidc.js";
import { signToken } from "../../session/token.js";
import { resolveRuntimeConfig, requireAudience } from "../config.js";
import { validateRedirect } from "../util/redirect.js";
import { requireEnv, requireSecret } from "../../util/env";

const STATE_COOKIE = "ms_oauth_state";
// Short TTL — same reasoning as Google/GitHub state cookies (see google.ts comment).
const STATE_TTL_SECONDS = 180;
const SESSION_COOKIE = "sso_session";
const SESSION_TTL_SECONDS = 86400;

function resolveTenant(): string {
  return getEnv("MICROSOFT_TENANT") || "common";
}

const TENANT_WILDCARDS = new Set(["common", "organizations", "consumers"]);

/** Tenant ids permitted to sign in (MICROSOFT_ALLOWED_TENANTS, comma-separated). */
function resolveAllowedTenants(): string[] {
  return (getEnv("MICROSOFT_ALLOWED_TENANTS") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function microsoftEndpoints(tenant: string): {
  authorizeUrl: string;
  tokenUrl: string;
  jwksUrl: string;
} {
  const base = getEnv("MICROSOFT_OAUTH_BASE_URL");
  if (base) {
    return {
      authorizeUrl: `${base}/${tenant}/oauth2/v2.0/authorize`,
      tokenUrl: `${base}/${tenant}/oauth2/v2.0/token`,
      jwksUrl: `${base}/${tenant}/discovery/v2.0/keys`,
    };
  }
  return {
    authorizeUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
    tokenUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
    jwksUrl: `https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys`,
  };
}

// Log the real reason server-side; never expose it in the redirect URL.
function errorRedirect(c: Context, reason: string): Response {
  console.error(`[microsoft] ${reason}`);
  return c.redirect("/auth/error", 302);
}

export async function handleMicrosoftLogin(c: Context): Promise<Response> {
  try {
    const clientId = requireEnv("MICROSOFT_CLIENT_ID");
    const redirectUri = requireEnv("MICROSOFT_REDIRECT_URI");
    const sessionSecret = requireSecret("SESSION_SECRET");
    const tenant = resolveTenant();
    const { allowedOrigins } = resolveRuntimeConfig();
    // Validate redirect before storing it in the signed state cookie.
    const redirect = validateRedirect(c.req.query("redirect"), allowedOrigins);
    console.log(
      `[microsoft] login: raw redirect=${c.req.query("redirect") ?? "<none>"} → stored=${redirect}`,
    );

    const state = generateOAuthState();
    // OIDC nonce, bound into the id_token and checked at callback.
    const nonce = generateOAuthState();
    const { codeVerifier, codeChallenge } = await generatePkcePair();

    const signedState = await signOAuthState(
      { state, codeVerifier, redirect, nonce },
      sessionSecret,
      STATE_TTL_SECONDS,
    );

    c.header(
      "Set-Cookie",
      `${STATE_COOKIE}=${signedState}; HttpOnly; Secure; SameSite=Lax; Path=/auth; Max-Age=${STATE_TTL_SECONDS}`,
    );

    const { authorizeUrl } = microsoftEndpoints(tenant);
    const params = new URLSearchParams({
      client_id: clientId,
      response_type: "code",
      scope: "openid email profile",
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      redirect_uri: redirectUri,
      response_mode: "query",
    });

    return c.redirect(`${authorizeUrl}?${params.toString()}`, 302);
  } catch (err) {
    return errorRedirect(
      c,
      `login error: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`,
    );
  }
}

export async function handleMicrosoftCallback(
  c: Context,
  signingKeyResolver: () => Promise<string | CryptoKey>,
): Promise<Response> {
  try {
    const sessionSecret = requireSecret("SESSION_SECRET");

    const stateParam = c.req.query("state");
    const code = c.req.query("code");

    if (!code) return errorRedirect(c, "callback: missing code parameter");
    if (!stateParam) return errorRedirect(c, "callback: missing state parameter");

    const cookieHeader = c.req.header("cookie") ?? "";
    const match = cookieHeader.match(/(?:^|;\s*)ms_oauth_state=([^;]+)/);
    if (!match) return errorRedirect(c, "callback: missing state cookie");

    const verified = await verifyOAuthState(match[1], sessionSecret);
    if (!verified) {
      return errorRedirect(c, "callback: invalid or expired state cookie");
    }
    if (verified.state !== stateParam) {
      return errorRedirect(c, "callback: state parameter mismatch");
    }

    const clientId = requireEnv("MICROSOFT_CLIENT_ID");
    const clientSecret = requireSecret("MICROSOFT_CLIENT_SECRET");
    const redirectUri = requireEnv("MICROSOFT_REDIRECT_URI");
    const tenant = resolveTenant();
    const allowedTenants = resolveAllowedTenants();
    if (TENANT_WILDCARDS.has(tenant) && allowedTenants.length === 0) {
      console.warn(
        `[microsoft] MICROSOFT_TENANT is a wildcard ('${tenant}') and MICROSOFT_ALLOWED_TENANTS is unset — any Microsoft tenant can authenticate. Set MICROSOFT_TENANT to your tenant id, or list permitted tenants in MICROSOFT_ALLOWED_TENANTS.`,
      );
    }
    const { tokenUrl, jwksUrl } = microsoftEndpoints(tenant);

    const tokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        code_verifier: verified.codeVerifier,
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
      }).toString(),
    });
    if (!tokenRes.ok) {
      const detail = await tokenRes.text().catch(() => "");
      return errorRedirect(
        c,
        `callback: token exchange failed status=${tokenRes.status} body=${detail}`,
      );
    }
    const tokenBody = (await tokenRes.json()) as { id_token?: string };
    if (!tokenBody.id_token) {
      return errorRedirect(c, "callback: no id_token in response");
    }

    const jwks = createRemoteJWKSet(new URL(jwksUrl));
    let claims;
    try {
      claims = await verifyMicrosoftIdToken(
        tokenBody.id_token,
        jwks,
        clientId,
        tenant,
        verified.nonce,
        allowedTenants,
      );
    } catch (err) {
      return errorRedirect(
        c,
        `callback: id_token verification failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (!claims.sub) {
      return errorRedirect(c, "callback: id_token missing sub claim");
    }

    const { issuer, audience, defaultClaims } = resolveRuntimeConfig();
    const identityClaims: Record<string, string> = {};
    for (const claim of defaultClaims) {
      if (claim === "email") {
        // Microsoft's `email` is not guaranteed verified; forward it only when
        // `xms_edov` (email domain owner verified) is set. Identity is `sub`/`oid`,
        // not email. If your tenant doesn't emit xms_edov, enable the `email`
        // optional claim / domain ownership so verified email can flow.
        const email = verifiedEmail(claims, "xms_edov");
        if (email) identityClaims.email = email;
        continue;
      }
      const val = claims[claim as keyof typeof claims];
      if (typeof val === "string") identityClaims[claim] = val;
    }

    const signingKey = await signingKeyResolver();
    const sessionToken = await signToken(
      String(claims.sub),
      signingKey,
      SESSION_TTL_SECONDS,
      // Embed iss/aud when configured.
      {
        iss: issuer || undefined,
        aud: requireAudience(audience),
        claims: Object.keys(identityClaims).length > 0 ? identityClaims : undefined,
      },
    );
    const sessionCookieName = getEnv("SESSION_COOKIE") || SESSION_COOKIE;

    // Clear the state cookie, then set the session cookie.
    c.header(
      "Set-Cookie",
      `${STATE_COOKIE}=; Path=/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    );
    c.header(
      "Set-Cookie",
      `${sessionCookieName}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`,
      { append: true },
    );

    console.log(
      `[microsoft] callback ok: sub=${claims.sub} cookie=${sessionCookieName} claims=[${Object.keys(identityClaims).join(",")}] → redirect=${verified.redirect}`,
    );
    return c.redirect(verified.redirect, 302);
  } catch (err) {
    return errorRedirect(
      c,
      `callback error: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`,
    );
  }
}
