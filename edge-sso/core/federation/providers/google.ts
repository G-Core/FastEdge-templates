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
import { verifyGoogleIdToken } from "./google-oidc.js";
import { signToken } from "../../session/token.js";
import { resolveRuntimeConfig, requireAudience } from "../config.js";
import { validateRedirect } from "../util/redirect.js";
import { requireEnv, requireSecret } from "../../util/env";

const STATE_COOKIE = "gg_oauth_state";
// Short TTL: the OAuth round-trip completes in seconds. Keep the residual window
// small. Bump back up (e.g. 300) if slow interactive logins start hitting
// "expired state cookie".
const STATE_TTL_SECONDS = 180;
const SESSION_COOKIE = "sso_session";
const SESSION_TTL_SECONDS = 86400;

const AUTHORIZE_URL_DEFAULT = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL_DEFAULT = "https://oauth2.googleapis.com/token";
const JWKS_URL_DEFAULT = "https://www.googleapis.com/oauth2/v3/certs";

function googleEndpoints(): {
  authorizeUrl: string;
  tokenUrl: string;
  jwksUrl: string;
} {
  const oauthBase = getEnv("GOOGLE_OAUTH_BASE_URL");
  const jwksOverride = getEnv("GOOGLE_JWKS_URL");
  return {
    authorizeUrl: oauthBase
      ? `${oauthBase}/o/oauth2/v2/auth`
      : AUTHORIZE_URL_DEFAULT,
    tokenUrl: oauthBase ? `${oauthBase}/token` : TOKEN_URL_DEFAULT,
    jwksUrl: jwksOverride ?? JWKS_URL_DEFAULT,
  };
}

// Log the real reason server-side; never expose it in the redirect URL.
function errorRedirect(c: Context, reason: string): Response {
  console.error(`[google] ${reason}`);
  return c.redirect("/auth/error", 302);
}

export async function handleGoogleLogin(c: Context): Promise<Response> {
  try {
    const clientId = requireEnv("GOOGLE_CLIENT_ID");
    const redirectUri = requireEnv("GOOGLE_REDIRECT_URI");
    const sessionSecret = requireSecret("SESSION_SECRET");
    const { allowedOrigins } = resolveRuntimeConfig();
    // Validate redirect before storing it in the signed state cookie.
    const redirect = validateRedirect(c.req.query("redirect"), allowedOrigins);
    console.log(`[google] login: redirect=${redirect ?? "<none>"}`);

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

    const { authorizeUrl } = googleEndpoints();
    const params = new URLSearchParams({
      client_id: clientId,
      response_type: "code",
      scope: "openid email profile",
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      redirect_uri: redirectUri,
      access_type: "online",
      prompt: "select_account",
    });

    return c.redirect(`${authorizeUrl}?${params.toString()}`, 302);
  } catch (err) {
    return errorRedirect(
      c,
      `login error: ${err instanceof Error ? `${err.message}\n${err.stack}` : String(err)}`,
    );
  }
}

export async function handleGoogleCallback(
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
    const match = cookieHeader.match(/(?:^|;\s*)gg_oauth_state=([^;]+)/);
    if (!match) return errorRedirect(c, "callback: missing state cookie");

    const verified = await verifyOAuthState(match[1], sessionSecret);
    if (!verified) {
      return errorRedirect(c, "callback: invalid or expired state cookie");
    }
    if (verified.state !== stateParam) {
      return errorRedirect(c, "callback: state parameter mismatch");
    }

    const clientId = requireEnv("GOOGLE_CLIENT_ID");
    const clientSecret = requireSecret("GOOGLE_CLIENT_SECRET");
    const redirectUri = requireEnv("GOOGLE_REDIRECT_URI");
    const { tokenUrl, jwksUrl } = googleEndpoints();

    // FastEdge's outbound fetch strips our explicit
    // `Content-Type: application/x-www-form-urlencoded` on the way out, and
    // Google's API gateway then defaults to JSON parsing (returning "Invalid
    // JSON payload" on the form-encoded body). Workaround: send JSON instead —
    // Google's token endpoint accepts JSON bodies, and the gateway's default
    // JSON expectation matches.
    const bodyStr = JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      code_verifier: verified.codeVerifier,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
    });
    const tokenHeaders = new Headers();
    tokenHeaders.set("Accept", "application/json");
    tokenHeaders.set("Content-Type", "application/json");
    const tokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: tokenHeaders,
      body: bodyStr,
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
      claims = await verifyGoogleIdToken(
        tokenBody.id_token,
        jwks,
        clientId,
        verified.nonce,
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
        // Forward the email only if Google marked it verified.
        const email = verifiedEmail(claims, "email_verified");
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
      `[google] callback ok: sub=${claims.sub} cookie=${sessionCookieName} claims=[${Object.keys(identityClaims).join(",")}] → redirect=${verified.redirect}`,
    );
    return c.redirect(verified.redirect, 302);
  } catch (err) {
    return errorRedirect(
      c,
      `callback error: ${err instanceof Error ? `${err.message}\n${err.stack}` : String(err)}`,
    );
  }
}
