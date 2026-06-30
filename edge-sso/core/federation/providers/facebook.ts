import type { Context } from "hono";
import { getEnv } from "fastedge::env";
import {
  generateOAuthState,
  generatePkcePair,
  signOAuthState,
  verifyOAuthState,
} from "./common.js";
import { signToken } from "../../session/token.js";
import { resolveRuntimeConfig, requireAudience } from "../config.js";
import { validateRedirect } from "../util/redirect.js";
import { requireEnv, requireSecret } from "../../util/env";

const STATE_COOKIE = "fb_oauth_state";
// Short TTL — same reasoning as other state cookies (see google.ts comment).
const STATE_TTL_SECONDS = 180;
const SESSION_COOKIE = "sso_session";
const SESSION_TTL_SECONDS = 86400;
const DEFAULT_API_VERSION = "v21.0";

function resolveVersion(): string {
  return getEnv("FACEBOOK_API_VERSION") || DEFAULT_API_VERSION;
}

function facebookEndpoints(version: string): {
  authorizeUrl: string;
  tokenUrl: string;
  userUrl: string;
} {
  const oauthBase = getEnv("FACEBOOK_OAUTH_BASE_URL");
  const apiBase = getEnv("FACEBOOK_API_BASE_URL");
  return {
    authorizeUrl: oauthBase
      ? `${oauthBase}/${version}/dialog/oauth`
      : `https://www.facebook.com/${version}/dialog/oauth`,
    tokenUrl: apiBase
      ? `${apiBase}/${version}/oauth/access_token`
      : `https://graph.facebook.com/${version}/oauth/access_token`,
    userUrl: apiBase
      ? `${apiBase}/${version}/me`
      : `https://graph.facebook.com/${version}/me`,
  };
}

// Log the real reason server-side; never expose it in the redirect URL.
function errorRedirect(c: Context, reason: string): Response {
  console.error(`[facebook] ${reason}`);
  return c.redirect("/auth/error", 302);
}

interface FacebookUser {
  id?: string;
  name?: string | null;
  email?: string | null;
  picture?: {
    data?: {
      url?: string;
      is_silhouette?: boolean;
    } | null;
  } | null;
}

export async function handleFacebookLogin(c: Context): Promise<Response> {
  try {
    const clientId = requireEnv("FACEBOOK_CLIENT_ID");
    const redirectUri = requireEnv("FACEBOOK_REDIRECT_URI");
    const sessionSecret = requireSecret("SESSION_SECRET");
    const version = resolveVersion();
    const { allowedOrigins } = resolveRuntimeConfig();
    // Validate redirect before storing it in the signed state cookie.
    const redirect = validateRedirect(c.req.query("redirect"), allowedOrigins);
    console.log(`[facebook] login: redirect=${redirect ?? "<none>"}`);

    const state = generateOAuthState();
    const { codeVerifier, codeChallenge } = await generatePkcePair();

    // No OIDC nonce — Facebook is plain OAuth2, not OIDC. CSRF protection
    // comes from the signed state cookie + state parameter round-trip.
    const signedState = await signOAuthState(
      { state, codeVerifier, redirect },
      sessionSecret,
      STATE_TTL_SECONDS,
    );

    c.header(
      "Set-Cookie",
      `${STATE_COOKIE}=${signedState}; HttpOnly; Secure; SameSite=Lax; Path=/auth; Max-Age=${STATE_TTL_SECONDS}`,
    );

    const { authorizeUrl } = facebookEndpoints(version);
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      state,
      scope: "email,public_profile",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      response_type: "code",
    });

    return c.redirect(`${authorizeUrl}?${params.toString()}`, 302);
  } catch (err) {
    return errorRedirect(
      c,
      `login error: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`,
    );
  }
}

export async function handleFacebookCallback(
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
    const match = cookieHeader.match(/(?:^|;\s*)fb_oauth_state=([^;]+)/);
    if (!match) return errorRedirect(c, "callback: missing state cookie");

    const verified = await verifyOAuthState(match[1], sessionSecret);
    if (!verified) {
      return errorRedirect(c, "callback: invalid or expired state cookie");
    }
    if (verified.state !== stateParam) {
      return errorRedirect(c, "callback: state parameter mismatch");
    }

    const clientId = requireEnv("FACEBOOK_CLIENT_ID");
    const clientSecret = requireSecret("FACEBOOK_CLIENT_SECRET");
    const redirectUri = requireEnv("FACEBOOK_REDIRECT_URI");
    const version = resolveVersion();
    const { tokenUrl, userUrl } = facebookEndpoints(version);

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
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
      }).toString(),
    });
    if (!tokenRes.ok) {
      const detail = await tokenRes.text().catch(() => "");
      return errorRedirect(
        c,
        `callback: token exchange failed status=${tokenRes.status} body=${detail}`,
      );
    }
    const tokenBody = (await tokenRes.json()) as { access_token?: string };
    if (!tokenBody.access_token) {
      return errorRedirect(c, "callback: no access_token in response");
    }

    // picture{url} uses Facebook's field-expansion syntax — URLSearchParams
    // encodes the braces, which the Graph API accepts.
    const userParams = new URLSearchParams({
      fields: "id,name,email,picture{url}",
    });
    const userRes = await fetch(`${userUrl}?${userParams.toString()}`, {
      headers: {
        accept: "application/json",
        authorization: `Bearer ${tokenBody.access_token}`,
      },
    });
    if (!userRes.ok) {
      const detail = await userRes.text().catch(() => "");
      return errorRedirect(
        c,
        `callback: user fetch failed status=${userRes.status} body=${detail}`,
      );
    }
    const user = (await userRes.json()) as FacebookUser;
    if (!user.id) {
      return errorRedirect(c, "callback: Facebook user has no id");
    }

    const { issuer, audience, defaultClaims } = resolveRuntimeConfig();
    const identityClaims: Record<string, string> = {};
    for (const claim of defaultClaims) {
      if (claim === "name" && user.name) {
        identityClaims.name = user.name;
      } else if (claim === "email" && user.email) {
        // Facebook requires a confirmed email on the account and the Graph `/me`
        // email is that verified address, so there is no separate flag to gate on.
        identityClaims.email = user.email;
      } else if (claim === "picture" && user.picture?.data?.url) {
        identityClaims.picture = user.picture.data.url;
      }
      // given_name / family_name: not available from basic Facebook API
    }

    const signingKey = await signingKeyResolver();
    const sessionToken = await signToken(
      user.id,
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
      `[facebook] callback ok: sub=${user.id} cookie=${sessionCookieName} claims=[${Object.keys(identityClaims).join(",")}] → redirect=${verified.redirect}`,
    );
    return c.redirect(verified.redirect, 302);
  } catch (err) {
    return errorRedirect(
      c,
      `callback error: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`,
    );
  }
}
