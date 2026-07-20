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

const STATE_COOKIE = "gh_oauth_state";
const STATE_TTL_SECONDS = 180;
const SESSION_COOKIE = "sso_session";
const SESSION_TTL_SECONDS = 86400;

const AUTHORIZE_URL_DEFAULT = "https://github.com/login/oauth/authorize";
const TOKEN_URL_DEFAULT = "https://github.com/login/oauth/access_token";
const USER_URL_DEFAULT = "https://api.github.com/user";
const EMAILS_URL_DEFAULT = "https://api.github.com/user/emails";

function githubEndpoints(): {
  authorizeUrl: string;
  tokenUrl: string;
  userUrl: string;
  emailsUrl: string;
} {
  const oauthBase = getEnv("GITHUB_OAUTH_BASE_URL");
  const apiBase = getEnv("GITHUB_API_BASE_URL");
  return {
    authorizeUrl: oauthBase
      ? `${oauthBase}/login/oauth/authorize`
      : AUTHORIZE_URL_DEFAULT,
    tokenUrl: oauthBase
      ? `${oauthBase}/login/oauth/access_token`
      : TOKEN_URL_DEFAULT,
    userUrl: apiBase ? `${apiBase}/user` : USER_URL_DEFAULT,
    emailsUrl: apiBase ? `${apiBase}/user/emails` : EMAILS_URL_DEFAULT,
  };
}

interface GitHubEmail {
  email?: string;
  primary?: boolean;
  verified?: boolean;
}

/**
 * GitHub's profile `email` is the public profile field — it may be unset or
 * unverified, so trusting it lets a user present an address they don't control.
 * Fetch /user/emails (the `user:email` scope is already requested) and return
 * the verified primary address (or any verified one); `null` if none/uncertain.
 */
async function fetchVerifiedEmail(
  emailsUrl: string,
  accessToken: string,
): Promise<string | null> {
  try {
    const res = await fetch(emailsUrl, {
      headers: {
        accept: "application/json",
        authorization: `Bearer ${accessToken}`,
        "user-agent": "fastedge-sso",
      },
    });
    if (!res.ok) return null;
    const emails = (await res.json()) as GitHubEmail[];
    if (!Array.isArray(emails)) return null;
    const verified = emails.filter(
      (e) => e.verified === true && typeof e.email === "string",
    );
    const chosen = verified.find((e) => e.primary === true) ?? verified[0];
    return chosen?.email ?? null;
  } catch {
    return null;
  }
}

// Log the real reason server-side; never expose it in the redirect URL.
function errorRedirect(c: Context, reason: string): Response {
  console.error(`[github] ${reason}`);
  return c.redirect("/auth/error", 302);
}

export async function handleGitHubLogin(c: Context): Promise<Response> {
  try {
    const clientId = requireEnv("GITHUB_CLIENT_ID");
    const sessionSecret = requireSecret("SESSION_SECRET");
    const { allowedOrigins } = resolveRuntimeConfig();
    // Validate redirect before storing it in the signed state cookie.
    const redirect = validateRedirect(c.req.query("redirect"), allowedOrigins);
    console.log(
      `[github] login: raw redirect=${c.req.query("redirect") ?? "<none>"} → stored=${redirect}`,
    );

    const state = generateOAuthState();
    const { codeVerifier, codeChallenge } = await generatePkcePair();

    const signedState = await signOAuthState(
      { state, codeVerifier, redirect },
      sessionSecret,
      STATE_TTL_SECONDS,
    );

    c.header(
      "Set-Cookie",
      `${STATE_COOKIE}=${signedState}; HttpOnly; Secure; SameSite=Lax; Path=/auth; Max-Age=${STATE_TTL_SECONDS}`,
    );

    const { authorizeUrl } = githubEndpoints();
    const params = new URLSearchParams({
      client_id: clientId,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      scope: "read:user user:email",
      allow_signup: "true",
    });

    return c.redirect(`${authorizeUrl}?${params.toString()}`, 302);
  } catch (err) {
    return errorRedirect(
      c,
      `login error: ${err instanceof Error ? `${err.message}\n${err.stack}` : String(err)}`,
    );
  }
}

export async function handleGitHubCallback(
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
    const match = cookieHeader.match(/(?:^|;\s*)gh_oauth_state=([^;]+)/);
    if (!match) return errorRedirect(c, "callback: missing state cookie");

    const verified = await verifyOAuthState(match[1], sessionSecret);
    if (!verified) {
      return errorRedirect(c, "callback: invalid or expired state cookie");
    }
    if (verified.state !== stateParam) {
      return errorRedirect(c, "callback: state parameter mismatch");
    }

    const clientId = requireEnv("GITHUB_CLIENT_ID");
    const clientSecret = requireSecret("GITHUB_CLIENT_SECRET");
    const { tokenUrl, userUrl, emailsUrl } = githubEndpoints();

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

    const userRes = await fetch(userUrl, {
      headers: {
        accept: "application/json",
        authorization: `Bearer ${tokenBody.access_token}`,
        "user-agent": "fastedge-sso",
      },
    });
    if (!userRes.ok) {
      const detail = await userRes.text().catch(() => "");
      return errorRedirect(
        c,
        `callback: user fetch failed status=${userRes.status} body=${detail}`,
      );
    }
    const user = (await userRes.json()) as {
      id?: number | string;
      login?: string;
      name?: string | null;
      email?: string | null;
      avatar_url?: string | null;
    };
    if (user.id === undefined || user.id === null) {
      return errorRedirect(c, "callback: GitHub user has no id");
    }

    const { issuer, audience, defaultClaims } = resolveRuntimeConfig();
    const identityClaims: Record<string, string> = {};

    // Only emit a verified email. Fetched once, only when requested.
    let verifiedEmail: string | null = null;
    if (defaultClaims.includes("email")) {
      verifiedEmail = await fetchVerifiedEmail(emailsUrl, tokenBody.access_token);
    }

    for (const claim of defaultClaims) {
      if (claim === "name") {
        // GitHub `name` can be null — fall back to `login` (always present)
        const val = user.name ?? user.login;
        if (val) identityClaims.name = val;
      } else if (claim === "email" && verifiedEmail) {
        identityClaims.email = verifiedEmail;
      } else if (claim === "picture" && user.avatar_url) {
        identityClaims.picture = user.avatar_url;
      }
      // given_name / family_name: not available from GitHub API
    }

    const signingKey = await signingKeyResolver();
    const sessionToken = await signToken(
      String(user.id),
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
      `[github] callback ok: sub=${user.id} cookie=${sessionCookieName} claims=[${Object.keys(identityClaims).join(",")}] → redirect=${verified.redirect}`,
    );
    return c.redirect(verified.redirect, 302);
  } catch (err) {
    return errorRedirect(
      c,
      `callback error: ${err instanceof Error ? `${err.message}\n${err.stack}` : String(err)}`,
    );
  }
}
