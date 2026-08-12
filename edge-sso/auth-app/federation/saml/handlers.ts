import type { Context } from "hono";
import { getEnv } from "fastedge::env";
import { getSamlConfig } from "./config.js";
import { buildSamlRedirectUrl, generateRequestId } from "./request.js";
import { validateSamlResponse } from "./response.js";
import { extractSamlClaims, parseSamlClaimMap } from "./claims.js";
import {
  signToken,
  signRelayCookie,
  verifyRelayCookie,
  signRequestBinding,
  verifyRequestBinding,
} from "../../session/token.js";
import { resolveRuntimeConfig, requireAudience } from "../config.js";
import { validateRedirect } from "../util/redirect.js";

const RELAY_COOKIE = "saml_relay";
const SESSION_COOKIE = "sso_session";

export async function handleSamlLogin(c: Context): Promise<Response> {
  try {
    const config = getSamlConfig();
    const { allowedOrigins } = resolveRuntimeConfig();
    const redirect = validateRedirect(c.req.query("redirect"), allowedOrigins);

    // Bind this login to an AuthnRequest ID, carried in RelayState (which the
    // IdP echoes back on the callback POST — a cookie cannot, see token.ts).
    const requestId = generateRequestId();
    const relayState = await signRequestBinding(requestId, config.sessionSecret);
    const idpUrl = await buildSamlRedirectUrl(config, { requestId, relayState });
    const relayCookieValue = await signRelayCookie(redirect, config.sessionSecret);

    // SameSite=None (not Lax): the IdP returns the SAMLResponse via a cross-site
    // top-level POST to the ACS, and Lax cookies are NOT sent on cross-site POST
    // navigations — so a Lax relay cookie never arrives and the post-login
    // redirect always degrades to "/". None+Secure lets it survive the callback.
    // It stays HttpOnly + signed + short-lived, and the redirect it carries is
    // re-validated against the origin allowlist on read.
    c.header(
      "Set-Cookie",
      `${RELAY_COOKIE}=${relayCookieValue}; HttpOnly; Secure; SameSite=None; Path=/auth; Max-Age=300`,
    );

    return c.redirect(idpUrl, 302);
  } catch (err) {
    // Log real reason server-side; show only a generic page to the browser.
    console.error(
      `[saml] login error: ${err instanceof Error ? `${err.message}\n${err.stack}` : String(err)}`,
    );
    return c.redirect("/auth/error", 302);
  }
}

export async function handleSamlCallback(
  c: Context,
  signingKeyResolver: () => Promise<string | CryptoKey>,
): Promise<Response> {
  try {
    const config = getSamlConfig();
    const { allowedOrigins, issuer, audience, defaultClaims } = resolveRuntimeConfig();

    const formData = await c.req.formData();
    const samlResponseB64 = formData.get("SAMLResponse");
    if (!samlResponseB64 || typeof samlResponseB64 !== "string") {
      throw new Error("Missing SAMLResponse in callback");
    }

    // Require the response to answer an AuthnRequest WE issued. RelayState
    // carries a signed request id; the assertion's signed InResponseTo must
    // match it. Rejects responses to requests we never issued and forged/altered
    // RelayState. (Does not stop replay of a captured full POST — that needs
    // writable state.)
    const relayState = formData.get("RelayState");
    const expectedRequestId =
      typeof relayState === "string"
        ? await verifyRequestBinding(relayState, config.sessionSecret)
        : null;
    if (!expectedRequestId) {
      throw new Error("Missing or invalid RelayState request binding");
    }

    const claims = await validateSamlResponse(samlResponseB64, config);

    if (claims.inResponseTo !== expectedRequestId) {
      throw new Error("InResponseTo does not match the issued AuthnRequest");
    }

    // Validate the relay redirect (carried in the saml_relay cookie) before
    // using it. RelayState is no longer a redirect source — it carries the
    // signed request binding above.
    let redirectUrl = "/";
    const cookieHeader = c.req.header("cookie") ?? "";
    const relayCookieMatch = cookieHeader.match(
      new RegExp(`(?:^|;\\s*)${RELAY_COOKIE}=([^;]+)`),
    );
    if (relayCookieMatch) {
      const verified = await verifyRelayCookie(relayCookieMatch[1], config.sessionSecret);
      if (verified) redirectUrl = validateRedirect(verified, allowedOrigins);
    }

    const claimMap = parseSamlClaimMap(getEnv("SAML_CLAIM_MAP"));
    const identityClaims = extractSamlClaims(claims.attributes, defaultClaims, claimMap);

    const signingKey = await signingKeyResolver();
    const sessionToken = await signToken(
      claims.nameId,
      signingKey,
      86400,
      // Embed iss/aud when configured.
      {
        iss: issuer || undefined,
        aud: requireAudience(audience),
        claims: Object.keys(identityClaims).length > 0 ? identityClaims : undefined,
      },
    );

    const sessionCookieName = getEnv("SESSION_COOKIE") || SESSION_COOKIE;

    // Clear the relay cookie, then set the session cookie.
    c.header(
      "Set-Cookie",
      `${RELAY_COOKIE}=; Path=/auth; HttpOnly; Secure; SameSite=None; Max-Age=0`,
    );
    c.header(
      "Set-Cookie",
      `${sessionCookieName}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
      { append: true },
    );

    return c.redirect(redirectUrl, 302);
  } catch (err) {
    // Log real reason server-side; show only a generic page to the browser.
    console.error(
      `[saml] callback error: ${err instanceof Error ? `${err.message}\n${err.stack}` : String(err)}`,
    );
    return c.redirect("/auth/error", 302);
  }
}
