import { Hono } from "hono";
import type { Context } from "hono";
import { html } from "hono/html";
import { getEnv } from "fastedge::env";
import { Chooser } from "./chooser";
import { resolveRuntimeConfig, resolveBranding } from "./config";
import { buildLoginUrl } from "./providers/registry";
import { ErrorPage } from "./error";
import { validateRedirect } from "./util/redirect";
import { handleGitHubLogin, handleGitHubCallback } from "./providers/github";
import { handleGoogleLogin, handleGoogleCallback } from "./providers/google";
import { handleMicrosoftLogin, handleMicrosoftCallback } from "./providers/microsoft";
import { handleFacebookLogin, handleFacebookCallback } from "./providers/facebook";
import { handleSamlLogin, handleSamlCallback } from "./saml/handlers";
import { requireEs256SigningKey, requireHs256Secret } from "../session/key.js";

export interface AuthAppOptions {
  /** Identity-delivery variant this template represents. */
  variant: "gate-only" | "cookie" | "header";
}

export function createAuthApp(options: AuthAppOptions): Hono {
  const app = new Hono();
  const auth = new Hono();

  const signingKeyResolver =
    options.variant === "cookie" ? requireEs256SigningKey : requireHs256Secret;

  // Redirect requests on non-canonical hosts to the canonical host.
  // Runs before every route — protects the entire /auth surface.
  app.use("*", async (c, next) => {
    const canonical = getEnv("CANONICAL_HOST");
    if (!canonical) return next();
    // Strip port (host: "example.com:8080" → "example.com") — present in test
    // runners and local dev; production FastEdge sends bare host.
    const host = (c.req.header("host") ?? "").split(":")[0];
    if (host && host !== canonical) {
      const url = new URL(c.req.url);
      return c.redirect(`https://${canonical}${url.pathname}${url.search}`, 301);
    }
    return next();
  });

  const chooserHandler = (c: Context) => {
    const { providers, allowedOrigins } = resolveRuntimeConfig();
    const branding = resolveBranding();
    // Validate redirect before weaving it into login links.
    const raw = c.req.query("redirect");
    const redirect = raw !== undefined ? validateRedirect(raw, allowedOrigins) : undefined;
    const effectiveRedirect = redirect === "/" ? undefined : redirect;
    return c.html(
      html`<!doctype html>${(
        <Chooser providers={providers} redirect={effectiveRedirect} branding={branding} />
      )}`,
    );
  };
  // A Hono sub-app mounted at /auth matches `get("/")` for `/auth` but not for
  // `/auth/`. The filter's default CHOOSER_URL is `/auth/`, so register the
  // trailing-slash form on the parent too — both must render the chooser.
  auth.get("/", chooserHandler);
  app.get("/auth/", chooserHandler);

  // Same enabled-provider set as data — the integration surface for embedded
  // login UIs (mode C). See context/integration.md.
  auth.get("/providers", (c) => {
    const { providers, allowedOrigins } = resolveRuntimeConfig();
    // Validate redirect before embedding it in login URLs.
    const raw = c.req.query("redirect");
    const redirect = raw !== undefined ? validateRedirect(raw, allowedOrigins) : undefined;
    const effectiveRedirect = redirect === "/" ? undefined : redirect;
    return c.json({
      providers: providers.map((p) => ({
        id: p.id,
        label: p.label,
        loginUrl: buildLoginUrl(p.loginPath, effectiveRedirect),
      })),
    });
  });

  // Branding config as JSON — lets custom login pages (Tier 2) auto-style
  // themselves to match the operator's LOGIN_PAGE_* env vars without re-reading
  // them from the server side.
  auth.get("/branding", (c) => c.json(resolveBranding()));

  // Clear the SSO session cookie and redirect to a safe destination. The filter
  // already bypasses /auth/**, so this route is never gated.
  auth.get("/logout", (c) => {
    const { allowedOrigins } = resolveRuntimeConfig();
    const raw = c.req.query("redirect");
    const dest = raw !== undefined ? validateRedirect(raw, allowedOrigins) : "/";
    const sessionCookieName = getEnv("SESSION_COOKIE") || "sso_session";
    c.header(
      "Set-Cookie",
      `${sessionCookieName}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    );
    return c.redirect(dest, 302);
  });

  // The error route ignores ?message= — the page shows a generic message.
  // The real reason was logged server-side before the redirect.
  auth.get("/error", (c) =>
    c.html(html`<!doctype html>${(<ErrorPage />)}`),
  );

  if (options.variant === "cookie") {
    auth.get("/.well-known/jwks.json", (c) => {
      const jwk = getEnv("SESSION_PUBLIC_JWK");
      if (!jwk) {
        return c.json({ error: "JWKS not configured" }, 503);
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(jwk);
      } catch {
        return c.json({ error: "Invalid SESSION_PUBLIC_JWK" }, 500);
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        return c.json({ error: "Invalid SESSION_PUBLIC_JWK" }, 500);
      }
      // Defence in depth: publish only public JWK members. If an operator pastes
      // a JWK that still carries private key material (RSA/EC `d`, CRT factors,
      // symmetric `k`), strip it so the public endpoint can never leak the key.
      const PUBLIC_JWK_FIELDS = new Set([
        "kty", "crv", "x", "y", "n", "e", "kid", "use", "alg", "key_ops",
      ]);
      const publicJwk: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
        if (PUBLIC_JWK_FIELDS.has(k)) publicJwk[k] = v;
      }
      return c.json({ keys: [publicJwk] });
    });
  }

  auth.get("/login/github", handleGitHubLogin);
  auth.get("/callback/github", (c) => handleGitHubCallback(c, signingKeyResolver));
  auth.get("/login/google", handleGoogleLogin);
  auth.get("/callback/google", (c) => handleGoogleCallback(c, signingKeyResolver));
  auth.get("/login/microsoft", handleMicrosoftLogin);
  auth.get("/callback/microsoft", (c) => handleMicrosoftCallback(c, signingKeyResolver));
  auth.get("/login/facebook", handleFacebookLogin);
  auth.get("/callback/facebook", (c) => handleFacebookCallback(c, signingKeyResolver));

  auth.get("/login", handleSamlLogin);
  auth.post("/callback", (c) => handleSamlCallback(c, signingKeyResolver));

  app.route("/auth", auth);
  return app;
}
