import { getEnv } from "fastedge::env";
import { selectProviders, type ResolvedProvider } from "./providers/registry";
import { type ClaimName, parseDefaultClaims } from "../session/token.js";

export type { ClaimName };
export { parseDefaultClaims };

export interface RuntimeConfig {
  /** Providers enabled for this deployment (creds present ∩ SSO_PROVIDERS). */
  providers: ResolvedProvider[];
  /** Origins permitted for the ?redirect= parameter. Empty = relative URLs only. */
  allowedOrigins: string[];
  /** Token issuer claim added to every session JWT. Empty = omit claim. */
  issuer: string;
  /** Token audience claim added to every session JWT. Empty = omit claim. */
  audience: string;
  /**
   * Identity claims to embed in the session JWT beyond `sub`.
   * Populated from the `SSO_CLAIMS` env var (comma-separated ClaimName list).
   * Defaults to empty — no extra claims unless configured.
   */
  defaultClaims: ClaimName[];
}

/** Branding config for the built-in login page. Resolved from LOGIN_PAGE_* env vars. */
export interface LoginPageBranding {
  /** Page <title> and <h1>. Default: "Sign in". */
  title: string;
  /** Subheading below the title. Default: "Choose a sign-in method". */
  subtitle: string;
  /** URL to a logo image displayed above the title. Omitted when not set. */
  logoUrl?: string;
  /** URL to a favicon. Omitted when not set. */
  faviconUrl?: string;
  /** CSS color for buttons and focus rings. Default: "#0066cc". */
  accentColor: string;
  /** Page background color. Default: "#f0f2f5". */
  backgroundColor: string;
  /** URL to a customer CSS file linked last — full visual override. Omitted when not set. */
  cssUrl?: string;
}

/**
 * Resolve per-request runtime config from env + secrets (never KV — too
 * expensive per read). Instances are stateless, so this runs per request; the
 * cost is trivial.
 */
export function resolveRuntimeConfig(): RuntimeConfig {
  const providers = selectProviders(getEnv("SSO_PROVIDERS"), (key) => {
    const v = getEnv(key);
    return v !== null && v !== "";
  });

  // IDP_LABEL / IDP_ICON_URL override the SAML provider's display name and icon.
  const idpLabel = getEnv("IDP_LABEL") || null;
  const idpIconUrl = getEnv("IDP_ICON_URL") || null;
  const resolvedProviders: ResolvedProvider[] = providers.map((p) => {
    if (p.id !== "saml") return p;
    return {
      ...p,
      label: idpLabel ?? p.label,
      iconUrl: idpIconUrl ?? undefined,
    };
  });

  const rawOrigins = getEnv("SSO_ALLOWED_ORIGINS") ?? "";
  const allowedOrigins = rawOrigins
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const issuer = getEnv("SSO_ISSUER") ?? "";
  const audience = getEnv("SSO_AUDIENCE") ?? "";
  const defaultClaims = parseDefaultClaims(getEnv("SSO_CLAIMS"));
  return { providers: resolvedProviders, allowedOrigins, issuer, audience, defaultClaims };
}

/**
 * The session token's `aud` is required: it names the deployment a token is for,
 * and the CDN filter rejects any session whose `aud` doesn't match its own
 * SSO_AUDIENCE (and refuses everything when unset). Signing a token without an
 * audience would therefore mint a session no correctly-configured filter accepts,
 * so we fail loudly at sign time instead. To share sessions across apps, set the
 * SAME SSO_AUDIENCE on each; to isolate them (the default), give each its own.
 */
export function requireAudience(audience: string): string {
  if (!audience) {
    throw new Error(
      "SSO_AUDIENCE is required — set it to this deployment's audience (it must match the CDN filter's SSO_AUDIENCE). Use the same value across apps only to deliberately share sessions.",
    );
  }
  return audience;
}

/**
 * Resolve login page branding from LOGIN_PAGE_* env vars.
 * Called only on the chooser route and GET /auth/branding — not on every request.
 */
export function resolveBranding(): LoginPageBranding {
  return {
    title: getEnv("LOGIN_PAGE_TITLE") || "Sign in",
    subtitle: getEnv("LOGIN_PAGE_SUBTITLE") || "Choose a sign-in method",
    logoUrl: getEnv("LOGIN_PAGE_LOGO_URL") || undefined,
    faviconUrl: getEnv("LOGIN_PAGE_FAVICON_URL") || undefined,
    accentColor: getEnv("LOGIN_PAGE_ACCENT_COLOR") || "#0066cc",
    backgroundColor: getEnv("LOGIN_PAGE_BACKGROUND_COLOR") || "#f0f2f5",
    cssUrl: getEnv("LOGIN_PAGE_CSS_URL") || undefined,
  };
}
