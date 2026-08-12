// Pure provider registry + selection logic. NO virtual (`fastedge::*`) imports —
// this module is unit-tested under Node. The IO wiring (reading secrets/env)
// lives in ../config.ts, which is only exercised inside the WASM runtime.

export interface ProviderDef {
  /** Stable id used in the SSO_PROVIDERS allowlist and /auth/providers JSON. */
  id: string;
  /** Human label for the chooser button ("Sign in with <label>"). */
  label: string;
  /** Login route (no query); the redirect param is appended by buildLoginUrl. */
  loginPath: string;
  /** Env var whose presence means this provider is configured/usable. */
  credKey: string;
}

// Order here is the display/JSON order (stable; not the allowlist's order).
// Future providers are added here only; the filter stays provider-agnostic.
export const PROVIDER_REGISTRY: ProviderDef[] = [
  {
    id: "google",
    label: "Google",
    loginPath: "/auth/login/google",
    credKey: "GOOGLE_CLIENT_ID",
  },
  {
    id: "github",
    label: "GitHub",
    loginPath: "/auth/login/github",
    credKey: "GITHUB_CLIENT_ID",
  },
  {
    id: "microsoft",
    label: "Microsoft",
    loginPath: "/auth/login/microsoft",
    credKey: "MICROSOFT_CLIENT_ID",
  },
  {
    id: "facebook",
    label: "Facebook",
    loginPath: "/auth/login/facebook",
    credKey: "FACEBOOK_CLIENT_ID",
  },
  {
    id: "saml",
    label: "SSO",
    loginPath: "/auth/login",
    credKey: "IDP_SSO_URL",
  },
];

export interface ResolvedProvider {
  id: string;
  label: string;
  loginPath: string;
  /** Customer-supplied icon URL. Only set for the SAML provider via IDP_ICON_URL. */
  iconUrl?: string;
}

/** Parse a comma-separated allowlist into normalized provider ids. */
export function parseAllowlist(csv: string | null | undefined): string[] {
  return (csv ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
}

/**
 * Resolve the enabled provider set:
 *   - if SSO_PROVIDERS is set → allowlist ∩ providers-with-creds
 *   - else                    → every provider whose creds are present
 * Result order follows PROVIDER_REGISTRY, not the allowlist.
 */
export function selectProviders(
  allowCsv: string | null | undefined,
  hasCred: (credKey: string) => boolean,
): ResolvedProvider[] {
  const allow = parseAllowlist(allowCsv);
  return PROVIDER_REGISTRY.filter(
    (p) => hasCred(p.credKey) && (allow.length === 0 || allow.includes(p.id)),
  ).map((p) => ({ id: p.id, label: p.label, loginPath: p.loginPath }));
}

/**
 * Build a login URL, preserving the post-login redirect target when present.
 * NOTE: `redirect` is already validated (via validateRedirect) at every call
 * site before it reaches here; this function only URL-encodes it.
 */
export function buildLoginUrl(loginPath: string, redirect?: string): string {
  return redirect
    ? `${loginPath}?redirect=${encodeURIComponent(redirect)}`
    : loginPath;
}
