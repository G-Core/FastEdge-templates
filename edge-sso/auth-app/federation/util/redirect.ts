/**
 * Validates a `?redirect=` URL against the deployment's allowlist.
 *
 * Relative paths starting with a single `/` are always allowed. Absolute URLs
 * must have an origin that appears verbatim in `allowedOrigins`. Everything
 * else falls back to `/`.
 *
 * `allowedOrigins` comes from `SSO_ALLOWED_ORIGINS` (comma-separated, e.g.
 * `https://mysite.com,https://other.com`). An empty list allows only relative
 * URLs — the safe default for deployments that haven't configured an allowlist.
 */
export function validateRedirect(
  url: string | undefined,
  allowedOrigins: string[],
): string {
  if (!url || url.trim() === "") return "/";
  const trimmed = url.trim();
  // Reject control characters (CR, LF, NUL, DEL, …) before anything else. A
  // percent-decoded `?redirect=` can carry them, and a relative path containing
  // CR/LF would otherwise pass the relative-path check below and land in the
  // `Location` header verbatim — an HTTP response-splitting vector. Don't echo
  // the value back in the log (it could itself contain CR/LF — log injection).
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
    console.warn(`[redirect] rejected — value contains control characters; falling back to "/"`);
    return "/";
  }
  // Relative path, but NOT a protocol-relative reference. Browsers normalize a
  // backslash to a forward slash, so `/\evil.com` and `/\/evil.com` resolve to
  // `//evil.com` → an off-origin redirect. Reject a leading `/` followed
  // by either `/` or `\` before treating the value as a safe relative path.
  if (trimmed.startsWith("/") && !/^\/[\\/]/.test(trimmed)) return trimmed;
  // Absolute URL — check origin against allowlist
  try {
    const origin = new URL(trimmed).origin;
    if (allowedOrigins.some((o) => o === origin)) return trimmed;
    // Observability: a supplied redirect was rejected. The usual cause is a
    // missing/incorrect SSO_ALLOWED_ORIGINS — without this log the request
    // silently degrades to "/" and looks like a normal no-redirect login.
    console.warn(
      `[redirect] rejected "${trimmed}" — origin "${origin}" not in SSO_ALLOWED_ORIGINS [${allowedOrigins.join(", ") || "<empty>"}]; falling back to "/"`,
    );
  } catch {
    console.warn(
      `[redirect] rejected "${trimmed}" — not a valid absolute URL or safe relative path; falling back to "/"`,
    );
  }
  return "/";
}
