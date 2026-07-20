/**
 * `@gcoredev/fastedge-test` >= 0.2 returns the `set-cookie` response header as a
 * string[] (multi-valued, via getSetCookie) instead of collapsing duplicates into
 * one string (the old 0.1.x behaviour). Normalize to a single string so substring /
 * regex checks work regardless of how many cookies were set.
 */
export function parseSetCookieAsString(headers: Record<string, unknown>): string {
  const raw = headers["set-cookie"];
  if (Array.isArray(raw)) return raw.join("; ");
  return typeof raw === "string" ? raw : "";
}
