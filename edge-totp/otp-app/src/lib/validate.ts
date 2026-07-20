/**
 * Only relative paths (starting with `/` but not `//` or `/\`) are allowed as
 * redirect targets. Absolute URLs are rejected — same-host is required and the
 * handoff ticket already came from the trusted origin. Anything else collapses
 * to `/`, so a tampered/odd `next` can't become an open redirect.
 */
export function validateRedirect(next: string): string {
  if (
    typeof next === "string" &&
    next.startsWith("/") &&
    !/^\/[\\/]/.test(next)
  ) {
    return next;
  }
  return "/";
}

/**
 * Parse a boolean config value. Unset/empty returns `fallback`; `true/1/yes`
 * and `false/0/no` (case-insensitive) map as expected; any other value falls
 * back rather than guessing. Kept here (dependency-free) so it is unit-testable
 * under plain Node alongside validateInt.
 */
export function parseBool(
  raw: string | null | undefined,
  fallback: boolean,
): boolean {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const v = raw.trim().toLowerCase();
  if (v === "true" || v === "1" || v === "yes") return true;
  if (v === "false" || v === "0" || v === "no") return false;
  return fallback;
}

/**
 * Parse an integer config value, applying `fallback` when unset/empty and
 * rejecting anything that is not a whole number within [min, max]. We fail
 * loudly rather than let `parseInt` silently coerce: `parseInt("6abc")` is 6
 * (hides a typo) and `parseInt("abc")` is NaN (turns into a confusing run-time
 * misbehaviour — e.g. drift=NaN makes the verify loop never run so every code
 * "fails"). A misconfigured edge app should surface the bad value, not degrade
 * quietly.
 *
 * Kept dependency-free (no `fastedge::*` imports) so it is unit-testable under
 * plain Node.
 */
export function validateInt(
  name: string,
  raw: string | null | undefined,
  fallback: number,
  bounds: { min?: number; max?: number } = {},
): number {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n)) {
    throw new Error(`Config error: ${name}="${raw}" must be an integer`);
  }
  if (bounds.min !== undefined && n < bounds.min) {
    throw new Error(`Config error: ${name}=${n} must be >= ${bounds.min}`);
  }
  if (bounds.max !== undefined && n > bounds.max) {
    throw new Error(`Config error: ${name}=${n} must be <= ${bounds.max}`);
  }
  return n;
}
