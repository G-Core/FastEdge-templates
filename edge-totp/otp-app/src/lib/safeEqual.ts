/**
 * Constant-time string comparison.
 *
 * Returns early only on a length mismatch (string length is not secret here);
 * otherwise compares every character so the time taken does not reveal how
 * many leading characters matched. Used for comparing secrets — TOTP codes
 * and the enroll API key — where a timing oracle would otherwise leak data.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
