import type { Context } from "hono";

/**
 * Append a Set-Cookie header to a Hono context.
 * Uses c.header(..., { append: true }) so multiple cookies can be set in one
 * response.
 */
export function appendCookie(
  c: Context,
  name: string,
  value: string,
  opts: {
    maxAge: number;
    path?: string;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: "Lax" | "Strict" | "None";
  },
): void {
  const path = opts.path ?? "/";
  const parts = [`${name}=${value}`, `Path=${path}`, `Max-Age=${opts.maxAge}`];
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  if (opts.secure !== false) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite ?? "Lax"}`);
  c.header("Set-Cookie", parts.join("; "), { append: true });
}
