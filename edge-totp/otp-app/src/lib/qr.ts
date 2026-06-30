import { renderSVG } from "uqr";

/**
 * Render an otpauth:// URI to an inline SVG string.
 * uqr is pure-JS / SVG-string — no canvas or Node built-ins.
 * Security: the otpauth URI embeds the seed — never send it to an
 * external QR service. Render locally only.
 */
export function otpauthToSvg(uri: string): string {
  return renderSVG(uri);
}
