// Shared HTML helpers for the hosted challenge/enroll pages. Kept in one place
// so the escaping used on every reflected value (branding, error text) has a
// single definition to audit, and the branding chrome can't drift between the
// two pages.

// Allowlist: hex (#rgb / #rrggbb / #rrggbbaa), CSS named colors (letters only),
// rgb/rgba/hsl/hsla with numeric args, and CSS custom properties.
// Rejects anything containing ; : ( ) that would escape the CSS value context.
const CSS_COLOR_RE =
  /^(#[0-9a-fA-F]{3,8}|[a-zA-Z]+|(?:rgba?|hsla?)\([\d\s,.%/]+\)|var\(--[\w-]+\))$/;

function safeCssColor(value: string, fallback: string): string {
  return CSS_COLOR_RE.test(value.trim()) ? value.trim() : fallback;
}

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export interface Branding {
  brandName?: string | null;
  brandLogoUrl?: string | null;
  brandFaviconUrl?: string | null;
  brandButtonColor?: string | null;
  brandButtonHoverColor?: string | null;
}

export interface Chrome {
  title: string;
  logoHtml: string;
  faviconHtml: string;
  btnColor: string;
  btnHoverCss: string;
}

/**
 * Derive the escaped, ready-to-interpolate branding fragments shared by both
 * pages. `baseTitle` is the page-specific heading (e.g. "Two-factor
 * authentication"); the brand name, when set, is appended after a separator.
 */
export function brandingChrome(b: Branding, baseTitle: string): Chrome {
  return {
    title: b.brandName
      ? `${baseTitle} · ${escapeHtml(b.brandName)}`
      : baseTitle,
    logoHtml: b.brandLogoUrl
      ? `<img src="${escapeHtml(b.brandLogoUrl)}" alt="${escapeHtml(b.brandName ?? "")}" class="logo">`
      : "",
    faviconHtml: b.brandFaviconUrl
      ? `<link rel="icon" href="${escapeHtml(b.brandFaviconUrl)}">`
      : "",
    btnColor: safeCssColor(b.brandButtonColor ?? "", "#0066cc"),
    btnHoverCss: b.brandButtonHoverColor
      ? `background: ${safeCssColor(b.brandButtonHoverColor, "#0055aa")};`
      : "filter: brightness(0.88);",
  };
}
