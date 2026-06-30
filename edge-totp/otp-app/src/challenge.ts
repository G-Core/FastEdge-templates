import { escapeHtml, brandingChrome } from "./lib/html.js";

function errorMessage(error: string): string {
  switch (error) {
    case "invalid": return "Incorrect code — please try again.";
    case "locked":  return "Too many failed attempts. Please restart.";
    case "expired": return "Session expired. Please restart.";
    default:        return "Something went wrong. Please try again.";
  }
}

export function renderChallengePage(opts: {
  formAction: string;
  ticket: string;
  error?: string;
  digits?: number;
  brandName?: string | null;
  brandLogoUrl?: string | null;
  brandFaviconUrl?: string | null;
  brandButtonColor?: string | null;
  brandButtonHoverColor?: string | null;
}): string {
  const { formAction, ticket, error } = opts;
  const digits = opts.digits ?? 6;
  const errorHtml = error
    ? `<p class="error">${escapeHtml(errorMessage(error))}</p>`
    : "";
  const { title, logoHtml, faviconHtml, btnColor, btnHoverCss } =
    brandingChrome(opts, "Two-factor authentication");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>${title}</title>
  ${faviconHtml}
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 400px; margin: 80px auto; padding: 0 20px; color: #111; }
    .logo { display: block; max-height: 48px; max-width: 180px; margin: 0 auto 24px; }
    h1 { font-size: 1.35rem; margin: 0 0 6px; }
    .hint { color: #555; margin: 0 0 24px; font-size: 0.95rem; }
    .error { color: #c00; margin: 0 0 16px; font-size: 0.95rem; }
    input[type=text] {
      font-size: 2rem; letter-spacing: 0.5em; width: 100%; padding: 12px 8px;
      border: 1px solid #ccc; border-radius: 6px; text-align: center;
    }
    input[type=text]:focus { outline: 2px solid ${btnColor}; border-color: transparent; }
    button {
      margin-top: 14px; width: 100%; padding: 13px; font-size: 1rem;
      background: ${btnColor}; color: #fff; border: none; border-radius: 6px; cursor: pointer;
    }
    button:hover { ${btnHoverCss} }
  </style>
</head>
<body>
  ${logoHtml}
  <h1>Two-factor authentication</h1>
  <p class="hint">Enter the ${digits}-digit code from your authenticator app.</p>
  ${errorHtml}
  <form method="POST" action="${escapeHtml(formAction)}">
    <input type="hidden" name="t" value="${escapeHtml(ticket)}">
    <input
      type="text"
      name="code"
      inputmode="numeric"
      pattern="[0-9 ]*"
      maxlength="${digits + 2}"
      autocomplete="one-time-code"
      autofocus
      placeholder="${"0".repeat(digits)}"
      aria-label="One-time code"
    >
    <button type="submit">Verify</button>
  </form>
</body>
</html>`;
}
