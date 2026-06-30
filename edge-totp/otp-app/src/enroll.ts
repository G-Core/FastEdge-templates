import { escapeHtml, brandingChrome } from "./lib/html.js";

function errorMessage(error: string): string {
  switch (error) {
    case "invalid": return "Incorrect code — please scan the QR code again and try once more.";
    case "kv":      return "Enrollment could not be saved. Please try again.";
    default:        return "Something went wrong. Please try again.";
  }
}

export function renderEnrollPage(opts: {
  formAction: string;
  svgQr: string;
  error?: string;
  digits?: number;
  brandName?: string | null;
  brandLogoUrl?: string | null;
  brandFaviconUrl?: string | null;
  brandButtonColor?: string | null;
  brandButtonHoverColor?: string | null;
}): string {
  const { formAction, svgQr, error } = opts;
  const digits = opts.digits ?? 6;
  const errorHtml = error
    ? `<p class="error">${escapeHtml(errorMessage(error))}</p>`
    : "";
  const { title, logoHtml, faviconHtml, btnColor, btnHoverCss } =
    brandingChrome(opts, "Activate two-factor authentication");

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
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 440px; margin: 60px auto; padding: 0 20px; color: #111; }
    .logo { display: block; max-height: 48px; max-width: 180px; margin: 0 auto 24px; }
    h1 { font-size: 1.35rem; margin: 0 0 6px; }
    .intro { color: #555; margin: 0 0 24px; font-size: 0.95rem; }
    ol { margin: 0 0 20px; padding-left: 1.4em; color: #555; font-size: 0.95rem; line-height: 1.7; }
    ol li { margin-bottom: 4px; }
    .qr { text-align: center; margin: 0 0 24px; }
    .qr svg { max-width: 220px; height: auto; border: 1px solid #eee; border-radius: 8px; padding: 8px; }
    .error { color: #c00; margin: 0 0 16px; font-size: 0.95rem; }
    label { display: block; font-size: 0.9rem; color: #555; margin-bottom: 6px; }
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
  <h1>Set up two-factor authentication</h1>
  <p class="intro">Protect your account with a one-time code from your phone.</p>
  <ol>
    <li>Install an authenticator app — Google Authenticator, Authy, or similar.</li>
    <li>Tap <strong>+</strong> or <strong>Add account</strong> and scan the QR code below.</li>
    <li>Enter the ${digits}-digit code shown in the app to confirm.</li>
  </ol>
  <div class="qr">${svgQr}</div>
  ${errorHtml}
  <p class="error" id="js-error" hidden></p>
  <form method="POST" action="${escapeHtml(formAction)}">
    <label for="code">Confirmation code</label>
    <input
      type="text"
      id="code"
      name="code"
      inputmode="numeric"
      pattern="[0-9 ]*"
      maxlength="${digits + 2}"
      autocomplete="one-time-code"
      autofocus
      placeholder="${"0".repeat(digits)}"
      aria-label="One-time code"
    >
    <button type="submit">Activate</button>
  </form>
  <script>
    // Submit the code as JSON via fetch(). On success the server returns
    // { next } for us to navigate to (a 303 from a fetch() can't drive the
    // top-level window).
    (function () {
      var form = document.querySelector("form");
      var input = document.getElementById("code");
      var btn = form.querySelector("button");
      var errEl = document.getElementById("js-error");
      function showError(msg) {
        errEl.textContent = msg;
        errEl.hidden = false;
        btn.disabled = false;
        input.value = "";
        input.focus();
      }
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        errEl.hidden = true;
        btn.disabled = true;
        var code = (input.value || "").replace(/\\s/g, "");
        fetch(form.action, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code: code }),
        }).then(function (res) {
          return res.json().catch(function () { return {}; }).then(function (data) {
            if (res.ok && data && data.next) {
              window.location.href = data.next;
              return;
            }
            showError((data && data.message) || "Something went wrong. Please try again.");
          });
        }).catch(function () {
          showError("Network error — please try again.");
        });
      });
    })();
  </script>
</body>
</html>`;
}
