import type { FC } from "hono/jsx";

// Shows a generic fixed message regardless of any URL parameter. The real error
// reason is logged server-side before the redirect — it never reaches the
// browser. This prevents information disclosure AND phishing via crafted
// /auth/error?message=<attacker-text>.
export const ErrorPage: FC = () => (
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Authentication Error</title>
    </head>
    <body style="display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif;padding:2rem;text-align:center">
      <h1 style="font-size:2rem;margin-bottom:1rem">Authentication Error</h1>
      <p style="color:#c00;max-width:480px;line-height:1.5">
        Sign-in failed — please try again.
      </p>
      <a href="/auth/" style="margin-top:2rem;color:#0066cc;text-decoration:underline">
        Try again
      </a>
    </body>
  </html>
);
