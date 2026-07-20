import type { FC } from "hono/jsx";
import { buildLoginUrl, type ResolvedProvider } from "./providers/registry";
import type { LoginPageBranding } from "./config";

/**
 * Server-rendered login page (hono/jsx — no React, no client bundle).
 *
 * Three-tier customization:
 *   Tier 1 — LOGIN_PAGE_* env vars (branding prop) style the built-in page.
 *   Tier 2 — LOGIN_PAGE_CSS_URL links a customer stylesheet (loaded last, full
 *             override). CSS variables --lp-accent and --lp-bg are entry points.
 *   Tier 3 — Set LOGIN_PAGE_URL (filter env) to redirect unauthenticated users
 *             to a fully custom page; that page uses GET /auth/providers for data.
 *
 * Provider buttons follow each IdP's branding guidelines: Google uses the
 * official "G" mark and button style; GitHub uses the Octocat mark.
 * The SAML button label is configurable via IDP_LABEL; its icon via IDP_ICON_URL.
 */

// Static CSS — uses CSS variables so LOGIN_PAGE_CSS_URL can trivially restyle.
// Dynamic brand values (accent, bg) are injected via the <html style> attribute
// rather than directly in this string, so no escaping concerns here.
const PAGE_CSS = `
*{box-sizing:border-box;margin:0;padding:0}
body{
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  background:var(--lp-bg,#f0f2f5);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  padding:1rem;
  -webkit-font-smoothing:antialiased;
}
.card{
  background:#fff;
  border-radius:8px;
  box-shadow:0 2px 16px rgba(0,0,0,.10);
  padding:2.5rem 2rem;
  width:100%;
  max-width:400px;
  text-align:center;
}
.logo{max-height:48px;width:auto;margin-bottom:1.5rem}
.card h1{font-size:1.375rem;color:#1a1a1a;font-weight:600;margin-bottom:.375rem}
.subtitle{color:#666;font-size:.875rem;margin-bottom:2rem;line-height:1.4}
.providers{display:flex;flex-direction:column;gap:.625rem}
.btn{
  display:flex;
  align-items:center;
  justify-content:center;
  gap:.625rem;
  width:100%;
  height:44px;
  padding:0 1rem;
  border:none;
  border-radius:4px;
  font-size:.9375rem;
  font-weight:500;
  text-decoration:none;
  white-space:nowrap;
  transition:opacity .15s ease;
}
.btn:hover,.btn:focus-visible{opacity:.85}
.btn:focus-visible{outline:2px solid var(--lp-accent,#0066cc);outline-offset:2px}
.btn-google{background:#fff;border:1px solid #dadce0;color:#3c4043}
.btn-github{background:#24292e;color:#fff}
.btn-microsoft{background:#fff;border:1px solid #8c8c8c;color:#5e5e5e}
.btn-facebook{background:#1877f2;color:#fff}
.btn-sso{background:var(--lp-accent,#0066cc);color:#fff}
.btn-icon{flex-shrink:0;display:block;width:18px;height:18px}
.btn-icon-initial{
  border-radius:50%;
  background:rgba(255,255,255,.25);
  display:flex;
  align-items:center;
  justify-content:center;
  font-size:11px;
  font-weight:700;
  line-height:1;
}
.no-providers{color:#888;font-size:.875rem;line-height:1.5}
`;

const GoogleIcon: FC = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
    <path
      d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
      fill="#4285F4"
    />
    <path
      d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
      fill="#34A853"
    />
    <path
      d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
      fill="#FBBC05"
    />
    <path
      d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
      fill="#EA4335"
    />
  </svg>
);

const GitHubIcon: FC = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
    <path
      fill="currentColor"
      d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"
    />
  </svg>
);

const MicrosoftIcon: FC = () => (
  <svg viewBox="0 0 21 21" width="18" height="18" aria-hidden="true">
    <rect x="1" y="1" width="9" height="9" fill="#f25022" />
    <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
    <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
    <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
  </svg>
);

const FacebookIcon: FC = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
    <path
      fill="currentColor"
      d="M13.397 20.997v-8.196h2.765l.411-3.209h-3.176V7.548c0-.926.258-1.56 1.587-1.56h1.684V3.127A22.336 22.336 0 0 0 14.201 3c-2.444 0-4.122 1.492-4.122 4.231v2.355H7.332v3.209h2.753v8.202h3.312z"
    />
  </svg>
);

const ProviderButton: FC<{ provider: ResolvedProvider; redirect?: string }> = ({
  provider,
  redirect,
}) => {
  const href = buildLoginUrl(provider.loginPath, redirect);

  if (provider.id === "google") {
    return (
      <a href={href} class="btn btn-google">
        <GoogleIcon />
        Sign in with Google
      </a>
    );
  }

  if (provider.id === "github") {
    return (
      <a href={href} class="btn btn-github">
        <GitHubIcon />
        Sign in with GitHub
      </a>
    );
  }

  if (provider.id === "microsoft") {
    return (
      <a href={href} class="btn btn-microsoft">
        <MicrosoftIcon />
        Sign in with Microsoft
      </a>
    );
  }

  if (provider.id === "facebook") {
    return (
      <a href={href} class="btn btn-facebook">
        <FacebookIcon />
        Sign in with Facebook
      </a>
    );
  }

  // SAML / future providers — configurable label and optional icon
  return (
    <a href={href} class="btn btn-sso">
      {provider.iconUrl ? (
        <img
          src={provider.iconUrl}
          alt=""
          width="18"
          height="18"
          class="btn-icon"
        />
      ) : (
        <span class="btn-icon btn-icon-initial" aria-hidden="true">
          {provider.label.charAt(0).toUpperCase()}
        </span>
      )}
      Sign in with {provider.label}
    </a>
  );
};

export const Chooser: FC<{
  providers: ResolvedProvider[];
  redirect?: string;
  branding: LoginPageBranding;
}> = ({ providers, redirect, branding }) => {
  // CSS variables are set on <html> as a style attribute — hono/jsx auto-escapes
  // attribute values, so no injection risk from the color strings.
  const cssVars = `--lp-accent:${branding.accentColor};--lp-bg:${branding.backgroundColor}`;

  return (
    <html lang="en" style={cssVars}>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{branding.title}</title>
        {branding.faviconUrl && <link rel="icon" href={branding.faviconUrl} />}
        <style dangerouslySetInnerHTML={{ __html: PAGE_CSS }} />
        {branding.cssUrl && (
          <link rel="stylesheet" href={branding.cssUrl} />
        )}
      </head>
      <body>
        <div class="card">
          {branding.logoUrl && (
            <img src={branding.logoUrl} alt="Logo" class="logo" />
          )}
          <h1>{branding.title}</h1>
          <p class="subtitle">{branding.subtitle}</p>
          {providers.length === 0 ? (
            <p class="no-providers">No sign-in providers are configured.</p>
          ) : (
            <div class="providers">
              {providers.map((p) => (
                <ProviderButton provider={p} redirect={redirect} />
              ))}
            </div>
          )}
        </div>
      </body>
    </html>
  );
};
