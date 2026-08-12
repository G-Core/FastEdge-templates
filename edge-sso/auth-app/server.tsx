import { Hono } from "hono";
import { createAuthApp } from "./federation/index.js";
import { getEnv } from "fastedge::env";

// One auth-app now serves all three identity-delivery variants — SSO_VARIANT
// picks the behavior at runtime. Must equal the CDN filter's SSO_VARIANT.
const VALID_VARIANTS = ["gate-only", "cookie", "header"] as const;
type Variant = (typeof VALID_VARIANTS)[number];

function isValidVariant(v: string | null | undefined): v is Variant {
  return (VALID_VARIANTS as readonly string[]).includes(v ?? "");
}

// Env vars aren't available during the build-time wizer snapshot, only at
// request time — so the app must be built lazily on first request, not at
// module scope (every other getEnv() call in this codebase is likewise
// inside a route handler, never top-level).
let app: Hono | undefined;

function getApp(): Hono {
  if (app) return app;

  const rawVariant = getEnv("SSO_VARIANT");
  if (isValidVariant(rawVariant)) {
    app = createAuthApp({ variant: rawVariant });
    return app;
  }

  // Unlike the filter, the auth-app isn't a security gate — there's nothing to
  // "fail closed" against — but a silent default would mask a misconfiguration
  // (e.g. auth-app on "cookie" while the filter is on "header"). Surface it
  // loudly instead of guessing.
  const misconfigured = new Hono();
  misconfigured.all("*", (c) =>
    c.text(
      `SSO_VARIANT is not configured or invalid (got: ${JSON.stringify(rawVariant)}). ` +
        `Set it to one of: ${VALID_VARIANTS.join(", ")} — it must match the CDN filter's SSO_VARIANT.`,
      500,
    ),
  );
  app = misconfigured;
  return app;
}

addEventListener("fetch", (event: FetchEvent) => {
  event.respondWith(getApp().fetch(event.request));
});
