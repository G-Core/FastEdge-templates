import { createAuthApp } from "@sso/core";

// Header variant: the edge verifies the session JWT and injects x-sso-* identity
// headers upstream so the origin can identify the user without verifying the token itself.
const app = createAuthApp({ variant: "header" });

addEventListener("fetch", (event: FetchEvent) => {
  event.respondWith(app.fetch(event.request));
});
