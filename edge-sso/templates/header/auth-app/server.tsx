/* FastEdge Deployment Magic Comments
* appName: "headers-auth-app"
* appId: "875579"
* appUrl: "https://headers-auth-app-4732724.fastedge.cdn.gc.onl/"
* outputFile: "saml-app/templates/header/auth-app/wasm/headers-auth-app.wasm"
* buildDirectory: "saml-app/templates/header/auth-app"
*/
import { createAuthApp } from "@sso/core";

// Header variant: the edge verifies the session JWT and injects X-Forwarded-User
// upstream so the origin can identify the user without verifying the token itself.
const app = createAuthApp({ variant: "header" });

addEventListener("fetch", (event: FetchEvent) => {
  event.respondWith(app.fetch(event.request));
});
