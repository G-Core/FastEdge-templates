import { createAuthApp } from "@sso/core";

const app = createAuthApp({ variant: "cookie" });

addEventListener("fetch", (event: FetchEvent) => {
  event.respondWith(app.fetch(event.request));
});
