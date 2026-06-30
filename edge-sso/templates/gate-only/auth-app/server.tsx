import { createAuthApp } from "@sso/core";

// Gate-only variant: the edge allows or denies based on the session JWT.
// No identity information is forwarded to the origin.
const app = createAuthApp({ variant: "gate-only" });

addEventListener("fetch", (event: FetchEvent) => {
  event.respondWith(app.fetch(event.request));
});
