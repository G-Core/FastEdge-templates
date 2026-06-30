// The gate-only auth-app is a thin preset over @sso/core (HS256, no JWKS route).
// Shared federation/token logic is tested in the cookie auth-app's suites; this
// asserts only the variant-specific surface + that the built artifact boots.
import { runNonCookieVariantSmoke } from "../../../cookie/auth-app/tests/non-cookie-smoke.js";

await runNonCookieVariantSmoke("./wasm/gate-auth-app.wasm", "gate-only");
