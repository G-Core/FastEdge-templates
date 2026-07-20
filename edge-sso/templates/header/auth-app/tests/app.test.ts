// The header auth-app is a thin preset over @sso/core (HS256, no JWKS route) —
// identical to gate-only at the auth-app level; the header-specific behaviour
// (X-Forwarded-* injection) lives in the cdn-filter and is tested there. Shared
// federation/token logic is tested in the cookie auth-app's suites; this asserts
// only the variant-specific surface + that the built artifact boots.
import { runNonCookieVariantSmoke } from "../../../cookie/auth-app/tests/non-cookie-smoke.js";

await runNonCookieVariantSmoke("./wasm/headers-auth-app.wasm", "header");
