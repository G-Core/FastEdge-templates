use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use fastedge::proxywasm::secret;
use proxy_wasm::traits::*;
use proxy_wasm::types::{Action, ContextType, LogLevel};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Verifier as _;

// Identity-delivery variant, selected at runtime via SSO_VARIANT so one wasm
// binary serves all three deployments. Each variant pins its own JWT
// algorithm (a token can never select its own verification path — see
// verify_jwt) and behavior for cookie stripping / header injection.
#[derive(Clone, Copy, PartialEq)]
enum Variant {
    GateOnly,
    Cookie,
    Header,
}

impl Variant {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "gate-only" => Some(Variant::GateOnly),
            "cookie" => Some(Variant::Cookie),
            "header" => Some(Variant::Header),
            _ => None,
        }
    }

    // cookie: the origin holds only a public key, so it must be
    // asymmetric (ES256). gate-only/header: the filter is the only verifier,
    // so a symmetric secret (HS256) is fine.
    fn expected_alg(self) -> &'static str {
        match self {
            Variant::Cookie => "ES256",
            Variant::GateOnly | Variant::Header => "HS256",
        }
    }

    // gate-only and header: strip the session cookie so origins never see
    // the raw JWT. cookie: the origin needs it, so leave it in place.
    fn strip_session_cookie(self) -> bool {
        !matches!(self, Variant::Cookie)
    }

    // header only: inject identity as x-sso-* request headers.
    fn inject_user_header(self) -> bool {
        matches!(self, Variant::Header)
    }
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(SsoGuardRoot)
    });
}}

struct SsoGuardRoot;

impl Context for SsoGuardRoot {}

impl RootContext for SsoGuardRoot {
    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(SsoGuard))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct SsoGuard;

impl Context for SsoGuard {}

const DEFAULT_AUTH_PREFIX: &str = "/auth";
const DEFAULT_COOKIE: &str = "sso_session";

// The header variant injects identity as x-sso-* request headers (x-sso-user
// plus per-claim headers). Each is cleared/injected via SsoGuard::put_user_header
// so a client cannot smuggle a spoofed copy past the filter, while respecting
// the CDN's request-header propagation rules (see that method).

impl HttpContext for SsoGuard {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let full_path = self
            .get_property(vec!["request.path"])
            .and_then(|v| String::from_utf8(v).ok())
            .unwrap_or_default();

        let auth_prefix = env::var("AUTH_PREFIX")
            .unwrap_or_else(|_| DEFAULT_AUTH_PREFIX.to_string());

        // The auth-app serves AUTH_PREFIX/** as an origin under single-domain
        // routing; gating it would redirect-loop the login flow.
        if is_auth_path(&full_path, &auth_prefix) {
            return Action::Continue;
        }

        let cookie_name =
            env::var("SESSION_COOKIE").unwrap_or_else(|_| DEFAULT_COOKIE.to_string());
        let chooser = env::var("LOGIN_PAGE_URL")
            .unwrap_or_else(|_| format!("{}/", auth_prefix));

        // SSO_VARIANT is REQUIRED and fail-closed, same rationale as
        // SSO_AUDIENCE below: a filter that doesn't know its own variant
        // can't know which alg to trust or whether to strip/inject anything,
        // so it refuses every session rather than guessing.
        let variant = match env::var("SSO_VARIANT").ok().as_deref().and_then(Variant::parse) {
            Some(v) => v,
            None => {
                return self.deny(
                    &full_path,
                    &chooser,
                    "SSO_VARIANT not configured or invalid — refusing all sessions (set SSO_VARIANT to gate-only, cookie, or header)",
                );
            }
        };

        let cookie_header = self.get_http_request_header("cookie").unwrap_or_default();
        let token = match extract_cookie(&cookie_header, &cookie_name) {
            Some(t) => t,
            None => return self.deny(&full_path, &chooser, "no session cookie"),
        };

        let claims = match verify_jwt(&token, variant) {
            Err(reason) => return self.deny(&full_path, &chooser, reason),
            Ok(c) => c,
        };

        // Audience is REQUIRED and fail-closed. A filter with no SSO_AUDIENCE set
        // cannot know which tokens are meant for it, so it refuses every session
        // rather than trusting any signed token. When set, the token's `aud` must
        // match. This binds each token to its deployment: distinct SSO_AUDIENCE
        // per app = isolated sessions; the SAME SSO_AUDIENCE on two apps = sessions
        // deliberately shared between them. It must match the auth-app's SSO_AUDIENCE.
        let expected_aud = env::var("SSO_AUDIENCE").unwrap_or_default();
        if expected_aud.is_empty() {
            return self.deny(
                &full_path,
                &chooser,
                "SSO_AUDIENCE not configured — refusing all sessions (set SSO_AUDIENCE to this deployment's audience; it must match the auth-app)",
            );
        }
        if !aud_matches(&claims.aud, &expected_aud) {
            return self.deny(&full_path, &chooser, "aud mismatch");
        }

        // Issuer is optional: validated only when SSO_ISSUER is configured. The
        // signing key already establishes issuer trust in this single-key model,
        // so this is a defense-in-depth / observability check, not a gate.
        if let Ok(expected) = env::var("SSO_ISSUER") {
            if !expected.is_empty() && claims.iss.as_deref() != Some(expected.as_str()) {
                return self.deny(&full_path, &chooser, "iss mismatch");
            }
        }

        // Observability: the session was accepted. Without this, a working filter
        // is silent and indistinguishable (in logs) from one that never ran.
        println!(
            "sso_guard: authorized — valid session (sub={}) for {full_path}",
            claims.sub.as_deref().unwrap_or("<none>")
        );

        // gate-only and header variants: strip the session cookie so origins
        // never see the raw JWT.
        if variant.strip_session_cookie() {
            let stripped = cookie_header
                .split(';')
                .map(str::trim)
                .filter(|p| !p.starts_with(&format!("{cookie_name}=")))
                .collect::<Vec<_>>()
                .join("; ");
            if stripped.is_empty() {
                self.set_http_request_header("cookie", None);
            } else {
                self.set_http_request_header("cookie", Some(&stripped));
            }
        }

        // Header variant: inject identity as x-sso-* request headers.
        //
        // The origin trusts x-sso-*, so a client must never smuggle its own copy
        // past the filter. put_user_header clears any client-supplied value and
        // injects only what the verified token yields.
        //
        // Propagation constraint (FastEdge CDN): the origin-fetch carries a
        // proxy-wasm request-header mutation only when the header already existed
        // in the client request (set replaces it) or when we add() a new line;
        // set() of a brand-new header is dropped before the origin. put_user_header
        // therefore chooses set vs add based on the header's original presence.
        if variant.inject_user_header() {
            self.put_user_header("x-sso-user", claims.sub.as_deref());
            self.put_user_header("x-sso-email", claims.email.as_deref());
            self.put_user_header("x-sso-name", claims.name.as_deref());
            self.put_user_header("x-sso-picture", claims.picture.as_deref());
            self.put_user_header("x-sso-given-name", claims.given_name.as_deref());
            self.put_user_header("x-sso-family-name", claims.family_name.as_deref());
        }

        Action::Continue
    }
}

impl SsoGuard {
    // Inject (or clear) one managed x-sso-* request header so the verified value
    // reaches the origin under the FastEdge CDN's propagation rules:
    //   - value present, header already in request -> set  (replace in place)
    //   - value present, header absent             -> add  (create the only copy)
    //   - no value,      header already in request -> set None (clear client value)
    //   - no value,      header absent             -> nothing to do
    //
    // Presence is read once, before mutating, because the CDN keys propagation off
    // the header's ORIGINAL presence in the client request, not the filter's view:
    // set() of a brand-new header is silently dropped before the origin, whereas
    // set() of an existing header and add() both propagate. A client-supplied
    // header with no matching claim is blanked (set None) rather than truly
    // removed, so the origin MUST treat an empty x-sso-* as absent.
    fn put_user_header(&mut self, name: &str, value: Option<&str>) {
        let present = self.get_http_request_header(name).is_some();
        match value {
            Some(v) if present => self.set_http_request_header(name, Some(v)),
            Some(v) => self.add_http_request_header(name, v),
            None if present => self.set_http_request_header(name, None),
            None => {}
        }
    }

    fn deny(&mut self, full_path: &str, chooser: &str, reason: &str) -> Action {
        println!("sso_guard: redirect — {reason}");
        let scheme = self
            .get_property(vec!["request.scheme"])
            .and_then(|v| String::from_utf8(v).ok())
            .unwrap_or_else(|| "https".to_string());
        let host = self
            .get_property(vec!["request.host"])
            .and_then(|v| String::from_utf8(v).ok())
            .unwrap_or_default();
        let original = format!("{scheme}://{host}{full_path}");
        let encoded = urlencoding::encode(&original);
        let sep = if chooser.contains('?') { "&" } else { "?" };
        let location = format!("{chooser}{sep}redirect={encoded}");
        self.send_http_response(302, vec![("location", &location)], Some(b""));
        Action::Pause
    }
}

fn is_auth_path(full_path: &str, auth_prefix: &str) -> bool {
    let path = full_path.split('?').next().unwrap_or(full_path);
    path == auth_prefix || path.starts_with(&format!("{}/", auth_prefix))
}

fn extract_cookie(header: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    for pair in header.split(';') {
        let trimmed = pair.trim();
        if trimmed.starts_with(needle.as_str()) {
            return Some(trimmed[needle.len()..].to_string());
        }
    }
    None
}

struct JwtClaims {
    sub: Option<String>,
    iss: Option<String>,
    aud: Option<serde_json::Value>,
    email: Option<String>,
    name: Option<String>,
    picture: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
}

fn verify_jwt(token: &str, variant: Variant) -> Result<JwtClaims, &'static str> {
    let dot1 = token.find('.').ok_or("malformed token")?;
    let after_header = &token[dot1 + 1..];
    let dot2 = after_header.find('.').ok_or("malformed token")?;
    let header_b64 = &token[..dot1];
    let payload_b64 = &after_header[..dot2];
    let sig_b64 = &after_header[dot2 + 1..];
    let message = &token[..dot1 + 1 + dot2];

    let header_bytes =
        URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| "bad header encoding")?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| "bad header JSON")?;
    let alg = header["alg"].as_str().unwrap_or_default();

    // The accepted algorithm is pinned per variant (Variant::expected_alg), so
    // a token can never select its own verification path. cookie ⇒ ES256-only
    // (the origin holds only a public key); gate-only/header ⇒ HS256-only.
    let expected_alg = variant.expected_alg();
    if alg != expected_alg {
        println!(
            "sso_guard: token alg '{alg}' rejected — this filter accepts only {expected_alg} for SSO_VARIANT={expected_alg}; if the auth-app signs with a different alg, check SSO_VARIANT matches on both apps"
        );
        return Err("unexpected alg");
    }

    let sig_bytes =
        URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| "bad signature encoding")?;

    match variant {
        Variant::GateOnly | Variant::Header => {
            let secret = secret::get("SESSION_SECRET")
                .ok()
                .flatten()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            if secret.is_empty() {
                println!("sso_guard: SESSION_SECRET missing");
                return Err("missing session secret");
            }
            verify_hs256(message, &sig_bytes, &secret)?;
        }
        Variant::Cookie => {
            let jwk_json = match env::var("SESSION_PUBLIC_JWK") {
                Err(_) => {
                    println!(
                        "sso_guard: SESSION_PUBLIC_JWK env var is not set — add it to the CDN filter environment variables"
                    );
                    return Err("SESSION_PUBLIC_JWK not configured");
                }
                Ok(v) if v.is_empty() => {
                    println!(
                        "sso_guard: SESSION_PUBLIC_JWK env var is empty — ES256 verification impossible"
                    );
                    return Err("SESSION_PUBLIC_JWK is empty");
                }
                Ok(v) => v,
            };
            if let Err(e) = verify_es256(message, &sig_bytes, &jwk_json) {
                println!("sso_guard: ES256 verification failed: {e}");
                return Err(e);
            }
        }
    }

    let payload_bytes =
        URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| "bad payload encoding")?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| "bad payload JSON")?;

    let exp = payload["exp"]
        .as_u64()
        .or_else(|| payload["exp"].as_f64().map(|f| f as u64))
        .ok_or("missing exp claim")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if exp <= now {
        return Err("token expired");
    }

    // nbf is optional; when present, reject a token that is not valid yet.
    if let Some(nbf) = payload["nbf"]
        .as_u64()
        .or_else(|| payload["nbf"].as_f64().map(|f| f as u64))
    {
        if now < nbf {
            return Err("token not yet valid");
        }
    }

    Ok(JwtClaims {
        sub: payload["sub"].as_str().map(str::to_owned),
        iss: payload["iss"].as_str().map(str::to_owned),
        aud: payload.get("aud").cloned(),
        email: payload["email"].as_str().map(str::to_owned),
        name: payload["name"].as_str().map(str::to_owned),
        picture: payload["picture"].as_str().map(str::to_owned),
        given_name: payload["given_name"].as_str().map(str::to_owned),
        family_name: payload["family_name"].as_str().map(str::to_owned),
    })
}

fn verify_hs256(message: &str, sig_bytes: &[u8], secret: &str) -> Result<(), &'static str> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| "bad key length")?;
    mac.update(message.as_bytes());
    mac.verify_slice(sig_bytes).map_err(|_| "invalid signature")
}

fn verify_es256(message: &str, sig_bytes: &[u8], jwk_json: &str) -> Result<(), &'static str> {
    let jwk: serde_json::Value =
        serde_json::from_str(jwk_json).map_err(|_| "bad public key JSON")?;

    let x_b64 = jwk["x"].as_str().ok_or("missing x in JWK")?;
    let y_b64 = jwk["y"].as_str().ok_or("missing y in JWK")?;

    let x_bytes = URL_SAFE_NO_PAD.decode(x_b64).map_err(|_| "bad x encoding")?;
    let y_bytes = URL_SAFE_NO_PAD.decode(y_b64).map_err(|_| "bad y encoding")?;

    // Uncompressed SEC1 point: 0x04 || x (32 bytes) || y (32 bytes)
    let mut point_bytes = Vec::with_capacity(65);
    point_bytes.push(0x04u8);
    point_bytes.extend_from_slice(&x_bytes);
    point_bytes.extend_from_slice(&y_bytes);

    let encoded_point =
        p256::EncodedPoint::from_bytes(&point_bytes).map_err(|_| "invalid EC point")?;
    let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|_| "invalid public key")?;

    // JWT ES256 signature is IEEE P1363 (r‖s, 64 bytes for P-256)
    let signature = p256::ecdsa::Signature::try_from(sig_bytes.as_ref())
        .map_err(|_| "invalid signature format")?;

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| "invalid signature")
}

fn aud_matches(aud: &Option<serde_json::Value>, expected: &str) -> bool {
    match aud {
        None => false,
        Some(serde_json::Value::String(s)) => s == expected,
        Some(serde_json::Value::Array(arr)) => {
            arr.iter().any(|v| v.as_str() == Some(expected))
        }
        _ => false,
    }
}
