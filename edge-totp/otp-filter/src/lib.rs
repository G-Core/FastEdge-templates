use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use fastedge::proxywasm::secret;
use hmac::{Hmac, Mac};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use sha2::Sha256;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(OtpGuardRoot) });
}}

pub struct OtpGuardRoot;

impl Context for OtpGuardRoot {}

impl RootContext for OtpGuardRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(OtpGuard))
    }
}

struct OtpGuard;

impl Context for OtpGuard {}

const DEFAULT_COOKIE: &str = "mfa_session";
const DEFAULT_AUTH_PREFIX: &str = "/auth/totp";
const EXPECTED_ALG: &str = "HS256";

impl HttpContext for OtpGuard {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let full_path = self
            .get_property(vec!["request.path"])
            .and_then(|v| String::from_utf8(v).ok())
            .unwrap_or_default();

        let auth_prefix = env::var("AUTH_PREFIX")
            .unwrap_or_else(|_| DEFAULT_AUTH_PREFIX.to_string());

        // Bypass the totp-app paths (challenge, verify, enroll, JWKS) and /health.
        // Gating these would redirect-loop the TOTP flow.
        if is_bypass_path(&full_path, &auth_prefix) {
            return Action::Continue;
        }

        let cookie_name = env::var("MFA_SESSION_COOKIE")
            .unwrap_or_else(|_| DEFAULT_COOKIE.to_string());
        let login_url = env::var("MFA_LOGIN_URL").unwrap_or_default();

        let cookie_header = self.get_http_request_header("cookie").unwrap_or_default();
        let token = match extract_cookie(&cookie_header, &cookie_name) {
            Some(t) => t,
            None => return self.deny(&full_path, &login_url, "no mfa_session cookie"),
        };

        let claims = match verify_jwt(&token) {
            Err(reason) => return self.deny(&full_path, &login_url, reason),
            Ok(c) => c,
        };

        // MFA_AUDIENCE is required. Fail-closed if not configured — a filter
        // with no audience set cannot know which tokens belong to it, so it refuses
        // every session rather than trusting any signed token indiscriminately.
        let expected_aud = env::var("MFA_AUDIENCE").unwrap_or_default();
        if expected_aud.is_empty() {
            return self.deny(
                &full_path,
                &login_url,
                "MFA_AUDIENCE not configured — refusing all sessions (set MFA_AUDIENCE to match otp-app's MFA_AUDIENCE)",
            );
        }
        if !aud_matches(&claims.aud, &expected_aud) {
            return self.deny(&full_path, &login_url, "aud mismatch");
        }

        // MFA_ISSUER is optional — validated only when set.
        if let Ok(expected) = env::var("MFA_ISSUER") {
            if !expected.is_empty() && claims.iss.as_deref() != Some(expected.as_str()) {
                return self.deny(&full_path, &login_url, "iss mismatch");
            }
        }

        println!(
            "otp_guard: authorized — valid mfa_session (sub={}) for {full_path}",
            claims.sub.as_deref().unwrap_or("<none>")
        );

        Action::Continue
    }
}

impl OtpGuard {
    fn deny(&mut self, full_path: &str, login_url: &str, reason: &str) -> Action {
        println!("otp_guard: denied — {reason}");
        if login_url.is_empty() {
            // No redirect configured: fail-closed with 401.
            self.send_http_response(
                401,
                vec![("content-type", "text/plain")],
                Some(b"MFA required"),
            );
            return Action::Pause;
        }
        // Encode the return target as the *relative* request path only.
        // Building it from request.scheme/request.host would fold an
        // attacker-controllable Host header into the redirect= value, which a
        // login page that bounces back to `redirect` could turn into an open
        // redirect. A relative path is inherently same-origin and matches the
        // app's own same-host redirect policy (validateRedirect).
        let encoded = urlencoding::encode(full_path);
        let sep = if login_url.contains('?') { "&" } else { "?" };
        let location = format!("{login_url}{sep}redirect={encoded}");
        self.send_http_response(302, vec![("location", &location)], Some(b""));
        Action::Pause
    }
}

fn is_bypass_path(full_path: &str, auth_prefix: &str) -> bool {
    let path = full_path.split('?').next().unwrap_or(full_path);
    // Never bypass a path that carries traversal or encoded-separator
    // sequences. `/auth/totp/../admin` matches the prefix below but the origin
    // may normalise it back to `/admin`, slipping a protected resource past the
    // gate. If the path looks abnormal, fall through to the cookie check so it
    // is gated rather than waved through.
    if has_suspicious_sequence(path) {
        return false;
    }
    path == "/health"
        || path == auth_prefix
        || path.starts_with(&format!("{auth_prefix}/"))
}

/// Detect path segments that could be normalised by the origin into a
/// different resource: `..`, `//`, backslashes, or percent-encoded dots and
/// slashes (`%2e`, `%2f`, including double-encoding via `%25`).
fn has_suspicious_sequence(path: &str) -> bool {
    if path.contains("..") || path.contains("//") || path.contains('\\') {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") || lower.contains("%25")
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
}

fn verify_jwt(token: &str) -> Result<JwtClaims, &'static str> {
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

    // Alg is pinned to HS256 at compile time — token cannot select its own
    // verification path.
    if alg != EXPECTED_ALG {
        println!(
            "otp_guard: token alg '{alg}' rejected — filter accepts only {EXPECTED_ALG}"
        );
        return Err("unexpected alg");
    }

    let sig_bytes =
        URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| "bad signature encoding")?;

    let key_bytes = secret::get("MFA_SESSION_KEY")
        .ok()
        .flatten()
        .unwrap_or_default();
    let key = String::from_utf8(key_bytes).unwrap_or_default();
    if key.is_empty() {
        println!("otp_guard: MFA_SESSION_KEY not configured");
        return Err("missing session key");
    }
    verify_hs256(message, &sig_bytes, &key)?;

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

    // Honour nbf when present — a token must not be accepted before it becomes
    // valid. Absent nbf is fine (the claim is optional).
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
    })
}

fn verify_hs256(message: &str, sig_bytes: &[u8], secret: &str) -> Result<(), &'static str> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| "bad key length")?;
    mac.update(message.as_bytes());
    mac.verify_slice(sig_bytes).map_err(|_| "invalid signature")
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
