use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::env;

const SET_COOKIE_HEADER: &str = "Set-Cookie";

const COOKIE_NAME_PARAM: &str = "COOKIE_NAME";
const SECURE_PARAM: &str = "SECURE";
const HTTPONLY_PARAM: &str = "HTTPONLY";
const SAMESITE_PARAM: &str = "SAMESITE";

const COOKIE_NAME_WILDCARD: &str = "*";

const SECURE_ATTR: &str = "Secure";
const HTTPONLY_ATTR: &str = "HttpOnly";
const SAMESITE_ATTR: &str = "SameSite";
const SAMESITE_VALUE: &str = "SameSite=Strict";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(HttpHeadersRoot) });
}}

struct HttpHeadersRoot;

impl Context for HttpHeadersRoot {}

impl RootContext for HttpHeadersRoot {
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HttpHeaders {}))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct HttpHeaders {}

impl Context for HttpHeaders {}

impl HttpContext for HttpHeaders {
    fn on_http_response_headers(&mut self, _: usize, _: bool) -> Action {
        // The cookie name to target. If unset, there is nothing to do.
        let cookie_name = match env::var(COOKIE_NAME_PARAM) {
            Ok(name) => name,
            Err(_) => return Action::Continue,
        };

        // Per-attribute toggles. Only attributes whose env var equals "true" are applied.
        let add_secure = env_is_true(SECURE_PARAM);
        let add_httponly = env_is_true(HTTPONLY_PARAM);
        let add_samesite = env_is_true(SAMESITE_PARAM);
        if !add_secure && !add_httponly && !add_samesite {
            return Action::Continue;
        }

        // Collect the Set-Cookie values in their original order, computing the
        // modified value for each. We can't rewrite the whole header map: the host
        // collapses duplicate Set-Cookie entries down to one. Instead we clear the
        // Set-Cookie header and re-add each occurrence with add_http_response_header.
        let mut cookies: Vec<String> = Vec::new();
        let mut changed = false;

        for (name, value) in self.get_http_response_headers() {
            if !name.eq_ignore_ascii_case(SET_COOKIE_HEADER) {
                continue;
            }

            let new_value = match cookie_name_of(&value) {
                Some(cn) if cookie_name == COOKIE_NAME_WILDCARD || cn == cookie_name => {
                    let modified = modify_cookie(&value, add_secure, add_httponly, add_samesite);
                    if modified != value {
                        changed = true;
                    }
                    modified
                }
                _ => value,
            };
            cookies.push(new_value);
        }

        if changed {
            // Remove all existing Set-Cookie headers, then append each cookie back
            // as its own header occurrence so multiple cookies are preserved.
            self.set_http_response_header(SET_COOKIE_HEADER, None);
            for cookie in &cookies {
                self.add_http_response_header(SET_COOKIE_HEADER, cookie);
            }
        }

        Action::Continue
    }
}

/// Returns true only when the given env var is set to exactly "true".
fn env_is_true(name: &str) -> bool {
    env::var(name).map(|v| v == "true").unwrap_or(false)
}

/// Extracts the cookie name (the part before the first '=') from a Set-Cookie value.
fn cookie_name_of(cookie: &str) -> Option<String> {
    let first = cookie.split(';').next()?;
    let name = first.split('=').next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Appends the requested attributes to a Set-Cookie value.
/// Secure and HttpOnly are added only if not already present; SameSite is set to
/// Strict, overriding any existing SameSite value.
fn modify_cookie(cookie: &str, add_secure: bool, add_httponly: bool, add_samesite: bool) -> String {
    // Trim each segment and drop empties (e.g. from a trailing ';') so we don't
    // emit stray separators when re-joining.
    let mut segments: Vec<String> = cookie
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let has_secure = segments.iter().any(|s| s.eq_ignore_ascii_case(SECURE_ATTR));
    let has_httponly = segments.iter().any(|s| s.eq_ignore_ascii_case(HTTPONLY_ATTR));

    if add_samesite {
        // Drop any existing SameSite attribute so we can override it with Strict.
        segments.retain(|s| {
            let key = s.split('=').next().unwrap_or("").trim();
            !key.eq_ignore_ascii_case(SAMESITE_ATTR)
        });
        segments.push(SAMESITE_VALUE.to_string());
    }
    if add_secure && !has_secure {
        segments.push(SECURE_ATTR.to_string());
    }
    if add_httponly && !has_httponly {
        segments.push(HTTPONLY_ATTR.to_string());
    }

    segments.join("; ")
}
