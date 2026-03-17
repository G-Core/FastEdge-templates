use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::{str, env};
use htmd::HtmlToMarkdown;
use htmlize::unescape;

proxy_wasm::main! {{
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(HttpBodyRoot) });
}}

struct HttpBodyRoot;

impl Context for HttpBodyRoot {}

impl RootContext for HttpBodyRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HttpBody))
    }
}
struct HttpBody;
impl Context for HttpBody {}

const SERVER_ERROR: u32 = 500;
const CONVERT_FLAG: &str = "Convert";
const CONTENT_TYPE_HEADER: &str = "Content-Type";
const ACCEPT_HEADER: &str = "Accept";
const ACCEPT_ENCODING_HEADER: &str = "Accept-Encoding";
const CONTENT_LENGTH_HEADER: &str = "Content-Length";
const TRANSFER_ENCODING_HEADER: &str = "Transfer-Encoding";
const TRANSFER_ENCODING_CHUNKED: &str = "Chunked";
const MARKDOWN_MIME: &str = "text/markdown";
const HTML_MIME: &str = "text/html";
const IGNORE_BODY_ERROR_PARAM: &str = "IGNORE_ERROR";

impl HttpContext for HttpBody {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // remove any existing Convert flag to avoid interference from previous requests in the same context
        self.set_http_request_header(CONVERT_FLAG, None);
        let accept = match self.get_http_request_header(ACCEPT_HEADER) {
            None => return Action::Continue,
            Some(u) => u
        };

        if content_type_match(&accept, MARKDOWN_MIME) {
            println!("Markdown requested");
            self.add_http_request_header(CONVERT_FLAG, "markdown");
            self.set_http_request_header(ACCEPT_ENCODING_HEADER, None);  // prevent response compression
        }

        Action::Continue
    }

    fn on_http_response_headers(&mut self, _: usize, _: bool) -> Action {
        if self.get_http_request_header(CONVERT_FLAG).is_none() {
            return Action::Continue;
        };

        if let Some(content_type) = self.get_http_response_header(CONTENT_TYPE_HEADER) {
            if content_type_match(&content_type, HTML_MIME) {
                let path = match self.get_property(vec!["request.path"]) {
                    Some(p) => {
                        // Paths are not guaranteed to be valid UTF-8; decode lossily for logging
                        std::string::String::from_utf8_lossy(&p).into_owned()
                    }
                    None => "/".to_string()
                };
                println!("Got HTML to convert: {}", path);

                self.remove_http_response_header(CONTENT_LENGTH_HEADER);
                self.set_http_response_header(CONTENT_TYPE_HEADER, Some(MARKDOWN_MIME));
                self.set_http_response_header(TRANSFER_ENCODING_HEADER, Some(TRANSFER_ENCODING_CHUNKED));
                self.set_property(vec!["response.md"], Some(b"true"));
            }
        }

        // use Convert for cache key; merge with any existing Vary header
        if let Some(mut vary) = self.get_http_response_header("Vary") {
            let has_convert = vary
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case(CONVERT_FLAG));
            if !has_convert {
                if !vary.is_empty() {
                    vary.push_str(", ");
                }
                vary.push_str(CONVERT_FLAG);
                self.set_http_response_header("Vary", Some(&vary));
            }
        } else {
            self.set_http_response_header("Vary", Some(CONVERT_FLAG));
        }
        Action::Continue
    }

    fn on_http_response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if !end_of_stream {
            return Action::Pause;
        }

        // only process HTML
        if self.get_property(vec!["response.md"]).is_none() {
            return Action::Continue;
        }

        let path = match self.get_property(vec!["request.path"]) {
            Some(p) => {
                // Paths are not guaranteed to be valid UTF-8; decode lossily for logging
                std::string::String::from_utf8_lossy(&p).into_owned()
            }
            None => "/".to_string()
        };

        let ignore_error = env::var(IGNORE_BODY_ERROR_PARAM).unwrap_or_else(|_| "false".to_string()) == "true";

        if let Some(body_bytes) = self.get_http_response_body(0, body_size) {
            let body_str = match str::from_utf8(&body_bytes) {
                Ok(s) => s,
                Err(e) => {
                    println!("cannot convert body to string {}", e);
                    if ignore_error {
                        println!("Ignoring body error and passing through original response");
                        return Action::Continue;
                    }
                    self.send_http_response(SERVER_ERROR, vec![], Some(b"Origin response is not valid UTF-8"));
                    return Action::Pause;
                }
            };
            let converter = HtmlToMarkdown::builder()
                .skip_tags(vec!["script", "style", "svg", "noscript", "iframe", "link"])
                .build();
            let md = match converter.convert(body_str) {
                Ok(md) => md,
                Err(e) => {
                    println!("cannot convert HTML to Markdown: {}", e);
                    if ignore_error {
                        println!("Ignoring body error and passing through original response");
                        return Action::Continue;
                    }
                    self.send_http_response(SERVER_ERROR, vec![], Some(b"Failed to convert HTML to Markdown"));
                    return Action::Pause;
                }
            };
            // extra unescape for double-escaped HTML entities
            let md = unescape(md);
            self.set_http_response_body(0, body_size, md.as_bytes());
            println!("Converted HTML to Markdown: {}, size: {}", path, md.len());
        } else {
            println!("empty body in {}", path);
        }

        Action::Continue
    }
}

// Checks if the header value contains the expected content type, and charset either not specified or utf-8
fn content_type_match(header_value: &str, expected: &str) -> bool {
    let expected = expected.to_ascii_lowercase();

    // Accept header can be a comma-separated list
    for item in header_value.split(',') {
        let mut parts = item.split(';');
        let mime = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        if mime != expected {
            continue;
        }

        // Only allow missing charset or explicit utf-8 charset.
        let mut charset: Option<String> = None;
        for param in parts {
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("").trim().to_ascii_lowercase();
            if key == "charset" {
                let value = kv
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .to_ascii_lowercase();
                charset = Some(value);
            }
        }

        if charset.as_deref().is_none_or(|value| value == "utf-8") {
            return true;
        }
    }
    false
}
