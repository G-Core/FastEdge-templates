use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::str;

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

const INVALID: u32 = 400;
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

impl HttpContext for HttpBody {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
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
                    Some(p) => match std::string::String::from_utf8(p) {
                        Ok(s) => s,
                        Err(e) => {
                            println!("cannot convert path to string {}", e);
                            self.send_http_response(INVALID, vec![], Some(b"Origin response is not valid UTF-8"));
                            return Action::Pause;
                        }
                    },
                    None => "/".to_string()
                };
                println!("Got HTML to convert: {}", path);

                self.remove_http_response_header(CONTENT_LENGTH_HEADER);
                self.set_http_response_header(CONTENT_TYPE_HEADER, Some(MARKDOWN_MIME));
                self.set_http_response_header(TRANSFER_ENCODING_HEADER, Some(TRANSFER_ENCODING_CHUNKED));
                self.set_property(vec!["response.md"], Some(b"true"));
            }
        }
        // use Accept for cache key
        self.add_http_response_header("Vary", CONVERT_FLAG);
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
            Some(p) => match std::string::String::from_utf8(p) {
                Ok(s) => s,
                Err(e) => {
                    println!("cannot convert path to string {}", e);
                    self.send_http_response(INVALID, vec![], Some(b"Origin response is not valid UTF-8"));
                    return Action::Pause;
                }
            },
            None => "/".to_string()
        };

        if let Some(body_bytes) = self.get_http_response_body(0, body_size) {
            let body_str = match str::from_utf8(&body_bytes) {
                Ok(s) => s,
                Err(e) => {
                    println!("cannot convert body to string {}", e);
                    self.send_http_response(SERVER_ERROR, vec![], Some(b"Origin response is not valid UTF-8"));
                    return Action::Pause;
                }
            };
            let md = html2md::rewrite_html(body_str, true);
            self.set_http_response_body(0, body_size, md.as_bytes());
            println!("Converted HTML to Markdown: {}", path);
        } else {
            println!("empty body in {}", path);
        }

        Action::Continue
    }
}

fn content_type_match(ct: &str, expected: &str) -> bool
{
    ct.split(';').next().map(|s| s.trim()) == Some(expected)
}