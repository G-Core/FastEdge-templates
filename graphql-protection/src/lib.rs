use std::collections::{HashMap, HashSet};
use std::env;
use std::str::from_utf8;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde_json::Value as JsonValue;
use anyhow::{anyhow, Error};
use graphql_query::ast::{
    ASTContext, Definition, Document, ParseNode, Selection, SelectionSet, Value as GqlValue,
};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(HttpGraphQLRoot) });
}}

struct HttpGraphQLRoot;
impl Context for HttpGraphQLRoot {}
impl RootContext for HttpGraphQLRoot {
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HttpGraphQL {}))
    }
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct Config {
    endpoint: String,
    max_body_size: Option<usize>,
    max_value_size: Option<usize>,
    max_query_depth: Option<usize>,
    max_batch_size: Option<usize>,
    blocked_fields: HashSet<String>,
    block_debug: bool,
}

impl Config {
    fn from_env() -> Self {
        Config {
            // An optional param left blank in the portal can arrive as "", which
            // would otherwise match no path and silently disable the filter.
            endpoint: env::var("ENDPOINT")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/graphql".to_string()),
            max_body_size: env::var("MAX_BODY_SIZE").ok().and_then(|s| s.parse().ok()),
            max_value_size: env::var("MAX_VALUE_SIZE").ok().and_then(|s| s.parse().ok()),
            max_query_depth: env::var("MAX_QUERY_DEPTH").ok().and_then(|s| s.parse().ok()),
            max_batch_size: env::var("MAX_BATCH_SIZE").ok().and_then(|s| s.parse().ok()),
            blocked_fields: env::var("BLOCKED_FIELDS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            block_debug: env::var("BLOCK_DEBUG").map(|s| s == "true").unwrap_or(false),
        }
    }
}

struct GraphQLRequest<'a> {
    doc: &'a Document<'a>,
    variables: Option<JsonValue>,
}

enum RequestBody<'a> {
    Single(GraphQLRequest<'a>),
    Batch(Vec<GraphQLRequest<'a>>),
}

// --- Parsing ---

fn parse_body<'a>(ctx: &'a ASTContext, content_type: &str, body: &[u8]) -> Result<RequestBody<'a>, Error> {
    let ct = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    match ct.as_str() {
        "application/graphql" => {
            let query = from_utf8(body).map_err(|e| anyhow!("Invalid UTF-8: {}", e))?;
            let doc = Document::parse(ctx, query).map_err(|e| anyhow!("{}", e))?;
            Ok(RequestBody::Single(GraphQLRequest { doc, variables: None }))
        }
        "application/json" => {
            let json: JsonValue = serde_json::from_slice(body)
                .map_err(|e| anyhow!("Invalid JSON: {}", e))?;
            parse_json_body(ctx, json)
        }
        "application/x-www-form-urlencoded" => {
            let s = from_utf8(body).map_err(|e| anyhow!("Invalid UTF-8: {}", e))?;
            let query = form_get(s, "query")?
                .ok_or_else(|| anyhow!("Missing 'query' in form body"))?;
            // Unparseable variables must fail closed, not skip the variable checks.
            let variables = form_get(s, "variables")?
                .map(|v| serde_json::from_str(&v).map_err(|e| anyhow!("Invalid JSON in 'variables': {}", e)))
                .transpose()?;
            let doc = Document::parse(ctx, query).map_err(|e| anyhow!("{}", e))?;
            Ok(RequestBody::Single(GraphQLRequest { doc, variables }))
        }
        other => Err(anyhow!("Unsupported content type: {}", other)),
    }
}

fn parse_json_body<'a>(ctx: &'a ASTContext, json: JsonValue) -> Result<RequestBody<'a>, Error> {
    match json {
        JsonValue::Array(items) => {
            let requests = items.into_iter()
                .map(|item| parse_json_request(ctx, item))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RequestBody::Batch(requests))
        }
        obj @ JsonValue::Object(_) => Ok(RequestBody::Single(parse_json_request(ctx, obj)?)),
        _ => Err(anyhow!("JSON body must be an object or array")),
    }
}

fn parse_json_request<'a>(ctx: &'a ASTContext, obj: JsonValue) -> Result<GraphQLRequest<'a>, Error> {
    let query = obj["query"].as_str()
        .ok_or_else(|| anyhow!("Missing 'query' field"))?
        .to_owned();
    let variables = match obj.get("variables") {
        // Some servers accept variables as a JSON-encoded string: check what it decodes to.
        Some(JsonValue::String(s)) => Some(
            serde_json::from_str(s).map_err(|e| anyhow!("Invalid JSON in 'variables': {}", e))?,
        ),
        other => other.cloned(),
    };
    let doc = Document::parse(ctx, query).map_err(|e| anyhow!("{}", e))?;
    Ok(GraphQLRequest { doc, variables })
}

fn form_get(body: &str, key: &str) -> Result<Option<String>, Error> {
    let mut found = None;
    for pair in body.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if url_decode(k) == key {
            // Origins differ on first-vs-last wins, so a repeated key could
            // smuggle an unchecked value past the filter.
            if found.is_some() {
                return Err(anyhow!("Duplicate '{}' in form body", key));
            }
            found = Some(url_decode(v));
        }
    }
    Ok(found)
}

fn url_decode(s: &str) -> String {
    percent_decode(&s.replace('+', " "))
}

/// Normalises a request path for endpoint matching. The CDN does not normalise
/// paths and `request.path` includes the query string, so a plain comparison is
/// bypassed by `/graphql?x`, `//graphql`, `/GraphQL`, `/%67raphql`, `/a/../graphql`
/// and similar. This deliberately matches more than any origin would: a false
/// match only means a body gets inspected, a missed one skips every check.
fn normalize_path(raw: &str) -> String {
    // Only a literal `?` starts the query. Decoded `?`/`#`/`;` are cut per
    // segment instead, so `/graphql%3Bx` and `/x%3F/../graphql` both resolve to
    // `/graphql`, and `/api;v=1/graphql` to `/api/graphql`.
    let path = raw.split(['?', '#']).next().unwrap_or("");
    let decoded = decode_stable(path);
    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split(['/', '\\']) {
        let seg = seg.split([';', '?', '#']).next().unwrap_or("");
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    format!("/{}", segments.join("/")).to_ascii_lowercase()
}

/// Percent-decode repeatedly until the string stops changing. A single pass
/// leaves a double-encoded sequence partly encoded (`%252e` → `%2e`, `%253f` →
/// `%3f`), but an origin that re-decodes would resolve it fully; decoding to a
/// fixed point here keeps endpoint matching and query extraction from being
/// bypassed by multi-encoded `..`, `?`, `&` or `=`. Bounded so malformed input
/// cannot loop forever.
fn decode_stable(s: &str) -> String {
    let mut out = percent_decode(s);
    for _ in 0..8 {
        let again = percent_decode(&out);
        if again == out {
            break;
        }
        out = again;
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// --- Checks ---

fn check_requests(body: &RequestBody, config: &Config) -> Result<(), Error> {
    match body {
        RequestBody::Batch(requests) => {
            if let Some(max) = config.max_batch_size {
                if requests.len() > max {
                    return Err(anyhow!("Batch size {} exceeds limit {}", requests.len(), max));
                }
            }
            for req in requests {
                check_single(req, config)?;
            }
        }
        RequestBody::Single(req) => check_single(req, config)?,
    }
    Ok(())
}

fn check_single(req: &GraphQLRequest, config: &Config) -> Result<(), Error> {
    if let Some(max_depth) = config.max_query_depth {
        let depth = doc_depth(req.doc);
        if depth > max_depth {
            return Err(anyhow!("Query depth {} exceeds limit {}", depth, max_depth));
        }
        check_field_repetitions(req.doc, max_depth)?;
    }
    if let Some(max_value) = config.max_value_size {
        check_doc_values(req.doc, max_value)?;
        if let Some(vars) = &req.variables {
            check_json_values(vars, max_value)?;
        }
    }
    check_blocked_fields(req.doc, &config.blocked_fields)?;
    if config.block_debug {
        if debug_in_doc(req.doc) || debug_in_variables(req.variables.as_ref()) {
            return Err(anyhow!("Debug mode is not allowed"));
        }
    }
    Ok(())
}

fn debug_in_doc(doc: &Document) -> bool {
    doc.definitions.iter().any(|def| {
        let sel_set = match def {
            Definition::Operation(op) => &op.selection_set,
            Definition::Fragment(frag) => &frag.selection_set,
        };
        debug_in_sel_set(sel_set)
    })
}

fn debug_in_sel_set(sel_set: &SelectionSet) -> bool {
    sel_set.selections.iter().any(|sel| match sel {
        Selection::Field(field) => {
            field.arguments.children.iter().any(|arg| {
                arg.name == "debug"
                    && matches!(arg.value, GqlValue::Boolean(ref b) if b.value)
            }) || debug_in_sel_set(&field.selection_set)
        }
        Selection::InlineFragment(frag) => debug_in_sel_set(&frag.selection_set),
        Selection::FragmentSpread(_) => false,
    })
}

fn debug_in_variables(variables: Option<&JsonValue>) -> bool {
    variables
        .and_then(|v| v.get("debug"))
        .map(|v| v == &JsonValue::Bool(true))
        .unwrap_or(false)
}

fn check_field_repetitions(doc: &Document, max: usize) -> Result<(), Error> {
    for def in doc.definitions.iter() {
        let sel_set = match def {
            Definition::Operation(op) => &op.selection_set,
            Definition::Fragment(frag) => &frag.selection_set,
        };
        check_sel_set_repetitions(sel_set, max)?;
    }
    Ok(())
}

fn check_sel_set_repetitions(sel_set: &SelectionSet, max: usize) -> Result<(), Error> {
    // Count field names on this level
    let mut field_counts: HashMap<&str, usize> = HashMap::new();
    
    for sel in sel_set.selections.iter() {
        if let Selection::Field(field) = sel {
            *field_counts.entry(field.name).or_insert(0) += 1;
        }
    }
    
    // Check if any field exceeds the limit
    for (field_name, count) in field_counts.iter() {
        if *count > max {
            return Err(anyhow!(
                "Field '{}' appears {} times on the same level, exceeds limit {}",
                field_name,
                count,
                max
            ));
        }
    }
    
    // Recursively check nested selection sets
    for sel in sel_set.selections.iter() {
        match sel {
            Selection::Field(field) => {
                check_sel_set_repetitions(&field.selection_set, max)?;
            }
            Selection::InlineFragment(frag) => {
                check_sel_set_repetitions(&frag.selection_set, max)?;
            }
            Selection::FragmentSpread(_) => {
                // Ignore fragment spreads for now
            }
        }
    }
    
    Ok(())
}

fn check_blocked_fields(doc: &Document, blocked: &HashSet<String>) -> Result<(), Error> {
    if blocked.is_empty() {
        return Ok(());
    }
    for def in doc.definitions.iter() {
        let sel_set = match def {
            Definition::Operation(op) => &op.selection_set,
            Definition::Fragment(frag) => &frag.selection_set,
        };
        check_sel_set_blocked(sel_set, blocked)?;
    }
    Ok(())
}

fn check_sel_set_blocked(sel_set: &SelectionSet, blocked: &HashSet<String>) -> Result<(), Error> {
    for sel in sel_set.selections.iter() {
        match sel {
            Selection::Field(field) => {
                if blocked.contains(field.name) {
                    return Err(anyhow!("Field '{}' is not allowed", field.name));
                }
                check_sel_set_blocked(&field.selection_set, blocked)?;
            }
            Selection::InlineFragment(frag) => check_sel_set_blocked(&frag.selection_set, blocked)?,
            Selection::FragmentSpread(_) => {}
        }
    }
    Ok(())
}

fn doc_depth(doc: &Document) -> usize {
    let mut fragment_sets: HashMap<&str, &SelectionSet> = HashMap::new();
    for def in doc.definitions.iter() {
        if let Definition::Fragment(frag) = def {
            fragment_sets.insert(frag.name.name, &frag.selection_set);
        }
    }
    let mut memo = HashMap::new();
    doc.definitions.iter()
        .filter_map(|def| def.operation())
        .map(|op| sel_set_depth(&op.selection_set, &fragment_sets, &mut memo, &mut HashSet::new()))
        .max()
        .unwrap_or(0)
}

// Each fragment's depth is computed once and memoised: without it, a chain of
// fragments that each spread the next one twice costs 2^n work from a tiny body.
fn sel_set_depth<'a>(
    sel_set: &'a SelectionSet<'a>,
    fragments: &HashMap<&str, &'a SelectionSet<'a>>,
    memo: &mut HashMap<String, usize>,
    visiting: &mut HashSet<String>,
) -> usize {
    sel_set.selections.iter()
        .map(|sel| match sel {
            Selection::Field(field) => {
                if field.selection_set.is_empty() {
                    1
                } else {
                    1 + sel_set_depth(&field.selection_set, fragments, memo, visiting)
                }
            }
            Selection::InlineFragment(frag) => sel_set_depth(&frag.selection_set, fragments, memo, visiting),
            Selection::FragmentSpread(spread) => {
                let name = spread.name.name;
                if let Some(&depth) = memo.get(name) {
                    return depth;
                }
                if visiting.contains(name) {
                    return 0; // cycle guard
                }
                visiting.insert(name.to_owned());
                let depth = fragments.get(name)
                    .map(|s| sel_set_depth(s, fragments, memo, visiting))
                    .unwrap_or(0);
                visiting.remove(name);
                memo.insert(name.to_owned(), depth);
                depth
            }
        })
        .max()
        .unwrap_or(0)
}

fn check_doc_values(doc: &Document, max: usize) -> Result<(), Error> {
    for def in doc.definitions.iter() {
        let sel_set = match def {
            Definition::Operation(op) => {
                // A variable's default value is used when the client omits it.
                for var in op.variable_definitions.children.iter() {
                    check_gql_value(&var.default_value, max)?;
                }
                &op.selection_set
            }
            Definition::Fragment(frag) => &frag.selection_set,
        };
        check_sel_set_values(sel_set, max)?;
    }
    Ok(())
}

fn check_sel_set_values(sel_set: &SelectionSet, max: usize) -> Result<(), Error> {
    for sel in sel_set.selections.iter() {
        match sel {
            Selection::Field(field) => {
                for arg in field.arguments.children.iter() {
                    check_gql_value(&arg.value, max)?;
                }
                check_sel_set_values(&field.selection_set, max)?;
            }
            Selection::InlineFragment(frag) => check_sel_set_values(&frag.selection_set, max)?,
            Selection::FragmentSpread(_) => {}
        }
    }
    Ok(())
}

fn check_gql_value(value: &GqlValue, max: usize) -> Result<(), Error> {
    match value {
        GqlValue::String(s) if s.value.len() > max => {
            Err(anyhow!("String literal length {} exceeds limit {}", s.value.len(), max))
        }
        GqlValue::List(list) => {
            for v in list.children.iter() {
                check_gql_value(v, max)?;
            }
            Ok(())
        }
        GqlValue::Object(obj) => {
            for field in obj.children.iter() {
                check_gql_value(&field.value, max)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn check_json_values(value: &JsonValue, max: usize) -> Result<(), Error> {
    match value {
        JsonValue::String(s) if s.len() > max => {
            Err(anyhow!("Variable string length {} exceeds limit {}", s.len(), max))
        }
        JsonValue::Array(arr) => {
            for v in arr {
                check_json_values(v, max)?;
            }
            Ok(())
        }
        JsonValue::Object(obj) => {
            for v in obj.values() {
                check_json_values(v, max)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

// --- Proxy WASM ---

struct HttpGraphQL {}
impl Context for HttpGraphQL {}

impl HttpContext for HttpGraphQL {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // GraphQL over GET carries the query in the URL query string, which the
        // body hook never sees. Without inspecting it here, GET
        // /graphql?query={...} skips every depth/batch/value/blocked-field/debug
        // check. POST (and other body-bearing methods) are handled in
        // on_http_request_body.
        let Some(method) = self.get_property(vec!["request.method"]) else {
            return Action::Continue;
        };
        if method != b"GET" {
            return Action::Continue;
        }

        let config = Config::from_env();

        let Some(path) = self.get_property(vec!["request.path"]) else {
            return Action::Continue;
        };
        let raw = String::from_utf8_lossy(&path);
        if normalize_path(&raw) != normalize_path(&config.endpoint) {
            return Action::Continue;
        }

        // Extract the query string. The normal case has a literal `?`: parse from
        // the RAW remainder so form_get decodes each value exactly once (an
        // encoded `&`/`=` inside a value must not be split as a separator). A
        // request with no literal `?` but an encoded one (`%3f`, `%253f`) hiding a
        // query at this endpoint is obfuscation a real client never sends — decode
        // to a fixed point to expose it, so a re-decoding origin can't run an
        // unchecked query behind it.
        let decoded_qs;
        let qs = if let Some((_, q)) = raw.split_once('?') {
            q.split('#').next().unwrap_or(q)
        } else {
            decoded_qs = decode_stable(&raw);
            match decoded_qs.split_once('?') {
                Some((_, q)) => q.split('#').next().unwrap_or(q),
                None => return Action::Continue, // no query string → nothing to inspect
            }
        };

        // Size parity with the POST path: cap the query-string length before any
        // parsing (including form_get's scan), so an oversized GET query can't be
        // force-processed regardless of which params it carries.
        if let Some(limit) = config.max_body_size {
            if limit > 0 && qs.len() > limit {
                self.send_http_response(403, vec![("X-Reject-Reason", "Request body size exceeds limit")], None);
                return Action::Pause;
            }
        }

        // A bare GET to the endpoint (e.g. loading a GraphiQL IDE) carries no
        // `query` param and passes through untouched; a duplicated `query` key is
        // a smuggling attempt and is rejected.
        match form_get(qs, "query") {
            Ok(None) => return Action::Continue,
            Ok(Some(_)) => {}
            Err(e) => {
                println!("Failed to parse GET query string: {}", e);
                self.send_http_response(400, vec![("X-Reject-Reason", "Invalid GraphQL request")], None);
                return Action::Pause;
            }
        }

        let ctx = ASTContext::new();
        let body = match parse_body(&ctx, "application/x-www-form-urlencoded", qs.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                println!("Failed to parse GET query string: {}", e);
                self.send_http_response(400, vec![("X-Reject-Reason", "Invalid GraphQL request")], None);
                return Action::Pause;
            }
        };

        if let Err(e) = check_requests(&body, &config) {
            println!("Request check failed: {}", e);
            self.send_http_response(403, vec![("X-Reject-Reason", "GraphQL request blocked")], None);
            return Action::Pause;
        }

        Action::Continue
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        let Some(method) = self.get_property(vec!["request.method"]) else {
            return Action::Continue;
        };
        // GET is inspected in on_http_request_headers (its query rides in the URL,
        // not a body). Every other method that carries a GraphQL body — POST, but
        // also PUT/PATCH/etc. that a non-standard origin might honour — is
        // inspected here; a bodyless request (OPTIONS/HEAD) is handled below.
        if method == b"GET" {
            return Action::Continue;
        }

        let config = Config::from_env();

        let Some(path) = self.get_property(vec!["request.path"]) else {
            return Action::Continue;
        };
        if normalize_path(&String::from_utf8_lossy(&path)) != normalize_path(&config.endpoint) {
            return Action::Continue;
        }

        if let Some(limit) = config.max_body_size {
            if limit > 0 && body_size > limit {
                self.send_http_response(403, vec![("X-Reject-Reason", "Request body size exceeds limit")], None);
                return Action::Pause;
            }
        }

        // Buffer only matching requests within the size limit; everything else
        // streams through untouched above.
        if !end_of_stream {
            return Action::Pause;
        }

        // Bodyless request at the endpoint (e.g. an OPTIONS/HEAD probe or a CORS
        // preflight) — nothing to inspect, let it through rather than 400.
        if body_size == 0 {
            return Action::Continue;
        }

        let Some(body_bytes) = self.get_http_request_body(0, body_size) else {
            self.send_http_response(400, vec![("X-Reject-Reason", "Invalid GraphQL request")], None);
            return Action::Pause;
        };

        let content_type = self.get_http_request_header("Content-Type").unwrap_or_default();
        let ctx = ASTContext::new();

        let body = match parse_body(&ctx, &content_type, &body_bytes) {
            Ok(b) => b,
            Err(e) => {
                // Details go to the log only: echoing them would hand the client
                // the configured limits and risk invalid header characters.
                println!("Failed to parse body: {}", e);
                self.send_http_response(400, vec![("X-Reject-Reason", "Invalid GraphQL request")], None);
                return Action::Pause;
            }
        };

        if let Err(e) = check_requests(&body, &config) {
            println!("Request check failed: {}", e);
            self.send_http_response(403, vec![("X-Reject-Reason", "GraphQL request blocked")], None);
            return Action::Pause;
        }

        Action::Continue
    }
}
