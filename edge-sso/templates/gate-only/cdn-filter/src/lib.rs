use proxy_wasm::traits::RootContext;
use proxy_wasm::types::LogLevel;
use sso_guard::SsoGuardRoot;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(SsoGuardRoot)
    });
}}
