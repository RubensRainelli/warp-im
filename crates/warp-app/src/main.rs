/*
 * Personal and Educational Free License (PEF License / PEFL)
 * Version 1.0 - 2026-05-26
 * Copyright (c) 2026 Rubens Rainelli
 *
 * Contact Details:
 *   Email: rubens@rainelli.it
 *   GitHub: https://github.com/RubensRainelli/
 *   Tel: (+39) 342 811 5882
 *
 * Personal and educational free use permitted.
 * Corporate, business or enterprise use prohibited without written authorization and fee.
 * The full license can be found in the LICENSE file.
 */

//! # `warp-app` Desktop Native Binary Entrypoint
//!
//! Invokes [`warp_app::run_warp_app`] for Desktop Native targets (Linux, macOS, Windows).
//! Mobile Native (`Android`/`iOS`) and WebAssembly (`wasm32-unknown-unknown`) targets
//! link against the `warp_app` library target in [`src/lib.rs`](file:///home/antigravity/RubensRainelli/warp-im/crates/warp-app/src/lib.rs).

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    warp_app::run_warp_app().await
}
