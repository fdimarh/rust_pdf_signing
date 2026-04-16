//! Web/WASM HTTP client implementation using browser fetch API
//!
//! This implementation uses the browser's native fetch API for making HTTP requests
//! in WebAssembly contexts. It requires the `web-sys` crate for FFI bindings.

use super::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use std::error::Error as StdError;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// HTTP client implementation using browser fetch API
#[cfg(target_arch = "wasm32")]
pub struct FetchClient;

#[cfg(target_arch = "wasm32")]
impl FetchClient {
    /// Create a new FetchClient
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_arch = "wasm32")]
impl Default for FetchClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "wasm32")]
impl HttpClient for FetchClient {
    fn send(
        &self,
        request: HttpRequest,
    ) -> Result<HttpResponse, Box<dyn StdError + Send + Sync>> {
        // This is a placeholder. In a real WASM context, you would use:
        // - `reqwest` with WASM features enabled (simplest)
        // - `web-sys` + `js-sys` for raw fetch API (most control)
        // - `gloo-net` (recommended modern approach)

        // For now, we document the expected behavior:
        // 1. Convert HttpRequest to fetch Request
        // 2. Call fetch()
        // 3. Wait for response
        // 4. Convert fetch Response to HttpResponse

        Err("Fetch API implementation requires async/await support in WASM context".into())
    }
}

/// Non-WASM fallback (stub)
#[cfg(not(target_arch = "wasm32"))]
pub struct FetchClient;

#[cfg(not(target_arch = "wasm32"))]
impl FetchClient {
    /// Create a new FetchClient (non-WASM stub)
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for FetchClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl HttpClient for FetchClient {
    fn send(
        &self,
        _request: HttpRequest,
    ) -> Result<HttpResponse, Box<dyn StdError + Send + Sync>> {
        Err("Fetch API is only available in WebAssembly context".into())
    }
}

