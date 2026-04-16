//! Network abstraction layer for platform-independent HTTP operations.
//!
//! This module provides a trait-based abstraction for network operations (OCSP, CRL, TSA),
//! allowing different platform-specific implementations:
//! - Desktop: `reqwest::blocking::Client`
//! - Mobile: async-compatible implementations
//! - Web: Browser `fetch` API via `web-sys`

use std::error::Error as StdError;

/// HTTP method enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// HTTP request builder for abstraction
#[derive(Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    /// Create a new HTTP request
    pub fn new(method: HttpMethod, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Add a header to the request
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }

    /// Set the request body
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

/// HTTP response
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Check if the response status is success (2xx)
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Get the response body as bytes
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Convert response body to Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        self.body.clone()
    }
}

/// Trait for HTTP client implementations
/// Allows platform-specific implementations (desktop, mobile, web)
pub trait HttpClient: Send + Sync {
    /// Send an HTTP request and receive response
    fn send(
        &self,
        request: HttpRequest,
    ) -> Result<HttpResponse, Box<dyn StdError + Send + Sync>>;
}

/// Get the default HTTP client for the current platform
#[cfg(not(target_arch = "wasm32"))]
pub fn create_default_client() -> Box<dyn HttpClient> {
    #[cfg(feature = "default-http-client")]
    {
        Box::new(crate::network::desktop::ReqwestClient::new())
    }
    #[cfg(not(feature = "default-http-client"))]
    {
        Box::new(crate::network::null::NullHttpClient)
    }
}

/// WASM implementation
#[cfg(target_arch = "wasm32")]
pub fn create_default_client() -> Box<dyn HttpClient> {
    Box::new(crate::network::web::FetchClient::new())
}

/// Module for desktop implementation using reqwest
#[cfg(all(not(target_arch = "wasm32"), feature = "default-http-client"))]
pub mod desktop;

/// Module for web implementation using fetch API
#[cfg(target_arch = "wasm32")]
pub mod web;

/// Null implementation for platforms without network support
#[cfg(not(feature = "default-http-client"))]
pub mod null;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_request_builder() {
        let req = HttpRequest::new(HttpMethod::Post, "https://example.com/ocsp")
            .header("Content-Type", "application/ocsp-request")
            .body(vec![1, 2, 3, 4]);

        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.url, "https://example.com/ocsp");
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.body, Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn test_http_response_success() {
        let resp = HttpResponse {
            status: 200,
            body: vec![1, 2, 3],
        };
        assert!(resp.is_success());

        let resp_fail = HttpResponse {
            status: 404,
            body: vec![],
        };
        assert!(!resp_fail.is_success());
    }
}

