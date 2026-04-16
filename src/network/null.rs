//! Null HTTP client implementation for platforms without network support
//!
//! This is used when the `default-http-client` feature is not enabled,
//! or on platforms where network access is not available.

use super::{HttpClient, HttpRequest, HttpResponse};
use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub struct NetworkDisabledError;

impl fmt::Display for NetworkDisabledError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Network operations are disabled. Enable the 'default-http-client' feature to use network operations."
        )
    }
}

impl StdError for NetworkDisabledError {}

/// Null HTTP client that returns errors for all requests
pub struct NullHttpClient;

impl HttpClient for NullHttpClient {
    fn send(
        &self,
        _request: HttpRequest,
    ) -> Result<HttpResponse, Box<dyn StdError + Send + Sync>> {
        Err(Box::new(NetworkDisabledError))
    }
}

