//! Desktop HTTP client implementation using reqwest blocking client
//!
//! This implementation is used on desktop platforms where blocking I/O is acceptable.
//! For async contexts, consider the mobile implementation.

use super::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use std::error::Error as StdError;

/// HTTP client implementation using reqwest blocking API
pub struct ReqwestClient {
    client: reqwest::blocking::Client,
}

impl ReqwestClient {
    /// Create a new ReqwestClient
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
        }
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for ReqwestClient {
    fn send(
        &self,
        request: HttpRequest,
    ) -> Result<HttpResponse, Box<dyn StdError + Send + Sync>> {
        let mut req = match request.method {
            HttpMethod::Get => self.client.get(&request.url),
            HttpMethod::Post => self.client.post(&request.url),
        };

        // Add headers
        for (key, value) in request.headers {
            req = req.header(&key, &value);
        }

        // Add body if present
        if let Some(body) = request.body {
            req = req.body(body);
        }

        // Send request
        let response = req.send()?;
        let status = response.status().as_u16();
        let body = response.bytes()?.to_vec();

        Ok(HttpResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reqwest_client_creation() {
        let client = ReqwestClient::new();
        // Just ensure it can be created without panicking
        assert!(true);
    }
}

