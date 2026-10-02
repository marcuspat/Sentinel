//! Bounded reads of provider responses.
//!
//! `reqwest::Response::json()` buffers whatever the server sends.  A
//! misbehaving or hostile endpoint (the base URL is configurable) could hand
//! back gigabytes and take the process down.  These helpers stop reading at a
//! fixed limit.

use serde::de::DeserializeOwned;

use crate::error::AgentError;

/// Largest response body accepted from a model provider.  Completions are
/// kilobytes; this leaves two orders of magnitude of headroom.
pub(crate) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Largest error body kept for the error message.
pub(crate) const MAX_ERROR_BYTES: usize = 64 * 1024;

/// Read at most `limit` bytes of the body.  Returns the bytes and whether the
/// body was longer than the limit.
async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<(Vec<u8>, bool), AgentError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let room = limit - body.len();
        if chunk.len() > room {
            body.extend_from_slice(&chunk[..room]);
            return Ok((body, true));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, false))
}

/// Decode a JSON body, refusing anything over `limit` bytes.
pub(crate) async fn json_capped<T: DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
) -> Result<T, AgentError> {
    // Trust a declared length only to reject early; the stream is counted too.
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(too_large(limit));
    }
    let (body, truncated) = read_limited(response, limit).await?;
    if truncated {
        return Err(too_large(limit));
    }
    serde_json::from_slice(&body)
        .map_err(|e| AgentError::InvalidResponse(format!("failed to parse response: {e}")))
}

/// Read an error body as text, keeping at most `limit` bytes.
pub(crate) async fn text_capped(response: reqwest::Response, limit: usize) -> String {
    match read_limited(response, limit).await {
        Ok((body, truncated)) => {
            let mut text = String::from_utf8_lossy(&body).into_owned();
            if truncated {
                text.push_str(" …[truncated]");
            }
            text
        }
        Err(_) => "<unreadable body>".to_string(),
    }
}

fn too_large(limit: usize) -> AgentError {
    AgentError::InvalidResponse(format!(
        "response body exceeds the {limit}-byte limit; refusing to buffer it"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn get(server: &MockServer) -> reqwest::Response {
        reqwest::Client::new()
            .get(server.uri())
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn small_json_is_decoded() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"a": 1})))
            .mount(&server)
            .await;
        let v: serde_json::Value = json_capped(get(&server).await, 1024).await.unwrap();
        assert_eq!(v["a"], 1);
    }

    #[tokio::test]
    async fn oversized_body_is_refused_not_buffered() {
        let server = MockServer::start().await;
        let big = format!("{{\"pad\": \"{}\"}}", "x".repeat(10_000));
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(big))
            .mount(&server)
            .await;
        let err = json_capped::<serde_json::Value>(get(&server).await, 1024)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("exceeds the 1024-byte limit"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn error_text_is_truncated() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string("e".repeat(5_000)))
            .mount(&server)
            .await;
        let text = text_capped(get(&server).await, 100).await;
        assert!(text.starts_with(&"e".repeat(100)));
        assert!(text.ends_with("[truncated]"));
        assert!(text.len() < 200);
    }
}
