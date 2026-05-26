//! Captures stdout and stderr from a subprocess with a configurable byte limit.
//!
//! When the combined output exceeds `max_bytes`, both streams are truncated and
//! a human-readable marker is appended so callers can detect the condition.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Truncation marker appended to output that has been cut short.
const TRUNCATION_MARKER: &str = "\n[...output truncated...]";

/// Captures stdout and stderr concurrently with a shared byte-limit budget.
pub struct OutputCapture {
    /// Maximum number of bytes to retain across both stdout and stderr combined.
    pub max_bytes: usize,
}

impl OutputCapture {
    /// Create a new `OutputCapture` with the given byte limit.
    pub fn new(max_bytes: usize) -> Self {
        Self { max_bytes }
    }

    /// Read `stdout` and `stderr` concurrently, stopping each stream at the
    /// per-stream limit (`max_bytes / 2` each, so the total stays bounded).
    ///
    /// Returns `(stdout_string, stderr_string, was_truncated)`.
    pub async fn capture(
        &self,
        stdout: impl AsyncRead + Unpin + Send + 'static,
        stderr: impl AsyncRead + Unpin + Send + 'static,
    ) -> (String, String, bool) {
        // Split the budget evenly between the two streams.
        let per_stream = self.max_bytes / 2;

        let (stdout_result, stderr_result) = tokio::join!(
            read_limited(stdout, per_stream),
            read_limited(stderr, per_stream),
        );

        let (stdout_bytes, stdout_truncated) = stdout_result;
        let (stderr_bytes, stderr_truncated) = stderr_result;

        let truncated = stdout_truncated || stderr_truncated;

        let mut stdout_str = String::from_utf8_lossy(&stdout_bytes).into_owned();
        let mut stderr_str = String::from_utf8_lossy(&stderr_bytes).into_owned();

        if stdout_truncated {
            stdout_str.push_str(TRUNCATION_MARKER);
        }
        if stderr_truncated {
            stderr_str.push_str(TRUNCATION_MARKER);
        }

        (stdout_str, stderr_str, truncated)
    }
}

/// Read up to `limit` bytes from `reader`.
///
/// Returns `(bytes_read, was_truncated)`.  When the stream contains more than
/// `limit` bytes the excess is silently discarded and `was_truncated` is `true`.
async fn read_limited(mut reader: impl AsyncRead + Unpin, limit: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::with_capacity(limit.min(64 * 1024));
    let mut total = 0usize;
    let mut truncated = false;

    loop {
        // Stay within the limit.
        if total >= limit {
            // Try to read one more byte to see whether there is more data.
            let mut probe = [0u8; 1];
            match reader.read(&mut probe).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    truncated = true;
                    // Drain the rest without keeping it.
                    let mut drain = [0u8; 4096];
                    loop {
                        match reader.read(&mut drain).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                    break;
                }
            }
        }

        let remaining = limit - total;
        let chunk_cap = remaining.min(4096);
        let old_len = buf.len();
        buf.resize(old_len + chunk_cap, 0);

        match reader.read(&mut buf[old_len..]).await {
            Ok(0) => {
                buf.truncate(old_len);
                break;
            }
            Ok(n) => {
                buf.truncate(old_len + n);
                total += n;
            }
            Err(_) => {
                buf.truncate(old_len);
                break;
            }
        }
    }

    (buf, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn cursor(data: &[u8]) -> Cursor<Vec<u8>> {
        Cursor::new(data.to_vec())
    }

    #[tokio::test]
    async fn captures_small_output_without_truncation() {
        let cap = OutputCapture::new(1024);
        let (out, err, truncated) = cap.capture(cursor(b"hello"), cursor(b"world")).await;
        assert_eq!(out, "hello");
        assert_eq!(err, "world");
        assert!(!truncated);
    }

    #[tokio::test]
    async fn truncates_when_over_limit() {
        let cap = OutputCapture::new(10); // 5 bytes per stream
        let big = vec![b'x'; 100];
        let (out, _err, truncated) = cap.capture(cursor(&big), cursor(b"")).await;
        assert!(truncated, "should have been truncated");
        assert!(out.contains("[...output truncated...]"));
    }

    #[tokio::test]
    async fn empty_streams() {
        let cap = OutputCapture::new(1024);
        let (out, err, truncated) = cap.capture(cursor(b""), cursor(b"")).await;
        assert_eq!(out, "");
        assert_eq!(err, "");
        assert!(!truncated);
    }

    #[tokio::test]
    async fn exact_limit_not_truncated() {
        let cap = OutputCapture::new(10); // 5 bytes per stream
        let (out, err, truncated) =
            cap.capture(cursor(b"hello"), cursor(b"world")).await;
        assert_eq!(out, "hello");
        assert_eq!(err, "world");
        assert!(!truncated, "exact-limit data should not be truncated");
    }

    #[tokio::test]
    async fn stderr_truncation_independent_of_stdout() {
        let cap = OutputCapture::new(10); // 5 bytes per stream
        let (out, err, truncated) =
            cap.capture(cursor(b"hi"), cursor(b"this is way too long")).await;
        assert_eq!(out, "hi");
        assert!(truncated);
        assert!(err.contains("[...output truncated...]"));
    }
}
