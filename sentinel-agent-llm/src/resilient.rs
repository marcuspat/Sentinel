//! Retry, timeout and budget wrapper around any [`LlmBackend`] (ADR-020).
//!
//! The raw backends make one HTTP request and return whatever happens.  A
//! 429, a 529 "overloaded" or a dropped connection ended the session; a
//! request that hung held it for the client's full timeout; and nothing
//! bounded how many tokens a session could spend.
//!
//! [`ResilientBackend`] adds, for both text and tool calls:
//!
//! * a per-attempt deadline;
//! * bounded retries with exponential backoff and jitter for errors that are
//!   worth retrying, honouring `Retry-After`;
//! * a hard per-session budget on calls and on tokens.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tracing::{info, warn};

use crate::backend::{LlmBackend, LlmResponse, Message, ToolChoice, ToolResponse, ToolSpec};
use crate::error::AgentError;

/// When and how often to retry.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Total attempts including the first.  `1` disables retries.
    pub max_attempts: u32,
    /// Delay before the first retry; doubles each time.
    pub base_delay: Duration,
    /// Upper bound on a single computed backoff delay.
    pub max_delay: Duration,
    /// A server-requested `Retry-After` longer than this is not waited for;
    /// the rate-limit error is returned instead.
    pub max_retry_after: Duration,
    /// Deadline for one attempt.
    pub request_timeout: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(20),
            max_retry_after: Duration::from_secs(60),
            request_timeout: Duration::from_secs(120),
        }
    }
}

/// Hard limits for one session.  `0` means unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Model calls that returned a response.
    pub max_calls: u64,
    /// Input plus output tokens, as reported by the provider.
    pub max_tokens: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_calls: 100,
            max_tokens: 2_000_000,
        }
    }
}

impl Budget {
    pub const CALLS_ENV: &'static str = "SENTINEL_MAX_LLM_CALLS";
    pub const TOKENS_ENV: &'static str = "SENTINEL_MAX_LLM_TOKENS";

    /// Defaults, overridden by `$SENTINEL_MAX_LLM_CALLS` and
    /// `$SENTINEL_MAX_LLM_TOKENS` when they parse as integers.
    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var(Self::CALLS_ENV).ok().as_deref(),
            std::env::var(Self::TOKENS_ENV).ok().as_deref(),
        )
    }

    fn from_values(calls: Option<&str>, tokens: Option<&str>) -> Self {
        let d = Self::default();
        Self {
            max_calls: calls
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(d.max_calls),
            max_tokens: tokens
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(d.max_tokens),
        }
    }
}

/// Usage so far, for display and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Attempts that failed and were retried.
    pub retries: u64,
}

impl Usage {
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }
}

/// Whether an error is worth another attempt, and any server-given delay.
fn retry_hint(err: &AgentError) -> Option<Option<Duration>> {
    match err {
        AgentError::RateLimited { retry_after_secs } => {
            Some(Some(Duration::from_secs(*retry_after_secs)))
        }
        // Request timeout, conflict/lock, and every server-side failure
        // (500, 502, 503, 504, 529 overloaded).  Other 4xx are the caller's
        // fault and will not improve on retry.
        AgentError::ApiError { status, .. }
            if *status == 408 || *status == 409 || *status == 425 || *status >= 500 =>
        {
            Some(None)
        }
        AgentError::Network(_) | AgentError::Timeout { .. } => Some(None),
        _ => None,
    }
}

/// `base * 2^(attempt-1)`, capped, then scaled into `[50%, 100%]` so
/// simultaneous clients do not retry in lockstep.
fn backoff(policy: &RetryPolicy, attempt: u32) -> Duration {
    let exp = policy
        .base_delay
        .saturating_mul(1u32 << (attempt - 1).min(16))
        .min(policy.max_delay);
    // Not security-sensitive: sub-second clock noise is enough to decorrelate.
    let noise = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as u64;
    let scale = 500 + noise % 501; // 500..=1000 per mille
    Duration::from_nanos((exp.as_nanos() as u64 / 1000).saturating_mul(scale))
}

/// An [`LlmBackend`] with retries, deadlines and a session budget.
pub struct ResilientBackend {
    inner: Box<dyn LlmBackend>,
    policy: RetryPolicy,
    budget: Budget,
    calls: AtomicU64,
    input_tokens: AtomicU64,
    output_tokens: AtomicU64,
    retries: AtomicU64,
}

impl ResilientBackend {
    pub fn new(inner: Box<dyn LlmBackend>) -> Self {
        Self::with(inner, RetryPolicy::default(), Budget::default())
    }

    pub fn with(inner: Box<dyn LlmBackend>, policy: RetryPolicy, budget: Budget) -> Self {
        Self {
            inner,
            policy,
            budget,
            calls: AtomicU64::new(0),
            input_tokens: AtomicU64::new(0),
            output_tokens: AtomicU64::new(0),
            retries: AtomicU64::new(0),
        }
    }

    /// Calls, tokens and retries so far.
    pub fn usage(&self) -> Usage {
        Usage {
            calls: self.calls.load(Ordering::SeqCst),
            input_tokens: self.input_tokens.load(Ordering::SeqCst),
            output_tokens: self.output_tokens.load(Ordering::SeqCst),
            retries: self.retries.load(Ordering::SeqCst),
        }
    }

    /// Refuse a new call once either limit has been reached.  The check is
    /// made before the request, so the budget can be overshot by at most one
    /// response.
    fn check_budget(&self) -> Result<(), AgentError> {
        let usage = self.usage();
        if self.budget.max_calls != 0 && usage.calls >= self.budget.max_calls {
            return Err(AgentError::BudgetExceeded {
                what: "model calls".into(),
                used: usage.calls,
                limit: self.budget.max_calls,
            });
        }
        if self.budget.max_tokens != 0 && usage.total_tokens() >= self.budget.max_tokens {
            return Err(AgentError::BudgetExceeded {
                what: "tokens".into(),
                used: usage.total_tokens(),
                limit: self.budget.max_tokens,
            });
        }
        Ok(())
    }

    fn account(&self, input: u32, output: u32) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.input_tokens.fetch_add(input as u64, Ordering::SeqCst);
        self.output_tokens
            .fetch_add(output as u64, Ordering::SeqCst);
    }

    /// Run `attempt` under the deadline, retrying per the policy.
    async fn with_retries<T, F, Fut>(&self, mut attempt: F) -> Result<T, AgentError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, AgentError>>,
    {
        let max = self.policy.max_attempts.max(1);
        let mut n = 0u32;
        loop {
            n += 1;
            let timeout_ms = self.policy.request_timeout.as_millis() as u64;
            let result = match tokio::time::timeout(self.policy.request_timeout, attempt()).await {
                Ok(r) => r,
                Err(_) => Err(AgentError::Timeout { ms: timeout_ms }),
            };
            let err = match result {
                Ok(v) => {
                    if n > 1 {
                        info!(attempts = n, "model call succeeded after retry");
                    }
                    return Ok(v);
                }
                Err(e) => e,
            };

            let Some(server_delay) = retry_hint(&err) else {
                return Err(err);
            };
            if n >= max {
                warn!(attempts = n, error = %err, "model call failed; retries exhausted");
                return Err(err);
            }
            let delay = match server_delay {
                Some(d) if d > self.policy.max_retry_after => {
                    warn!(
                        retry_after_secs = d.as_secs(),
                        "server asked for a longer wait than allowed; not retrying"
                    );
                    return Err(err);
                }
                // The server knows its own limits: wait at least what it asked.
                Some(d) => d.max(backoff(&self.policy, n)),
                None => backoff(&self.policy, n),
            };
            self.retries.fetch_add(1, Ordering::SeqCst);
            warn!(attempt = n, delay_ms = delay.as_millis() as u64, error = %err, "retrying model call");
            tokio::time::sleep(delay).await;
        }
    }
}

#[async_trait]
impl LlmBackend for ResilientBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn model(&self) -> &str {
        self.inner.model()
    }

    async fn complete(
        &self,
        messages: Vec<Message>,
        max_tokens: u32,
    ) -> Result<LlmResponse, AgentError> {
        self.check_budget()?;
        let response = self
            .with_retries(|| self.inner.complete(messages.clone(), max_tokens))
            .await?;
        self.account(response.input_tokens, response.output_tokens);
        Ok(response)
    }

    fn supports_tools(&self) -> bool {
        self.inner.supports_tools()
    }

    async fn complete_with_tools(
        &self,
        messages: Vec<Message>,
        tools: &[ToolSpec],
        choice: ToolChoice,
        max_tokens: u32,
    ) -> Result<ToolResponse, AgentError> {
        self.check_budget()?;
        let response = self
            .with_retries(|| {
                self.inner
                    .complete_with_tools(messages.clone(), tools, choice.clone(), max_tokens)
            })
            .await?;
        self.account(response.input_tokens, response.output_tokens);
        Ok(response)
    }

    async fn health_check(&self) -> Result<(), AgentError> {
        self.inner.health_check().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Instant;

    /// Backend that plays back a script of results.
    struct Scripted {
        script: Mutex<VecDeque<Result<(u32, u32), AgentError>>>,
        calls: AtomicU64,
        hang: bool,
        tools: bool,
    }

    impl Scripted {
        fn new(script: Vec<Result<(u32, u32), AgentError>>) -> Self {
            Self {
                script: Mutex::new(script.into()),
                calls: AtomicU64::new(0),
                hang: false,
                tools: true,
            }
        }
        fn next(&self) -> Result<(u32, u32), AgentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok((10, 5)))
        }
    }

    #[async_trait]
    impl LlmBackend for Scripted {
        fn name(&self) -> &str {
            "scripted"
        }
        fn model(&self) -> &str {
            "m"
        }
        async fn complete(&self, _m: Vec<Message>, _t: u32) -> Result<LlmResponse, AgentError> {
            if self.hang {
                self.calls.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await;
            }
            let (i, o) = self.next()?;
            Ok(LlmResponse {
                content: "ok".into(),
                model: "m".into(),
                input_tokens: i,
                output_tokens: o,
                finish_reason: "end_turn".into(),
            })
        }
        fn supports_tools(&self) -> bool {
            self.tools
        }
        async fn complete_with_tools(
            &self,
            _m: Vec<Message>,
            _tools: &[ToolSpec],
            _c: ToolChoice,
            _t: u32,
        ) -> Result<ToolResponse, AgentError> {
            let (i, o) = self.next()?;
            Ok(ToolResponse {
                calls: vec![],
                text: String::new(),
                model: "m".into(),
                input_tokens: i,
                output_tokens: o,
                finish_reason: "tool_use".into(),
            })
        }
        async fn health_check(&self) -> Result<(), AgentError> {
            Ok(())
        }
    }

    fn fast() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 4,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(8),
            max_retry_after: Duration::from_secs(2),
            request_timeout: Duration::from_millis(200),
        }
    }

    fn api(status: u16) -> AgentError {
        AgentError::ApiError {
            status,
            message: "x".into(),
        }
    }

    fn msgs() -> Vec<Message> {
        vec![Message::user("hi")]
    }

    /// Wrap `inner`, keeping a handle to count its calls.
    fn wrap(
        inner: Scripted,
        policy: RetryPolicy,
        budget: Budget,
    ) -> (ResilientBackend, std::sync::Arc<Scripted>) {
        struct Shared(std::sync::Arc<Scripted>);
        #[async_trait]
        impl LlmBackend for Shared {
            fn name(&self) -> &str {
                self.0.name()
            }
            fn model(&self) -> &str {
                self.0.model()
            }
            async fn complete(&self, m: Vec<Message>, t: u32) -> Result<LlmResponse, AgentError> {
                self.0.complete(m, t).await
            }
            fn supports_tools(&self) -> bool {
                self.0.supports_tools()
            }
            async fn complete_with_tools(
                &self,
                m: Vec<Message>,
                tools: &[ToolSpec],
                c: ToolChoice,
                t: u32,
            ) -> Result<ToolResponse, AgentError> {
                self.0.complete_with_tools(m, tools, c, t).await
            }
            async fn health_check(&self) -> Result<(), AgentError> {
                self.0.health_check().await
            }
        }
        let shared = std::sync::Arc::new(inner);
        (
            ResilientBackend::with(Box::new(Shared(shared.clone())), policy, budget),
            shared,
        )
    }

    #[tokio::test]
    async fn transient_errors_are_retried_until_success() {
        let (backend, inner) = wrap(
            Scripted::new(vec![Err(api(529)), Err(api(503)), Ok((7, 3))]),
            fast(),
            Budget::default(),
        );
        let r = backend.complete(msgs(), 16).await.unwrap();
        assert_eq!(r.content, "ok");
        assert_eq!(inner.calls.load(Ordering::SeqCst), 3);
        let usage = backend.usage();
        assert_eq!(usage.retries, 2);
        assert_eq!(usage.calls, 1, "only the successful response is a call");
        assert_eq!((usage.input_tokens, usage.output_tokens), (7, 3));
    }

    #[tokio::test]
    async fn client_errors_are_not_retried() {
        for err in [
            api(400),
            api(401),
            api(403),
            api(404),
            AgentError::InvalidResponse("bad".into()),
            AgentError::CapabilityNotFound("x".into()),
        ] {
            let label = err.to_string();
            let (backend, inner) = wrap(Scripted::new(vec![Err(err)]), fast(), Budget::default());
            assert!(backend.complete(msgs(), 16).await.is_err());
            assert_eq!(inner.calls.load(Ordering::SeqCst), 1, "{label} was retried");
        }
    }

    #[tokio::test]
    async fn retries_stop_at_max_attempts_and_return_the_last_error() {
        let (backend, inner) = wrap(
            Scripted::new((0..10).map(|_| Err(api(500))).collect()),
            fast(),
            Budget::default(),
        );
        let err = backend.complete(msgs(), 16).await.unwrap_err();
        assert!(matches!(err, AgentError::ApiError { status: 500, .. }));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 4);
        assert_eq!(backend.usage().calls, 0);
    }

    #[tokio::test]
    async fn retry_after_is_honoured() {
        let (backend, inner) = wrap(
            Scripted::new(vec![
                Err(AgentError::RateLimited {
                    retry_after_secs: 1,
                }),
                Ok((1, 1)),
            ]),
            fast(),
            Budget::default(),
        );
        let t0 = Instant::now();
        backend.complete(msgs(), 16).await.unwrap();
        assert!(
            t0.elapsed() >= Duration::from_millis(1000),
            "waited {:?}",
            t0.elapsed()
        );
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn excessive_retry_after_is_not_waited_for() {
        let (backend, inner) = wrap(
            Scripted::new(vec![Err(AgentError::RateLimited {
                retry_after_secs: 3600,
            })]),
            fast(),
            Budget::default(),
        );
        let t0 = Instant::now();
        let err = backend.complete(msgs(), 16).await.unwrap_err();
        assert!(matches!(
            err,
            AgentError::RateLimited {
                retry_after_secs: 3600
            }
        ));
        assert!(t0.elapsed() < Duration::from_secs(1));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_hung_request_times_out_and_is_retried() {
        let mut hung = Scripted::new(vec![]);
        hung.hang = true;
        let policy = RetryPolicy {
            max_attempts: 2,
            request_timeout: Duration::from_millis(30),
            ..fast()
        };
        let (backend, inner) = wrap(hung, policy, Budget::default());
        let t0 = Instant::now();
        let err = backend.complete(msgs(), 16).await.unwrap_err();
        assert!(matches!(err, AgentError::Timeout { ms: 30 }), "{err}");
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn call_budget_stops_the_session() {
        let budget = Budget {
            max_calls: 2,
            max_tokens: 0,
        };
        let (backend, inner) = wrap(Scripted::new(vec![]), fast(), budget);
        backend.complete(msgs(), 16).await.unwrap();
        backend.complete(msgs(), 16).await.unwrap();
        let err = backend.complete(msgs(), 16).await.unwrap_err();
        assert!(
            matches!(
                err,
                AgentError::BudgetExceeded {
                    used: 2,
                    limit: 2,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            2,
            "no request once over budget"
        );
    }

    #[tokio::test]
    async fn token_budget_counts_text_and_tool_calls_together() {
        let budget = Budget {
            max_calls: 0,
            max_tokens: 100,
        };
        let (backend, inner) = wrap(
            Scripted::new(vec![Ok((40, 20)), Ok((30, 20))]),
            fast(),
            budget,
        );
        backend.complete(msgs(), 16).await.unwrap();
        backend
            .complete_with_tools(msgs(), &[], ToolChoice::Any, 16)
            .await
            .unwrap();
        assert_eq!(backend.usage().total_tokens(), 110);
        let err = backend
            .complete_with_tools(msgs(), &[], ToolChoice::Any, 16)
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::BudgetExceeded { .. }), "{err}");
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn zero_means_unlimited_and_wrapper_is_transparent() {
        let budget = Budget {
            max_calls: 0,
            max_tokens: 0,
        };
        let mut inner = Scripted::new(vec![]);
        inner.tools = false;
        let (backend, _) = wrap(inner, fast(), budget);
        for _ in 0..50 {
            backend.complete(msgs(), 16).await.unwrap();
        }
        assert_eq!(backend.name(), "scripted");
        assert_eq!(backend.model(), "m");
        assert!(
            !backend.supports_tools(),
            "tool support is the inner backend's"
        );
    }

    #[test]
    fn backoff_grows_is_capped_and_is_jittered_within_bounds() {
        let p = RetryPolicy {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(1000),
            ..RetryPolicy::default()
        };
        for (attempt, full) in [
            (1u32, 100u64),
            (2, 200),
            (3, 400),
            (4, 800),
            (5, 1000),
            (30, 1000),
        ] {
            let d = backoff(&p, attempt).as_millis() as u64;
            assert!(
                d >= full / 2 && d <= full,
                "attempt {attempt}: {d}ms not in [{}, {full}]",
                full / 2
            );
        }
    }

    #[test]
    fn budget_from_env_values() {
        let d = Budget::default();
        assert_eq!(Budget::from_values(None, None), d);
        assert_eq!(
            Budget::from_values(Some("5"), Some(" 1000 ")),
            Budget {
                max_calls: 5,
                max_tokens: 1000
            }
        );
        assert_eq!(
            Budget::from_values(Some("lots"), Some("")),
            d,
            "garbage keeps the default"
        );
        assert_eq!(
            Budget::from_values(Some("0"), None).max_calls,
            0,
            "0 = unlimited"
        );
    }
}
