//! `sentinel-policy` — safety-critical policy engine for the Sentinel project.
//!
//! Every capability invocation must pass policy evaluation before execution.
//! The engine is deny-by-default: if no rule explicitly allows a request, it
//! is rejected.
//!
//! # Crate layout
//!
//! * [`rules`]          — [`PolicyRule`], [`RuleEffect`], [`RuleCondition`]
//! * [`evaluator`]      — [`PolicyEvaluator`], [`PolicyRequest`], [`PolicyDecision`]
//! * [`kill_switch`]    — [`KillSwitch`] (AtomicBool-backed, thread-safe)
//! * [`resource_guard`] — [`ResourceGuard`] (path / service protection)
//! * [`error`]          — [`PolicyError`]
//! * [`engine`]         — re-exports + [`default_policy`] constructor

pub mod engine;
pub mod error;
pub mod evaluator;
pub mod kill_switch;
pub mod resource_guard;
pub mod rules;

pub use engine::default_policy;
pub use error::PolicyError;
pub use evaluator::{PolicyDecision, PolicyEffect, PolicyEvaluator, PolicyRequest};
pub use kill_switch::KillSwitch;
pub use resource_guard::ResourceGuard;
pub use rules::{PolicyRule, RuleCondition, RuleEffect};
