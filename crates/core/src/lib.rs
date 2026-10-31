//! weituo-core — the reusable EVM WAF rule-check engine.
//!
//! A **stateless** checking core: rules enter through the [`provider::RuleResolver`]
//! passed per call (feed it from a [`provider::RuleProvider`] backend or
//! [`static_loader`] for local yaml files), and [`checker::Checker`] evaluates
//! transactions against them with the [`weituo_expr`] DSL plus [`builtins`]
//! (generic chain-data RPC helpers) and the calldata [`decoder`].
//!
//! Everything stateful belongs to the embedding layer:
//!
//! - **rule caches / backends** — implement [`provider::RuleResolver`] over
//!   your own cache or a [`provider::RuleProvider`];
//! - **configuration** — construct [`policy::Policy`] and the allowlist from
//!   wherever your config lives;
//! - **external data** — price feeds, scam lists, … via a composite
//!   [`BuiltinProvider`](weituo_expr::context::BuiltinProvider) installed
//!   with [`checker::Checker::with_builtins_factory`]. The engine has no
//!   scam concept: screen spenders in your layer and deny before checking.
//!
//! No global state, no background tasks, no config files.

pub mod builtins;
pub mod chain;
pub mod checker;
pub mod decoder;
pub mod parse_rule;
pub mod policy;
pub mod provider;
pub mod static_loader;
#[cfg(feature = "svm")]
pub mod svm;
pub mod types;

pub use weituo_expr;
