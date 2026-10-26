//! weituo-core — the reusable EVM WAF rule-check engine.
//!
//! Pure checking core with no HTTP server: rules enter through the
//! [`provider::RuleProvider`] trait (or [`static_loader`] for local yaml
//! files), and [`checker::Checker`] evaluates transactions against them with
//! the [`weituo_expr`] DSL plus [`builtins`] (generic chain-data RPC helpers)
//! and the calldata [`decoder`].
//!
//! External-data hooks stay outside the engine: price feeds and scam lists
//! are supplied by the embedding layer through a composite
//! [`BuiltinProvider`](weituo_expr::context::BuiltinProvider)
//! ([`checker::Checker::new_with_builtins`]) and the
//! [`checker::ScamOracle`] trait.
//!
//! Embedding shape: build a [`checker::Checker`] from [`config::Settings`] and
//! any [`provider::RuleProvider`] implementation. All engine state (rule
//! caches) lives inside the constructed instance and its lifetime is owned
//! by the caller — no global state, no listeners.

pub mod builtins;
pub mod checker;
pub mod config;
pub mod decoder;
pub mod parse_rule;
pub mod provider;
pub mod rule_manager;
pub mod static_loader;
pub mod types;

pub use weituo_expr;
