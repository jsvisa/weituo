//! Decision policy — plain parameter values supplied by the embedding layer
//! when constructing a [`Checker`](crate::checker::Checker).
//!
//! No file loading, no environment handling lives here: the caller decides
//! where its configuration comes from and hands the values over.

use serde::Deserialize;

/// Policy for ERC20 `transfer` / `approve` calls that have no matching rule.
///
/// Scam screening is deliberately **not**
/// part of core: the embedding layer decodes the approve spender itself,
/// consults its own scam list and denies before invoking the checker — the
/// engine stays free of any scam concept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenOpPolicy {
    /// Allow token ops without a rule.
    #[default]
    AllowAll,
    /// Deny token ops without a rule (typed `TokenOpDenied` reason).
    DenyAll,
    /// No rule → fall through to rule lookup and report `NoRule`.
    RequireRule,
    /// Placeholder — currently behaves like [`TokenOpPolicy::RequireRule`].
    Whitelist,
}

/// Global decision parameters for the checker.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Allow contract deployment transactions (`tx.to` empty).
    pub allow_contract_creation: bool,
    /// Allow plain ETH sends (empty calldata).
    pub allow_native_transfer: bool,
    /// ERC20 `transfer`/`approve` policy when no rule matches the selector.
    pub token_op_policy: TokenOpPolicy,
    /// Allowed EIP-2718 transaction types (e.g. `[0, 1, 2]`).
    pub transaction_types: Vec<u64>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_contract_creation: true,
            allow_native_transfer: true,
            token_op_policy: TokenOpPolicy::AllowAll,
            transaction_types: vec![0, 1, 2],
        }
    }
}
