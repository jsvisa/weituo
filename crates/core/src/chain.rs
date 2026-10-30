//! Chain-family plumbing: which chain a transaction targets, the unified
//! transaction input, and the resolver surface the unified entry points use.
//!
//! Everything here is additive over the EVM-only API: existing types are
//! wrapped, never mutated (see docs/design-multichain.md §2).

use async_trait::async_trait;
use std::collections::HashMap;

use crate::provider::RuleResolver;
use crate::types::{RuleEntry, Transaction};

/// Identifies the target chain across families. EVM keeps numeric ids so
/// today's keys keep working; SVM/Sui use their network names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChainRef {
    Evm(u64),
    Svm(String),
    Sui(String),
}

impl From<u64> for ChainRef {
    fn from(n: u64) -> Self {
        Self::Evm(n)
    }
}

impl ChainRef {
    /// CAIP-2-style rendering: `"eip155:1"` / `"svm:mainnet-beta"` /
    /// `"sui:mainnet"`.
    pub fn to_family_network(&self) -> String {
        match self {
            Self::Evm(n) => format!("eip155:{n}"),
            Self::Svm(net) => format!("svm:{net}"),
            Self::Sui(net) => format!("sui:{net}"),
        }
    }

    /// Lowercase-normalization an address key needs for this family.
    /// EVM hex addresses are case-insensitive; SVM base58 addresses are
    /// case-sensitive; Sui hex is normalized to lowercase.
    pub(crate) fn normalize_address(&self, address: &str) -> String {
        match self {
            Self::Svm(_) => address.to_string(),
            _ => address.to_lowercase(),
        }
    }
}

/// Unified transaction input — wraps the existing EVM [`Transaction`] and the
/// new per-family types (added with their phases).
#[derive(Debug, Clone)]
pub enum ChainTx {
    Evm(Transaction),
    // Svm(SvmTx)   — phase 2 (feature `svm`)
    // Sui(SuiTx)   — phase 3 (feature `sui`)
}

impl ChainTx {
    /// Parse a JSON payload into the unified input.
    ///
    /// A top-level `"chain"` discriminator selects the family:
    /// - absent (or `"evm"`) → legacy strict EVM parse — today's payloads are
    ///   byte-identical, and a foreign-shaped payload without `chain` fails
    ///   the EVM parser's missing-field checks (fail-closed);
    /// - `"svm"` / `"sui"` → not supported yet (their phases land with the
    ///   `svm` / `sui` features).
    pub fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        match v.get("chain").and_then(|c| c.as_str()) {
            None | Some("evm") => {
                let tx: Transaction = serde_json::from_value(v.clone())
                    .map_err(|e| format!("invalid EVM transaction payload: {e}"))?;
                Ok(Self::Evm(tx))
            }
            Some("svm") => Err(
                "chain family 'svm' is not supported by this build (missing `svm` feature)"
                    .to_string(),
            ),
            Some("sui") => Err(
                "chain family 'sui' is not supported by this build (missing `sui` feature)"
                    .to_string(),
            ),
            Some(other) => Err(format!(
                "unknown chain family '{other}' — expected one of: evm, svm, sui"
            )),
        }
    }
}

/// Per-call rule source for the unified entry points — the family-aware
/// counterpart of [`RuleResolver`]. Core keeps no rule cache either way.
///
/// Not a blanket impl over `RuleResolver` (that would forbid a type from
/// implementing both); use [`CompatResolver`] to adapt an existing
/// `RuleResolver`.
#[async_trait]
pub trait ChainResolver: Send + Sync {
    /// Rules for one address on one chain, keyed by lowercase selector
    /// (`"*"` wildcard supported). `None` = unknown (the checker reports
    /// `NoContract`); an entry missing from the map reports `NoRule`.
    async fn contract_rules(
        &self,
        chain: ChainRef,
        address: &str,
    ) -> Option<HashMap<String, RuleEntry>>;

    /// RPC endpoint the `$`-builtins use for chain queries. `None` = unknown.
    fn chain_rpc_url(&self, chain: ChainRef) -> Option<String>;
}

/// Zero-cost adapter: lets any [`RuleResolver`] answer [`ChainResolver`]
/// lookups. `ChainRef::Evm(n)` delegates with `n`; SVM/Sui → `None`
/// (fail-closed). `Checker::check` wraps the caller's resolver in this
/// internally, so embedders never see it.
pub struct CompatResolver<'a, R: RuleResolver + ?Sized>(pub &'a R);

#[async_trait]
impl<'a, R: RuleResolver + ?Sized> ChainResolver for CompatResolver<'a, R> {
    async fn contract_rules(
        &self,
        chain: ChainRef,
        address: &str,
    ) -> Option<HashMap<String, RuleEntry>> {
        match chain {
            ChainRef::Evm(n) => self.0.contract_rules(n, address).await,
            ChainRef::Svm(_) | ChainRef::Sui(_) => None,
        }
    }

    fn chain_rpc_url(&self, chain: ChainRef) -> Option<String> {
        match chain {
            ChainRef::Evm(n) => self.0.chain_rpc_url(n),
            ChainRef::Svm(_) | ChainRef::Sui(_) => None,
        }
    }
}
