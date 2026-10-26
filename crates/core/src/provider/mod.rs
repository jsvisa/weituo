//! The rule-source integration points.
//!
//! [`RuleProvider`] fetches rules from a backend (HTTP API, database, …);
//! [`RuleResolver`] is what the checker consumes per call — typically a
//! cache sitting on top of a provider, owned by the embedding layer. The
//! engine itself holds no rule state.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::warn;

use crate::decoder::build_decoder;
use crate::types::{ExprValue, Rule, RuleClause, RuleEntry};

#[derive(Debug, Clone)]
pub struct ChainInfo {
    pub rpc_url: String,
}

#[async_trait]
#[allow(clippy::double_must_use)]
pub trait RuleProvider: Send + Sync {
    async fn fetch_chain_info(&self, chain_id: u64) -> Result<ChainInfo>;
    async fn fetch_contract_rules(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Result<HashMap<String, RuleEntry>>;
}

/// Per-call rule source for the checker — the engine keeps no rule cache.
///
/// Implementations live in the embedding layer and typically cache (TTL'd
/// fetches from a [`RuleProvider`], statically loaded yaml, …). Core treats
/// every answer as call-scoped data.
#[async_trait]
pub trait RuleResolver: Send + Sync {
    /// Rules for one contract, keyed by lowercase selector (`"*"` wildcard
    /// supported). `None` = contract unknown to the backend (the checker
    /// reports `NoContract`); an entry missing from the map reports `NoRule`.
    async fn contract_rules(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Option<HashMap<String, RuleEntry>>;

    /// RPC endpoint the `$`-builtins use for chain queries on this chain.
    /// `None` = unknown — RPC-backed builtins error if a rule uses them.
    fn chain_rpc_url(&self, chain_id: u64) -> Option<String>;
}

/// A [`RuleResolver`] over in-memory data — feed it the output of
/// [`crate::static_loader::load`] or your own prepared rules.
/// No I/O, no caching, no background tasks.
pub struct StaticResolver {
    contracts: HashMap<(u64, String), HashMap<String, RuleEntry>>,
    rpc_urls: HashMap<u64, String>,
}

impl StaticResolver {
    /// `contracts`: (chain_id, address) → selector → rule, `chains`: per-chain
    /// info (non-empty `rpc_url`s are used for the `$`-builtins).
    pub fn new(
        contracts: HashMap<(u64, String), HashMap<String, RuleEntry>>,
        chains: HashMap<u64, ChainInfo>,
    ) -> Self {
        let rpc_urls = chains
            .into_iter()
            .filter(|(_, info)| !info.rpc_url.is_empty())
            .map(|(chain_id, info)| (chain_id, info.rpc_url))
            .collect();
        Self {
            contracts,
            rpc_urls,
        }
    }
}

#[async_trait]
impl RuleResolver for StaticResolver {
    async fn contract_rules(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Option<HashMap<String, RuleEntry>> {
        self.contracts
            .get(&(chain_id, address.to_lowercase()))
            .cloned()
    }

    fn chain_rpc_url(&self, chain_id: u64) -> Option<String> {
        self.rpc_urls.get(&chain_id).cloned()
    }
}

/// Shared helper: convert the raw Rule list (from either backend) into
/// the selector → RuleEntry map that resolvers store.
pub fn parse_rules(raw: Vec<Rule>) -> HashMap<String, RuleEntry> {
    let mut map = HashMap::new();
    for rule in raw {
        let multicall = build_decoder(rule.decoder_type, rule.decoder_config.as_ref());
        let invalid_decoder = multicall.is_none() && rule.decoder_config.is_some();
        let mut clauses = Vec::new();
        for raw_clause in rule.rules {
            let expr = match ExprValue::try_from(raw_clause.expr) {
                Ok(e) => e,
                Err(e) => {
                    warn!("skipping clause in {}: {e}", rule.func);
                    continue;
                }
            };
            clauses.push(RuleClause {
                expr,
                vars: raw_clause.vars.unwrap_or_default(),
            });
        }
        if clauses.is_empty() && multicall.is_none() {
            warn!("no valid clauses for {}, skipping", rule.func);
            continue;
        }
        map.insert(
            rule.selector.to_lowercase(),
            RuleEntry {
                clauses,
                abi_item: rule.abi_item,
                multicall,
                invalid_decoder,
            },
        );
    }
    map
}
