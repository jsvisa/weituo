//! The rule-source integration point: [`RuleProvider`].
//!
//! `weituo-core` only defines the trait — concrete backends (emp-api,
//! waf-admin) live in the service layer. Implement this trait to feed rules
//! from any source, or use [`crate::static_loader`] for local yaml files.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::warn;

use crate::rule_manager::build_decoder;
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

/// Shared helper: convert the raw Rule list (from either backend) into
/// the selector → RuleEntry map that RuleManager stores.
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
