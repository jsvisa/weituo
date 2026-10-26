//! Minimal embedding example: build a `Checker` with your own rule provider.
//!
//! ```sh
//! cargo run -p weituo-core --example embed_checker
//! ```
//!
//! Everything here is local: the provider returns no rules, so the checker
//! falls through to the configured token-op policy (`config/default.toml`) —
//! swap `MyRules` for a real provider to check real transactions.

use std::{collections::HashMap, sync::Arc};

use weituo_core::{
    builtins::Builtins,
    checker::{CheckResult, Checker},
    config::Settings,
    provider::{ChainInfo, RuleProvider},
    rule_manager::RuleManager,
    types::{RuleEntry, Transaction},
};

/// Supply rules from wherever they live (HTTP API, database, files…).
struct MyRules;

#[async_trait::async_trait]
impl RuleProvider for MyRules {
    async fn fetch_chain_info(&self, _chain_id: u64) -> anyhow::Result<ChainInfo> {
        Ok(ChainInfo {
            rpc_url: String::new(),
        })
    }

    async fn fetch_contract_rules(
        &self,
        _chain_id: u64,
        _address: &str,
    ) -> anyhow::Result<HashMap<String, RuleEntry>> {
        Ok(HashMap::new())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = Settings::load_from("config/default.toml")?;
    let http = reqwest::Client::new();
    let provider: Arc<dyn RuleProvider> = Arc::new(MyRules);

    let builtins = Builtins::new(settings.clone(), http, Arc::clone(&provider));
    let rules = Arc::new(RuleManager::new(provider, settings.provider.clone()));
    let checker = Checker::new(
        rules,
        builtins,
        Vec::new(), // address allowlist
        None,       // no scam oracle injected
        settings.global_policy.clone(),
    );

    let tx: Transaction = serde_json::from_value(serde_json::json!({
        "chainId": 1,
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "data": "0x095ea7b30000000000000000000000000000000000000000000000000000000000000001",
        "value": 0,
    }))?;

    match checker.check(&tx).await {
        CheckResult::Ok => println!("allowed"),
        CheckResult::Denied(reason) => println!("denied: {reason}"),
    }
    Ok(())
}
