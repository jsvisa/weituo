//! Minimal embedding example: a stateless `Checker` over a `StaticResolver`.
//!
//! ```sh
//! cargo run -p weituo-core --example embed_checker
//! ```
//!
//! Everything here is local and immutable: rules are prepared in memory (in
//! real use they come from `static_loader::load` or a `RuleProvider` you
//! cache behind a `RuleResolver`), and the checker is constructed from plain
//! parameters — no config files, no background tasks.

use std::collections::HashMap;

use weituo_core::{
    checker::{CheckResult, Checker},
    policy::Policy,
    provider::{ChainInfo, StaticResolver},
    types::{ExprValue, RuleClause, RuleEntry, Transaction},
};

/// A tiny rule set: allow `approve` on the USDT proxy only when the spender
/// is the caller's own address.
fn rules() -> HashMap<(u64, String), HashMap<String, RuleEntry>> {
    let entry = RuleEntry {
        clauses: vec![RuleClause {
            expr: ExprValue::try_from(serde_json::json!("args.spender == from")).unwrap(),
            vars: HashMap::new(),
        }],
        abi_item: Some(
            serde_json::from_value(serde_json::json!({
                "type": "function",
                "name": "approve",
                "inputs": [
                    { "name": "spender", "type": "address" },
                    { "name": "amount",  "type": "uint256" }
                ],
                "outputs": []
            }))
            .unwrap(),
        ),
        family_abi: None,
        multicall: None,
        invalid_decoder: false,
    };
    HashMap::from([(
        (
            1u64,
            "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
        ),
        HashMap::from([("0x095ea7b3".to_string(), entry)]),
    )])
}

/// Rules come from `static_loader::load` or a `RuleProvider` you cache behind
/// a `RuleResolver`. Here: a static map plus one known RPC endpoint.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let resolver = StaticResolver::new(
        rules(),
        HashMap::from([(
            1u64,
            ChainInfo {
                rpc_url: String::new(), // set a real RPC URL to enable $-builtins
            },
        )]),
    );

    let checker = Checker::new(
        reqwest::Client::new(),
        Vec::new(), // sender allowlist
        Policy::default(),
    );

    // approve(spender=0x2222…, amount=1) — spender is NOT the sender → denied.
    let spender = "2222222222222222222222222222222222222222";
    let amount = format!("{:0>64}", "1");
    let data = format!("0x095ea7b3{spender:0>64}{amount}");
    let tx: Transaction = serde_json::from_value(serde_json::json!({
        "chainId": 1,
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0xdac17f958d2ee523a2206206994597c13d831ec7",
        "data": data,
        "value": 0,
    }))?;

    match checker.check(&tx, &resolver).await {
        CheckResult::Ok => println!("allowed"),
        CheckResult::Denied(reason) => println!("denied: {reason}"),
    }
    Ok(())
}
