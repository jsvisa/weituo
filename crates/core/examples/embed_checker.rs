//! Minimal embedding example: a stateless `Checker` over a `StaticResolver`,
//! checking both an EVM transaction and a Sui PTB through the unified
//! `check_tx` entry point.
//!
//! ```sh
//! cargo run -p weituo-core --example embed_checker
//! ```
//!
//! Everything here is local and immutable: rules are prepared in memory (in
//! real use they come from `static_loader::load_multi` or a `RuleProvider`
//! you cache behind a `RuleResolver`), and the checker is constructed from
//! plain parameters — no config files, no background tasks.

use std::collections::HashMap;

use weituo_core::{
    chain::{ChainRef, ChainTx},
    checker::{CheckResult, Checker},
    policy::Policy,
    provider::{ChainInfo, StaticResolver},
    types::{ExprValue, RuleClause, RuleEntry},
};

/// The EVM rule: allow `approve` on the USDT proxy only when the spender is
/// the caller's own address.
fn evm_rules() -> HashMap<(ChainRef, String), HashMap<String, RuleEntry>> {
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
            ChainRef::Evm(1),
            "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
        ),
        HashMap::from([("0x095ea7b3".to_string(), entry)]),
    )])
}

/// The Sui rule: allow `swap::do_swap` on the package only when the decoded
/// `amount` stays under the cap and the coin type matches.
fn sui_rules() -> HashMap<(ChainRef, String), HashMap<String, RuleEntry>> {
    let entry = RuleEntry {
        clauses: vec![RuleClause {
            expr: ExprValue::try_from(serde_json::json!(
                "args.amount <= vars.max and type_arguments[0] == vars.coin"
            ))
            .unwrap(),
            vars: serde_json::from_value(serde_json::json!({
                "max": "1000000000",
                "coin": "0x2::sui::SUI",
            }))
            .unwrap(),
        }],
        abi_item: None,
        family_abi: weituo_core::types::FamilyAbi::from_sui_json(serde_json::json!({
            "params": [
                { "name": "coin",     "type": "&mut 0x2::coin::Coin<T>" },
                { "name": "amount",   "type": "u64" },
                { "name": "ctx",      "type": "&mut 0x2::tx_context::TxContext" }
            ]
        })),
        multicall: None,
        invalid_decoder: false,
    };
    let package = "0xc3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2";
    HashMap::from([(
        (ChainRef::Sui("mainnet".into()), package.to_string()),
        HashMap::from([("swap::do_swap".to_string(), entry)]),
    )])
}

fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run())
}

async fn run() -> anyhow::Result<()> {
    // Rules come from `static_loader::load_multi` or a `RuleProvider` you
    // cache behind a `RuleResolver`. Here: one static map keyed by
    // `ChainRef` (the output shape of `load_multi`) plus known RPCs.
    let mut contracts = evm_rules();
    contracts.extend(sui_rules());
    let chains = HashMap::from([
        (
            ChainRef::Evm(1),
            ChainInfo {
                rpc_url: String::new(), // set a real RPC URL to enable $-builtins
            },
        ),
        (
            ChainRef::Sui("mainnet".into()),
            ChainInfo {
                rpc_url: String::new(),
            },
        ),
    ]);

    let resolver = StaticResolver::new_multi(contracts, chains);

    let checker = Checker::new(
        reqwest::Client::new(),
        Vec::new(), // sender allowlist
        Policy::default(),
    );

    // ── EVM: approve(spender=0x2222…, amount=1) — spender ≠ sender → denied.
    let spender = "2222222222222222222222222222222222222222";
    let amount = format!("{:0>64}", "1");
    let data = format!("0x095ea7b3{spender:0>64}{amount}");
    let evm_tx: weituo_core::types::Transaction = serde_json::from_value(serde_json::json!({
        "chainId": 1,
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0xdac17f958d2ee523a2206206994597c13d831ec7",
        "data": data,
        "value": 0,
    }))?;
    report("evm approve", checker.check(&evm_tx, &resolver).await);

    // ── Sui: PTB with one MoveCall whose amount exceeds the cap → denied.
    let sui_json = serde_json::json!({
        "chain": "sui",
        "chainId": "mainnet",
        "from": "0x9b7a9d6d2f2d5b0a5e5f6e2f4f0d1e2c3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
        "gasBudget": "100000000",
        "inputs": [
            { "kind": "pure", "valueType": "u64", "value": "2000000000" }
        ],
        "commands": [
            { "MoveCall": {
                "target": "0xc3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2::swap::do_swap",
                "typeArguments": ["0x2::sui::SUI"],
                // Reference params (`&mut Coin`, trailing TxContext) are
                // implicit — the arguments array carries only consuming
                // slots (design §8.2), so this is just the u64 amount.
                "arguments": [{ "Input": 0 }]
            } }
        ],
    });
    let sui_tx =
        ChainTx::from_json(&sui_json).map_err(|e| anyhow::anyhow!("invalid sui payload: {e}"))?;
    report("sui do_swap", checker.check_tx(&sui_tx, &resolver).await);

    Ok(())
}

fn report(label: &str, result: CheckResult) {
    match result {
        CheckResult::Ok => println!("{label}: allowed"),
        CheckResult::Denied(reason) => println!("{label}: denied: {reason}"),
    }
}
