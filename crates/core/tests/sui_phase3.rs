//! Phase 3 (Sui, feature `sui`) golden vectors: the §3.3 PTB (SplitCoins +
//! TransferObjects with `Result(0)` dataflow), a plain `coin::transfer`
//! MoveCall, `pay_sui`, Publish/Upgrade policy denials, variable-length
//! address normalization (`0x2` vs full 64-nibble hex), and fail-closed
//! decoding of unresolved `Result` arguments.

#![cfg(feature = "sui")]

use std::collections::HashMap;
use weituo_core::chain::{ChainRef, ChainTx};
use weituo_core::checker::{CheckResult, Checker};
use weituo_core::policy::{Policy, TokenOpPolicy};
use weituo_core::provider::{ChainInfo, StaticResolver};
use weituo_core::static_loader::load_multi;
use weituo_core::sui::{decode_sui_args, SuiTx};
use weituo_core::types::{FamilyAbi, RuleEntry};

// Fixture addresses (full 64-nibble lowercase hex)
const SENDER: &str = "0x9b7a9d6d2f2d5b0a5e5f6e2f4f0d1e2c3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d";
const RECIPIENT: &str = "0xa1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const WALLET2: &str = "0xb2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1";
const PACKAGE: &str = "0xc3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2";
/// The system package `0x2` in its full normalized form.
const SYSTEM_FULL: &str = "0x0000000000000000000000000000000000000000000000000000000000000002";
const COIN_TYPE: &str =
    "0xc3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2::usdc::USDC";

fn sui_tx(inputs: serde_json::Value, commands: serde_json::Value) -> SuiTx {
    let v = serde_json::json!({
        "chain": "sui",
        "chainId": "mainnet",
        "from": SENDER,
        "gasBudget": "100000000",
        "gasPrice": "750",
        "inputs": inputs,
        "commands": commands,
    });
    SuiTx::from_json(&v).unwrap()
}

fn rule_entry(
    sui_abi: Option<serde_json::Value>,
    expr: &str,
    vars: serde_json::Value,
) -> RuleEntry {
    RuleEntry {
        clauses: vec![weituo_core::types::RuleClause {
            expr: weituo_core::types::ExprValue::Single(expr.into()),
            vars: serde_json::from_value(vars).unwrap_or_default(),
        }],
        abi_item: None,
        family_abi: sui_abi.and_then(FamilyAbi::from_sui_json),
        multicall: None,
        invalid_decoder: false,
    }
}

fn resolver_with(key: (ChainRef, &str), selector: &str, entry: RuleEntry) -> StaticResolver {
    let key = (key.0, key.1.to_string());
    StaticResolver::new_multi(
        HashMap::from([(key, HashMap::from([(selector.to_string(), entry)]))]),
        HashMap::from([(
            ChainRef::Sui("mainnet".into()),
            ChainInfo {
                rpc_url: String::new(),
            },
        )]),
    )
}

fn strict() -> Policy {
    Policy {
        allow_native_transfer: false,
        token_op_policy: TokenOpPolicy::RequireRule,
        ..Default::default()
    }
}

fn result_code(r: &CheckResult) -> String {
    match r {
        CheckResult::Ok => "ok".to_string(),
        CheckResult::Denied(reason) => format!("{}:{}", reason.code(), reason),
    }
}

async fn check(checker: &Checker, tx: &SuiTx, resolver: &StaticResolver) -> CheckResult {
    checker.check_tx(&ChainTx::Sui(tx.clone()), resolver).await
}

/// The §3.3 golden PTB: SplitCoins(GasCoin, [1 SUI]) → TransferObjects to
/// `Input(1)`.
fn native_transfer_ptb() -> SuiTx {
    sui_tx(
        serde_json::json!([
            { "kind": "pure", "valueType": "u64", "value": "1000000000" },
            { "kind": "pure", "valueType": "address", "value": RECIPIENT }
        ]),
        serde_json::json!([
            { "SplitCoins": { "coin": {"GasCoin": true}, "amounts": [{"Input": 0}] } },
            { "TransferObjects": { "objects": [{"Result": 0}], "address": {"Input": 1} } }
        ]),
    )
}

// ── JSON wire ────────────────────────────────────────────────────────────────

#[test]
fn from_json_sui_parses_golden_ptb() {
    let tx = native_transfer_ptb();
    assert_eq!(tx.network, "mainnet");
    assert_eq!(tx.from, SENDER);
    assert_eq!(tx.gas_owner, SENDER); // defaults to from
    assert_eq!(tx.gas_budget, 100000000);
    assert_eq!(tx.gas_price, 750);
    assert_eq!(tx.inputs.len(), 2);
    assert_eq!(tx.commands.len(), 2);
}

#[test]
fn from_json_sui_gas_owner_explicit() {
    let v = serde_json::json!({
        "chain": "sui", "chainId": "mainnet", "from": SENDER,
        "gasOwner": RECIPIENT,
        "inputs": [], "commands": [{ "SplitCoins": { "coin": {"GasCoin": true}, "amounts": [] } }]
    });
    let tx = SuiTx::from_json(&v).unwrap();
    assert_eq!(tx.gas_owner, RECIPIENT);
}

#[test]
fn from_json_sui_numeric_chain_id_rejected() {
    let v = serde_json::json!({
        "chain": "sui", "chainId": 1, "from": SENDER,
        "inputs": [], "commands": []
    });
    assert!(
        SuiTx::from_json(&v).is_err(),
        "numeric chainId is an EVM id"
    );
}

#[test]
fn from_json_sui_bad_address_fails_closed() {
    let v = serde_json::json!({
        "chain": "sui", "chainId": "mainnet", "from": "0xzz9",
        "inputs": [], "commands": []
    });
    assert!(SuiTx::from_json(&v).is_err());
}

#[test]
fn from_json_sui_out_of_range_int_rejected_not_truncated() {
    // A u8 pure input with value 300 must fail the parse, not silently
    // truncate to 44 (regression: range-check against the declared width).
    let v = serde_json::json!({
        "chain": "sui", "chainId": "mainnet", "from": SENDER,
        "inputs": [{ "kind": "pure", "valueType": "u8", "value": "300" }],
        "commands": [{ "SplitCoins": { "coin": {"GasCoin": true}, "amounts": [{"Input": 0}] } }]
    });
    let err = SuiTx::from_json(&v).unwrap_err();
    assert!(err.contains("out of range"), "{err}");
    // Same for a vector element.
    let v = serde_json::json!({
        "chain": "sui", "chainId": "mainnet", "from": SENDER,
        "inputs": [{ "kind": "pure", "valueType": "vector<u16>", "value": [1, 70000] }],
        "commands": [{ "SplitCoins": { "coin": {"GasCoin": true}, "amounts": [{"Input": 0}] } }]
    });
    assert!(SuiTx::from_json(&v).is_err());
    // In-range values still parse.
    let v = serde_json::json!({
        "chain": "sui", "chainId": "mainnet", "from": SENDER,
        "inputs": [{ "kind": "pure", "valueType": "u8", "value": "255" }],
        "commands": [{ "SplitCoins": { "coin": {"GasCoin": true}, "amounts": [{"Input": 0}] } }]
    });
    assert!(SuiTx::from_json(&v).is_ok());
}

#[test]
fn from_json_sui_empty_commands_rejected() {
    let v = serde_json::json!({
        "chain": "sui", "chainId": "mainnet", "from": SENDER,
        "inputs": [], "commands": []
    });
    assert!(SuiTx::from_json(&v).is_err());
}

#[test]
fn chain_tx_from_json_sui_dispatches() {
    let v = serde_json::json!({
        "chain": "sui", "chainId": "mainnet", "from": SENDER,
        "inputs": [
            { "kind": "pure", "valueType": "u64", "value": "1000000000" },
            { "kind": "pure", "valueType": "address", "value": RECIPIENT }
        ],
        "commands": [
            { "SplitCoins": { "coin": {"GasCoin": true}, "amounts": [{"Input": 0}] } },
            { "TransferObjects": { "objects": [{"Result": 0}], "address": {"Input": 1} } }
        ]
    });
    let tx = ChainTx::from_json(&v).unwrap();
    assert!(matches!(tx, ChainTx::Sui(_)));
}

// ── Address normalization ────────────────────────────────────────────────────

#[test]
fn sui_addresses_normalize_to_full_hex() {
    let chain = ChainRef::Sui("mainnet".into());
    assert_eq!(chain.normalize_address("0x2"), SYSTEM_FULL);
    assert_eq!(chain.normalize_address("0x0002"), SYSTEM_FULL);
    assert_eq!(chain.normalize_address(PACKAGE), PACKAGE);
    assert_eq!(
        chain.normalize_address("0xABCDEF"),
        format!("0x{}abcdef", "0".repeat(58))
    );
}

// ── BCS decode of MoveCall arguments ─────────────────────────────────────────

#[test]
fn move_call_args_decode_positionally() {
    // pay::split(coin: Coin<SUI>, split_at: u64) — coin is by-value (object
    // param), split_at is a pure u64.
    let abi = FamilyAbi::from_sui_json(serde_json::json!({
        "params": [
            { "name": "coin", "type": "0x2::coin::Coin<0x2::sui::SUI>" },
            { "name": "split_at", "type": "u64" }
        ]
    }))
    .unwrap();
    let arguments = serde_json::json!([{ "GasCoin": true }, { "Input": 0 }]);
    let inputs = serde_json::json!([
        { "kind": "pure", "valueType": "u64", "value": "1000000000" }
    ]);
    let args = decode_sui_args(
        abi.as_ref(),
        arguments.as_array().unwrap(),
        inputs.as_array().unwrap(),
    )
    .unwrap();
    assert_eq!(args["coin"], serde_json::json!("0x2::sui::SUI")); // GasCoin sentinel
    assert_eq!(args["split_at"], serde_json::json!("1000000000"));
}

#[test]
fn reference_params_are_filtered() {
    // Signature declares &mut refs; only `split_at` (u64) consumes a slot.
    let abi = FamilyAbi::from_sui_json(serde_json::json!({
        "params": [
            { "name": "coin", "type": "&mut 0x2::coin::Coin<0x2::sui::SUI>" },
            { "name": "split_at", "type": "u64" },
            { "name": "ctx", "type": "&mut 0x2::tx_context::TxContext" }
        ]
    }))
    .unwrap();
    let arguments = serde_json::json!([{ "Input": 0 }]);
    let inputs = serde_json::json!([
        { "kind": "pure", "valueType": "u64", "value": "500" }
    ]);
    let args = decode_sui_args(
        abi.as_ref(),
        arguments.as_array().unwrap(),
        inputs.as_array().unwrap(),
    )
    .unwrap();
    assert_eq!(args["split_at"], serde_json::json!("500"));
    assert!(
        !args.contains_key("coin"),
        "filtered refs must not appear in args"
    );
}

#[test]
fn object_input_maps_to_object_id() {
    let abi = FamilyAbi::from_sui_json(serde_json::json!({
        "params": [{ "name": "coin", "type": "0x2::coin::Coin<0x2::sui::SUI>" }]
    }))
    .unwrap();
    let arguments = serde_json::json!([{ "Input": 0 }]);
    let inputs = serde_json::json!([
        { "kind": "object", "objectId": "0x0002" }
    ]);
    let args = decode_sui_args(
        abi.as_ref(),
        arguments.as_array().unwrap(),
        inputs.as_array().unwrap(),
    )
    .unwrap();
    // Object ids normalize to full 64-nibble hex at decode time.
    assert_eq!(args["coin"], serde_json::json!(SYSTEM_FULL));
}

// ── Native-transfer dataflow ─────────────────────────────────────────────────

#[tokio::test]
async fn native_transfer_allowed_by_policy() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), Policy::default());
    let tx = native_transfer_ptb();
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );
}

#[tokio::test]
async fn native_transfer_gate_disabled_denies_fail_closed() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let tx = native_transfer_ptb();
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32606),
        CheckResult::Ok => panic!("native-transfer gate off + no rules must deny"),
    }
}

#[tokio::test]
async fn native_transfer_rule_gates_amount_and_recipient() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let entry = rule_entry(
        Some(serde_json::json!({
            "params": [
                { "name": "amount", "type": "u64" },
                { "name": "recipient", "type": "address" }
            ]
        })),
        "args.recipient in vars.my_wallets and args.amount <= vars.max_sui",
        serde_json::json!({
            "my_wallets": [RECIPIENT, WALLET2],
            "max_sui": "2000000000"
        }),
    );
    let resolver = resolver_with(
        (ChainRef::Sui("mainnet".into()), SYSTEM_FULL),
        "native_transfer",
        entry,
    );
    let tx = native_transfer_ptb();
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );

    // Exceeding the amount cap denies with the expression.
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "pure", "valueType": "u64", "value": "3000000000" },
            { "kind": "pure", "valueType": "address", "value": RECIPIENT }
        ]),
        serde_json::json!([
            { "SplitCoins": { "coin": {"GasCoin": true}, "amounts": [{"Input": 0}] } },
            { "TransferObjects": { "objects": [{"Result": 0}], "address": {"Input": 1} } }
        ]),
    );
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32603),
        CheckResult::Ok => panic!("amount over cap must deny"),
    }

    // Recipient outside the allowlist denies.
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "pure", "valueType": "u64", "value": "1000000000" },
            { "kind": "pure", "valueType": "address", "value": PACKAGE }
        ]),
        serde_json::json!([
            { "SplitCoins": { "coin": {"GasCoin": true}, "amounts": [{"Input": 0}] } },
            { "TransferObjects": { "objects": [{"Result": 0}], "address": {"Input": 1} } }
        ]),
    );
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32603),
        CheckResult::Ok => panic!("recipient outside allowlist must deny"),
    }
}

#[tokio::test]
async fn pay_sui_synthesizes_native_transfer() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let entry = rule_entry(
        Some(serde_json::json!({
            "params": [
                { "name": "amount", "type": "u64" },
                { "name": "recipient", "type": "address" }
            ]
        })),
        "args.amount == 1000000000 and args.recipient == vars.r",
        serde_json::json!({ "r": RECIPIENT }),
    );
    let resolver = resolver_with(
        (ChainRef::Sui("mainnet".into()), SYSTEM_FULL),
        "native_transfer",
        entry,
    );
    // pay_sui(amounts: vector<u64>, recipients: vector<address>)
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "pure", "valueType": "vector<u64>", "value": [1000000000] },
            { "kind": "pure", "valueType": "vector<address>", "value": [RECIPIENT] }
        ]),
        serde_json::json!([
            { "MoveCall": { "target": "0x2::pay::pay_sui",
                            "typeArguments": ["0x2::sui::SUI"],
                            "arguments": [{"Input": 0}, {"Input": 1}] } }
        ]),
    );
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );

    // Same call with a non-allowlisted recipient denies via the rule.
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "pure", "valueType": "vector<u64>", "value": [1000000000] },
            { "kind": "pure", "valueType": "vector<address>", "value": [PACKAGE] }
        ]),
        serde_json::json!([
            { "MoveCall": { "target": "0x2::pay::pay_sui",
                            "typeArguments": ["0x2::sui::SUI"],
                            "arguments": [{"Input": 0}, {"Input": 1}] } }
        ]),
    );
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32603),
        CheckResult::Ok => panic!("pay_sui to a non-allowlisted recipient must deny"),
    }
}

// ── MoveCall rules ───────────────────────────────────────────────────────────

#[tokio::test]
async fn move_call_rule_evaluates_args_and_type_arguments() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let entry = rule_entry(
        Some(serde_json::json!({
            "params": [
                { "name": "coin", "type": "0x2::coin::Coin<0x2::sui::SUI>" },
                { "name": "amount", "type": "u64" }
            ]
        })),
        "type_arguments[0] == vars.coin and args.amount <= vars.max",
        serde_json::json!({ "coin": COIN_TYPE, "max": "1000000" }),
    );
    let resolver = resolver_with(
        (ChainRef::Sui("mainnet".into()), PACKAGE),
        "swap::do_swap",
        entry,
    );
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "object", "objectId": PACKAGE },
            { "kind": "pure", "valueType": "u64", "value": "500" }
        ]),
        serde_json::json!([
            { "MoveCall": { "target": "0XC3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2::Swap::Do_Swap",
                            "typeArguments": [COIN_TYPE],
                            "arguments": [{"Input": 0}, {"Input": 1}] } }
        ]),
    );
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );

    // Amount over cap → ExpressionDenied, message carries the command index.
    // command[0] (500) passes its rule; command[1] (2000000) violates the cap.
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "object", "objectId": PACKAGE },
            { "kind": "pure", "valueType": "u64", "value": "500" },
            { "kind": "pure", "valueType": "u64", "value": "2000000" }
        ]),
        serde_json::json!([
            { "MoveCall": { "target": "0xC3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2::swap::do_swap",
                            "typeArguments": [COIN_TYPE],
                            "arguments": [{"Input": 0}, {"Input": 1}] } },
            { "MoveCall": { "target": "0xC3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2::swap::do_swap",
                            "typeArguments": [COIN_TYPE],
                            "arguments": [{"Input": 0}, {"Input": 2}] } }
        ]),
    );
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => {
            assert_eq!(reason.code(), -32603);
            let msg = format!("{reason}");
            assert!(
                msg.contains("command[1]"),
                "denial must carry the command index: {msg}"
            );
        }
        CheckResult::Ok => panic!("amount over cap must deny"),
    }
}

#[tokio::test]
async fn unresolved_result_fails_closed() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let entry = rule_entry(
        Some(serde_json::json!({
            "params": [
                { "name": "amount", "type": "u64" },
                { "name": "other", "type": "u64" }
            ]
        })),
        "args.amount > 0 and args.other > 0",
        serde_json::json!({}),
    );
    let resolver = resolver_with(
        (ChainRef::Sui("mainnet".into()), PACKAGE),
        "swap::do_swap",
        entry,
    );
    // `other` receives an inter-command Result → null → expr errors (deny).
    // Self-referencing `Result(0)` inside command 0 is unresolvable.
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "pure", "valueType": "u64", "value": "500" }
        ]),
        serde_json::json!([
            { "MoveCall": { "target": "0xC3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2::swap::do_swap",
                            "typeArguments": [],
                            "arguments": [{"Input": 0}, {"Result": 0}] } }
        ]),
    );
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32500),
        CheckResult::Ok => panic!("unresolved Result arg must fail closed"),
    }
}

// ── Policy: creation + token ops ─────────────────────────────────────────────

#[tokio::test]
async fn publish_denied_by_default() {
    let checker = Checker::new(
        reqwest::Client::new(),
        Vec::new(),
        Policy {
            allow_contract_creation: false,
            ..Default::default()
        },
    );
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "pure", "valueType": "vector<u8>", "value": [1, 2, 3] }
        ]),
        serde_json::json!([
            { "Publish": { "modules": [{"Input": 0}], "dependencies": [] } }
        ]),
    );
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32602),
        CheckResult::Ok => panic!("Publish must deny by default"),
    }
}

#[tokio::test]
async fn upgrade_denied_by_default() {
    let checker = Checker::new(
        reqwest::Client::new(),
        Vec::new(),
        Policy {
            allow_contract_creation: false,
            ..Default::default()
        },
    );
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "object", "objectId": PACKAGE },
            { "kind": "pure", "valueType": "vector<u8>", "value": [1] }
        ]),
        serde_json::json!([
            { "Upgrade": { "modules": [{"Input": 1}], "dependencies": [],
                           "package": {"Input": 0}, "ticket": {"Input": 1} } }
        ]),
    );
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32602),
        CheckResult::Ok => panic!("Upgrade must deny by default"),
    }
}

#[tokio::test]
async fn publish_allowed_still_fails_closed_on_the_command() {
    // With creation allowed, Publish is not a MoveCall and has no rule
    // context — it must still fail closed (NoContract).
    let checker = Checker::new(
        reqwest::Client::new(),
        Vec::new(),
        Policy {
            allow_contract_creation: true,
            ..Default::default()
        },
    );
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "pure", "valueType": "vector<u8>", "value": [1, 2, 3] }
        ]),
        serde_json::json!([
            { "Publish": { "modules": [{"Input": 0}], "dependencies": [] } }
        ]),
    );
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32606),
        CheckResult::Ok => panic!("Publish must fail closed even when creation is allowed"),
    }
}

#[tokio::test]
async fn coin_transfer_token_op_deny_all_policy() {
    let checker = Checker::new(
        reqwest::Client::new(),
        Vec::new(),
        Policy {
            token_op_policy: TokenOpPolicy::DenyAll,
            ..Default::default()
        },
    );
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "object", "objectId": PACKAGE },
            { "kind": "pure", "valueType": "address", "value": RECIPIENT }
        ]),
        serde_json::json!([
            { "MoveCall": { "target": "0x2::coin::transfer",
                            "typeArguments": ["0x2::sui::SUI"],
                            "arguments": [{"Input": 0}, {"Input": 1}] } }
        ]),
    );
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32604),
        CheckResult::Ok => panic!("DenyAll token policy must deny coin::transfer"),
    }
}

#[tokio::test]
async fn coin_transfer_token_op_allow_all_policy() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), Policy::default());
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "object", "objectId": PACKAGE },
            { "kind": "pure", "valueType": "address", "value": RECIPIENT }
        ]),
        serde_json::json!([
            { "MoveCall": { "target": "0x2::coin::transfer",
                            "typeArguments": ["0x2::sui::SUI"],
                            "arguments": [{"Input": 0}, {"Input": 1}] } }
        ]),
    );
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );
}

#[tokio::test]
async fn allowlisted_sender_bypasses_sui_checks() {
    let checker = Checker::new(reqwest::Client::new(), vec![SENDER.to_string()], strict());
    let tx = sui_tx(
        serde_json::json!([
            { "kind": "object", "objectId": PACKAGE },
            { "kind": "pure", "valueType": "address", "value": RECIPIENT }
        ]),
        serde_json::json!([
            { "MoveCall": { "target": "0x2::coin::transfer",
                            "typeArguments": ["0x2::sui::SUI"],
                            "arguments": [{"Input": 0}, {"Input": 1}] } }
        ]),
    );
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    assert!(matches!(result, CheckResult::Ok));
}

// ── Static loading ───────────────────────────────────────────────────────────

#[test]
fn sui_rule_loads_with_module_selector_and_full_hex_address() {
    let dir = std::env::temp_dir().join(format!("weituo_sui3_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let yaml = format!(
        r#"
contracts:
  - chain: "sui:mainnet"
    address: "0x2"
    allowlist:
      - func: "native_transfer"
        abi: {{ params: [{{name: "amount", type: "u64"}}, {{name: "recipient", type: "address"}}] }}
        expr: "args.recipient in vars.my_wallets and args.amount <= vars.max_sui"
        vars:
          my_wallets: ["{RECIPIENT}"]
          max_sui: "2000000000"
"#
    );
    let yaml_path = dir.join("waf.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();
    let (_, contracts) = load_multi(yaml_path.to_str().unwrap(), dir.to_str().unwrap(), 1).unwrap();
    let rules = contracts
        .get(&(ChainRef::Sui("mainnet".into()), SYSTEM_FULL.to_string()))
        .expect("sui contract present under the FULL-hex address");
    assert!(
        rules.contains_key("native_transfer"),
        "rule must load under the module::function selector, got {:?}",
        rules.keys().collect::<Vec<_>>()
    );
}

#[test]
fn sui_rule_with_unknown_builtin_rejected_at_load() {
    let dir = std::env::temp_dir().join(format!("weituo_sui3b_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let yaml = format!(
        r#"
contracts:
  - chain: "sui:mainnet"
    address: "{PACKAGE}"
    allowlist:
      - func: "swap::do_swap"
        abi: {{ params: [{{name: "amount", type: "u64"}}] }}
        expr: "$erc20_balance_of('0x2') > 0 and args.amount > 0"
"#
    );
    let yaml_path = dir.join("waf.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();
    let (_, contracts) = load_multi(yaml_path.to_str().unwrap(), dir.to_str().unwrap(), 1).unwrap();
    let rules = contracts
        .get(&(ChainRef::Sui("mainnet".into()), PACKAGE.to_string()))
        .expect("sui contract present");
    assert!(
        rules.is_empty(),
        "rule referencing $erc20_* on Sui must be rejected at load, got {:?}",
        rules.keys().collect::<Vec<_>>()
    );
}

// ── test mode ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_tx_sui_inline_signature() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let mut tx = sui_tx(
        serde_json::json!([
            { "kind": "pure", "valueType": "u64", "value": "500" }
        ]),
        serde_json::json!([
            { "MoveCall": { "target": "0x2::pay::split",
                            "typeArguments": ["0x2::sui::SUI"],
                            "arguments": [{"Input": 0}] } }
        ]),
    );
    tx.abi = Some(
        FamilyAbi::from_sui_json(serde_json::json!({
            "params": [{ "name": "split_at", "type": "u64" }]
        }))
        .unwrap(),
    );
    tx.expr = Some("args.split_at == 500 and command_index == 0".into());
    let result = checker.test_tx(&ChainTx::Sui(tx.clone()), None).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );

    tx.expr = Some("args.split_at > 500".into());
    let result = checker.test_tx(&ChainTx::Sui(tx), None).await;
    match result {
        CheckResult::Denied(reason) => {
            assert_eq!(reason.code(), -32603);
            let msg = format!("{reason}");
            assert!(
                msg.contains("command[0]"),
                "test denial carries the index: {msg}"
            );
        }
        CheckResult::Ok => panic!("failing expr must deny"),
    }
}
