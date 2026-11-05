//! Eval-level tests for multichain context: `network`, family-prefixed
//! `chainId`, and `chain_fields` resolution (SVM `accounts`, Sui
//! `type_arguments`).

use std::collections::HashMap;
use std::sync::Arc;
use weituo_expr::{
    context::{BuiltinProvider, EvalContext},
    evaluate, Value,
};

struct NoBuiltins;

#[async_trait::async_trait]
impl BuiltinProvider for NoBuiltins {
    async fn call(&self, name: &str, _: &[Value], _: &EvalContext) -> anyhow::Result<Value> {
        Err(anyhow::anyhow!("no builtin: {name}"))
    }
}

fn svm_ctx() -> EvalContext {
    let mut chain_fields = HashMap::new();
    chain_fields.insert(
        "accounts".to_string(),
        serde_json::json!([
            "11111111111111111111111111111111",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
        ]),
    );
    chain_fields.insert(
        "signers".to_string(),
        serde_json::json!(["9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"]),
    );
    chain_fields.insert("instruction_index".to_string(), serde_json::json!(0));
    chain_fields.insert("num_instructions".to_string(), serde_json::json!(1));
    EvalContext {
        chain_id: 0,
        from_address: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM".to_string(),
        to_address: "11111111111111111111111111111111".to_string(),
        network: "svm:mainnet-beta".to_string(),
        chain_fields,
        ..Default::default()
    }
}

fn sui_ctx() -> EvalContext {
    let mut chain_fields = HashMap::new();
    chain_fields.insert(
        "type_arguments".to_string(),
        serde_json::json!(["0x2::sui::SUI", "0x5d4b::coin::COIN"]),
    );
    chain_fields.insert("command_index".to_string(), serde_json::json!(0));
    chain_fields.insert("command_kind".to_string(), serde_json::json!("MoveCall"));
    chain_fields.insert("gas_budget".to_string(), serde_json::json!(10_000_000));
    EvalContext {
        chain_id: 0,
        from_address: "0xaaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
            .to_string(),
        to_address: "0x2".to_string(),
        network: "sui:mainnet".to_string(),
        chain_fields,
        ..Default::default()
    }
}

// ── chainId per family ───────────────────────────────────────────────────────

#[tokio::test]
async fn chain_id_numeric_for_legacy_evm_context() {
    let ctx = EvalContext {
        chain_id: 1,
        ..Default::default()
    };
    let v = evaluate("chainId == 1", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(v, "legacy context (empty network) keeps numeric chainId");
}

#[tokio::test]
async fn chain_id_numeric_for_eip155_network() {
    let ctx = EvalContext {
        chain_id: 137,
        network: "eip155:137".to_string(),
        ..Default::default()
    };
    let v = evaluate("chainId == 137", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(v, "eip155: network keeps numeric chainId");
}

#[tokio::test]
async fn chain_id_is_network_name_for_svm() {
    let ctx = svm_ctx();
    let v = evaluate("chainId == \"mainnet-beta\"", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(v, "svm chainId is the bare network name");
}

#[tokio::test]
async fn chain_id_is_network_name_for_sui() {
    let ctx = sui_ctx();
    let v = evaluate("chainId == \"mainnet\"", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(v, "sui chainId is the bare network name");
}

// ── network identifier ───────────────────────────────────────────────────────

#[tokio::test]
async fn network_resolves_to_full_prefixed_string() {
    let ctx = svm_ctx();
    let v = evaluate(
        "network == \"svm:mainnet-beta\"",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(v, "network identifier exposes the family-prefixed string");
}

#[tokio::test]
async fn network_starts_with_family_prefix() {
    let ctx = sui_ctx();
    let v = evaluate("startswith(network, 'sui:')", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(v);
}

// ── SVM chain_fields ─────────────────────────────────────────────────────────

#[tokio::test]
async fn svm_accounts_indexed_access() {
    let ctx = svm_ctx();
    let v = evaluate(
        "accounts[1] == \"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA\"",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(v, "accounts[1] resolves through chain_fields");
}

#[tokio::test]
async fn svm_accounts_in_list() {
    let ctx = svm_ctx();
    let v = evaluate(
        "accounts[1] in ['TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA']",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(v, "accounts[N] works with `in`");
}

#[tokio::test]
async fn svm_accounts_length() {
    let ctx = svm_ctx();
    let v = evaluate("accounts.length == 3", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(v, "accounts.length works via list traversal");
}

#[tokio::test]
async fn svm_instruction_index_number() {
    let ctx = svm_ctx();
    let v = evaluate(
        "instruction_index == 0 and num_instructions == 1",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(v);
}

#[tokio::test]
async fn svm_unknown_index_evaluates_false_not_error() {
    let ctx = svm_ctx();
    let v = evaluate(
        "accounts[9] == \"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\"",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(!v, "out-of-range index compares false, no panic");
}

// ── Sui chain_fields ─────────────────────────────────────────────────────────

#[tokio::test]
async fn sui_type_arguments_membership() {
    let ctx = sui_ctx();
    let v = evaluate(
        "type_arguments[0] == \"0x2::sui::SUI\"",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(v);
}

#[tokio::test]
async fn sui_command_fields() {
    let ctx = sui_ctx();
    let v = evaluate(
        "command_index == 0 and command_kind == 'MoveCall'",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(v);
}

#[tokio::test]
async fn sui_gas_budget_arith() {
    let ctx = sui_ctx();
    let v = evaluate("gas_budget > 1000000", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(v);
}

#[tokio::test]
async fn svm_missing_chain_field_is_null_not_error() {
    let ctx = EvalContext {
        network: "svm:mainnet-beta".to_string(),
        ..Default::default()
    };
    let v = evaluate("accounts.length == 0", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(
        !v,
        "missing chain field evaluates Null; comparison is false"
    );
}

#[tokio::test]
async fn evm_context_has_no_chain_fields() {
    let ctx = EvalContext {
        chain_id: 1,
        ..Default::default()
    };
    let v = evaluate("accounts.length == 0", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(!v, "EVM context never exposes SVM/Sui fields");
}
