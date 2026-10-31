//! Validation-level tests for per-family semantic analysis: context-field
//! profiles, address-literal rules, and Anchor/Move param type names.

use std::collections::HashMap;
use weituo_expr::analyze::Family;
use weituo_expr::{validate_full, validate_full_for};

const BUILTINS: &[&str] = &["eth_getBalance", "sui_getBalance", "getBalance"];

fn svm_types() -> HashMap<String, String> {
    HashMap::from([
        ("to".to_string(), "pubkey".to_string()),
        ("lamports".to_string(), "u64".to_string()),
    ])
}

fn sui_types() -> HashMap<String, String> {
    HashMap::from([
        ("recipient".to_string(), "address".to_string()),
        ("amount".to_string(), "U64".to_string()),
    ])
}

// ── EVM regression: legacy profile unchanged ─────────────────────────────────

#[test]
fn evm_still_rejects_unknown_context_field() {
    let errs = validate_full(
        "accounts[1] == 5",
        &[],
        BUILTINS,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert!(!errs.is_empty(), "EVM family must not accept `accounts`");
}

#[test]
fn evm_accepts_classic_fields() {
    let errs = validate_full(
        "from_address == \"0x1111111111111111111111111111111111111111\" and gasLimit > 21000",
        &[],
        BUILTINS,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert!(errs.is_empty(), "unexpected: {errs:?}");
}

// ── SVM profile ──────────────────────────────────────────────────────────────

#[test]
fn svm_accepts_accounts_and_instruction_fields() {
    let errs = validate_full_for(
        "accounts[1] == vars.PROGRAM and instruction_index < num_instructions",
        Family::Svm,
        &[],
        BUILTINS,
        &HashMap::new(),
        &HashMap::from([(
            "PROGRAM".to_string(),
            serde_json::json!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        )]),
    );
    assert!(errs.is_empty(), "unexpected: {errs:?}");
}

#[test]
fn svm_rejects_evm_only_fields() {
    for expr in ["gasLimit > 21000", "gasPrice > 0", "value > 0"] {
        let errs = validate_full_for(
            expr,
            Family::Svm,
            &[],
            BUILTINS,
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(!errs.is_empty(), "`{expr}` must be rejected on SVM");
    }
}

#[test]
fn svm_chain_id_is_string() {
    let errs = validate_full_for(
        "chainId == \"mainnet-beta\"",
        Family::Svm,
        &[],
        BUILTINS,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert!(
        errs.is_empty(),
        "chainId == \"mainnet-beta\" must type-check: {errs:?}"
    );

    let errs = validate_full_for(
        "chainId == 1",
        Family::Svm,
        &[],
        BUILTINS,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert!(!errs.is_empty(), "numeric chainId must be rejected on SVM");
}

#[test]
fn svm_pubkey_param_validates_base58_literals() {
    let errs = validate_full_for(
        "args.to == \"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\"",
        Family::Svm,
        &["to"],
        BUILTINS,
        &svm_types(),
        &HashMap::new(),
    );
    assert!(errs.is_empty(), "valid base58 pubkey must pass: {errs:?}");
}

#[test]
fn svm_pubkey_param_rejects_hex_literal() {
    let errs = validate_full_for(
        "args.to == \"0x1111111111111111111111111111111111111111\"",
        Family::Svm,
        &["to"],
        BUILTINS,
        &svm_types(),
        &HashMap::new(),
    );
    assert!(
        !errs.is_empty(),
        "hex literal must be rejected for pubkey param"
    );
}

#[test]
fn svm_u64_param_rejects_string_literal() {
    let errs = validate_full_for(
        "args.lamports == \"1000\"",
        Family::Svm,
        &["lamports"],
        BUILTINS,
        &svm_types(),
        &HashMap::new(),
    );
    assert!(
        !errs.is_empty(),
        "string literal must be rejected for u64 param"
    );
}

// ── Sui profile ──────────────────────────────────────────────────────────────

#[test]
fn sui_accepts_command_and_type_argument_fields() {
    let errs = validate_full_for(
        "command_index == 0 and type_arguments[0] == \"0x2::sui::SUI\" and gas_budget > 0",
        Family::Sui,
        &[],
        BUILTINS,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert!(errs.is_empty(), "unexpected: {errs:?}");
}

#[test]
fn sui_rejects_evm_only_fields() {
    for expr in ["gasLimit > 21000", "value > 0"] {
        let errs = validate_full_for(
            expr,
            Family::Sui,
            &[],
            BUILTINS,
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(!errs.is_empty(), "`{expr}` must be rejected on Sui");
    }
}

#[test]
fn sui_address_requires_full_64_nibble_form() {
    let errs = validate_full_for(
        "args.recipient == \"0x2\"",
        Family::Sui,
        &["recipient"],
        BUILTINS,
        &sui_types(),
        &HashMap::new(),
    );
    assert!(
        !errs.is_empty(),
        "short hex literal must be rejected for address param"
    );

    let errs = validate_full_for(
        "args.recipient == \"0xaaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000\"",
        Family::Sui,
        &["recipient"],
        BUILTINS,
        &sui_types(),
        &HashMap::new(),
    );
    assert!(
        errs.is_empty(),
        "full 64-nibble literal must pass: {errs:?}"
    );
}

#[test]
fn sui_u64_param_accepts_number_literal() {
    let errs = validate_full_for(
        "args.amount == 1000",
        Family::Sui,
        &["amount"],
        BUILTINS,
        &sui_types(),
        &HashMap::new(),
    );
    assert!(errs.is_empty(), "unexpected: {errs:?}");
}

#[test]
fn sui_move_struct_param_type_checks_as_string() {
    let types = HashMap::from([(
        "coin".to_string(),
        "0x2::coin::Coin<0x2::sui::SUI>".to_string(),
    )]);
    let errs = validate_full_for(
        "vars.EXPECTED == args.coin",
        Family::Sui,
        &["coin"],
        BUILTINS,
        &types,
        &HashMap::from([(
            "EXPECTED".to_string(),
            serde_json::json!("0x2::coin::Coin<0x2::sui::SUI>"),
        )]),
    );
    assert!(errs.is_empty(), "unexpected: {errs:?}");
}
