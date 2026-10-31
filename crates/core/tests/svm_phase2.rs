//! Phase 2 (SVM, feature `svm`) golden vectors: System::Transfer, SPL
//! TransferChecked/ApproveChecked, an Anchor call with the discriminator
//! computed in-test, policy gates, and fail-closed decoding.
//!
//! Accounts arrive **pre-resolved** in the fixtures — core never sees ALT
//! indexes, so these tests pin the resolved-list contract.

#![cfg(feature = "svm")]

use std::collections::HashMap;
use weituo_core::chain::{ChainRef, ChainTx};
use weituo_core::checker::{CheckResult, Checker};
use weituo_core::policy::{Policy, TokenOpPolicy};
use weituo_core::provider::{ChainInfo, StaticResolver};
use weituo_core::static_loader::load_multi;
use weituo_core::svm::{decode_svm_args, SvmTx};
use weituo_core::types::{FamilyAbi, RuleEntry};

// Well-known programs
const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

// Fixture pubkeys (valid 32-byte base58)
const PAYER: &str = "67vHA8qZGCJKw1UNGUJZME4MwEWDRGWzp7MGvsut43A8";
const SOURCE: &str = "5Rtvwg6C7fnCFDSaLQmQJYp8kvVxLVeubPTN8o4yapQc";
const DEST: &str = "2yeKnh4vA5Tih3k7mF4kBpSCnEecpgbHUF7AohQo9LYB";
const MINT: &str = "FqUwnBMN1shpeqKVm7W5fN73tvrjVr19TQFFgkoFFzhq";
const PROGRAM: &str = "FnzeQN2vn5dwvipbm16xiQF74bzkfJCfTVNPNyja6WTc";

fn svm_tx(instructions: serde_json::Value) -> SvmTx {
    let mut v = serde_json::json!({
        "chain": "svm",
        "chainId": "mainnet-beta",
        "from": PAYER,
    });
    v["instructions"] = instructions;
    SvmTx::from_json(&v).unwrap()
}

fn rule_entry(
    svm_abi: Option<serde_json::Value>,
    expr: &str,
    vars: serde_json::Value,
) -> RuleEntry {
    use weituo_core::types::{ExprValue, FamilyAbi, RuleClause};
    RuleEntry {
        clauses: vec![RuleClause {
            expr: ExprValue::Single(expr.into()),
            vars: serde_json::from_value(vars).unwrap_or_default(),
        }],
        abi_item: None,
        family_abi: svm_abi.and_then(FamilyAbi::from_svm_json),
        multicall: None,
        invalid_decoder: false,
    }
}

fn resolver_with(key: (ChainRef, &str), selector: &str, entry: RuleEntry) -> StaticResolver {
    let key = (key.0, key.1.to_string());
    StaticResolver::new_multi(
        HashMap::from([(key, HashMap::from([(selector.to_string(), entry)]))]),
        HashMap::from([(
            ChainRef::Svm("mainnet-beta".into()),
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

async fn check(checker: &Checker, tx: &SvmTx, resolver: &StaticResolver) -> CheckResult {
    checker.check_tx(&ChainTx::Svm(tx.clone()), resolver).await
}

// ── JSON wire ────────────────────────────────────────────────────────────────

#[test]
fn from_json_svm_parses_instructions() {
    let v = serde_json::json!({
        "chain": "svm",
        "chainId": "mainnet-beta",
        "from": PAYER,
        "instructions": [
            {
                "programId": SYSTEM,
                "accounts": [PAYER, DEST],
                "data": "3Bxs4Bc3VYuGVB19"
            }
        ]
    });
    let tx = SvmTx::from_json(&v).unwrap();
    assert_eq!(tx.network, "mainnet-beta");
    assert_eq!(tx.from, PAYER);
    assert_eq!(
        tx.signers,
        vec![PAYER.to_string()],
        "signers default to [from]"
    );
    assert_eq!(tx.instructions.len(), 1);
    let ins = &tx.instructions[0];
    assert_eq!(ins.program_id, SYSTEM);
    assert_eq!(ins.accounts, vec![PAYER.to_string(), DEST.to_string()]);
    // base58 data decodes to tag 2 (u32 LE) + 1_000_000 (u64 LE)
    assert_eq!(
        ins.data,
        vec![2u8, 0, 0, 0, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0]
    );
}

#[test]
fn from_json_svm_accepts_hex_data() {
    let v = serde_json::json!({
        "chain": "svm", "chainId": "mainnet-beta", "from": PAYER,
        "instructions": [{"programId": SYSTEM, "accounts": [], "data": "0x0200000040420f0000000000"}]
    });
    let tx = SvmTx::from_json(&v).unwrap();
    assert_eq!(tx.instructions[0].data.len(), 12);
}

#[test]
fn from_json_svm_numeric_chain_id_rejected() {
    let v = serde_json::json!({
        "chain": "svm", "chainId": 101, "from": PAYER, "instructions": []
    });
    let err = SvmTx::from_json(&v).unwrap_err();
    assert!(
        err.contains("chainId"),
        "error should mention chainId: {err}"
    );
}

#[test]
fn from_json_svm_invalid_base58_rejected() {
    let v = serde_json::json!({
        "chain": "svm", "chainId": "mainnet-beta", "from": PAYER,
        "instructions": [{"programId": SYSTEM, "accounts": [], "data": "0OIl-not-base58!"}]
    });
    assert!(
        SvmTx::from_json(&v).is_err(),
        "invalid base58 data fails closed"
    );
}

#[test]
fn from_json_svm_malformed_pubkey_rejected() {
    // Wrong-length pubkey in accounts → fail closed
    let v = serde_json::json!({
        "chain": "svm", "chainId": "mainnet-beta", "from": "short",
        "instructions": [{"programId": SYSTEM, "accounts": [], "data": ""}]
    });
    assert!(SvmTx::from_json(&v).is_err());
}

// ── Discriminator + borsh decode (unit-level) ────────────────────────────────

#[test]
fn anchor_discriminator_matches_sha256_global_snake() {
    use weituo_core::svm::anchor_discriminator;
    // sha256("global:swap")[..8] — computed independently for this vector
    assert_eq!(
        anchor_discriminator("swap"),
        vec![0xf8, 0xc6, 0x9e, 0x91, 0xe1, 0x75, 0x87, 0xc8]
    );
}

#[test]
fn decode_svm_args_strips_and_decodes() {
    // TransferChecked layout after the 1-byte tag: amount u64 LE + decimals u8
    let abi = FamilyAbi::from_svm_json(serde_json::json!({
        "name": "0x0c",
        "args": [
            {"name": "amount", "type": "u64"},
            {"name": "decimals", "type": "u8"}
        ]
    }))
    .unwrap();
    let data = vec![12u8, 0x60, 0xe3, 0x16, 0, 0, 0, 0, 0, 6];
    let args = decode_svm_args(&abi, "0x0c", &data).unwrap();
    assert_eq!(args["amount"], serde_json::json!("1500000"));
    assert_eq!(args["decimals"], serde_json::json!("6"));
}

// ── Golden vector: native SOL transfer ───────────────────────────────────────

#[tokio::test]
async fn native_transfer_allowed_by_policy() {
    let checker = Checker::new(
        reqwest::Client::new(),
        Vec::new(),
        Policy {
            allow_native_transfer: true,
            ..Default::default()
        },
    );
    let tx = svm_tx(serde_json::json!([{
        "programId": SYSTEM, "accounts": [PAYER, DEST], "data": "3Bxs4Bc3VYuGVB19"
    }]));
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );
}

#[tokio::test]
async fn native_transfer_rule_gates_amount_and_recipient() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let tx = svm_tx(serde_json::json!([{
        "programId": SYSTEM, "accounts": [PAYER, DEST], "data": "3Bxs4Bc3VYuGVB19"
    }]));
    // System::Transfer tag is a u32 LE — the func prefix is the full 4 bytes.
    let resolver = resolver_with(
        (ChainRef::Svm("mainnet-beta".into()), SYSTEM),
        "0x02000000",
        rule_entry(
            Some(serde_json::json!({
                "name": "0x02000000",
                "args": [{"name": "lamports", "type": "u64"}]
            })),
            "accounts[1] == vars.recipient and args.lamports <= vars.max",
            serde_json::json!({"recipient": DEST, "max": "1000000"}),
        ),
    );
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );

    // Same rule, amount over the cap → denied
    let resolver = resolver_with(
        (ChainRef::Svm("mainnet-beta".into()), SYSTEM),
        "0x02000000",
        rule_entry(
            Some(serde_json::json!({
                "name": "0x02000000",
                "args": [{"name": "lamports", "type": "u64"}]
            })),
            "args.lamports <= vars.max",
            serde_json::json!({"max": "999999"}),
        ),
    );
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Denied(_)),
        "{}",
        result_code(&result)
    );
}

// ── Golden vector: SPL TransferChecked ───────────────────────────────────────

#[tokio::test]
async fn spl_transfer_checked_rule_checks_accounts_and_amount() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let tx = svm_tx(serde_json::json!([{
        "programId": TOKEN_PROGRAM,
        "accounts": [SOURCE, MINT, DEST, PAYER],
        "data": "hLUbXd2WXhY69"
    }]));
    let resolver = resolver_with(
        (ChainRef::Svm("mainnet-beta".into()), TOKEN_PROGRAM),
        "0x0c",
        rule_entry(
            Some(serde_json::json!({
                "name": "0x0c",
                "args": [
                    {"name": "amount", "type": "u64"},
                    {"name": "decimals", "type": "u8"}
                ]
            })),
            "accounts[1] == vars.mint and accounts[2] in vars.wallets and args.amount <= vars.max",
            serde_json::json!({"mint": MINT, "wallets": [DEST, PAYER], "max": "1500000"}),
        ),
    );
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );
}

#[tokio::test]
async fn spl_approve_checked_wrong_destination_denied() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    // ApproveChecked: tag 13 + amount u64 (500) + decimals u8 (6)
    let tx = svm_tx(serde_json::json!([{
        "programId": TOKEN_PROGRAM,
        "accounts": [SOURCE, MINT, DEST, PAYER],
        "data": "nU5nZnj1ZA4Ah"
    }]));
    let resolver = resolver_with(
        (ChainRef::Svm("mainnet-beta".into()), TOKEN_PROGRAM),
        "0x0d",
        rule_entry(
            Some(serde_json::json!({
                "name": "0x0d",
                "args": [
                    {"name": "amount", "type": "u64"},
                    {"name": "decimals", "type": "u8"}
                ]
            })),
            "accounts[1] == vars.mint and args.amount <= vars.max",
            serde_json::json!({"mint": DEST, "max": "1000"}),
        ),
    );
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Denied(_)),
        "mint mismatch must deny: {}",
        result_code(&result)
    );
}

// ── Golden vector: Anchor program call ───────────────────────────────────────

#[tokio::test]
async fn anchor_call_with_computed_discriminator() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    // swap(amount: u64) — discriminator sha256("global:swap")[..8] + 2_000_000 u64 LE
    let tx = svm_tx(serde_json::json!([{
        "programId": PROGRAM,
        "accounts": [PAYER, SOURCE, DEST],
        "data": "0xf8c69e91e17587c880841e0000000000"
    }]));
    let resolver = resolver_with(
        (ChainRef::Svm("mainnet-beta".into()), PROGRAM),
        "0xf8c69e91e17587c8",
        rule_entry(
            Some(serde_json::json!({
                "name": "swap",
                "args": [{"name": "amount", "type": "u64"}]
            })),
            "args.amount <= vars.max_notional and accounts.length == 3 and instruction_index == 0",
            serde_json::json!({"max_notional": "2000000"}),
        ),
    );
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "rule keyed by discriminator must match the hex data prefix: {}",
        result_code(&result)
    );
}

// ── Multi-instruction semantics ──────────────────────────────────────────────

#[tokio::test]
async fn every_instruction_is_checked_and_indexed() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let tx = svm_tx(serde_json::json!([
        {"programId": SYSTEM, "accounts": [PAYER, DEST], "data": "3Bxs4Bc3VYuGVB19"},
        {"programId": TOKEN_PROGRAM, "accounts": [SOURCE, MINT, DEST, PAYER], "data": "hLUbXd2WXhY69"}
    ]));
    // Only the System instruction has a rule — the SPL instruction denies.
    let resolver = resolver_with(
        (ChainRef::Svm("mainnet-beta".into()), SYSTEM),
        "0x02000000",
        rule_entry(
            Some(serde_json::json!({
                "name": "0x02000000",
                "args": [{"name": "lamports", "type": "u64"}]
            })),
            "args.lamports <= vars.max",
            serde_json::json!({"max": "1000000"}),
        ),
    );
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => {
            let msg = reason.to_string();
            assert!(
                msg.contains("instruction[1]"),
                "denial must carry the instruction index: {msg}"
            );
        }
        CheckResult::Ok => panic!("second instruction must be denied"),
    }
}

// ── Policy gates ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn spl_token_op_deny_all_policy() {
    let checker = Checker::new(
        reqwest::Client::new(),
        Vec::new(),
        Policy {
            token_op_policy: TokenOpPolicy::DenyAll,
            ..Default::default()
        },
    );
    let tx = svm_tx(serde_json::json!([{
        "programId": TOKEN_PROGRAM,
        "accounts": [SOURCE, MINT, DEST, PAYER],
        "data": "hLUbXd2WXhY69"
    }]));
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32604),
        CheckResult::Ok => panic!("DenyAll token policy must deny SPL transfer"),
    }
}

#[tokio::test]
async fn spl_token_op_allow_all_policy() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), Policy::default());
    let tx = svm_tx(serde_json::json!([{
        "programId": TOKEN_PROGRAM,
        "accounts": [SOURCE, MINT, DEST, PAYER],
        "data": "hLUbXd2WXhY69"
    }]));
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );
}

#[tokio::test]
async fn allowlisted_sender_bypasses_svm_checks() {
    let checker = Checker::new(reqwest::Client::new(), vec![PAYER.to_string()], strict());
    let tx = svm_tx(serde_json::json!([{
        "programId": TOKEN_PROGRAM,
        "accounts": [SOURCE, MINT, DEST, PAYER],
        "data": "hLUbXd2WXhY69"
    }]));
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    assert!(matches!(result, CheckResult::Ok));
}

#[tokio::test]
async fn token_2022_is_a_token_program_too() {
    let checker = Checker::new(
        reqwest::Client::new(),
        Vec::new(),
        Policy {
            token_op_policy: TokenOpPolicy::DenyAll,
            ..Default::default()
        },
    );
    let tx = svm_tx(serde_json::json!([{
        "programId": TOKEN_2022,
        "accounts": [SOURCE, MINT, DEST, PAYER],
        "data": "hLUbXd2WXhY69"
    }]));
    let resolver = StaticResolver::new_multi(HashMap::new(), HashMap::new());
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32604),
        CheckResult::Ok => panic!("Token-2022 transfers are token ops"),
    }
}

// ── Fail-closed decoding ─────────────────────────────────────────────────────

#[tokio::test]
async fn truncated_borsh_fails_closed() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    // Tag + only 4 of the 8 lamport bytes
    let tx = svm_tx(serde_json::json!([{
        "programId": SYSTEM, "accounts": [PAYER, DEST], "data": "0x0200000040420f00"
    }]));
    let resolver = resolver_with(
        (ChainRef::Svm("mainnet-beta".into()), SYSTEM),
        "0x02000000",
        rule_entry(
            Some(serde_json::json!({
                "name": "0x02000000",
                "args": [{"name": "lamports", "type": "u64"}]
            })),
            "args.lamports <= vars.max",
            serde_json::json!({"max": "1000000"}),
        ),
    );
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(
            reason.code(),
            -32500,
            "args missing → expression errors → EvalError deny: {reason}"
        ),
        CheckResult::Ok => panic!("truncated payload must not pass"),
    }
}

#[tokio::test]
async fn unresolvable_defined_type_fails_closed() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let tx = svm_tx(serde_json::json!([{
        "programId": PROGRAM,
        "accounts": [PAYER, SOURCE, DEST],
        "data": "0xf8c69e91e17587c880841e0000000000"
    }]));
    let resolver = resolver_with(
        (ChainRef::Svm("mainnet-beta".into()), PROGRAM),
        "0xf8c69e91e17587c8",
        rule_entry(
            Some(serde_json::json!({
                "name": "swap",
                "args": [{"name": "params", "type": {"defined": {"name": "SwapParams"}}}]
            })),
            "args.params.amount <= vars.max",
            serde_json::json!({"max": "1000"}),
        ),
    );
    let result = check(&checker, &tx, &resolver).await;
    match result {
        CheckResult::Denied(reason) => assert_eq!(reason.code(), -32500),
        CheckResult::Ok => panic!("unresolvable IDL type must not pass"),
    }
}

// ── Load-time validation ─────────────────────────────────────────────────────

#[test]
fn svm_rule_using_evm_only_builtin_fails_at_load() {
    let dir = std::env::temp_dir().join(format!("weituo_svm_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let yaml = format!(
        r#"
contracts:
  - chain: "svm:mainnet-beta"
    address: "{SYSTEM}"
    allowlist:
      - func: "0x02000000"
        abi: {{ name: "0x02000000", args: [{{name: "lamports", type: "u64"}}] }}
        expr: "$erc20_balance_of(accounts[1], accounts[1]) > 0"
"#
    );
    let yaml_path = dir.join("waf.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();
    let (_, contracts) = load_multi(yaml_path.to_str().unwrap(), dir.to_str().unwrap(), 1).unwrap();
    let rules = contracts
        .get(&(ChainRef::Svm("mainnet-beta".into()), SYSTEM.to_string()))
        .expect("svm contract present");
    assert!(
        rules.is_empty(),
        "rule referencing $erc20_* on SVM must be rejected at load, got {:?}",
        rules.keys().collect::<Vec<_>>()
    );
}

#[test]
fn svm_rule_with_valid_expr_loads() {
    let dir = std::env::temp_dir().join(format!("weituo_svm2_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let yaml = format!(
        r#"
contracts:
  - chain: "svm:mainnet-beta"
    address: "{SYSTEM}"
    allowlist:
      - func: "0x02000000"
        abi: {{ name: "0x02000000", args: [{{name: "lamports", type: "u64"}}] }}
        expr: "accounts[1] == vars.r and args.lamports <= vars.max"
        vars:
          r: "{DEST}"
          max: "1000000"
"#
    );
    let yaml_path = dir.join("waf.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();
    let (_, contracts) = load_multi(yaml_path.to_str().unwrap(), dir.to_str().unwrap(), 1).unwrap();
    let rules = contracts
        .get(&(ChainRef::Svm("mainnet-beta".into()), SYSTEM.to_string()))
        .expect("svm contract present");
    assert!(
        rules.contains_key("0x02000000"),
        "valid SVM rule must load with the 4-byte tag key, got {:?}",
        rules.keys().collect::<Vec<_>>()
    );
}

// ── test_tx with inline ABI ──────────────────────────────────────────────────

#[tokio::test]
async fn test_tx_svm_inline_abi() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), strict());
    let mut tx = svm_tx(serde_json::json!([{
        "programId": SYSTEM, "accounts": [PAYER, DEST], "data": "3Bxs4Bc3VYuGVB19"
    }]));
    tx.abi = Some(
        FamilyAbi::from_svm_json(serde_json::json!({
            "name": "0x02000000",
            "args": [{"name": "lamports", "type": "u64"}]
        }))
        .unwrap(),
    );
    tx.expr = Some("args.lamports == 1000000 and accounts[1] == vars.dest".into());
    tx.vars = Some(serde_json::from_value(serde_json::json!({"dest": DEST})).unwrap());
    let result = checker.test_tx(&ChainTx::Svm(tx.clone()), None).await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );

    tx.expr = Some("args.lamports > 999999999".into());
    let result = checker.test_tx(&ChainTx::Svm(tx), None).await;
    assert!(matches!(result, CheckResult::Denied(_)));
}
