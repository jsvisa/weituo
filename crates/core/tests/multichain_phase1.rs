//! Phase 1 (foundations) tests: `ChainRef` / `ChainTx` / `ChainResolver` /
//! `CompatResolver`, `check` ≡ `check_tx(Evm(tx))` equivalence, the JSON
//! `chain` discriminator, and the YAML `chain:` rule key.

use std::collections::HashMap;
use weituo_core::chain::{ChainRef, ChainResolver, ChainTx, CompatResolver};
use weituo_core::checker::{CheckResult, Checker};
use weituo_core::policy::Policy;
use weituo_core::provider::{ChainInfo, RuleResolver, StaticResolver};
use weituo_core::static_loader::load_multi;
use weituo_core::types::{AbiItem, ExprValue, RuleClause, RuleEntry, Transaction};

const TOKEN: &str = "0xdac17f958d2ee523a2206206994597c13d831ec7";
const SENDER: &str = "0x1111111111111111111111111111111111111111";
const SPENDER: &str = "2222222222222222222222222222222222222222";

fn approve_tx() -> Transaction {
    serde_json::from_value(serde_json::json!({
        "chainId": 1, "from": SENDER, "to": TOKEN,
        "data": format!("0x095ea7b3{SPENDER:0>64}{:0>64}", "1"), "value": 0,
    }))
    .unwrap()
}

fn approve_rule(expr: &str) -> RuleEntry {
    let abi: AbiItem = serde_json::from_value(serde_json::json!({
        "type": "function", "name": "approve",
        "inputs": [
            { "name": "spender", "type": "address" },
            { "name": "amount", "type": "uint256" }
        ],
        "outputs": []
    }))
    .unwrap();
    RuleEntry {
        clauses: vec![RuleClause {
            expr: ExprValue::Single(expr.into()),
            vars: HashMap::new(),
        }],
        abi_item: Some(abi),
        family_abi: None,
        multicall: None,
        invalid_decoder: false,
    }
}

fn approve_resolver(rules: HashMap<(u64, String), HashMap<String, RuleEntry>>) -> StaticResolver {
    StaticResolver::new(
        rules,
        HashMap::from([(
            1u64,
            ChainInfo {
                rpc_url: String::new(),
            },
        )]),
    )
}

fn result_code(r: &CheckResult) -> String {
    match r {
        CheckResult::Ok => "ok".to_string(),
        CheckResult::Denied(reason) => format!("{}:{}", reason.code(), reason),
    }
}

// ── ChainRef ─────────────────────────────────────────────────────────────────

#[test]
fn chain_ref_from_u64_is_evm() {
    assert_eq!(ChainRef::from(137u64), ChainRef::Evm(137));
}

#[test]
fn chain_ref_network_rendering() {
    assert_eq!(ChainRef::Evm(1).to_family_network(), "eip155:1");
    assert_eq!(
        ChainRef::Svm("mainnet-beta".into()).to_family_network(),
        "svm:mainnet-beta"
    );
    assert_eq!(
        ChainRef::Sui("mainnet".into()).to_family_network(),
        "sui:mainnet"
    );
}

#[test]
fn chain_ref_usable_as_map_key() {
    let mut m = HashMap::new();
    m.insert(ChainRef::Evm(1), "evm");
    m.insert(ChainRef::Svm("mainnet-beta".into()), "svm");
    assert_eq!(m[&ChainRef::from(1u64)], "evm");
    assert_eq!(m[&ChainRef::Svm("mainnet-beta".into())], "svm");
}

// ── CompatResolver ───────────────────────────────────────────────────────────

#[tokio::test]
async fn compat_resolver_delegates_evm_and_fails_closed_otherwise() {
    let resolver = approve_resolver(HashMap::from([(
        (1u64, TOKEN.to_string()),
        HashMap::from([("0x095ea7b3".to_string(), approve_rule("true"))]),
    )]));
    let compat = CompatResolver(&resolver);

    assert!(
        compat
            .contract_rules(ChainRef::Evm(1), TOKEN)
            .await
            .is_some(),
        "Evm(1) delegates to the wrapped RuleResolver"
    );
    assert!(
        compat
            .contract_rules(ChainRef::Svm("mainnet-beta".into()), "prog")
            .await
            .is_none(),
        "Svm lookups fail closed"
    );
    assert!(
        compat
            .contract_rules(ChainRef::Sui("mainnet".into()), "pkg")
            .await
            .is_none(),
        "Sui lookups fail closed"
    );
    assert_eq!(
        compat.chain_rpc_url(ChainRef::Evm(1)),
        RuleResolver::chain_rpc_url(&resolver, 1)
    );
    assert_eq!(compat.chain_rpc_url(ChainRef::Sui("mainnet".into())), None);
}

// ── check ≡ check_tx(Evm(tx)) ────────────────────────────────────────────────

#[tokio::test]
async fn check_tx_denial_matches_check() {
    let rule = approve_rule("args.spender == from");
    let resolver = approve_resolver(HashMap::from([(
        (1u64, TOKEN.to_string()),
        HashMap::from([("0x095ea7b3".to_string(), rule)]),
    )]));
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), Policy::default());
    let tx = approve_tx();

    let via_check = checker.check(&tx, &resolver).await;
    let via_check_tx = checker
        .check_tx(&ChainTx::Evm(tx.clone()), &CompatResolver(&resolver))
        .await;

    assert!(
        matches!(via_check, CheckResult::Denied(_)),
        "expected denial via check"
    );
    assert_eq!(
        result_code(&via_check),
        result_code(&via_check_tx),
        "check_tx(Evm) must agree with check"
    );
}

#[tokio::test]
async fn check_tx_pass_matches_check() {
    let rule = approve_rule("args.spender == from");
    let resolver = approve_resolver(HashMap::from([(
        (1u64, TOKEN.to_string()),
        HashMap::from([("0x095ea7b3".to_string(), rule)]),
    )]));
    let checker = Checker::new(
        reqwest::Client::new(),
        vec![SENDER.to_string()],
        Policy::default(),
    );
    let tx = approve_tx();

    let via_check = checker.check(&tx, &resolver).await;
    let via_check_tx = checker
        .check_tx(&ChainTx::Evm(tx.clone()), &CompatResolver(&resolver))
        .await;

    assert!(matches!(via_check, CheckResult::Ok), "allowlist → Ok");
    assert_eq!(result_code(&via_check), result_code(&via_check_tx));
}

#[tokio::test]
async fn evm_rules_can_reference_network_identifier() {
    // `network == "eip155:1"` must pass through both entry points — proves
    // EvalContext.network is populated on the unified path.
    let rule = approve_rule("args.spender == from and network == 'eip155:1'");
    let resolver = approve_resolver(HashMap::from([(
        (1u64, TOKEN.to_string()),
        HashMap::from([("0x095ea7b3".to_string(), rule)]),
    )]));
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), Policy::default());
    let tx = approve_tx();

    // Denies because spender != from — but reaching ExpressionDenied (not
    // EvalError) proves `network` resolved without error.
    for result in [
        checker.check(&tx, &resolver).await,
        checker
            .check_tx(&ChainTx::Evm(tx.clone()), &CompatResolver(&resolver))
            .await,
    ] {
        match result {
            CheckResult::Denied(reason) => assert_eq!(reason.code(), -32603),
            CheckResult::Ok => panic!("expected ExpressionDenied"),
        }
    }

    // And a rule that matches the actual sender passes via check_tx too.
    let rule = approve_rule("network == 'eip155:1' and from != to_address");
    let resolver = approve_resolver(HashMap::from([(
        (1u64, TOKEN.to_string()),
        HashMap::from([("0x095ea7b3".to_string(), rule)]),
    )]));
    let result = checker
        .check_tx(&ChainTx::Evm(tx.clone()), &CompatResolver(&resolver))
        .await;
    assert!(
        matches!(result, CheckResult::Ok),
        "{}",
        result_code(&result)
    );
}

// ── test ≡ test_tx(Evm(tx)) ──────────────────────────────────────────────────

#[tokio::test]
async fn test_tx_matches_test() {
    let checker = Checker::new(reqwest::Client::new(), Vec::new(), Policy::default());
    let mut tx = approve_tx();
    tx.expr = Some("args.spender == '0x2222222222222222222222222222222222222222'".into());
    tx.abi = Some(
        serde_json::from_value(serde_json::json!({
            "type": "function", "name": "approve",
            "inputs": [
                { "name": "spender", "type": "address" },
                { "name": "amount", "type": "uint256" }
            ],
            "outputs": []
        }))
        .unwrap(),
    );

    let via_test = checker.test(&tx, None).await;
    let via_test_tx = checker.test_tx(&ChainTx::Evm(tx.clone()), None).await;

    assert_eq!(
        result_code(&via_test),
        result_code(&via_test_tx),
        "test_tx(Evm) must agree with test"
    );
}

// ── JSON wire: chain discriminator ───────────────────────────────────────────

#[test]
fn from_json_absent_chain_is_legacy_evm() {
    let v = serde_json::json!({
        "chainId": 1, "from": SENDER, "to": TOKEN, "data": "0x095ea7b3", "value": 0
    });
    let tx = ChainTx::from_json(&v).unwrap();
    match tx {
        ChainTx::Evm(t) => {
            assert_eq!(t.chain_id, 1);
            assert_eq!(t.to, TOKEN);
        }
        _ => panic!("expected Evm"),
    }
}

#[test]
fn from_json_explicit_evm_chain() {
    let v = serde_json::json!({
        "chain": "evm", "chainId": "0x1", "from": SENDER, "to": TOKEN,
        "data": "0x095ea7b3", "value": 0
    });
    let tx = ChainTx::from_json(&v).unwrap();
    match tx {
        ChainTx::Evm(t) => assert_eq!(t.chain_id, 1),
        _ => panic!("expected Evm"),
    }
}

#[test]
fn from_json_missing_required_evm_fields_fails_closed() {
    // An instructions-shaped payload without `chain` must fail the EVM parser
    // (missing chainId/to/data) — never silently allowed.
    let v = serde_json::json!({
        "from": SENDER,
        "instructions": []
    });
    assert!(ChainTx::from_json(&v).is_err());
}

#[test]
fn from_json_unknown_chain_rejected() {
    let v = serde_json::json!({ "chain": "cosmos", "chainId": "cosmoshub-4" });
    let err = ChainTx::from_json(&v).unwrap_err();
    assert!(
        err.to_lowercase().contains("chain"),
        "error should mention the chain problem: {err}"
    );
}

// ── ChainResolver over StaticResolver ────────────────────────────────────────

#[tokio::test]
async fn static_resolver_answers_chain_resolver_lookups() {
    let resolver = approve_resolver(HashMap::from([(
        (1u64, TOKEN.to_string()),
        HashMap::from([("0x095ea7b3".to_string(), approve_rule("true"))]),
    )]));
    assert!(
        ChainResolver::contract_rules(&resolver, ChainRef::Evm(1), TOKEN)
            .await
            .is_some()
    );
    assert!(
        ChainResolver::contract_rules(&resolver, ChainRef::Evm(2), TOKEN)
            .await
            .is_none(),
        "different chain → None"
    );
}

// ── YAML chain key ───────────────────────────────────────────────────────────

#[test]
fn load_multi_legacy_chain_id_key_yields_evm_keys() {
    let dir = std::env::temp_dir().join(format!("weituo_p1_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let yaml = format!(
        r#"
contracts:
  - chain_id: 1
    address: "{TOKEN}"
    allowlist:
      - func: "approve(address,uint256)"
        expr: "args.spender == from"
"#
    );
    let yaml_path = dir.join("waf.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();

    let (chains, contracts) = load_multi(yaml_path.to_str().unwrap(), dir.to_str().unwrap(), 1)
        .expect("load_multi must parse legacy chain_id yaml");
    assert!(chains.contains_key(&ChainRef::Evm(1)));
    let rules = contracts
        .get(&(ChainRef::Evm(1), TOKEN.to_string()))
        .expect("rules keyed under (Evm(1), lowercase address)");
    assert!(rules.contains_key("0x095ea7b3"));
}

#[test]
fn load_multi_svm_and_sui_chain_keys() {
    let dir = std::env::temp_dir().join(format!("weituo_p1b_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let yaml = r#"
contracts:
  - chain: "svm:mainnet-beta"
    address: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
    allowlist:
      - func: "0x0c"
        expr: "true"
  - chain: "sui:mainnet"
    address: "0x2"
    allowlist:
      - func: "pay::split"
        expr: "true"
"#;
    let yaml_path = dir.join("waf.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();

    let (chains, contracts) = load_multi(yaml_path.to_str().unwrap(), dir.to_str().unwrap(), 1)
        .expect("load_multi must parse chain: yaml");

    assert!(chains.contains_key(&ChainRef::Svm("mainnet-beta".into())));
    assert!(chains.contains_key(&ChainRef::Sui("mainnet".into())));

    // SVM: base58 address is case-sensitive — stored verbatim, hex func verbatim.
    let svm = contracts
        .get(&(
            ChainRef::Svm("mainnet-beta".into()),
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string(),
        ))
        .expect("svm contract keyed by verbatim program id");
    assert!(
        svm.contains_key("0x0c"),
        "hex func stored verbatim, got {:?}",
        svm.keys().collect::<Vec<_>>()
    );

    // Sui: "module::function" selector, lowercased; address normalized to
    // the full 64-nibble hex form at load time.
    let sui = contracts
        .get(&(
            ChainRef::Sui("mainnet".into()),
            "0x0000000000000000000000000000000000000000000000000000000000000002".to_string(),
        ))
        .expect("sui contract keyed by normalized package");
    assert!(
        sui.contains_key("pay::split"),
        "sui selector is module::function, got {:?}",
        sui.keys().collect::<Vec<_>>()
    );
}

#[test]
fn load_multi_mixed_chains_and_legacy_load_still_works() {
    let dir = std::env::temp_dir().join(format!("weituo_p1c_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let yaml = format!(
        r#"
contracts:
  - chain_id: 137
    address: "{TOKEN}"
    allowlist:
      - func: "approve(address,uint256)"
        expr: "true"
  - chain: "sui:mainnet"
    address: "0x2"
    allowlist:
      - func: "pay::split"
        expr: "true"
"#
    );
    let yaml_path = dir.join("waf.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();

    let (chains, contracts) =
        load_multi(yaml_path.to_str().unwrap(), dir.to_str().unwrap(), 1).unwrap();
    assert!(chains.contains_key(&ChainRef::Evm(137)));
    assert!(chains.contains_key(&ChainRef::Sui("mainnet".into())));
    assert!(contracts.contains_key(&(ChainRef::Evm(137), TOKEN.to_string())));

    // Legacy `load` keeps its signature: EVM entries survive, non-EVM skipped.
    let (chains, contracts) =
        weituo_core::static_loader::load(yaml_path.to_str().unwrap(), dir.to_str().unwrap(), 1)
            .unwrap();
    assert!(chains.contains_key(&137));
    assert!(contracts.contains_key(&(137u64, TOKEN.to_string())));
}
