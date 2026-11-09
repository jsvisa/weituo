//! Tests for address handling in WAF expressions.
//!
//! ABI type=address decodes to an EIP-55 checksummed string ("0xdAC17F958D2ee523a...").
//!
//! Rules may contain literals in any casing. The evaluator normalises both
//! sides to lowercase for == / != / in / not_in, so case never causes a mismatch.

use std::sync::Arc;
use weituo_expr::context::BuiltinProvider;
use weituo_expr::eval::Value;
use weituo_expr::{evaluate, EvalContext};

// ── Shared constants ──────────────────────────────────────────────────────────

/// USDT contract — EIP-55 checksum
const USDT_CS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
/// USDT contract — lowercase
const USDT_LC: &str = "0xdac17f958d2ee523a2206206994597c13d831ec7";
/// USDT contract — uppercase
const USDT_UC: &str = "0xDAC17F958D2EE523A2206206994597C13D831EC7";

/// Zero address
const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";

/// A typical user address — lowercase (as it comes from tx.from)
const ALICE: &str = "0xca6f3defbc6041299837725f6430f33b0f24e5c0";
const ALICE_CS: &str = "0xCA6F3Defbc6041299837725f6430f33B0F24e5C0";

// ── Mock builtins ─────────────────────────────────────────────────────────────

struct MockBuiltins;

#[async_trait::async_trait]
impl BuiltinProvider for MockBuiltins {
    async fn call(&self, name: &str, _args: &[Value], _ctx: &EvalContext) -> anyhow::Result<Value> {
        Err(anyhow::anyhow!("unhandled mock builtin: ${name}"))
    }
}

fn builtins() -> Arc<dyn BuiltinProvider> {
    Arc::new(MockBuiltins)
}

fn ctx(chain_id: u64, from: &str, to: &str, args: &[(&str, serde_json::Value)]) -> EvalContext {
    let mut c = EvalContext::new(chain_id, from, to);
    for (k, v) in args {
        c.args.insert(k.to_string(), v.clone());
    }
    c
}

async fn check(expr: &str, c: &EvalContext) -> bool {
    evaluate(expr, c, builtins()).await.expect(expr)
}

// ── 1. ABI type=address — decoded as EIP-55 checksummed string ───────────────

#[tokio::test]
async fn abi_address_eq_checksummed_literal() {
    // Rule written with EIP-55 checksum; decoded value is also EIP-55
    let c = ctx(1, ALICE, USDT_LC, &[("to", serde_json::json!(USDT_CS))]);
    assert!(
        check(&format!("args.to == '{USDT_CS}'"), &c).await,
        "checksum == checksum"
    );
}

#[tokio::test]
async fn abi_address_eq_lowercase_literal() {
    // Rule written with lowercase; decoded value is EIP-55 — must still match
    let c = ctx(1, ALICE, USDT_LC, &[("to", serde_json::json!(USDT_CS))]);
    assert!(
        check(&format!("args.to == '{USDT_LC}'"), &c).await,
        "checksum == lowercase"
    );
}

#[tokio::test]
async fn abi_address_eq_uppercase_literal() {
    let c = ctx(1, ALICE, USDT_LC, &[("to", serde_json::json!(USDT_CS))]);
    assert!(
        check(&format!("args.to == '{USDT_UC}'"), &c).await,
        "checksum == uppercase"
    );
}

#[tokio::test]
async fn abi_address_ne_different_address() {
    let c = ctx(1, ALICE, USDT_LC, &[("to", serde_json::json!(USDT_CS))]);
    assert!(
        check(&format!("args.to != '{ALICE}'"), &c).await,
        "different addresses are !="
    );
}

#[tokio::test]
async fn abi_address_in_list_checksummed() {
    let c = ctx(
        1,
        ALICE,
        USDT_LC,
        &[("spender", serde_json::json!(USDT_CS))],
    );
    assert!(check(&format!("args.spender in ['{USDT_CS}', '{ALICE_CS}']"), &c).await);
}

#[tokio::test]
async fn abi_address_in_list_mixed_case() {
    // Rule list has lowercase; decoded is checksummed — must match
    let c = ctx(
        1,
        ALICE,
        USDT_LC,
        &[("spender", serde_json::json!(USDT_CS))],
    );
    assert!(check(&format!("args.spender in ['{USDT_LC}', '{ALICE}']"), &c).await);
}

#[tokio::test]
async fn abi_address_not_in_list() {
    let c = ctx(
        1,
        ALICE,
        USDT_LC,
        &[("spender", serde_json::json!(ALICE_CS))],
    );
    assert!(check(&format!("args.spender not in ['{USDT_LC}']"), &c).await);
}

// ── 4. Zero address ───────────────────────────────────────────────────────────

#[tokio::test]
async fn zero_address_literal_comparison() {
    let c = ctx(
        1,
        ALICE,
        "0xcontract",
        &[("to", serde_json::json!(ZERO_ADDR))],
    );
    assert!(check(&format!("args.to == '{ZERO_ADDR}'"), &c).await);
}

#[tokio::test]
async fn nonzero_address_ne_zero() {
    let c = ctx(
        1,
        ALICE,
        "0xcontract",
        &[("to", serde_json::json!(USDT_CS))],
    );
    assert!(check(&format!("args.to != '{ZERO_ADDR}'"), &c).await);
}

// ── 5. Context fields: from_address, to_address ──────────────────────────────

#[tokio::test]
async fn from_address_is_lowercase() {
    // from_address comes from tx.from which is always stored lowercase
    let c = ctx(1, ALICE, USDT_LC, &[]);
    assert!(check(&format!("from_address == '{ALICE}'"), &c).await);
    assert!(
        check(&format!("from_address == '{ALICE_CS}'"), &c).await,
        "case-insensitive"
    );
}

#[tokio::test]
async fn to_address_comparison() {
    let c = ctx(1, ALICE, USDT_LC, &[]);
    assert!(check(&format!("to_address == '{USDT_LC}'"), &c).await);
    assert!(
        check(&format!("to_address == '{USDT_CS}'"), &c).await,
        "case-insensitive"
    );
}

#[tokio::test]
async fn from_address_ne_to_address() {
    let c = ctx(1, ALICE, USDT_LC, &[]);
    assert!(check("from_address != to_address", &c).await);
}

#[tokio::test]
async fn sender_not_in_blocklist() {
    // Common pattern: ensure sender is not a blocked address
    let c = ctx(1, ALICE, USDT_LC, &[]);
    assert!(
        check(
            &format!("from_address not in ['{ZERO_ADDR}', '{USDT_LC}']"),
            &c
        )
        .await
    );
}

// ── 6. Composite rule patterns ────────────────────────────────────────────────

#[tokio::test]
async fn pattern_address_allowlist_spender() {
    // Rule: approve(address spender, uint256 amount) — spender must be on allowlist
    let approved1 = "0xa152f8bb749c55e9943a3a0a3111d18ee2b3f94e";
    let approved2 = "0xdef1c0ded9bec7f1a1670819833240f027b25eff";
    let c = ctx(
        1,
        ALICE,
        USDT_LC,
        &[
            ("spender", serde_json::json!(approved1)),
            ("amount", serde_json::json!("1000000000000000000")),
        ],
    );
    assert!(
        check(
            &format!("args.spender in ['{approved1}', '{approved2}']"),
            &c
        )
        .await
    );
}
