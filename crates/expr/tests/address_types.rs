//! Tests for address handling in WAF expressions.
//!
//! Addresses appear in three forms after ABI decoding:
//!
//!   ABI type=address  → EIP-55 checksummed string  "0xdAC17F958D2ee523a..."
//!   ABI type=uint256  → decimal string              "917551056842671309..."
//!   ABI type=bytes32  → 32-byte hex string          "0x000000...dac17f..."
//!
//! Rules may contain literals in any casing. The evaluator normalises both
//! sides to lowercase for == / != / in / not_in, so case never causes a mismatch.
//!
//! The $b32int2addr builtin converts uint256-as-decimal or bytes32-as-hex
//! to a plain address string for comparison with from_address / to_address.

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
/// USDT as uint256 decimal (address interpreted as 160-bit integer)
const USDT_DEC: &str = "1248875146012964071876423320777688075155124985543";

/// ETH sentinel address (used as token address in 1inch/DEX rules)
const ETH_SENTINEL_CS: &str = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
const ETH_SENTINEL_LC: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
/// ETH sentinel as uint256 decimal
const ETH_SENTINEL_DEC: &str = "1364068194842176056990105843868530818345537040110";

/// Zero address
const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";

/// A typical user address — lowercase (as it comes from tx.from)
const ALICE: &str = "0xca6f3defbc6041299837725f6430f33b0f24e5c0";
const ALICE_CS: &str = "0xCA6F3Defbc6041299837725f6430f33B0F24e5C0";
/// ALICE as uint256 decimal
const ALICE_DEC: &str = "1155696913850774659901214920371889448726756124096";
/// ALICE packed in bytes32 (left-padded with 12 zero bytes)
const ALICE_B32: &str = "0x000000000000000000000000ca6f3defbc6041299837725f6430f33b0f24e5c0";

// ── Mock builtins ─────────────────────────────────────────────────────────────

struct MockBuiltins;

#[async_trait::async_trait]
impl BuiltinProvider for MockBuiltins {
    async fn call(&self, name: &str, args: &[Value], _ctx: &EvalContext) -> anyhow::Result<Value> {
        match name {
            "b32int2addr" => {
                // args.receiver is now Value::BigUint (decoded uint256)
                let hex = match args.first() {
                    Some(Value::BigUint(u)) => format!("{u:x}"),
                    Some(Value::Str(s)) if s.starts_with("0x") || s.starts_with("0X") => {
                        s[2..].to_string()
                    }
                    Some(Value::Str(s)) => decimal_to_hex(s),
                    Some(Value::Int(i)) => format!("{i:x}"),
                    _ => "0".into(),
                };
                let padded = format!("{:0>64}", hex);
                let addr = &padded[padded.len().saturating_sub(40)..];
                Ok(Value::Str(format!("0x{addr}")))
            }
            "is_approved_token" | "is_approved_spender" => Ok(Value::Bool(true)),
            "is_not_blocked_spender" => Ok(Value::Bool(true)),
            "price_of" => Ok(Value::Float(1.0)),
            _ => Err(anyhow::anyhow!("unhandled mock builtin: ${name}")),
        }
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

// ── 2. ABI type=uint256 — decoded as decimal string, use $b32int2addr ─────────
//
// Common swap-router pattern:
//   func: uniswapV3SwapTo(uint256 receiver, ...)
//   expr: $b32int2addr(args.receiver) == from_address

#[tokio::test]
async fn uint256_as_address_b32int2addr_equals_sender() {
    // receiver is encoded as uint256; sender sent to themselves
    let c = ctx(
        1,
        ALICE,
        USDT_LC,
        &[("receiver", serde_json::json!(ALICE_DEC))],
    );
    assert!(
        check("$b32int2addr(args.receiver) == from_address", &c).await,
        "$b32int2addr(uint256_decimal) should equal from_address"
    );
}

#[tokio::test]
async fn uint256_as_address_b32int2addr_wrong_sender_denied() {
    // receiver is USDT, not the sender → should NOT equal from_address
    let c = ctx(
        1,
        ALICE,
        USDT_LC,
        &[("receiver", serde_json::json!(USDT_DEC))],
    );
    assert!(
        !check("$b32int2addr(args.receiver) == from_address", &c).await,
        "receiver != sender → expression false → tx denied"
    );
}

#[tokio::test]
async fn uint256_eth_sentinel_via_b32int2addr() {
    // Pattern: $b32int2addr(args.baseRequest.fromToken) == '0xEeee...'
    let c = ctx(
        56,
        ALICE,
        "0xrouter",
        &[(
            "baseRequest",
            serde_json::json!({
                "fromToken": ETH_SENTINEL_DEC,
                "fromTokenAmount": "500000000000000000",
                "toToken": "0xother",
                "minReturnAmount": "1"
            }),
        )],
    );
    assert!(
        check(
            &format!("$b32int2addr(args.baseRequest.fromToken) == '{ETH_SENTINEL_LC}'"),
            &c
        )
        .await,
        "ETH sentinel uint256 → address matches"
    );
}

#[tokio::test]
async fn uint256_eth_sentinel_checksummed_literal() {
    // Rule uses checksummed literal; comparison is case-insensitive
    let c = ctx(
        1,
        ALICE,
        "0xrouter",
        &[("fromToken", serde_json::json!(ETH_SENTINEL_DEC))],
    );
    assert!(
        check(
            &format!("$b32int2addr(args.fromToken) == '{ETH_SENTINEL_CS}'"),
            &c
        )
        .await
    );
}

// ── 3. ABI type=bytes32 — decoded as "0x00...addr" hex string ─────────────────
//
// bytes32 fields that encode an address have 12 leading zero bytes.
// $b32int2addr takes the last 20 bytes.

#[tokio::test]
async fn bytes32_as_address_b32int2addr_equals_sender() {
    // ALICE packed in bytes32
    let c = ctx(
        1,
        ALICE,
        "0xcontract",
        &[("receiver", serde_json::json!(ALICE_B32))],
    );
    assert!(
        check("$b32int2addr(args.receiver) == from_address", &c).await,
        "bytes32(addr) → address == from_address"
    );
}

#[tokio::test]
async fn bytes32_zero_padded_address_equals_target() {
    // Another bytes32 pattern: compare to a specific address
    let c = ctx(
        1,
        ALICE,
        "0xcontract",
        &[("recipient", serde_json::json!(ALICE_B32))],
    );
    assert!(check(&format!("$b32int2addr(args.recipient) == '{ALICE}'"), &c).await);
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
async fn zero_address_from_uint256_zero() {
    // 0 as uint256 → 0x0000...0000
    let c = ctx(
        1,
        ALICE,
        "0xcontract",
        &[("recipient", serde_json::json!("0"))],
    );
    assert!(
        check(
            &format!("$b32int2addr(args.recipient) == '{ZERO_ADDR}'"),
            &c
        )
        .await
    );
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
async fn pattern_uniswap_v3_swap_to_self() {
    // Rule: uniswapV3SwapTo — receiver (uint256) must equal sender
    // pools.length must be 1 (single hop)
    let c = ctx(
        1,
        ALICE,
        "0x1111111254eeb25477b68fb85ed929f73a960582",
        &[
            ("receiver", serde_json::json!(ALICE_DEC)),
            ("pools", serde_json::json!(["0xpool1"])),
        ],
    );
    assert!(
        check(
            "$b32int2addr(args.receiver) == from_address and args.pools.length == 1",
            &c
        )
        .await
    );
}

#[tokio::test]
async fn pattern_approved_token_transfer() {
    // Rule: transfer(address to, uint256 amount) to an approved token
    // $is_approved_token(to_address) — mocked as true
    let c = ctx(
        1,
        ALICE,
        USDT_LC,
        &[
            ("to", serde_json::json!(ALICE_CS)),
            ("amount", serde_json::json!("1000000")), // 1 USDT
        ],
    );
    assert!(check("$is_approved_token(to_address) and args.amount > 0", &c).await);
}

#[tokio::test]
async fn pattern_swap_from_eth_sentinel() {
    // Pattern from 1inch/DexRouter: from-token is ETH sentinel
    let c = ctx(
        56,
        ALICE,
        "0xrouter",
        &[(
            "baseRequest",
            serde_json::json!({
                "fromToken":       ETH_SENTINEL_DEC,
                "fromTokenAmount": "100000000000000000",  // 0.1 BNB
                "toToken":         "0xother",
                "minReturnAmount": "1"
            }),
        )],
    );
    assert!(
        check(
            &format!(
                "$b32int2addr(args.baseRequest.fromToken) == '{ETH_SENTINEL_LC}' \
                  and args.baseRequest.fromTokenAmount <= 2000000000000000000"
            ),
            &c
        )
        .await
    );
}

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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Decimal integer string → hex string (no 0x prefix).
fn decimal_to_hex(dec: &str) -> String {
    let mut digits: Vec<u8> = dec
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    let mut hex = Vec::new();
    loop {
        let mut remainder = 0u32;
        let mut new_digits = Vec::new();
        for &d in &digits {
            let cur = remainder * 10 + d as u32;
            new_digits.push((cur / 16) as u8);
            remainder = cur % 16;
        }
        hex.push(remainder as u8);
        let start = new_digits
            .iter()
            .position(|&x| x != 0)
            .unwrap_or(new_digits.len());
        digits = new_digits[start..].to_vec();
        if digits.is_empty() {
            break;
        }
    }
    hex.reverse();
    hex.iter().map(|&n| format!("{n:x}")).collect()
}
