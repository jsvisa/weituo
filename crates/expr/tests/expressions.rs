//! Integration tests for the weituo-expr crate.
//! Covers rule evaluation and context handling, without network calls.
//! Builtins that require RPC/oracle are mocked via MockBuiltins.

use std::collections::HashMap;
use std::sync::Arc;
use weituo_expr::context::BuiltinProvider;
use weituo_expr::{evaluate, validate_syntax, EvalContext, Value};

// ── Mock builtin provider ─────────────────────────────────────────────────────

struct MockBuiltins {
    /// name → return value
    responses: HashMap<String, Value>,
}

impl MockBuiltins {
    fn new() -> Self {
        Self {
            responses: HashMap::new(),
        }
    }
    fn with(mut self, name: &str, val: Value) -> Self {
        self.responses.insert(name.to_string(), val);
        self
    }
    fn arc(self) -> Arc<dyn BuiltinProvider> {
        Arc::new(self)
    }
}

#[async_trait::async_trait]
impl BuiltinProvider for MockBuiltins {
    async fn call(&self, name: &str, args: &[Value], _ctx: &EvalContext) -> anyhow::Result<Value> {
        // Handle a few builtins inline for richer tests
        match name {
            "now_ts" => return Ok(Value::Int(1_700_000_000)),
            "pow" => {
                let base = args.first().and_then(|v| v.as_f64()).unwrap_or(0.0);
                let exp = args.get(1).and_then(|v| v.as_f64()).unwrap_or(1.0);
                return Ok(Value::Float(base.powf(exp)));
            }
            "b32int2addr" => {
                let raw = match args.first() {
                    Some(Value::Str(s)) => s.clone(),
                    Some(Value::Int(i)) => format!("{i:x}"),
                    _ => "0".into(),
                };
                let hex = raw.trim_start_matches("0x");
                let padded = format!("{:0>40}", hex);
                let addr = &padded[padded.len().saturating_sub(40)..];
                return Ok(Value::Str(format!("0x{addr}")));
            }
            _ => {}
        }
        self.responses
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("mock: no response for ${name}"))
    }
}

fn builtins() -> Arc<dyn BuiltinProvider> {
    MockBuiltins::new().arc()
}

fn ctx() -> EvalContext {
    EvalContext::new(1, "0xaabbcc", "0xdeadbeef")
}

fn ctx_with_args(args: &[(&str, serde_json::Value)]) -> EvalContext {
    let mut c = ctx();
    for (k, v) in args {
        c.args.insert(k.to_string(), v.clone());
    }
    c
}

async fn eval(expr: &str, ctx: &EvalContext) -> bool {
    evaluate(expr, ctx, builtins()).await.unwrap()
}

async fn eval_with(expr: &str, ctx: &EvalContext, b: Arc<dyn BuiltinProvider>) -> bool {
    evaluate(expr, ctx, b).await.unwrap()
}

// ── Syntax validation ─────────────────────────────────────────────────────────

#[test]
fn valid_syntax_returns_none() {
    assert!(validate_syntax("args.value < 100").is_none());
    assert!(validate_syntax("from_address == '0xaabb'").is_none());
    assert!(validate_syntax("args.spender in ['0xAA', '0xBB']").is_none());
}

#[test]
fn invalid_syntax_returns_error() {
    assert!(validate_syntax("args.value <").is_some());
    assert!(validate_syntax("(unclosed").is_some());
}

// ── Boolean operators ─────────────────────────────────────────────────────────

#[tokio::test]
async fn and_both_true() {
    assert!(eval("true and true", &ctx()).await);
}
#[tokio::test]
async fn and_one_false() {
    assert!(!eval("true and false", &ctx()).await);
}
#[tokio::test]
async fn or_one_true() {
    assert!(eval("false or true", &ctx()).await);
}
#[tokio::test]
async fn or_both_false() {
    assert!(!eval("false or false", &ctx()).await);
}
#[tokio::test]
async fn not_true() {
    assert!(!eval("not true", &ctx()).await);
}
#[tokio::test]
async fn not_false() {
    assert!(eval("not false", &ctx()).await);
}

// ── Comparisons ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn int_eq() {
    assert!(eval("1 == 1", &ctx()).await);
}
#[tokio::test]
async fn int_ne() {
    assert!(eval("1 != 2", &ctx()).await);
}
#[tokio::test]
async fn int_lt() {
    assert!(eval("1 < 2", &ctx()).await);
}
#[tokio::test]
async fn int_le() {
    assert!(eval("2 <= 2", &ctx()).await);
}
#[tokio::test]
async fn int_gt() {
    assert!(eval("3 > 2", &ctx()).await);
}
#[tokio::test]
async fn int_ge() {
    assert!(eval("2 >= 2", &ctx()).await);
}
#[tokio::test]
async fn float_gt() {
    assert!(eval("1.5 > 1.0", &ctx()).await);
}
#[tokio::test]
async fn str_eq() {
    assert!(eval("'hello' == 'hello'", &ctx()).await);
}
/// All address comparisons are case-insensitive.
/// Rules may contain checksummed (EIP-55), uppercase, or lowercase address literals.
/// The decoder may return lowercase; both sides are normalised before comparing.
#[tokio::test]
async fn str_eq_case_insensitive() {
    assert!(eval("'0xABCD' == '0xabcd'", &ctx()).await);
}

#[tokio::test]
async fn address_eq_checksum_vs_lowercase() {
    // decoded args.to is lowercase; rule literal uses EIP-55 checksum → must match
    let ctx = ctx_with_args(&[(
        "to",
        serde_json::json!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
    )]);
    assert!(
        eval(
            "args.to == '0xdAC17F958D2ee523a2206206994597C13D831ec7'",
            &ctx
        )
        .await
    );
}

#[tokio::test]
async fn address_ne_different_address() {
    let ctx = ctx_with_args(&[(
        "to",
        serde_json::json!("0xaabbcc0000000000000000000000000000000000"),
    )]);
    assert!(
        eval(
            "args.to != '0x1234560000000000000000000000000000000000'",
            &ctx
        )
        .await
    );
}

#[tokio::test]
async fn address_in_list_checksum_vs_lowercase() {
    // decoded lowercase; rule list uses checksummed literals
    let ctx = ctx_with_args(&[(
        "spender",
        serde_json::json!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
    )]);
    assert!(eval(
        "args.spender in ['0xdAC17F958D2ee523a2206206994597C13D831ec7', '0xA0b86991c6218b36c1D19D4a2e9Eb0cE3606eB48']",
        &ctx,
    ).await);
}

#[tokio::test]
async fn address_in_list_lowercase_vs_uppercase() {
    let ctx = ctx_with_args(&[(
        "spender",
        serde_json::json!("0xAAAA000000000000000000000000000000000000"),
    )]);
    assert!(
        eval(
            "args.spender in ['0xaaaa000000000000000000000000000000000000']",
            &ctx
        )
        .await
    );
}

#[tokio::test]
async fn address_not_in_list() {
    let ctx = ctx_with_args(&[(
        "spender",
        serde_json::json!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
    )]);
    assert!(
        eval(
            "args.spender not in ['0xdAC17F958D2ee523a2206206994597C13D831ec7']",
            &ctx,
        )
        .await
    );
}
#[tokio::test]
async fn str_ne() {
    assert!(eval("'foo' != 'bar'", &ctx()).await);
}
#[tokio::test]
async fn null_eq() {
    assert!(eval("null == null", &ctx()).await);
}
#[tokio::test]
async fn bool_true_literal() {
    assert!(eval("true", &ctx()).await);
}
#[tokio::test]
async fn bool_false_literal() {
    assert!(!eval("false", &ctx()).await);
}

// ── Arithmetic ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn add() {
    assert!(eval("1 + 1 == 2", &ctx()).await);
}
#[tokio::test]
async fn sub() {
    assert!(eval("5 - 3 == 2", &ctx()).await);
}
#[tokio::test]
async fn mul() {
    assert!(eval("3 * 4 == 12", &ctx()).await);
}
#[tokio::test]
async fn div() {
    assert!(eval("10 / 4 == 2.5", &ctx()).await);
}
#[tokio::test]
async fn neg() {
    assert!(eval("-5 < 0", &ctx()).await);
}
#[tokio::test]
async fn float_arith() {
    assert!(eval("1e18 / 1e18 == 1.0", &ctx()).await);
}

// ── In operator (set membership) ─────────────────────────────────────────────

#[tokio::test]
async fn in_str_list_match() {
    let ctx = ctx_with_args(&[("spender", serde_json::json!("0xAA"))]);
    assert!(eval("args.spender in ['0xAA', '0xBB']", &ctx).await);
}

#[tokio::test]
async fn in_str_list_no_match() {
    let ctx = ctx_with_args(&[("spender", serde_json::json!("0xCC"))]);
    assert!(!eval("args.spender in ['0xAA', '0xBB']", &ctx).await);
}

#[tokio::test]
async fn not_in_list() {
    let ctx = ctx_with_args(&[("spender", serde_json::json!("0xCC"))]);
    assert!(eval("args.spender not in ['0xAA', '0xBB']", &ctx).await);
}

#[tokio::test]
async fn in_int_list() {
    let ctx = ctx_with_args(&[("id", serde_json::json!("2"))]);
    assert!(eval("args.id in [1, 2, 3]", &ctx).await);
}

// ── Attribute access ──────────────────────────────────────────────────────────

#[tokio::test]
async fn args_access() {
    let ctx = ctx_with_args(&[("amount", serde_json::json!("500"))]);
    assert!(eval("args.amount == '500'", &ctx).await);
}

#[tokio::test]
async fn from_address_access() {
    assert!(eval("from_address == '0xaabbcc'", &ctx()).await);
}

#[tokio::test]
async fn chain_id_access() {
    assert!(eval("chainId == 1", &ctx()).await);
}

#[tokio::test]
async fn missing_arg_is_null() {
    assert!(eval("args.missing == null", &ctx()).await);
}

// ── Typical WAF rule patterns ─────────────────────────────────────────────────

#[tokio::test]
async fn value_limit_rule() {
    // WAF allowlist rule: true = transaction passes (allowed), false = transaction denied
    // Rule: allow transfers where _value < 10000 USDT (6 decimals = 10_000_000_000)
    let ctx = ctx_with_args(&[("_value", serde_json::json!("9999999999"))]);
    assert!(eval("args._value < 10000000000", &ctx).await); // 9999999999 < 10e9 → true → ALLOW

    let ctx = ctx_with_args(&[("_value", serde_json::json!("10000000001"))]);
    assert!(!eval("args._value < 10000000000", &ctx).await); // 10e9+1 < 10e9 → false → DENY
}

#[tokio::test]
async fn address_blocklist_rule() {
    let ctx = ctx_with_args(&[("spender", serde_json::json!("0xBAD"))]);
    assert!(eval("args.spender in ['0xBAD', '0xEVIL']", &ctx).await);
}

#[tokio::test]
async fn compound_and_rule() {
    let ctx = ctx_with_args(&[
        ("amount", serde_json::json!("500")),
        ("recipient", serde_json::json!("0xGOOD")),
    ]);
    // Both must be true for denial
    assert!(eval("args.amount == '500' and args.recipient == '0xGOOD'", &ctx).await);
}

#[tokio::test]
async fn compound_or_rule() {
    let ctx = ctx_with_args(&[("flag", serde_json::json!("1"))]);
    assert!(eval("args.flag == '0' or args.flag == '1'", &ctx).await);
}

// ── $ builtins (mocked) ───────────────────────────────────────────────────────

#[tokio::test]
async fn now_ts_builtin() {
    // $now_ts() returns a positive integer
    assert!(eval("$now_ts() > 0", &ctx()).await);
}

#[tokio::test]
async fn pow_builtin() {
    assert!(eval("$pow(10, 6) == 1000000.0", &ctx()).await);
}

#[tokio::test]
async fn pow_in_expression() {
    // Mirror: $erc20_balance_of / $pow(10, decimals) <= 1e6
    // With mocked balance = 500_000 * 10^6 (500k USDT)
    let b = MockBuiltins::new()
        .with("erc20_balance_of", Value::Int(500_000_000_000))
        .with("erc20_decimals", Value::Int(6))
        .arc();
    let ctx = ctx_with_args(&[
        ("token", serde_json::json!("0xusdt")),
        ("owner", serde_json::json!("0xzero")),
    ]);
    // 500_000_000_000 / 10^6 == 500_000 ≤ 1_000_000 → true → ALLOW
    assert!(
        eval_with(
            "$erc20_balance_of(token, owner) / $pow(10, $erc20_decimals(token)) <= 1000000",
            &ctx,
            b
        )
        .await
    );
}

#[tokio::test]
async fn price_of_mocked() {
    let b = MockBuiltins::new()
        .with("price_of", Value::Float(2500.0))
        .arc();
    assert!(eval_with("$price_of(token) > 100", &ctx(), b).await);
}

#[tokio::test]
async fn b32int2addr_builtin() {
    // From test_context.py: b32int2addr(1364068194842176056990105843868530818345537040110)
    // == 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    let ctx = ctx_with_args(&[(
        "fromToken",
        serde_json::json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    )]);
    assert!(
        eval(
            "$b32int2addr(args.fromToken) == '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'",
            &ctx
        )
        .await
    );
}

#[tokio::test]
async fn is_contract_mocked() {
    let b = MockBuiltins::new()
        .with("is_contract", Value::Bool(true))
        .arc();
    let ctx = ctx_with_args(&[("token", serde_json::json!("0xusdt"))]);
    assert!(eval_with("$is_contract(token) == true", &ctx, b).await);
}

#[tokio::test]
async fn is_eoa_mocked() {
    let b = MockBuiltins::new().with("is_eoa", Value::Bool(false)).arc();
    let ctx = ctx_with_args(&[("token", serde_json::json!("0xusdt"))]);
    assert!(eval_with("$is_eoa(token) == false", &ctx, b).await);
}

// ── And-list (multiple expressions, all must pass) ────────────────────────────
// List-format rule expr: ["expr1", "expr2"] — each entry evaluated
// Each is evaluated independently; all must be true to deny

#[tokio::test]
async fn and_list_both_pass() {
    // Simulated by evaluating two expressions separately
    let ctx = ctx_with_args(&[
        ("amount", serde_json::json!("500")),
        ("to", serde_json::json!("0xBAD")),
    ]);
    let e1 = evaluate("args.amount == '500'", &ctx, builtins())
        .await
        .unwrap();
    let e2 = evaluate("args.to == '0xBAD'", &ctx, builtins())
        .await
        .unwrap();
    assert!(e1 && e2);
}

// ── Array indexing: args.field[n] ─────────────────────────────────────────────

#[tokio::test]
async fn array_index_first_element() {
    let ctx = ctx_with_args(&[("amounts", serde_json::json!(["100", "200", "300"]))]);
    assert!(eval("args.amounts[0] == '100'", &ctx).await);
}

#[tokio::test]
async fn array_index_second_element() {
    let ctx = ctx_with_args(&[("amounts", serde_json::json!(["100", "200", "300"]))]);
    assert!(eval("args.amounts[1] == '200'", &ctx).await);
}

#[tokio::test]
async fn array_index_numeric_comparison() {
    // Typical WAF rule: each amount in a list must be below limit
    let ctx = ctx_with_args(&[("_amounts", serde_json::json!(["500000000", "300000000"]))]);
    assert!(eval("args._amounts[0] <= 1000000000000000000000", &ctx).await);
}

#[tokio::test]
async fn array_index_out_of_bounds_is_null() {
    let ctx = ctx_with_args(&[("arr", serde_json::json!(["x"]))]);
    assert!(eval("args.arr[99] == null", &ctx).await);
}

#[tokio::test]
async fn array_length_property() {
    let ctx = ctx_with_args(&[("pools", serde_json::json!(["0xaa", "0xbb"]))]);
    assert!(eval("args.pools.length == 2", &ctx).await);
}

#[tokio::test]
async fn array_length_comparison() {
    // Real waf.yaml rule: args.pools.length == 1
    let ctx = ctx_with_args(&[("pools", serde_json::json!(["0xdeadbeef"]))]);
    assert!(eval("args.pools.length == 1", &ctx).await);
}

// ── Nested tuple field access: args.tuple_field.nested_field ─────────────────

#[tokio::test]
async fn nested_tuple_field_access() {
    let ctx = ctx_with_args(&[(
        "baseRequest",
        serde_json::json!({
            "fromToken": "917551056842671309452305380979543736893630245704",
            "toToken": "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
            "fromTokenAmount": "1300000000",
            "minReturnAmount": "491871113895310812",
            "deadLine": "1748416561"
        }),
    )]);
    assert!(eval("args.baseRequest.fromTokenAmount > 0", &ctx).await);
    assert!(eval("args.baseRequest.minReturnAmount > 0", &ctx).await);
}

#[tokio::test]
async fn nested_tuple_address_field() {
    let ctx = ctx_with_args(&[(
        "swap",
        serde_json::json!({
            "tokenIn": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            "amountIn": "1000000000000000000"
        }),
    )]);
    assert!(
        eval(
            "args.swap.tokenIn == '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'",
            &ctx
        )
        .await
    );
}

#[tokio::test]
async fn nested_tuple_missing_field_is_null() {
    let ctx = ctx_with_args(&[("req", serde_json::json!({"amount": "100"}))]);
    assert!(eval("args.req.nonexistent == null", &ctx).await);
}

#[tokio::test]
async fn deeply_nested_access() {
    let ctx = ctx_with_args(&[(
        "order",
        serde_json::json!({
            "params": {
                "offerer": "0xdAC17F958D2ee523a2206206994597C13D831ec7"
            }
        }),
    )]);
    assert!(
        eval(
            "args.order.params.offerer == '0xdac17f958d2ee523a2206206994597c13d831ec7'",
            &ctx
        )
        .await
    );
}

#[tokio::test]
async fn array_of_tuples_index_then_field() {
    // args.batches[0].fromToken — array of tuples, then field
    let ctx = ctx_with_args(&[(
        "batches",
        serde_json::json!([
            {"fromToken": "917551056842671309452305380979543736893630245704", "amount": "100"},
            {"fromToken": "0", "amount": "200"}
        ]),
    )]);
    assert!(eval("args.batches[0].amount == '100'", &ctx).await);
    assert!(eval("args.batches[1].amount == '200'", &ctx).await);
}

#[tokio::test]
async fn real_waf_yaml_pattern_amounts_length() {
    // Pattern from waf.yaml: args._amounts.length > 1
    let ctx = ctx_with_args(&[("_amounts", serde_json::json!(["500", "300"]))]);
    assert!(eval("args._amounts.length > 1", &ctx).await);
}

#[tokio::test]
async fn real_waf_yaml_pattern_min_amounts() {
    // Pattern from waf.yaml: args._min_amounts[0] > 0 and args._min_amounts[1] > 0
    let ctx = ctx_with_args(&[("_min_amounts", serde_json::json!(["1", "2"]))]);
    assert!(
        eval(
            "args._min_amounts[0] > 0 and args._min_amounts[1] > 0",
            &ctx
        )
        .await
    );
}

// ── uint256 exact arithmetic (no f64 precision loss) ─────────────────────────
//
// With f64, 10^21-1 and 10^21 round to the same float. With U256 both
// the decoded value (BigUint) and the literal (BigUint from parser) are exact.

#[tokio::test]
async fn uint256_boundary_is_exact_not_f64() {
    // 10^21 - 1 must be strictly less than 10^21.
    // Pure f64 would make them equal (both round to 1e21).
    let ctx = ctx_with_args(&[("amount", serde_json::json!("999999999999999999999"))]);
    assert!(
        eval("args.amount < 1000000000000000000000", &ctx).await,
        "10^21-1 < 10^21 must be true (would fail with f64)"
    );
    assert!(
        !eval("args.amount == 1000000000000000000000", &ctx).await,
        "10^21-1 != 10^21 must be true (would fail with f64)"
    );
}

#[tokio::test]
async fn uint256_equal_at_boundary() {
    let ctx = ctx_with_args(&[("amount", serde_json::json!("1000000000000000000000"))]);
    assert!(
        !eval("args.amount < 1000000000000000000000", &ctx).await,
        "10^21 is not < 10^21"
    );
    assert!(
        eval("args.amount == 1000000000000000000000", &ctx).await,
        "10^21 == 10^21"
    );
}

#[tokio::test]
async fn uint256_max_value_exact() {
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let ctx = ctx_with_args(&[("allowance", serde_json::json!(max))]);
    assert!(
        eval(&format!("args.allowance == {max}"), &ctx).await,
        "uint256::MAX exact equality"
    );
}

#[tokio::test]
async fn uint256_in_list_exact() {
    // Real pattern from waf.yaml: pool address encoded as uint256
    let pool = "1086020387990224579426449227685652610525455118070";
    let ctx = ctx_with_args(&[("pool", serde_json::json!(pool))]);
    assert!(eval(&format!("args.pool == {pool}"), &ctx).await);
    assert!(eval(&format!("args.pool in [{pool}]"), &ctx).await);
}

#[tokio::test]
async fn uint256_arithmetic_with_float_still_works() {
    // Mixed: BigUint / float → lossy f64, but sufficient for price checks
    let ctx = ctx_with_args(&[("amount", serde_json::json!("1000000000000000000"))]);
    // args.amount / 1e18 ≈ 1.0 > 0.95 → true
    assert!(eval("args.amount / 1e18 > 0.95", &ctx).await);
}

// ── String functions ──────────────────────────────────────────────────────────

#[tokio::test]
async fn len_string() {
    assert!(eval("len('0xabcdef') == 8", &ctx()).await);
    assert!(
        eval(
            "len(args.sym) == 4",
            &ctx_with_args(&[("sym", serde_json::json!("USDT"))])
        )
        .await
    );
}

#[tokio::test]
async fn len_empty_string_is_zero() {
    assert!(eval("len('') == 0", &ctx()).await);
}

#[tokio::test]
async fn len_combined_with_compare() {
    // Typical WAF rule: reject unknown symbol lengths
    let ctx = ctx_with_args(&[(
        "to",
        serde_json::json!("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
    )]);
    assert!(eval("len(args.to) >= 40", &ctx).await);
    assert!(eval("len(args.to) == 42", &ctx).await);
}

#[tokio::test]
async fn lower_string() {
    assert!(eval("lower('ABCdef') == 'abcdef'", &ctx()).await);
    assert!(
        eval(
            "lower(args.token) == '0xeeee'",
            &ctx_with_args(&[("token", serde_json::json!("0xEEEE"))])
        )
        .await
    );
}

#[tokio::test]
async fn upper_string() {
    assert!(eval("upper('AbCdEf') == 'ABCDEF'", &ctx()).await);
}

#[tokio::test]
async fn contains_string() {
    assert!(eval("contains('0xdeadbeef', 'dead')", &ctx()).await);
    assert!(
        !eval("contains('0xdeadbeef', 'DEAD')", &ctx()).await,
        "case-sensitive"
    );
    assert!(!eval("contains('0xdeadbeef', 'cafe')", &ctx()).await);
    assert!(eval("contains('', '')", &ctx()).await);
}

#[tokio::test]
async fn startswith_string() {
    assert!(eval("startswith('0xdeadbeef', '0x')", &ctx()).await);
    assert!(
        !eval("startswith('0xDEADbeef', '0X')", &ctx()).await,
        "case-sensitive"
    );
    assert!(!eval("startswith('0xdeadbeef', 'beef')", &ctx()).await);
    assert!(eval("startswith('', '')", &ctx()).await);
}

#[tokio::test]
async fn endswith_string() {
    assert!(eval("endswith('0xdeadbeef', 'beef')", &ctx()).await);
    assert!(
        !eval("endswith('0xDEADbeef', 'BEEF')", &ctx()).await,
        "case-sensitive"
    );
    assert!(!eval("endswith('0xdeadbeef', 'dead')", &ctx()).await);
}

#[tokio::test]
async fn case_insensitive_match_via_lower() {
    // contains/startswith/endswith are case-sensitive; combine with lower()
    // for a case-insensitive check.
    let ctx = ctx_with_args(&[(
        "token",
        serde_json::json!("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
    )]);
    assert!(!eval("startswith(args.token, '0xeeee')", &ctx).await);
    assert!(eval("startswith(lower(args.token), '0xeeee')", &ctx).await);
    assert!(eval("contains(lower(args.token), 'eeeee')", &ctx).await);
}

#[tokio::test]
async fn substring_string() {
    assert!(eval("substring('0xdeadbeef', 0, 2) == '0x'", &ctx()).await);
    assert!(eval("substring('0xdeadbeef', 2, 6) == 'dead'", &ctx()).await);
    // exclusive end
    assert!(eval("substring('abc', 0, 2) == 'ab'", &ctx()).await);
}

#[tokio::test]
async fn substring_negative_and_clamped() {
    // negative index counts from the end
    assert!(eval("substring('0xdeadbeef', -2, 10) == 'ef'", &ctx()).await);
    // clamping: end beyond length
    assert!(eval("substring('0xdeadbeef', 2, 999) == 'deadbeef'", &ctx()).await);
    // start beyond end → empty
    assert!(eval("substring('0xdeadbeef', 5, 2) == ''", &ctx()).await);
    // negative start before beginning → clamped to 0
    assert!(eval("substring('abcdef', -100, 3) == 'abc'", &ctx()).await);
}

#[tokio::test]
async fn string_functions_on_args() {
    let ctx = ctx_with_args(&[(
        "token",
        serde_json::json!("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
    )]);
    assert!(eval("startswith(lower(args.token), '0xeeee')", &ctx).await);
    assert!(eval("len(args.token) == 42", &ctx).await);
    assert!(eval("substring(args.token, 0, 2) == '0x'", &ctx).await);
}

// ── Error cases ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn division_by_zero_is_error() {
    let result = evaluate("1 / 0", &ctx(), builtins()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn unknown_builtin_is_error() {
    let result = evaluate("$does_not_exist()", &ctx(), builtins()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn unknown_function_is_error() {
    let result = evaluate("sqrt(4)", &ctx(), builtins()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn len_non_string_is_error() {
    let result = evaluate("len(42)", &ctx(), builtins()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn substring_wrong_arity_is_error() {
    let result = evaluate("substring('abc', 1)", &ctx(), builtins()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn substring_non_integer_bound_is_error() {
    let result = evaluate("substring('abc', 'x', 2)", &ctx(), builtins()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn contains_wrong_type_is_error() {
    let result = evaluate("contains('abc', 5)", &ctx(), builtins()).await;
    assert!(result.is_err());
}
