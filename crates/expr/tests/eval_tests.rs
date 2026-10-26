use std::collections::HashMap;
use std::sync::Arc;
use weituo_expr::{
    context::{BuiltinProvider, EvalContext},
    eval::Value,
    evaluate, evaluate_explain,
};

struct NoBuiltins;

#[async_trait::async_trait]
impl BuiltinProvider for NoBuiltins {
    async fn call(&self, name: &str, _: &[Value], _: &EvalContext) -> anyhow::Result<Value> {
        Err(anyhow::anyhow!("no builtin: {name}"))
    }
}

fn ctx_with_vars(
    args: HashMap<String, serde_json::Value>,
    vars: HashMap<String, serde_json::Value>,
) -> EvalContext {
    EvalContext {
        chain_id: 1,
        args,
        from_address: "0xsender".to_string(),
        to_address: "0xcontract".to_string(),
        vars,
        ..Default::default()
    }
}

#[tokio::test]
async fn vars_equality_passes_when_value_matches() {
    let mut args = HashMap::new();
    args.insert(
        "token".to_string(),
        serde_json::json!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
    );
    let mut vars = HashMap::new();
    vars.insert(
        "USDT".to_string(),
        serde_json::json!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
    );

    let ctx = ctx_with_vars(args, vars);
    let result = evaluate("args.token == vars.USDT", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(
        result,
        "args.token == vars.USDT should be true when values match"
    );
}

#[tokio::test]
async fn vars_equality_fails_when_value_differs() {
    let mut args = HashMap::new();
    args.insert("token".to_string(), serde_json::json!("0xother"));
    let mut vars = HashMap::new();
    vars.insert(
        "USDT".to_string(),
        serde_json::json!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
    );

    let ctx = ctx_with_vars(args, vars);
    let result = evaluate("args.token == vars.USDT", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(
        !result,
        "args.token == vars.USDT should be false when values differ"
    );
}

#[tokio::test]
async fn vars_in_array_passes_when_token_is_in_list() {
    let mut args = HashMap::new();
    args.insert("token".to_string(), serde_json::json!("0xweth"));
    let mut vars = HashMap::new();
    vars.insert("ETH".to_string(), serde_json::json!("0xeeee"));
    vars.insert("WETH".to_string(), serde_json::json!("0xweth"));

    let ctx = ctx_with_vars(args, vars);
    let result = evaluate(
        "args.token in [vars.ETH, vars.WETH]",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(
        result,
        "token matching one of the vars entries should be in the list"
    );
}

#[tokio::test]
async fn vars_in_array_fails_when_token_not_in_list() {
    let mut args = HashMap::new();
    args.insert("token".to_string(), serde_json::json!("0xunknown"));
    let mut vars = HashMap::new();
    vars.insert("ETH".to_string(), serde_json::json!("0xeeee"));
    vars.insert("WETH".to_string(), serde_json::json!("0xweth"));

    let ctx = ctx_with_vars(args, vars);
    let result = evaluate(
        "args.token in [vars.ETH, vars.WETH]",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(!result, "unknown token should not be in the vars list");
}

#[tokio::test]
async fn undefined_vars_resolves_to_null_not_panic() {
    let ctx = ctx_with_vars(HashMap::new(), HashMap::new());
    // vars.MISSING is not defined — should resolve to Null, comparison returns false
    let result = evaluate("vars.MISSING == 'x'", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(!result);
}

#[tokio::test]
async fn deeper_vars_path_resolves_to_null() {
    let mut vars = HashMap::new();
    vars.insert("FOO".to_string(), serde_json::json!("hello"));
    let ctx = ctx_with_vars(HashMap::new(), vars);
    // vars.FOO.bar is a deeper path — must resolve to Null → false
    let result = evaluate("vars.FOO.bar == 'hello'", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(!result, "deeper vars path must resolve to Null");
}

// ── Task 2: $block().field eval ───────────────────────────────────────────────

struct BlockBuiltins;

#[async_trait::async_trait]
impl BuiltinProvider for BlockBuiltins {
    async fn call(&self, name: &str, _: &[Value], _: &EvalContext) -> anyhow::Result<Value> {
        match name {
            "block" => Ok(Value::from(serde_json::json!({
                "timestamp": 1_700_000_000_i64,
                "number": 18_000_000_i64,
                "gasLimit": 30_000_000_i64,
            }))),
            _ => Err(anyhow::anyhow!("unknown builtin: {name}")),
        }
    }
}

fn plain_ctx() -> EvalContext {
    EvalContext::new(1, "0xaaa", "0xbbb")
}

#[tokio::test]
async fn block_timestamp_arithmetic() {
    // deadline (1_699_999_999) <= $block().timestamp + 86400 → true
    let mut c = plain_ctx();
    c.args
        .insert("deadline".to_string(), serde_json::json!("1699999999"));
    let ok = evaluate(
        "args.deadline <= $block().timestamp + 86400",
        &c,
        Arc::new(BlockBuiltins),
    )
    .await
    .unwrap();
    assert!(ok);
}

#[tokio::test]
async fn block_timestamp_expired_deadline() {
    // deadline (1_700_090_001) > $block().timestamp + 86400 → rule fires (denied)
    let mut c = plain_ctx();
    c.args
        .insert("deadline".to_string(), serde_json::json!("1700090001"));
    let ok = evaluate(
        "args.deadline <= $block().timestamp + 86400",
        &c,
        Arc::new(BlockBuiltins),
    )
    .await
    .unwrap();
    assert!(!ok);
}

#[tokio::test]
async fn block_number_field() {
    let ok = evaluate("$block().number > 0", &plain_ctx(), Arc::new(BlockBuiltins))
        .await
        .unwrap();
    assert!(ok);
}

#[tokio::test]
async fn block_missing_field_is_null_falsy() {
    // Accessing a non-existent field → Null → arithmetic fails or comparison is false
    let result = evaluate(
        "$block().nonexistent > 0",
        &plain_ctx(),
        Arc::new(BlockBuiltins),
    )
    .await;
    assert!(result.is_err() || !result.unwrap());
}

// ── Task 3: <<, >>, % eval ───────────────────────────────────────────────────

fn args_ctx(pairs: &[(&str, serde_json::Value)]) -> EvalContext {
    let mut args = HashMap::new();
    for (k, v) in pairs {
        args.insert(k.to_string(), v.clone());
    }
    ctx_with_vars(args, HashMap::new())
}

#[tokio::test]
async fn modulo_small_integer_divisible() {
    let ctx = args_ctx(&[("amount", serde_json::json!(32_i64))]);
    assert!(
        evaluate("args.amount % 32 == 0", &ctx, Arc::new(NoBuiltins))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn modulo_small_integer_not_divisible() {
    let ctx = args_ctx(&[("amount", serde_json::json!(33_i64))]);
    assert!(
        !evaluate("args.amount % 32 == 0", &ctx, Arc::new(NoBuiltins))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn modulo_biguint_divisible() {
    // 32 * 10^16 is divisible by 32
    let ctx = args_ctx(&[("amount", serde_json::json!("320000000000000000"))]);
    assert!(
        evaluate("args.amount % 32 == 0", &ctx, Arc::new(NoBuiltins))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn modulo_biguint_not_divisible() {
    // 10^18 + 1 is not divisible by 32 (remainder = 1)
    let ctx = args_ctx(&[("amount", serde_json::json!("1000000000000000001"))]);
    assert!(
        !evaluate("args.amount % 32 == 0", &ctx, Arc::new(NoBuiltins))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn shl_128_is_large() {
    // 10^18 <= 2^128
    let ctx = args_ctx(&[("amount", serde_json::json!("1000000000000000000"))]);
    assert!(
        evaluate("args.amount <= 1 << 128", &ctx, Arc::new(NoBuiltins))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn shl_just_above_limit() {
    // 2^128 + 1 is NOT <= 2^128
    let just_over = "340282366920938463463374607431768211457";
    let ctx = args_ctx(&[("amount", serde_json::json!(just_over))]);
    assert!(
        !evaluate("args.amount <= 1 << 128", &ctx, Arc::new(NoBuiltins))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn shl_256_wraps_and_minus_1_is_max_u256() {
    // 1 << 256 wraps to 0 in U256; 0 - 1 wraps to U256::MAX
    let ctx = args_ctx(&[("amount", serde_json::json!("1000000000000000000"))]);
    assert!(
        evaluate("args.amount != (1 << 256) - 1", &ctx, Arc::new(NoBuiltins))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn shr_halves_value() {
    let ctx = args_ctx(&[("amount", serde_json::json!(64_i64))]);
    assert!(
        evaluate("args.amount >> 1 == 32", &ctx, Arc::new(NoBuiltins))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn modulo_in_conjunction_with_address_check() {
    let mut c = EvalContext::new(1, "0xabc", "0xcontract");
    c.args.insert("to".to_string(), serde_json::json!("0xabc"));
    c.args
        .insert("amount".to_string(), serde_json::json!(64_i64));
    assert!(evaluate(
        "args.to == from_address and args.amount % 32 == 0",
        &c,
        Arc::new(NoBuiltins)
    )
    .await
    .unwrap());
}

// ── Exact big-integer arithmetic (no f64 precision loss) ────────────────────

#[tokio::test]
async fn big_uint_mul_keeps_full_precision() {
    // 2·(10^18+1) is not representable in f64: f64 rounds it to 2·10^18, so the
    // old float path wrongly matched 2000000000000000000. The exact path must
    // keep 2000000000000000002.
    let ctx = args_ctx(&[("amount", serde_json::json!("1000000000000000001"))]);
    assert!(evaluate(
        "args.amount * 2 == 2000000000000000002",
        &ctx,
        Arc::new(NoBuiltins)
    )
    .await
    .unwrap());
    assert!(!evaluate(
        "args.amount * 2 == 2000000000000000000",
        &ctx,
        Arc::new(NoBuiltins)
    )
    .await
    .unwrap());
}

#[tokio::test]
async fn big_uint_mul_negative_result_exact() {
    // -2·(10^18+1) is far below i64::MIN; the exact path must keep the value
    // exact as a BigInt instead of going through f64.
    let ctx = args_ctx(&[("amount", serde_json::json!("1000000000000000001"))]);
    assert!(evaluate("args.amount * -2 < 0", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap());
}

#[tokio::test]
async fn exact_integer_division_when_even() {
    let ctx = args_ctx(&[("amount", serde_json::json!("1000000000000000000"))]);
    assert!(evaluate(
        "args.amount / 2 == 500000000000000000",
        &ctx,
        Arc::new(NoBuiltins)
    )
    .await
    .unwrap());
}

#[tokio::test]
async fn non_integral_division_stays_float() {
    // 10 / 4 == 2.5 keeps float semantics for non-even quotients.
    let ctx = args_ctx(&[("amount", serde_json::json!(10))]);
    assert!(
        evaluate("args.amount / 4 == 2.5", &ctx, Arc::new(NoBuiltins))
            .await
            .unwrap()
    );
}

// ── evaluate_explain: which condition failed ─────────────────────────────────

#[tokio::test]
async fn explain_first_and_condition_fails() {
    let ctx = args_ctx(&[
        ("receiver", serde_json::json!("0xother")),
        ("minAmount", serde_json::json!("10")),
    ]);
    let (ok, explain) = evaluate_explain(
        "args.receiver == '0xsender' and args.minAmount > 0",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(!ok);
    let explain = explain.unwrap();
    assert_eq!(explain.source, "args.receiver == '0xsender'");
    assert_eq!(explain.values.as_deref(), Some("'0xother' == '0xsender'"));
}

#[tokio::test]
async fn explain_middle_and_condition_fails() {
    let ctx = args_ctx(&[
        ("receiver", serde_json::json!("0xsender")),
        ("minAmount", serde_json::json!("0")),
        ("deadline", serde_json::json!("100")),
    ]);
    let (ok, explain) = evaluate_explain(
        "args.receiver == '0xsender' and args.minAmount > 0 and args.deadline > 1",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(!ok);
    let explain = explain.unwrap();
    assert_eq!(explain.source, "args.minAmount > 0");
    assert_eq!(explain.values.as_deref(), Some("0 > 0"));
}

#[tokio::test]
async fn explain_none_when_all_pass() {
    let ctx = args_ctx(&[
        ("receiver", serde_json::json!("0xsender")),
        ("minAmount", serde_json::json!("10")),
    ]);
    let (ok, explain) = evaluate_explain(
        "args.receiver == '0xsender' and args.minAmount > 0",
        &ctx,
        Arc::new(NoBuiltins),
    )
    .await
    .unwrap();
    assert!(ok);
    assert_eq!(explain, None);
}

#[tokio::test]
async fn explain_none_for_single_condition() {
    let ctx = args_ctx(&[("minAmount", serde_json::json!("0"))]);
    let (ok, explain) = evaluate_explain("args.minAmount > 0", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(!ok);
    assert_eq!(
        explain, None,
        "a single condition has no narrower sub-condition"
    );
}

#[tokio::test]
async fn explain_first_failing_or_branch() {
    let ctx = args_ctx(&[("x", serde_json::json!(1)), ("y", serde_json::json!(2))]);
    let (ok, explain) =
        evaluate_explain("args.x == 99 or args.y == 99", &ctx, Arc::new(NoBuiltins))
            .await
            .unwrap();
    assert!(!ok);
    let explain = explain.unwrap();
    assert_eq!(explain.source, "args.x == 99");
    assert_eq!(explain.values.as_deref(), Some("1 == 99"));
}

#[tokio::test]
async fn explain_not_reports_negated_condition() {
    let ctx = args_ctx(&[("x", serde_json::json!(5))]);
    let (ok, explain) = evaluate_explain("not (args.x > 0)", &ctx, Arc::new(NoBuiltins))
        .await
        .unwrap();
    assert!(!ok);
    assert_eq!(explain.unwrap().source, "not args.x > 0");
}
