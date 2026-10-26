use std::collections::HashMap;
use std::sync::Arc;
use weituo_expr::{
    context::{BuiltinProvider, EvalContext},
    eval::Value,
    evaluate,
};

struct NoBuiltins;

#[async_trait::async_trait]
impl BuiltinProvider for NoBuiltins {
    async fn call(&self, name: &str, _: &[Value], _: &EvalContext) -> anyhow::Result<Value> {
        Err(anyhow::anyhow!("no builtin: {name}"))
    }
}

fn ctx_with_order_info(order_info: &str) -> EvalContext {
    let mut args = HashMap::new();
    args.insert("orderInfo".to_string(), serde_json::json!(order_info));

    EvalContext {
        chain_id: 1,
        args,
        from_address: "0xsender".to_string(),
        to_address: "0xcontract".to_string(),
        vars: HashMap::new(),
        ..Default::default()
    }
}

#[tokio::test]
async fn nested_tuple_field_access_allows_whitespace_before_each_dot() {
    let mut args = HashMap::new();
    args.insert(
        "order".to_string(),
        serde_json::json!({"recipient": "0xabc", "amount": 100}),
    );

    let ctx = EvalContext {
        chain_id: 1,
        args,
        from_address: "0xsender".to_string(),
        to_address: "0xcontract".to_string(),
        vars: HashMap::new(),
        ..Default::default()
    };

    for expr in [
        "args.order.recipient == '0xabc'",
        "args.order . recipient == '0xabc'",
        "args . order.recipient == '0xabc'",
        "args.order .amount == 100",
    ] {
        assert!(
            evaluate(expr, &ctx, Arc::new(NoBuiltins)).await.unwrap(),
            "{expr} should evaluate for nested tuple field access"
        );
    }
}

#[tokio::test]
async fn args_field_access_has_same_behavior_with_dot_whitespace() {
    let passing_ctx = ctx_with_order_info("1");
    let failing_ctx = ctx_with_order_info("0");

    for expr in [
        "args.orderInfo > 0",
        "args. orderInfo > 0",
        "args . orderInfo > 0",
        "args . orderInfo  >  0",
    ] {
        assert!(
            evaluate(expr, &passing_ctx, Arc::new(NoBuiltins))
                .await
                .unwrap(),
            "{expr} should pass when orderInfo is positive"
        );
        assert!(
            !evaluate(expr, &failing_ctx, Arc::new(NoBuiltins))
                .await
                .unwrap(),
            "{expr} should fail when orderInfo is zero"
        );
    }
}
