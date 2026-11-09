use serde_json::json;
use weituo_core::parse_rule::{parse_rule_param, parse_rule_param_with_builtins};
use weituo_expr::analyze::KNOWN_BUILTINS;

#[test]
fn default_builtins_reject_custom_name() {
    let resp = parse_rule_param(json!(1), &json!({ "expr": "$is_xxx_approved(to_address)" }));

    assert!(resp.result.is_none());
    assert!(resp.error.is_some());
}

#[test]
fn extended_builtins_accept_custom_name() {
    let known = [KNOWN_BUILTINS, &["is_xxx_approved"]].concat();
    let resp = parse_rule_param_with_builtins(
        json!(1),
        &json!({ "expr": "$is_xxx_approved(to_address) and $price_of(to_address) > 1" }),
        &known,
    );

    assert!(resp.error.is_none(), "{:?}", resp.error);
    assert_eq!(resp.result, Some(json!("ok")));
}
