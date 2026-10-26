use std::collections::HashMap;
use weituo_expr::{analyze::KNOWN_BUILTINS, validate_full};

const fn no_abi() -> &'static [&'static str] {
    &[]
}
fn no_types() -> HashMap<String, String> {
    HashMap::new()
}
fn no_vars() -> HashMap<String, serde_json::Value> {
    HashMap::new()
}

#[test]
fn defined_var_passes_validation() {
    let mut vars = HashMap::new();
    vars.insert("USDT".to_string(), serde_json::json!("0xdac17f"));

    let errs = validate_full(
        "args.token == vars.USDT",
        no_abi(),
        KNOWN_BUILTINS,
        &no_types(),
        &vars,
    );
    assert!(
        errs.is_empty(),
        "defined var should not produce errors: {errs:?}"
    );
}

#[test]
fn undefined_var_in_empty_vars_dict_passes() {
    // When vars dict is empty, vars.X should be flagged as undefined
    let errs = validate_full(
        "args.token == vars.USDT",
        no_abi(),
        KNOWN_BUILTINS,
        &no_types(),
        &no_vars(),
    );
    assert_eq!(
        errs.len(),
        1,
        "expected error for undefined var in empty vars dict"
    );
    assert!(errs[0].contains("vars.USDT"), "{}", errs[0]);
    assert!(errs[0].contains("no vars defined"), "{}", errs[0]);
}

#[test]
fn undefined_var_in_non_empty_vars_dict_produces_error() {
    let mut vars = HashMap::new();
    vars.insert("ETH".to_string(), serde_json::json!("0xeeee")); // USDT is NOT here

    let errs = validate_full(
        "args.token == vars.USDT", // USDT undefined
        no_abi(),
        KNOWN_BUILTINS,
        &no_types(),
        &vars,
    );
    assert_eq!(errs.len(), 1);
    assert!(
        errs[0].contains("vars.USDT"),
        "error should name the undefined var: {}",
        errs[0]
    );
    assert!(
        errs[0].contains("ETH"),
        "error should list defined vars: {}",
        errs[0]
    );
}

#[test]
fn undefined_var_inside_in_array_produces_error() {
    let mut vars = HashMap::new();
    vars.insert("ETH".to_string(), serde_json::json!("0xeeee"));
    // WETH is not defined

    let errs = validate_full(
        "args.token in [vars.ETH, vars.WETH]",
        no_abi(),
        KNOWN_BUILTINS,
        &no_types(),
        &vars,
    );
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("vars.WETH"));
}

#[test]
fn all_defined_vars_in_array_passes() {
    let mut vars = HashMap::new();
    vars.insert("ETH".to_string(), serde_json::json!("0xeeee"));
    vars.insert("WETH".to_string(), serde_json::json!("0xweth"));

    let errs = validate_full(
        "args.token in [vars.ETH, vars.WETH]",
        no_abi(),
        KNOWN_BUILTINS,
        &no_types(),
        &vars,
    );
    assert!(errs.is_empty(), "{errs:?}");
}

// ── Type-checking tests ───────────────────────────────────────────────────────

fn types_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn address_field_vs_string_literal_passes() {
    let types = types_map(&[("to", "address")]);
    let errs = validate_full(
        "args.to == '0xdAC17F958D2ee523a2206206994597C13D831ec7'",
        &["to"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn address_field_vs_short_string_literal_errors() {
    let types = types_map(&[("to", "address")]);
    let errs = validate_full(
        "args.to == '0xdeadbeef'",
        &["to"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(errs[0].contains("invalid address"), "{}", errs[0]);
}

#[test]
fn address_field_vs_mixed_case_literal_passes_after_normalization() {
    let types = types_map(&[("to", "address")]);
    let errs = validate_full(
        "args.to == '0xdAC17F958D2ee523a2206206994597C13D831ec8'",
        &["to"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn address_field_vs_non_hex_literal_errors() {
    let types = types_map(&[("to", "address")]);
    let errs = validate_full(
        "args.to == '0xdAC17F958D2ee523a2206206994597C13D831ecZ'",
        &["to"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(errs[0].contains("invalid address"), "{}", errs[0]);
}

#[test]
fn address_field_vs_mixed_case_var_passes_after_normalization() {
    let types = types_map(&[("to", "address")]);
    let mut vars = HashMap::new();
    vars.insert(
        "recipient".to_string(),
        serde_json::json!("0xdAC17F958D2ee523a2206206994597C13D831ec8"),
    );
    let errs = validate_full(
        "args.to == vars.recipient",
        &["to"],
        KNOWN_BUILTINS,
        &types,
        &vars,
    );
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn nested_tuple_unknown_field_errors() {
    let types = types_map(&[("order", "tuple"), ("order.recipient", "address")]);
    let errs = validate_full(
        "args.order.recipent == '0xdAC17F958D2ee523a2206206994597C13D831ec7'",
        &["order"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(errs[0].contains("args.order.recipent"), "{}", errs[0]);
}

#[test]
fn array_length_vs_string_literal_errors() {
    let types = types_map(&[("users", "address[]")]);
    let errs = validate_full(
        "args.users.length == '1'",
        &["users"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(errs[0].contains("args.users.length"), "{}", errs[0]);
}

#[test]
fn nested_tuple_address_field_rejects_non_address_literal() {
    let types = types_map(&[("order", "tuple"), ("order.recipient", "address")]);
    let errs = validate_full(
        "args.order.recipient == 1",
        &["order"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(errs[0].contains("args.order.recipient"), "{}", errs[0]);
}

#[test]
fn tuple_array_address_field_accepts_mixed_case_literal_after_normalization() {
    let types = types_map(&[("orders", "tuple[]"), ("orders.recipient", "address")]);
    let errs = validate_full(
        "args.orders[0].recipient == '0xdAC17F958D2ee523a2206206994597C13D831ec8'",
        &["orders"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn address_field_vs_integer_literal_errors() {
    let types = types_map(&[("to", "address")]);
    let errs = validate_full(
        "args.to == 122",
        &["to"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("args.to"), "{}", errs[0]);
    assert!(errs[0].contains("address"), "{}", errs[0]);
}

#[test]
fn uint256_field_vs_integer_literal_passes() {
    let types = types_map(&[("amount", "uint256")]);
    let errs = validate_full(
        "args.amount > 1000000",
        &["amount"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn uint256_field_vs_string_literal_errors() {
    let types = types_map(&[("amount", "uint256")]);
    let errs = validate_full(
        "args.amount < 'foo'",
        &["amount"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("args.amount"), "{}", errs[0]);
}

#[test]
fn bool_field_vs_bool_literal_passes() {
    let types = types_map(&[("flag", "bool")]);
    let errs = validate_full(
        "args.flag == true",
        &["flag"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn bool_field_vs_integer_literal_errors() {
    let types = types_map(&[("flag", "bool")]);
    let errs = validate_full(
        "args.flag == 1",
        &["flag"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert_eq!(errs.len(), 1);
}

#[test]
fn address_field_vs_string_var_passes() {
    let types = types_map(&[("to", "address")]);
    let mut vars = HashMap::new();
    vars.insert(
        "USDT".to_string(),
        serde_json::json!("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
    );
    let errs = validate_full(
        "args.to == vars.USDT",
        &["to"],
        KNOWN_BUILTINS,
        &types,
        &vars,
    );
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn address_field_vs_number_var_errors() {
    let types = types_map(&[("to", "address")]);
    let mut vars = HashMap::new();
    vars.insert("N".to_string(), serde_json::json!(122));
    let errs = validate_full("args.to == vars.N", &["to"], KNOWN_BUILTINS, &types, &vars);
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("args.to"), "{}", errs[0]);
    assert!(errs[0].contains("vars.N"), "{}", errs[0]);
}

#[test]
fn args_fields_with_different_abi_types_error() {
    let types = types_map(&[("amount", "uint256"), ("to", "address")]);
    let errs = validate_full(
        "args.amount == args.to",
        &["amount", "to"],
        KNOWN_BUILTINS,
        &types,
        &no_vars(),
    );
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(errs[0].contains("args.amount"), "{}", errs[0]);
    assert!(errs[0].contains("args.to"), "{}", errs[0]);
}

#[test]
fn no_param_types_skips_type_checking() {
    // When param_types is empty, no type errors even for mismatched literal
    let errs = validate_full(
        "args.to == 122",
        &["to"],
        KNOWN_BUILTINS,
        &no_types(),
        &no_vars(),
    );
    assert!(
        errs.is_empty(),
        "empty param_types = skip type check: {errs:?}"
    );
}
