//! Tests for waf_parseRule semantic validation.

use std::collections::HashMap;
use weituo_expr::{
    analyze::{KNOWN_BUILTINS, KNOWN_FUNCTIONS},
    eval::supported_functions,
    validate_full, validate_syntax,
};

const fn no_abi() -> Vec<&'static str> {
    vec![]
}

fn vfull(expr: &str, params: &[&str]) -> Vec<String> {
    validate_full(
        expr,
        params,
        KNOWN_BUILTINS,
        &HashMap::new(),
        &HashMap::new(),
    )
}

// ── Syntax-only ───────────────────────────────────────────────────────────────

#[test]
fn syntax_ok() {
    assert!(validate_syntax("args.value < 100").is_none());
}

#[test]
fn syntax_error() {
    assert!(validate_syntax("args.value <").is_some());
}

// ── Syntax error hints ────────────────────────────────────────────────────────

fn syntax_err(expr: &str) -> String {
    validate_syntax(expr).expect("expected a syntax error")
}

#[test]
fn hint_builtin_field_without_parens() {
    // $block.timestamp() → $block().timestamp
    let msg = syntax_err("args.deadline <= $block.timestamp()");
    assert!(msg.contains("hint:"), "{msg}");
    assert!(msg.contains("$block().timestamp"), "{msg}");
}

#[test]
fn hint_single_equals() {
    let msg = syntax_err("args.value = 5");
    assert!(msg.contains("=="), "{msg}");
}

#[test]
fn hint_js_boolean_operators() {
    assert!(syntax_err("args.a > 0 && args.b > 1").contains("`and`"));
    assert!(syntax_err("args.a > 0 || args.b > 1").contains("`or`"));
    assert!(syntax_err("!args.ok").contains("`not`"));
}

#[test]
fn hint_unbalanced_parens() {
    assert!(syntax_err("(args.value > 0").contains("closing"));
    assert!(syntax_err("args.value > 0)").contains("`)"));
}

#[test]
fn hint_trailing_operator() {
    assert!(syntax_err("args.value <").contains("ends unexpectedly"));
}

// ── Valid expressions (no ABI) ────────────────────────────────────────────────

#[test]
fn valid_simple_comparison() {
    let errs = vfull("args.value < 100", &no_abi());
    assert!(errs.is_empty());
}

#[test]
fn valid_known_builtin() {
    let errs = vfull("$price_of(args.token) > 100", &no_abi());
    assert!(errs.is_empty());
}

#[test]
fn is_scam_is_a_known_builtin() {
    let errs = vfull("$is_scam(args.spender)", &no_abi());
    assert!(errs.is_empty(), "unexpected validation errors: {errs:?}");
}

#[test]
fn is_scam_addr_is_no_longer_a_known_builtin() {
    let errs = vfull("$is_scam_addr(args.spender)", &no_abi());
    assert!(errs.iter().any(|error| error.contains("unknown builtin")));
}

#[test]
fn valid_context_fields() {
    // from_address, to_address, chainId, value are always valid
    let errs = vfull("from_address == '0xdeadbeef'", &no_abi());
    assert!(errs.is_empty());
}

// ── Unknown builtin ───────────────────────────────────────────────────────────

#[test]
fn unknown_builtin_is_error() {
    let errs = vfull("$does_not_exist(args.x) > 0", &no_abi());
    assert!(!errs.is_empty());
    assert!(
        errs[0].contains("does_not_exist"),
        "error should mention the name: {:?}",
        errs
    );
}

#[test]
fn unknown_builtin_mentions_available() {
    let errs = vfull("$foobar(x)", &no_abi());
    assert!(!errs.is_empty());
    assert!(
        errs[0].contains("price_of"),
        "error should list known builtins: {:?}",
        errs
    );
}

#[test]
fn all_known_builtins_accepted() {
    // Each known builtin used in a minimal expression should produce no builtin errors
    for name in KNOWN_BUILTINS {
        let expr = format!("${name}(args.x)");
        let errs = vfull(&expr, &no_abi());
        // Only args.x might be flagged if ABI provided — but with empty ABI it's skipped
        assert!(errs.is_empty(), "known builtin ${name} flagged: {errs:?}");
    }
}

// ── Plain function calls (string functions) ──────────────────────────────────

#[test]
fn known_functions_accepted() {
    let exprs = [
        "len(args.to) == 42",
        "lower(args.to) == '0xabc'",
        "upper(args.to) == '0XABC'",
        "contains(args.to, '0x')",
        "startswith(args.to, '0x')",
        "endswith(args.to, 'abc')",
        "substring(args.to, 0, 2) == '0x'",
    ];
    for expr in exprs {
        let errs = vfull(expr, &no_abi());
        assert!(errs.is_empty(), "known function flagged: {expr} — {errs:?}");
    }
}

#[test]
fn unknown_function_is_error() {
    let errs = vfull("sqrt(args.x)", &no_abi());
    assert!(!errs.is_empty());
    assert!(
        errs[0].contains("sqrt"),
        "error should mention the name: {:?}",
        errs
    );
}

#[test]
fn unknown_function_mentions_available() {
    let errs = vfull("bogus(args.x)", &no_abi());
    assert!(!errs.is_empty());
    assert!(
        errs[0].contains("substring"),
        "error should list available functions: {:?}",
        errs
    );
}

#[test]
fn function_wrong_arity_is_error() {
    let errs = vfull("contains('a')", &no_abi());
    assert!(!errs.is_empty());
    assert!(
        errs[0].contains("contains"),
        "error should mention the function: {:?}",
        errs
    );
}

#[test]
fn known_functions_match_eval_support() {
    // analyze::KNOWN_FUNCTIONS (validation) and eval::supported_functions
    // (runtime dispatch) are two lists that must never drift apart.
    let mut declared: Vec<(&str, usize)> = KNOWN_FUNCTIONS.to_vec();
    let mut supported: Vec<(&str, usize)> = supported_functions()
        .iter()
        .map(|(n, a)| (*n, *a))
        .collect();
    declared.sort_unstable();
    supported.sort_unstable();
    assert_eq!(
        declared, supported,
        "analyze::KNOWN_FUNCTIONS and eval::supported_functions must stay in sync"
    );
}

// ── ABI-aware args.X validation ───────────────────────────────────────────────

#[test]
fn valid_args_field_with_abi() {
    let params = vec!["to", "amount"];
    let errs = vfull("args.amount < 1e9", &params);
    assert!(
        errs.is_empty(),
        "valid args.amount should not error: {errs:?}"
    );
}

#[test]
fn unknown_args_field_with_abi() {
    let params = vec!["to", "amount"];
    let errs = vfull("args.typo < 1e9", &params);
    assert!(!errs.is_empty());
    assert!(
        errs[0].contains("typo"),
        "should mention the unknown field: {:?}",
        errs
    );
    assert!(
        errs[0].contains("amount"),
        "should list available params: {:?}",
        errs
    );
}

#[test]
fn args_without_abi_is_unchecked() {
    // When no ABI provided, args.anything should NOT be flagged
    let errs = vfull("args.whatever < 1e9", &no_abi());
    assert!(
        errs.is_empty(),
        "args.x without ABI should not error: {errs:?}"
    );
}

#[test]
fn multiple_args_fields_checked() {
    let params = vec!["to", "amount"];
    let errs = vfull("args.to != '0x0' and args.badfield > 0", &params);
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("badfield"));
}

#[test]
fn nested_args_field() {
    // args.spender in list — spender must be a known param
    let params = vec!["spender", "amount"];
    let errs = vfull("args.spender in ['0xAA', '0xBB']", &params);
    assert!(errs.is_empty());
}

#[test]
fn nested_args_field_unknown() {
    let params = vec!["spender", "amount"];
    let errs = vfull("args.wrongField in ['0xAA', '0xBB']", &params);
    assert!(!errs.is_empty());
    assert!(errs[0].contains("wrongField"));
}

// ── Combined syntax + semantic ────────────────────────────────────────────────

#[test]
fn syntax_error_reported_before_semantic() {
    let params = vec!["amount"];
    let errs = vfull("args.amount <", &params);
    // syntax error takes precedence — only one error returned
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("syntax error"), "{errs:?}");
}

#[test]
fn both_builtin_and_arg_error_reported() {
    let params = vec!["amount"];
    let errs = vfull("$badbuiltin(args.badarg) > 0", &params);
    assert_eq!(errs.len(), 2, "should report both errors: {errs:?}");
}

#[test]
fn erc20_decimals_used_correctly() {
    let params = vec!["token", "owner"];
    let errs = vfull(
        "$erc20_balance_of(args.token, args.owner) / $pow(10, $erc20_decimals(args.token)) <= 1000000",
        &params,
    );
    assert!(
        errs.is_empty(),
        "valid erc20 expression should not error: {errs:?}"
    );
}

#[test]
fn price_of_with_unknown_arg() {
    let params = vec!["token"];
    let errs = vfull("$price_of(args.wrongName) > 100", &params);
    assert!(!errs.is_empty());
    assert!(errs[0].contains("wrongName"));
}

// ── AND-list format ───────────────────────────────────────────────────────────
// (each expression validated independently)

#[test]
fn and_list_all_valid() {
    let params = vec!["amount", "to"];
    for expr in &["args.amount > 0", "args.to != '0x0'"] {
        let errs = vfull(expr, &params);
        assert!(errs.is_empty(), "{expr}: {errs:?}");
    }
}

#[test]
fn and_list_one_invalid() {
    let params = vec!["amount"];
    let errs = vfull("args.oops > 0", &params);
    assert!(!errs.is_empty());
}

// ── Task 1: nested tuple / array.length type checker ─────────────────────────

#[test]
fn nested_tuple_field_no_type_error() {
    let mut types = HashMap::new();
    types.insert("params".to_string(), "tuple".to_string());
    types.insert("params.recipient".to_string(), "address".to_string());
    let errs = validate_full(
        "args.params.recipient == '0xdAC17F958D2ee523a2206206994597C13D831ec7'",
        &["params"],
        KNOWN_BUILTINS,
        &types,
        &HashMap::new(),
    );
    assert!(errs.is_empty(), "unexpected errors: {errs:?}");
}

#[test]
fn nested_tuple_num_field_no_type_error() {
    let mut types = HashMap::new();
    types.insert("desc".to_string(), "tuple".to_string());
    types.insert("desc.dstReceiver".to_string(), "address".to_string());
    types.insert("desc.minReturnAmount".to_string(), "uint256".to_string());
    let errs = validate_full(
        "args.desc.dstReceiver == from_address and args.desc.minReturnAmount > 0",
        &["desc"],
        KNOWN_BUILTINS,
        &types,
        &HashMap::new(),
    );
    assert!(errs.is_empty(), "unexpected errors: {errs:?}");
}

#[test]
fn array_length_field_no_type_error() {
    let mut types = HashMap::new();
    types.insert("users".to_string(), "address[]".to_string());
    let errs = validate_full(
        "args.users.length == 1",
        &["users"],
        KNOWN_BUILTINS,
        &types,
        &HashMap::new(),
    );
    assert!(errs.is_empty(), "unexpected errors: {errs:?}");
}

// ── Task 2: $builtin().field syntax ──────────────────────────────────────────

// ── Context field validation ──────────────────────────────────────────────────

#[test]
fn in_operator_type_mismatch_context_field() {
    // from_address is str; list contains ints → mismatch
    let errs = vfull("from_address in [0, 1]", &[]);
    assert!(
        !errs.is_empty(),
        "from_address in [0,1] should be a type error"
    );
    assert!(errs[0].contains("type mismatch"), "got: {}", errs[0]);

    // value is num; list contains strings → mismatch
    let errs2 = vfull("value in ['abc', 'def']", &[]);
    assert!(!errs2.is_empty(), "value in ['abc'] should be a type error");
    assert!(errs2[0].contains("type mismatch"), "got: {}", errs2[0]);
}

#[test]
fn in_operator_type_ok() {
    // from_address in list of address strings — ok
    let errs = vfull("from_address in ['0xaaa', '0xbbb']", &[]);
    assert!(
        errs.is_empty(),
        "from_address in [str,str] should be valid, got: {errs:?}"
    );

    // value in list of ints — ok
    let errs2 = vfull("value in [0, 1000]", &[]);
    assert!(
        errs2.is_empty(),
        "value in [num,num] should be valid, got: {errs2:?}"
    );
}

#[test]
fn unknown_bare_identifier_is_error() {
    let errs = vfull("valu2 == 0", &[]);
    assert!(!errs.is_empty(), "unknown identifier should error");
    assert!(
        errs[0].contains("unknown identifier 'valu2'"),
        "got: {}",
        errs[0]
    );
}

#[test]
fn known_context_fields_ok() {
    for expr in &[
        "from_address == '0xdeadbeef'",
        "to_address == from_address",
        "value > 0",
        "chainId == 1",
        "gasPrice < 100",
        "gasLimit > 0",
    ] {
        let errs = vfull(expr, &[]);
        assert!(errs.is_empty(), "{expr} should be valid, got: {errs:?}");
    }
}

#[test]
fn context_field_type_mismatch_str_vs_int() {
    // from_address is "str"; comparing with int literal is a mismatch
    let errs = vfull("from_address == 0", &[]);
    assert!(!errs.is_empty(), "from_address == 0 should be a type error");
    assert!(errs[0].contains("type mismatch"), "got: {}", errs[0]);
    assert!(errs[0].contains("from_address"), "got: {}", errs[0]);
}

#[test]
fn context_field_type_mismatch_num_vs_str() {
    // value is "num"; comparing with string literal is a mismatch
    let errs = vfull("value == 'abc'", &[]);
    assert!(!errs.is_empty(), "value == 'abc' should be a type error");
    assert!(errs[0].contains("type mismatch"), "got: {}", errs[0]);
}

#[test]
fn unknown_root_in_path_is_error() {
    let errs = vfull("event.from_address == from_address", &[]);
    assert!(!errs.is_empty(), "unknown root 'event' should error");
    assert!(
        errs[0].contains("unknown identifier 'event'"),
        "got: {}",
        errs[0]
    );
}

#[test]
fn block_unknown_field_is_error() {
    let errs = validate_full(
        "args.deadline <= $block().tx + 86400",
        &["deadline"],
        KNOWN_BUILTINS,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert!(
        !errs.is_empty(),
        "unknown $block() field should be an error"
    );
    assert!(
        errs[0].contains("unknown field '$block().tx'"),
        "got: {}",
        errs[0]
    );
}

#[test]
fn block_known_fields_ok() {
    for field in &[
        "timestamp",
        "number",
        "gasUsed",
        "gasLimit",
        "baseFeePerGas",
    ] {
        let expr = format!("$block().{field} > 0");
        let errs = validate_full(&expr, &[], KNOWN_BUILTINS, &HashMap::new(), &HashMap::new());
        assert!(
            errs.is_empty(),
            "$block().{field} should be valid, got: {errs:?}"
        );
    }
}

#[test]
fn builtin_field_access_parses_ok() {
    assert!(
        validate_syntax("$block().timestamp > 0").is_none(),
        "number field"
    );
    assert!(
        validate_syntax("$block().number > 0").is_none(),
        "number field 2"
    );
    assert!(
        validate_syntax("args.deadline <= $block().timestamp + 3*24*3600").is_none(),
        "arithmetic on builtin field"
    );
}

#[test]
fn builtin_field_access_semantics_ok() {
    let errs = validate_full(
        "args.deadline <= $block().timestamp + 86400",
        &["deadline"],
        KNOWN_BUILTINS,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert!(errs.is_empty(), "unexpected semantic errors: {errs:?}");
}

#[test]
fn unknown_builtin_still_errors_with_path() {
    let errs = validate_full(
        "$not_a_builtin().field > 0",
        &[],
        KNOWN_BUILTINS,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert!(!errs.is_empty());
    assert!(errs[0].contains("not_a_builtin"));
}

#[test]
fn depth2_type_check_still_fires() {
    let mut types = HashMap::new();
    types.insert("token".to_string(), "address".to_string());
    let errs = validate_full(
        "args.token == 42",
        &["token"],
        KNOWN_BUILTINS,
        &types,
        &HashMap::new(),
    );
    assert!(
        !errs.is_empty(),
        "type mismatch should be reported at depth 2"
    );
    assert!(errs[0].contains("type mismatch"));
}

// ── Task 3: <<, >>, % operators ──────────────────────────────────────────────

#[test]
fn modulo_operator_parses() {
    assert!(
        validate_syntax("args.amount % 32 == 0").is_none(),
        "basic mod"
    );
    assert!(
        validate_syntax("args.amount % 32 == 0 and args.to == from_address").is_none(),
        "mod in conjunction"
    );
    assert!(
        validate_syntax("args.to == from_address and args.amount % 32 == 0").is_none(),
        "mod at end of conjunction"
    );
}

#[test]
fn shl_operator_parses() {
    assert!(
        validate_syntax("args.amount <= 1 << 128").is_none(),
        "shl 128"
    );
    assert!(
        validate_syntax("args.amount != ((1 << 256) - 1)").is_none(),
        "uint256 max pattern"
    );
    assert!(
        validate_syntax("args.totalAmount > 0 and args.totalAmount != ((1 << 256) - 1)").is_none(),
        "shl in conjunction"
    );
}

#[test]
fn shr_operator_parses() {
    assert!(validate_syntax("args.amount >> 1 > 0").is_none(), "shr");
}

#[test]
fn modulo_precedence_binds_tighter_than_cmp() {
    // "amount % 32 == 0" must parse as "(amount % 32) == 0"
    assert!(validate_syntax("args.amount % 32 == 0").is_none());
}

#[test]
fn shl_precedence_below_add() {
    assert!(validate_syntax("(1 + 2) << 3 > 0").is_none());
    assert!(validate_syntax("args.amount <= 1 << 128").is_none());
}

// ── Task 4: # comment stripping ──────────────────────────────────────────────

#[test]
fn comment_full_line_stripped() {
    let expr = "# this whole line is a comment\nargs.value > 0";
    assert!(validate_syntax(expr).is_none(), "full comment line");
}

#[test]
fn comment_end_of_line_stripped() {
    let expr = "args.amount > 0 # check the amount";
    assert!(validate_syntax(expr).is_none(), "end-of-line comment");
}

#[test]
fn comment_mid_body_stripped() {
    let expr = "args.users.length == 1 and args.users[0] == from_address\n  # Acorn";
    assert!(
        validate_syntax(expr).is_none(),
        "mid-body comment line must be stripped"
    );
}

#[test]
fn comment_between_clauses() {
    let expr = "args.amount > 0\n# ensure recipient\nand args.to == from_address";
    assert!(validate_syntax(expr).is_none(), "comment between clauses");
}

#[test]
fn hash_inside_single_quoted_string_preserved() {
    assert!(validate_syntax("args.symbol == '#ETH'").is_none());
}

#[test]
fn hash_inside_double_quoted_string_preserved() {
    assert!(validate_syntax("args.symbol == \"#ETH\"").is_none());
}

#[test]
fn comment_after_quoted_string() {
    let expr = "args.token == '0xdeadbeef' # token check";
    assert!(validate_syntax(expr).is_none());
}
