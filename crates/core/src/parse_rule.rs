use crate::types::{expression_param_names, expression_param_types, AbiItem, JsonRpcResponse};
use std::collections::HashMap;

/// Validate a rule expression against the engine's default `$` builtins
/// ([`KNOWN_BUILTINS`](weituo_expr::analyze::KNOWN_BUILTINS)).
pub fn parse_rule_param(id: serde_json::Value, param: &serde_json::Value) -> JsonRpcResponse {
    parse_rule_param_with_builtins(id, param, weituo_expr::analyze::KNOWN_BUILTINS)
}

/// Like [`parse_rule_param`], but validates `$name(...)` calls against
/// `known_builtins`. Embeddings that install extra builtins via
/// [`Checker::with_builtins_factory`](crate::checker::Checker::with_builtins_factory)
/// pass the default list extended with their own names, e.g.
/// `[KNOWN_BUILTINS, &["is_xxx_approved"]].concat()`.
pub fn parse_rule_param_with_builtins(
    id: serde_json::Value,
    param: &serde_json::Value,
    known_builtins: &[&str],
) -> JsonRpcResponse {
    let expr = match param.get("expr").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return JsonRpcResponse::err(id, -32700, "missing 'expr' field (must be a string)");
        }
    };

    let abi = match param.get("abi") {
        Some(value) => match serde_json::from_value::<AbiItem>(value.clone()) {
            Ok(abi) => Some(abi),
            Err(err) => {
                return JsonRpcResponse::err(id, -32700, format!("invalid 'abi' field: {err}"));
            }
        },
        None => None,
    };
    let param_names: Vec<String> = abi
        .as_ref()
        .map(|item| expression_param_names(&item.inputs))
        .unwrap_or_default();
    let param_refs: Vec<&str> = param_names.iter().map(String::as_str).collect();
    let param_types = abi
        .as_ref()
        .map(|item| expression_param_types(&item.inputs))
        .unwrap_or_default();

    let var_values: HashMap<String, serde_json::Value> = match param.get("vars") {
        Some(value) => match value.as_object() {
            Some(obj) => obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            None => {
                return JsonRpcResponse::err(id, -32700, "'vars' field must be an object");
            }
        },
        None => HashMap::new(),
    };

    let all_errors: Vec<serde_json::Value> = weituo_expr::validate_full(
        &expr,
        &param_refs,
        known_builtins,
        &param_types,
        &var_values,
    )
    .into_iter()
    .map(|err| serde_json::json!({ "expr": expr, "error": err }))
    .collect();

    if all_errors.is_empty() {
        JsonRpcResponse::ok(id, "ok")
    } else {
        JsonRpcResponse::err_with_data(
            id,
            -32702,
            format!("rule validation failed: {} error(s)", all_errors.len()),
            Some(serde_json::Value::Array(all_errors)),
        )
    }
}
