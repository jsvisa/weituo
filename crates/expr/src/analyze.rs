use crate::ast::{AttrSegment, BinOp, Expr};
use alloy_primitives::Address;
/// Semantic analysis of a parsed expression AST.
///
/// Checks:
/// 1. `args.X`         — X must be in param_names (when non-empty).
/// 2. `$builtin`       — name must be in known_builtins.
/// 3. `vars.X`         — X must be in var_values.
/// 4. Type mismatch    — args.X ABI type vs literal/vars kind.
/// 5. `$block().field` — field must be a known block attribute.
use std::collections::HashMap;

/// Top-level transaction context fields available in every expression.
/// Any bare identifier not in this list (and not `args.*` / `vars.*`) is rejected.
pub const KNOWN_CONTEXT_FIELDS: &[(&str, &str)] = &[
    ("from_address", "str"),
    ("to_address", "str"),
    ("chainId", "num"),
    ("value", "num"),
    ("gasPrice", "num"),
    ("gasLimit", "num"),
];

/// Chain family — selects the context-field profile and address validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Family {
    #[default]
    Evm,
    Svm,
    Sui,
}

/// Per-family context-field profiles. `kind`: "str" | "num" | "list".
/// List-valued fields (`accounts`, `type_arguments`, `signers`) are indexed
/// in expressions (`accounts[1]`, `accounts.length`).
pub const SVM_CONTEXT_FIELDS: &[(&str, &str)] = &[
    ("from_address", "str"),
    ("to_address", "str"),
    ("chainId", "str"),
    ("network", "str"),
    ("instruction_index", "num"),
    ("num_instructions", "num"),
    ("signers", "list"),
    ("accounts", "list"),
];

pub const SUI_CONTEXT_FIELDS: &[(&str, &str)] = &[
    ("from_address", "str"),
    ("to_address", "str"),
    ("chainId", "str"),
    ("network", "str"),
    ("command_index", "num"),
    ("num_commands", "num"),
    ("command_kind", "str"),
    ("gas_budget", "num"),
    ("gas_price", "num"),
    ("type_arguments", "list"),
];

/// Context fields known to a family. `chain_fields` extras declared by the
/// embedding layer are appended by the caller, not here.
pub const fn known_context_fields(family: Family) -> &'static [(&'static str, &'static str)] {
    match family {
        Family::Evm => KNOWN_CONTEXT_FIELDS,
        Family::Svm => SVM_CONTEXT_FIELDS,
        Family::Sui => SUI_CONTEXT_FIELDS,
    }
}

/// Decimal block fields from `eth_getBlockByNumber` that are safe to access via `$block().field`.
/// Also the whitelist for the `$block()` builtin's output — the builtin keeps only these fields.
pub const BLOCK_FIELDS: &[&str] = &[
    "number",
    "timestamp",
    "gasUsed",
    "gasLimit",
    "baseFeePerGas",
];

#[derive(Debug, Clone)]
pub struct SemanticError {
    pub message: String,
}

impl std::fmt::Display for SemanticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub const KNOWN_BUILTINS: &[&str] = &[
    "price_of",
    "now_ts",
    "pow",
    "block",
    "gas_price",
    "is_eoa",
    "is_contract",
    "balance_of",
    "erc20_balance_of",
    "erc20_allowance",
    "erc20_total_supply",
    "erc20_decimals",
    "is_approved_token",
    "is_approved_spender",
    "is_not_blocked_spender",
    "is_scam",
    "b32int2addr",
];

/// Plain function calls supported by the evaluator, mapped to their arity.
/// Must stay identical to `eval::supported_functions` — a regression test
/// compares the two lists.
pub const KNOWN_FUNCTIONS: &[(&str, usize)] = &[
    ("len", 1),
    ("lower", 1),
    ("upper", 1),
    ("contains", 2),
    ("startswith", 2),
    ("endswith", 2),
    ("substring", 3),
];

pub fn validate_semantics(
    ast: &Expr,
    param_names: &[&str],
    known_builtins: &[&str],
    param_types: &HashMap<String, String>,
    var_values: &HashMap<String, serde_json::Value>,
) -> Vec<SemanticError> {
    validate_semantics_for(
        ast,
        Family::Evm,
        param_names,
        known_builtins,
        param_types,
        var_values,
    )
}

/// Family-aware semantic validation. `family` selects the context-field
/// profile and the address-literal validation rules.
pub fn validate_semantics_for(
    ast: &Expr,
    family: Family,
    param_names: &[&str],
    known_builtins: &[&str],
    param_types: &HashMap<String, String>,
    var_values: &HashMap<String, serde_json::Value>,
) -> Vec<SemanticError> {
    let mut errors = Vec::new();
    walk(
        ast,
        family,
        param_names,
        known_builtins,
        param_types,
        var_values,
        &mut errors,
    );
    errors
}

fn walk(
    expr: &Expr,
    family: Family,
    params: &[&str],
    builtins: &[&str],
    param_types: &HashMap<String, String>,
    var_values: &HashMap<String, serde_json::Value>,
    errors: &mut Vec<SemanticError>,
) {
    match expr {
        Expr::And(l, r) | Expr::Or(l, r) => {
            walk(l, family, params, builtins, param_types, var_values, errors);
            walk(r, family, params, builtins, param_types, var_values, errors);
        }
        Expr::Arith { lhs: l, rhs: r, .. } => {
            walk(l, family, params, builtins, param_types, var_values, errors);
            walk(r, family, params, builtins, param_types, var_values, errors);
        }
        Expr::BinOp { op, lhs, rhs } => {
            walk(
                lhs,
                family,
                params,
                builtins,
                param_types,
                var_values,
                errors,
            );
            walk(
                rhs,
                family,
                params,
                builtins,
                param_types,
                var_values,
                errors,
            );
            check_type_compat(op, lhs, rhs, family, param_types, var_values, errors);
        }
        Expr::Not(inner) | Expr::Neg(inner) => {
            walk(
                inner,
                family,
                params,
                builtins,
                param_types,
                var_values,
                errors,
            );
        }
        Expr::In { val, list, .. } => {
            walk(
                val,
                family,
                params,
                builtins,
                param_types,
                var_values,
                errors,
            );
            for item in list {
                walk(
                    item,
                    family,
                    params,
                    builtins,
                    param_types,
                    var_values,
                    errors,
                );
            }
            check_in_type_compat(val, list, family, param_types, var_values, errors);
        }
        Expr::Builtin { name, args, path } => {
            if !builtins.contains(&name.as_str()) {
                errors.push(SemanticError {
                    message: format!(
                        "unknown builtin '${}' — available: {}",
                        name,
                        builtins.join(", ")
                    ),
                });
            }
            // Validate the first field segment for builtins with a known return schema.
            if let (Some(AttrSegment::Field(field)), "block") = (path.first(), name.as_str()) {
                if !BLOCK_FIELDS.contains(&field.as_str()) {
                    errors.push(SemanticError {
                        message: format!(
                            "unknown field '$block().{}' — known fields: {}",
                            field,
                            BLOCK_FIELDS.join(", ")
                        ),
                    });
                }
            }
            for a in args {
                walk(a, family, params, builtins, param_types, var_values, errors);
            }
        }
        Expr::FuncCall { name, args } => {
            match KNOWN_FUNCTIONS.iter().find(|(n, _)| *n == name.as_str()) {
                Some((_, arity)) => {
                    if args.len() != *arity {
                        errors.push(SemanticError {
                            message: format!(
                                "{name}() expects {arity} argument(s), got {}",
                                args.len()
                            ),
                        });
                    }
                }
                None => {
                    let available: Vec<&str> = KNOWN_FUNCTIONS.iter().map(|(n, _)| *n).collect();
                    errors.push(SemanticError {
                        message: format!(
                            "unknown function '{name}()' — available: {}",
                            available.join(", ")
                        ),
                    });
                }
            }
            for a in args {
                walk(a, family, params, builtins, param_types, var_values, errors);
            }
        }
        Expr::Attribute(parts) => {
            let root = parts[0].as_field();
            let fields = known_context_fields(family);

            // Bare identifier — must be a known transaction context field
            if parts.len() == 1 {
                if let Some(name) = root {
                    let known = fields.iter().any(|(f, _)| *f == name);
                    if !known {
                        let available: Vec<&str> = fields.iter().map(|(f, _)| *f).collect();
                        errors.push(SemanticError {
                            message: format!(
                                "unknown identifier '{}' — context fields: {}",
                                name,
                                available.join(", ")
                            ),
                        });
                    }
                }
                return;
            }

            // Multi-segment path: root must be args, vars, or a known context field root
            let known_root = matches!(root, Some("args") | Some("vars"))
                || root.is_some_and(|r| fields.iter().any(|(f, _)| *f == r));
            if !known_root {
                if let Some(name) = root {
                    errors.push(SemanticError {
                        message: format!(
                            "unknown identifier '{}' — context fields: {}; use args.* for calldata, vars.* for user-defined variables",
                            name,
                            fields.iter().map(|(f, _)| *f).collect::<Vec<_>>().join(", ")
                        ),
                    });
                }
                return;
            }

            // Check args.X against ABI parameter names
            if root == Some("args") && !params.is_empty() {
                if let Some(field) = parts[1].as_field() {
                    if !params.contains(&field) {
                        errors.push(SemanticError {
                            message: format!(
                                "unknown arg 'args.{}' — ABI parameters: {}",
                                field,
                                params.join(", ")
                            ),
                        });
                    }
                }
                if !param_types.is_empty() {
                    if let Some(path) = unknown_args_attr_path(expr, param_types) {
                        errors.push(SemanticError {
                            message: format!("unknown arg '{path}'"),
                        });
                    }
                }
            }

            // Check vars.X against defined var names
            if root == Some("vars") {
                if let Some(field) = parts[1].as_field() {
                    if !var_values.contains_key(field) {
                        let var_names = var_values
                            .keys()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(", ");
                        let msg = if var_names.is_empty() {
                            format!("undefined var 'vars.{field}' — no vars defined")
                        } else {
                            format!("undefined var 'vars.{field}' — defined vars: [{var_names}]")
                        };
                        errors.push(SemanticError { message: msg });
                    }
                }
            }
        }
        Expr::Lit(_) => {}
    }
}

// ── Type checking ────────────────────────────────────────────────────────────

fn check_type_compat(
    _op: &BinOp,
    lhs: &Expr,
    rhs: &Expr,
    family: Family,
    param_types: &HashMap<String, String>,
    var_values: &HashMap<String, serde_json::Value>,
    errors: &mut Vec<SemanticError>,
) {
    // ── args.X type check (requires ABI) ─────────────────────────────────────
    if !param_types.is_empty() && (is_args_attr(lhs) || is_args_attr(rhs)) {
        if is_args_attr(lhs) && is_args_attr(rhs) {
            if let (Some((lhs_solidity_type, lhs_path)), Some((rhs_solidity_type, rhs_path))) = (
                solidity_type_for_args_attr(lhs, param_types),
                solidity_type_for_args_attr(rhs, param_types),
            ) {
                let lhs_kind = solidity_kind(lhs_solidity_type);
                let rhs_kind = solidity_kind(rhs_solidity_type);
                if lhs_kind != rhs_kind && lhs_kind != "unknown" && rhs_kind != "unknown" {
                    errors.push(SemanticError {
                        message: format!(
                            "type mismatch: '{}' is {} ({}) but compared to '{}' which is {} ({})",
                            lhs_path,
                            lhs_solidity_type,
                            lhs_kind,
                            rhs_path,
                            rhs_solidity_type,
                            rhs_kind
                        ),
                    });
                }
            }
            return;
        }

        let (args_expr, other_expr) = if is_args_attr(lhs) {
            (lhs, rhs)
        } else {
            (rhs, lhs)
        };
        if let Some((solidity_type, arg_path)) = solidity_type_for_args_attr(args_expr, param_types)
        {
            let expected = solidity_kind(solidity_type);
            if let Some(actual) = expr_kind(other_expr, family, var_values) {
                if expected != actual && expected != "unknown" {
                    let detail = format_other(other_expr, actual);
                    errors.push(SemanticError {
                        message: format!(
                            "type mismatch: '{}' is {} ({}) but compared to {}",
                            arg_path, solidity_type, expected, detail
                        ),
                    });
                } else if is_address_like(solidity_type) {
                    if let Some(message) = invalid_address_message(other_expr, var_values, family) {
                        errors.push(SemanticError {
                            message: format!("invalid address for '{}': {message}", arg_path),
                        });
                    }
                }
            }
        }
        return;
    }

    // ── context field type check (always active) ──────────────────────────────
    let (ctx_expr, other_expr) = if is_context_field(lhs, family) {
        (lhs, rhs)
    } else if is_context_field(rhs, family) {
        (rhs, lhs)
    } else {
        return;
    };

    if let Some(expected) = context_field_kind(ctx_expr, family) {
        // List-valued fields (accounts, type_arguments, …) are compared
        // element-wise in practice; skip whole-value kind checks for them.
        if expected == "list" {
            return;
        }
        if let Some(actual) = expr_kind(other_expr, family, var_values) {
            if expected != actual {
                let name = context_field_name(ctx_expr).unwrap_or("?");
                let detail = format_other(other_expr, actual);
                errors.push(SemanticError {
                    message: format!(
                        "type mismatch: '{}' is {} but compared to {}",
                        name, expected, detail
                    ),
                });
            }
        }
    }
}

/// Type-check `val in [e1, e2, …]` — every list element must match val's type.
fn check_in_type_compat(
    val: &Expr,
    list: &[Expr],
    family: Family,
    param_types: &HashMap<String, String>,
    var_values: &HashMap<String, serde_json::Value>,
    errors: &mut Vec<SemanticError>,
) {
    // Determine the expected kind of the LHS (`val`)
    let expected: &'static str = if is_context_field(val, family) {
        match context_field_kind(val, family) {
            Some(k) => k,
            None => return,
        }
    } else if !param_types.is_empty() && is_args_attr(val) {
        let (solidity_type, _) = match solidity_type_for_args_attr(val, param_types) {
            Some(value) => value,
            None => return,
        };
        solidity_kind(solidity_type)
    } else {
        return; // can't determine val's type — skip
    };

    if expected == "unknown" || expected == "list" {
        return;
    }

    for item in list {
        if let Some(actual) = expr_kind(item, family, var_values) {
            if actual != expected {
                let detail = format_other(item, actual);
                let val_name = if is_context_field(val, family) {
                    context_field_name(val).unwrap_or("val").to_string()
                } else {
                    solidity_type_for_args_attr(val, param_types)
                        .map_or("val".to_string(), |(_, path)| path)
                };
                errors.push(SemanticError {
                    message: format!(
                        "type mismatch: '{}' is {} but list contains {}",
                        val_name, expected, detail
                    ),
                });
                return; // report once per `in` expression, not once per element
            }
        }
        if let Some(("address", path)) = solidity_type_for_args_attr(val, param_types) {
            if let Some(message) = invalid_address_message(item, var_values, family) {
                errors.push(SemanticError {
                    message: format!("invalid address for '{path}': {message}"),
                });
                return;
            }
        }
    }
}

fn is_args_attr(expr: &Expr) -> bool {
    matches!(expr, Expr::Attribute(parts) if parts.len() >= 2 && parts[0].as_field() == Some("args"))
}

fn solidity_type_for_args_attr<'a>(
    expr: &Expr,
    param_types: &'a HashMap<String, String>,
) -> Option<(&'a str, String)> {
    match resolve_args_attr(expr, param_types)? {
        ArgsAttrResolution::Known {
            solidity_type,
            path,
        } => Some((solidity_type, path)),
        ArgsAttrResolution::Unknown { .. } => None,
    }
}

fn unknown_args_attr_path(expr: &Expr, param_types: &HashMap<String, String>) -> Option<String> {
    match resolve_args_attr(expr, param_types)? {
        ArgsAttrResolution::Known { .. } => None,
        ArgsAttrResolution::Unknown { path } => Some(path),
    }
}

enum ArgsAttrResolution<'a> {
    Known {
        solidity_type: &'a str,
        path: String,
    },
    Unknown {
        path: String,
    },
}

fn resolve_args_attr<'a>(
    expr: &Expr,
    param_types: &'a HashMap<String, String>,
) -> Option<ArgsAttrResolution<'a>> {
    if let Expr::Attribute(parts) = expr {
        if parts[0].as_field() != Some("args") {
            return None;
        }
        let first_field = parts.get(1)?.as_field()?;
        let mut field_path = first_field.to_string();
        let mut display_path = format!("args.{first_field}");
        let Some(mut solidity_type) = param_types.get(&field_path).map(String::as_str) else {
            return Some(ArgsAttrResolution::Unknown { path: display_path });
        };

        for segment in &parts[2..] {
            match segment {
                AttrSegment::Field(field) => {
                    display_path.push('.');
                    display_path.push_str(field);
                    if field == "length" && is_array_type(solidity_type) {
                        solidity_type = "uint256";
                        continue;
                    }
                    field_path.push('.');
                    field_path.push_str(field);
                    let Some(component_type) = param_types.get(&field_path).map(String::as_str)
                    else {
                        return Some(ArgsAttrResolution::Unknown { path: display_path });
                    };
                    solidity_type = component_type;
                }
                AttrSegment::Index(index) => {
                    display_path.push('[');
                    display_path.push_str(&index.to_string());
                    display_path.push(']');
                    let Some(element_type) = array_element_type(solidity_type) else {
                        return Some(ArgsAttrResolution::Unknown { path: display_path });
                    };
                    solidity_type = element_type;
                }
            }
        }
        return Some(ArgsAttrResolution::Known {
            solidity_type,
            path: display_path,
        });
    }
    None
}

fn is_array_type(solidity_type: &str) -> bool {
    solidity_type.ends_with(']')
}

fn array_element_type(solidity_type: &str) -> Option<&str> {
    if let Some(element_type) = solidity_type.strip_suffix("[]") {
        return Some(element_type);
    }
    let open = solidity_type.rfind('[')?;
    solidity_type
        .ends_with(']')
        .then_some(&solidity_type[..open])
}

fn is_context_field(expr: &Expr, family: Family) -> bool {
    let fields = known_context_fields(family);
    matches!(expr, Expr::Attribute(parts)
        if parts.len() == 1
        && parts[0].as_field().is_some_and(|n| fields.iter().any(|(f, _)| *f == n))
    )
}

fn context_field_name(expr: &Expr) -> Option<&str> {
    if let Expr::Attribute(parts) = expr {
        if parts.len() == 1 {
            return parts[0].as_field();
        }
    }
    None
}

fn context_field_kind(expr: &Expr, family: Family) -> Option<&'static str> {
    let name = context_field_name(expr)?;
    known_context_fields(family)
        .iter()
        .find(|(f, _)| *f == name)
        .map(|(_, k)| *k)
}

fn format_other(expr: &Expr, actual: &str) -> String {
    match expr {
        Expr::Attribute(parts) if parts[0].as_field() == Some("vars") => {
            let var_name = parts.get(1).and_then(|p| p.as_field()).unwrap_or("?");
            format!("'vars.{}' ({})", var_name, actual)
        }
        _ => format!("{} literal", actual),
    }
}

/// Types whose decoded values are address-like strings: EVM `address`,
/// Move `address`/`Address` (normalized renderings), Anchor `pubkey`.
fn is_address_like(ty: &str) -> bool {
    matches!(ty, "address" | "Address" | "pubkey")
}

/// Maps a Solidity ABI type string to the runtime value kind. Extended with
/// Anchor (SVM) and normalized-Move (Sui) type names so per-family
/// `param_types` maps type-check the same way.
fn solidity_kind(ty: &str) -> &'static str {
    if ty == "address" || ty == "Address" || ty == "pubkey" || ty == "string" {
        "str"
    } else if ty == "bool" || ty == "Bool" {
        "bool"
    } else if is_uint_or_int_type(ty) {
        "num"
    } else if ty.starts_with("bytes") {
        // EVM bytes/bytesN and similar opaque binaries
        "str"
    } else if ty.contains("::") {
        // Move struct type (e.g. "0x2::coin::Coin<0x2::sui::SUI>") — opaque string value
        "str"
    } else {
        "unknown"
    }
}

/// `uint*`/`int*` (EVM ABI), `u8`…`u256`/`i8`…`i256` (Anchor IDL),
/// `U8`…/`I8`… (normalized Move, matched case-insensitively).
fn is_uint_or_int_type(ty: &str) -> bool {
    let lower = ty.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("uint") {
        return rest.is_empty() || rest.bytes().all(|b| b.is_ascii_digit());
    }
    if let Some(rest) = lower.strip_prefix("int") {
        return rest.is_empty() || rest.bytes().all(|b| b.is_ascii_digit());
    }
    match lower.strip_prefix('u').or_else(|| lower.strip_prefix('i')) {
        Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// Returns the kind of the expression if it can be determined statically.
/// Returns None for dynamic expressions (args.X, builtins, function calls).
fn expr_kind(
    expr: &Expr,
    family: Family,
    var_values: &HashMap<String, serde_json::Value>,
) -> Option<&'static str> {
    match expr {
        Expr::Lit(lit) => Some(literal_kind(lit)),
        Expr::Attribute(parts) => {
            if parts.len() == 1 {
                // Bare context field (from_address, value, …)
                context_field_kind(expr, family)
            } else if parts[0].as_field() == Some("vars") && parts.len() == 2 {
                let name = parts[1].as_field()?;
                var_values.get(name).map(json_kind)
            } else {
                None // args.X or other attribute — can't determine statically
            }
        }
        _ => None,
    }
}

const fn literal_kind(lit: &crate::ast::Literal) -> &'static str {
    use crate::ast::Literal;
    match lit {
        Literal::Str(_) => "str",
        Literal::Int(_) | Literal::BigUint(_) | Literal::Float(_) => "num",
        Literal::Bool(_) => "bool",
        Literal::Null => "unknown",
    }
}

fn invalid_address_message(
    expr: &Expr,
    var_values: &HashMap<String, serde_json::Value>,
    family: Family,
) -> Option<String> {
    let value = match expr {
        Expr::Lit(crate::ast::Literal::Str(value)) => value.as_str(),
        Expr::Attribute(parts) if parts.len() == 2 && parts[0].as_field() == Some("vars") => {
            var_values.get(parts[1].as_field()?)?.as_str()?
        }
        _ => return None,
    };

    validate_address_value(value, family)
}

/// Family-aware address-literal validation. Returns the error message when
/// the literal is not a valid address for the family.
fn validate_address_value(value: &str, family: Family) -> Option<String> {
    match family {
        Family::Evm => {
            if value.len() != 42 {
                return Some(format!("expected 42 characters, got {}", value.len()));
            }
            let normalized = value.to_lowercase();
            normalized
                .parse::<Address>()
                .err()
                .map(|_| "address is invalid".to_string())
        }
        Family::Svm => {
            // base58: 32-byte pubkeys encode to 32–44 chars from the
            // base58 alphabet (0, O, I, l are excluded).
            const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            if !(32..=44).contains(&value.len()) {
                return Some(format!(
                    "expected 32–44 base58 characters, got {}",
                    value.len()
                ));
            }
            if !value.bytes().all(|b| BASE58.contains(&b)) {
                return Some("address contains invalid base58 characters".to_string());
            }
            None
        }
        Family::Sui => {
            // Full 64-nibble lowercase hex, optional 0x prefix. Short forms
            // are rejected at load so literals match normalized rule keys.
            let hex = value.strip_prefix("0x").unwrap_or(value);
            if hex.len() != 64 {
                return Some(format!(
                    "expected the full 64-nibble lowercase hex form, got {} characters",
                    hex.len()
                ));
            }
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some("address contains invalid hex characters".to_string());
            }
            None
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::String(_) => "str",
        serde_json::Value::Number(_) => "num",
        serde_json::Value::Bool(_) => "bool",
        _ => "unknown",
    }
}
