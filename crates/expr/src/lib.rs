pub mod analyze;
pub mod ast;
pub mod context;
pub mod eval;
pub mod parser;

use anyhow::Result;
use std::{collections::HashMap, sync::Arc};

pub use context::{BuiltinProvider, EvalContext};
pub use eval::{Evaluator, Explain, Value};
pub use parser::parse;

/// Strip Python-style `# ...` line comments from an expression string.
/// Respects single- and double-quoted string literals (# inside quotes is kept).
fn strip_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.lines() {
        out.push_str(strip_line_comment(line));
        out.push('\n');
    }
    out
}

fn strip_line_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

/// Parse and evaluate a single expression. Returns `true` = transaction **denied**.
pub async fn evaluate(
    expr: &str,
    ctx: &EvalContext,
    builtins: Arc<dyn BuiltinProvider>,
) -> Result<bool> {
    let ast = parse(expr)?;
    Ok(Evaluator::new(builtins).eval(&ast, ctx).await?.as_bool())
}

/// Parse and evaluate a single expression, returning whether it passed plus —
/// when it did not pass — the failing conjunct as an [`Explain`] (DSL source
/// plus the evaluated operand values).
/// e.g. for `a > 0 and b > 1` with `b = 0`: `(false, Some(Explain { source: "b > 1", values: Some("0 > 1") }))`.
pub async fn evaluate_explain(
    expr: &str,
    ctx: &EvalContext,
    builtins: Arc<dyn BuiltinProvider>,
) -> Result<(bool, Option<Explain>)> {
    let ast = parse(expr)?;
    let (value, explain) = Evaluator::new(builtins).eval_explain(&ast, ctx).await?;
    Ok((value.as_bool(), explain))
}

/// Validate expression syntax without evaluating. Returns the error string if invalid.
pub fn validate_syntax(expr: &str) -> Option<String> {
    let cleaned = strip_comments(expr);
    parse(&cleaned).err().map(|e| e.to_string())
}

/// Full validation: syntax + semantic checks.
///
/// - `param_names`: ABI parameter names to validate `args.X` against. Empty = skip.
/// - `known_builtins`: valid `$name` identifiers. Use `analyze::KNOWN_BUILTINS`.
/// - `param_types`: maps ABI param name → Solidity type string (e.g. `"address"`).
///   Empty = skip type checking.
/// - `var_values`: maps var name → JSON value. When a `vars.X` reference is found,
///   X must be a key in this map, otherwise it is an error.
pub fn validate_full(
    expr: &str,
    param_names: &[&str],
    known_builtins: &[&str],
    param_types: &HashMap<String, String>,
    var_values: &HashMap<String, serde_json::Value>,
) -> Vec<String> {
    let cleaned = strip_comments(expr);
    let ast = match parse(&cleaned) {
        Ok(a) => a,
        Err(e) => return vec![format!("syntax error: {e}")],
    };
    analyze::validate_semantics(&ast, param_names, known_builtins, param_types, var_values)
        .into_iter()
        .map(|e| e.message)
        .collect()
}
