use alloy_primitives::{I256, U256};
use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use std::sync::Arc;

use crate::ast::{AttrSegment, *};
use crate::context::{BuiltinProvider, EvalContext};

/// The runtime value type for expression evaluation.
///
/// Integer arithmetic uses exact types to avoid f64 precision loss:
///   - ABI uint256/uint128/etc  → BigUint(U256)  (exact comparison)
///   - ABI int256/int128/etc    → BigInt(I256)   (exact comparison)
///   - Small literals & builtins → Int(i64)       (fits in i64)
///   - Float operations         → Float(f64)     (price_of, pow, etc.)
///
/// f64 is only used when float operations are explicitly needed
/// (mixed arithmetic with $price_of, $pow, etc.).
#[derive(Debug, Clone)]
pub enum Value {
    Bool(bool),
    /// Small signed integer — literals, counter values, decimals
    Int(i64),
    /// Large unsigned integer — decoded uint256 from ABI, large literals
    BigUint(U256),
    /// Large signed integer — decoded int256 from ABI
    BigInt(I256),
    /// Floating point — results of $price_of, $pow, scientific notation
    Float(f64),
    Str(String),
    Null,
    /// A JSON object or array — produced by builtins like `$block()`.
    /// Field-traversable via a `path`; evaluates as falsy in boolean context.
    Json(Box<serde_json::Value>),
}

impl Value {
    pub fn as_bool(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::BigUint(u) => !u.is_zero(),
            Value::BigInt(i) => !i.is_zero(),
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Null | Value::Json(_) => false,
        }
    }

    /// Lossy conversion to f64. Used for float arithmetic ($price_of * amount, etc.).
    /// For exact integer comparisons use `cmp_exact` instead.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            Value::BigUint(u) => Some(u.to_string().parse::<f64>().unwrap_or(f64::INFINITY)),
            Value::BigInt(i) => Some(i.to_string().parse::<f64>().unwrap_or(f64::NAN)),
            // Decimal strings from decoded args: coerce to BigUint first, then f64
            Value::Str(s) if is_decimal_int(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }

    /// Try to get an exact U256 representation for integer comparison.
    pub fn as_u256(&self) -> Option<U256> {
        match self {
            Value::BigUint(u) => Some(*u),
            Value::Int(i) if *i >= 0 => Some(U256::from(*i as u64)),
            Value::Str(s) if is_decimal_int(s) => s.parse::<U256>().ok(),
            _ => None,
        }
    }

    /// Try to get an exact I256 representation for signed integer arithmetic.
    pub fn as_i256(&self) -> Option<I256> {
        match self {
            Value::BigInt(i) => Some(*i),
            Value::Int(i) => I256::try_from(*i).ok(),
            Value::BigUint(u) => I256::try_from(*u).ok(),
            Value::Str(s) if is_decimal_int(s) || s.starts_with('-') => s.parse::<I256>().ok(),
            _ => None,
        }
    }

    pub const fn type_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::BigUint(_) => "uint256",
            Value::BigInt(_) => "int256",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::Null => "null",
            Value::Json(_) => "json",
        }
    }
}

impl From<Literal> for Value {
    fn from(l: Literal) -> Self {
        match l {
            Literal::Int(i) => Value::Int(i),
            Literal::BigUint(u) => Value::BigUint(u),
            Literal::Float(f) => Value::Float(f),
            Literal::Str(s) => Value::Str(s),
            Literal::Bool(b) => Value::Bool(b),
            Literal::Null => Value::Null,
        }
    }
}

impl From<serde_json::Value> for Value {
    fn from(v: serde_json::Value) -> Self {
        match v {
            serde_json::Value::Bool(b) => Value::Bool(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else {
                    Value::Float(n.as_f64().unwrap_or(0.0))
                }
            }
            // Decimal integer strings from ABI decoder → BigUint for exact comparison
            serde_json::Value::String(s) if is_decimal_int(&s) => {
                if let Ok(u) = s.parse::<U256>() {
                    Value::BigUint(u)
                } else {
                    Value::Str(s)
                }
            }
            serde_json::Value::String(s) => Value::Str(s),
            serde_json::Value::Null => Value::Null,
            v @ (serde_json::Value::Object(_) | serde_json::Value::Array(_)) => {
                Value::Json(Box::new(v))
            }
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::BigUint(u) => write!(f, "{u}"),
            Value::BigInt(i) => write!(f, "{i}"),
            Value::Float(v) => write!(f, "{v}"),
            Value::Str(s) => write!(f, "{s}"),
            Value::Null => write!(f, "null"),
            Value::Json(j) => write!(f, "{j}"),
        }
    }
}

/// True if `s` is a valid non-negative decimal integer (no leading zeros except "0").
fn is_decimal_int(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

/// Which condition of an `and`/`or` chain rejected the request, plus the raw
/// runtime values involved so callers can show *why* it failed.
#[derive(Debug, Clone, PartialEq)]
pub struct Explain {
    /// DSL source of the failing sub-expression, e.g. `"args.a > 0"`.
    pub source: String,
    /// The operands substituted with their runtime values, e.g. `"1024 > 1024"`.
    /// `None` when the failing expression is not a binary comparison.
    pub values: Option<String>,
}

pub struct Evaluator {
    builtins: Arc<dyn BuiltinProvider>,
}

impl Evaluator {
    pub fn new(builtins: Arc<dyn BuiltinProvider>) -> Self {
        Self { builtins }
    }

    pub async fn eval(&self, expr: &Expr, ctx: &EvalContext) -> Result<Value> {
        self.eval_inner(expr, ctx).await
    }

    /// Evaluate `expr`, additionally returning the source of the first failing
    /// conjunct when the expression evaluates to false. This lets callers report
    /// *which* condition of an `and`/`or` chain actually rejected the request.
    ///
    /// The explanation is `Some(..)` only when a false result can be narrowed to
    /// a specific sub-expression (e.g. the left `and` branch that short-circuited).
    #[async_recursion]
    #[allow(clippy::double_must_use)]
    pub async fn eval_explain(
        &self,
        expr: &Expr,
        ctx: &EvalContext,
    ) -> Result<(Value, Option<Explain>)> {
        match expr {
            Expr::And(l, r) => {
                let (lv, le) = self.eval_explain(l, ctx).await?;
                if !lv.as_bool() {
                    let explain = match le {
                        Some(e) => Some(e),
                        None => Some(self.explain_failed(l, ctx).await),
                    };
                    return Ok((lv, explain));
                }
                let (rv, re) = self.eval_explain(r, ctx).await?;
                if !rv.as_bool() {
                    let explain = match re {
                        Some(e) => Some(e),
                        None => Some(self.explain_failed(r, ctx).await),
                    };
                    return Ok((rv, explain));
                }
                Ok((Value::Bool(true), None))
            }
            Expr::Or(l, r) => {
                let (lv, le) = self.eval_explain(l, ctx).await?;
                if lv.as_bool() {
                    return Ok((lv, None));
                }
                let (rv, re) = self.eval_explain(r, ctx).await?;
                if rv.as_bool() {
                    return Ok((rv, None));
                }
                let explain = match le.or(re) {
                    Some(e) => Some(e),
                    None => Some(self.explain_failed(l, ctx).await),
                };
                Ok((Value::Bool(false), explain))
            }
            Expr::Not(inner) => {
                let (iv, _) = self.eval_explain(inner, ctx).await?;
                if iv.as_bool() {
                    Ok((
                        Value::Bool(false),
                        Some(Explain {
                            source: expr.render(),
                            values: None,
                        }),
                    ))
                } else {
                    Ok((Value::Bool(true), None))
                }
            }
            _ => Ok((self.eval_inner(expr, ctx).await?, None)),
        }
    }

    /// Build the explain for a failing sub-expression: the DSL source plus, when
    /// it is a binary comparison, the operands substituted with their evaluated
    /// values (e.g. `args.a > 0` with `a = 1024` renders as `1024 > 0`).
    async fn explain_failed(&self, expr: &Expr, ctx: &EvalContext) -> Explain {
        let values = match expr {
            Expr::BinOp { op, lhs, rhs } => {
                match (
                    self.eval_inner(lhs, ctx).await,
                    self.eval_inner(rhs, ctx).await,
                ) {
                    (Ok(l), Ok(r)) => Some(format!(
                        "{} {} {}",
                        render_operand(&l),
                        binop_symbol(op),
                        render_operand(&r)
                    )),
                    _ => None,
                }
            }
            _ => None,
        };
        Explain {
            source: expr.render(),
            values,
        }
    }

    #[async_recursion]
    #[allow(clippy::double_must_use)]
    async fn eval_inner(&self, expr: &Expr, ctx: &EvalContext) -> Result<Value> {
        match expr {
            Expr::And(l, r) => {
                if !self.eval_inner(l, ctx).await?.as_bool() {
                    return Ok(Value::Bool(false));
                }
                Ok(Value::Bool(self.eval_inner(r, ctx).await?.as_bool()))
            }
            Expr::Or(l, r) => {
                if self.eval_inner(l, ctx).await?.as_bool() {
                    return Ok(Value::Bool(true));
                }
                Ok(Value::Bool(self.eval_inner(r, ctx).await?.as_bool()))
            }
            Expr::Not(inner) => Ok(Value::Bool(!self.eval_inner(inner, ctx).await?.as_bool())),

            Expr::BinOp { op, lhs, rhs } => {
                let l = self.eval_inner(lhs, ctx).await?;
                let r = self.eval_inner(rhs, ctx).await?;
                eval_binop(op, &l, &r)
            }

            Expr::In { val, list, negated } => {
                let v = self.eval_inner(val, ctx).await?;
                let mut found = false;
                for item in list {
                    if values_eq(&v, &self.eval_inner(item, ctx).await?) {
                        found = true;
                        break;
                    }
                }
                Ok(Value::Bool(if *negated { !found } else { found }))
            }

            Expr::Arith { op, lhs, rhs } => {
                let l = self.eval_inner(lhs, ctx).await?;
                let r = self.eval_inner(rhs, ctx).await?;
                eval_arith(op, l, r)
            }

            Expr::Neg(inner) => match self.eval_inner(inner, ctx).await? {
                Value::Int(i) => Ok(Value::Int(-i)),
                Value::Float(f) => Ok(Value::Float(-f)),
                v => Err(anyhow!("negation of {}", v.type_name())),
            },

            Expr::Builtin { name, args, path } => {
                let mut vals = Vec::with_capacity(args.len());
                for a in args {
                    vals.push(self.eval_inner(a, ctx).await?);
                }
                let result = self.builtins.call(name, &vals, ctx).await?;
                if path.is_empty() {
                    Ok(result)
                } else {
                    let json = match result {
                        Value::Json(j) => *j,
                        _ => return Ok(Value::Null),
                    };
                    Ok(traverse_json(json, path))
                }
            }

            Expr::FuncCall { name, args } => {
                let mut vals = Vec::with_capacity(args.len());
                for a in args {
                    vals.push(self.eval_inner(a, ctx).await?);
                }
                eval_func(name, &vals)
            }

            Expr::Attribute(parts) => Ok(resolve_attribute(parts, ctx)),

            Expr::Lit(l) => Ok(Value::from(l.clone())),
        }
    }
}

/// String helpers exposed as plain function calls in the DSL.
///
/// `contains`/`startswith`/`endswith` are **case-sensitive**, matching Rust's
/// `str` methods (`==`, `!=`, `=~` remain case-insensitive). Use `lower()` /
/// `upper()` for a case-insensitive check.
///
/// `len()` and `substring()` operate on **bytes**, not characters — consistent
/// with each other (`substring(s, 0, len(s)) == s`), and equal to character
/// counts for ASCII input (hex addresses, token symbols).
///
/// - `len(s)`                     → int (byte length)
/// - `lower(s)` / `upper(s)`      → str
/// - `contains(s, needle)`        → bool (case-sensitive)
/// - `startswith(s, prefix)`      → bool (case-sensitive)
/// - `endswith(s, suffix)`        → bool (case-sensitive)
/// - `substring(s, start, end)`   → str (byte indices, exclusive end, negative
///   indices count from the end, out-of-range clamped)
fn eval_func(name: &str, vals: &[Value]) -> Result<Value> {
    match name {
        "len" => {
            let s = str_arg(vals, "len", 1)?;
            Ok(Value::Int(s.len() as i64))
        }
        "lower" => {
            let s = str_arg(vals, "lower", 1)?;
            Ok(Value::Str(s.to_lowercase()))
        }
        "upper" => {
            let s = str_arg(vals, "upper", 1)?;
            Ok(Value::Str(s.to_uppercase()))
        }
        "contains" => {
            let (s, needle) = two_str_args(vals, "contains")?;
            Ok(Value::Bool(s.contains(needle)))
        }
        "startswith" => {
            let (s, prefix) = two_str_args(vals, "startswith")?;
            Ok(Value::Bool(s.starts_with(prefix)))
        }
        "endswith" => {
            let (s, suffix) = two_str_args(vals, "endswith")?;
            Ok(Value::Bool(s.ends_with(suffix)))
        }
        "substring" => {
            let s = str_arg(vals, "substring", 3)?;
            let start = int_arg(vals.get(1), "substring", "start")?;
            let end = int_arg(vals.get(2), "substring", "end")?;
            Ok(Value::Str(substring(s, start, end)))
        }
        _ => Err(anyhow!("unknown function: {name}()")),
    }
}

/// Single source of truth for the plain functions the evaluator supports.
/// `analyze::KNOWN_FUNCTIONS` must stay identical — a regression test compares
/// the two lists.
pub const fn supported_functions() -> &'static [(&'static str, usize)] {
    &[
        ("len", 1),
        ("lower", 1),
        ("upper", 1),
        ("contains", 2),
        ("startswith", 2),
        ("endswith", 2),
        ("substring", 3),
    ]
}

fn str_arg<'a>(vals: &'a [Value], name: &str, arity: usize) -> Result<&'a str> {
    if vals.len() != arity {
        return Err(anyhow!("{name}() expects {arity} argument(s)"));
    }
    match vals.first() {
        Some(Value::Str(s)) => Ok(s),
        _ => Err(anyhow!("{name}() expects a string argument")),
    }
}

fn two_str_args<'a>(vals: &'a [Value], name: &str) -> Result<(&'a str, &'a str)> {
    if vals.len() != 2 {
        return Err(anyhow!("{name}() expects 2 arguments"));
    }
    let a = match &vals[0] {
        Value::Str(s) => s,
        _ => return Err(anyhow!("{name}() expects string arguments")),
    };
    let b = match &vals[1] {
        Value::Str(s) => s,
        _ => return Err(anyhow!("{name}() expects string arguments")),
    };
    Ok((a, b))
}

fn int_arg(v: Option<&Value>, name: &str, arg: &str) -> Result<i64> {
    match v {
        Some(Value::Int(i)) => Ok(*i),
        _ => Err(anyhow!("{name}() {arg} must be an integer")),
    }
}

/// `substring(s, start, end)` — byte-based slice with negative indices
/// counting from the end (exclusive `end`). Both bounds are clamped to
/// `[0, len]`; empty string when `start >= end`.
fn substring(s: &str, start: i64, end: i64) -> String {
    let len = s.len() as i64;
    let norm = |i: i64| if i < 0 { len + i } else { i }.clamp(0, len);
    let s_idx = norm(start);
    let e_idx = norm(end);
    if e_idx <= s_idx {
        return String::new();
    }
    s.get(s_idx as usize..e_idx as usize)
        .unwrap_or_default()
        .to_string()
}

const fn binop_symbol(op: &BinOp) -> &'static str {
    match op {
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Le => "<=",
        BinOp::Gt => ">",
        BinOp::Ge => ">=",
        BinOp::Regex => "=~",
    }
}

/// Render a runtime value for the `data` preview string. Strings are quoted to
/// stay unambiguous next to numbers (e.g. `'0xabc' == '0xdef'`).
fn render_operand(v: &Value) -> String {
    match v {
        Value::Str(s) => format!("'{s}'"),
        Value::Json(j) => j.to_string(),
        other => other.to_string(),
    }
}

fn eval_binop(op: &BinOp, l: &Value, r: &Value) -> Result<Value> {
    if op == &BinOp::Regex {
        let s = match l {
            Value::Str(s) => s,
            _ => return Err(anyhow!("=~ lhs must be string")),
        };
        let pat = match r {
            Value::Str(s) => s,
            _ => return Err(anyhow!("=~ rhs must be string")),
        };
        return Ok(Value::Bool(s.contains(pat.as_str())));
    }

    // Exact integer comparison — avoids f64 precision loss for large uint256 values.
    // Used when at least one side is a BigUint (decoded from ABI or large literal).
    if let (Some(lu), Some(ru)) = (l.as_u256(), r.as_u256()) {
        return Ok(Value::Bool(match op {
            BinOp::Eq => lu == ru,
            BinOp::Ne => lu != ru,
            BinOp::Lt => lu < ru,
            BinOp::Le => lu <= ru,
            BinOp::Gt => lu > ru,
            BinOp::Ge => lu >= ru,
            BinOp::Regex => unreachable!(),
        }));
    }

    // Float comparison — for mixed float/uint or purely float operands
    if let (Some(lf), Some(rf)) = (l.as_f64(), r.as_f64()) {
        return Ok(Value::Bool(match op {
            BinOp::Eq => (lf - rf).abs() < 1e-12,
            BinOp::Ne => (lf - rf).abs() >= 1e-12,
            BinOp::Lt => lf < rf,
            BinOp::Le => lf <= rf,
            BinOp::Gt => lf > rf,
            BinOp::Ge => lf >= rf,
            BinOp::Regex => unreachable!(),
        }));
    }

    Ok(Value::Bool(match op {
        BinOp::Eq => values_eq(l, r),
        BinOp::Ne => !values_eq(l, r),
        _ => return Err(anyhow!("{op:?} not supported for {}", l.type_name())),
    }))
}

pub fn values_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Str(s1), Value::Str(s2)) => s1.to_lowercase() == s2.to_lowercase(),
        (Value::Bool(b1), Value::Bool(b2)) => b1 == b2,
        (Value::Null, Value::Null) => true,
        // Exact integer equality when both can be represented as U256
        _ if a.as_u256().is_some() && b.as_u256().is_some() => a.as_u256() == b.as_u256(),
        _ => match (a.as_f64(), b.as_f64()) {
            (Some(f1), Some(f2)) => (f1 - f2).abs() < 1e-12,
            _ => false,
        },
    }
}

fn eval_arith(op: &ArithOp, l: Value, r: Value) -> Result<Value> {
    match op {
        ArithOp::Mod => match (l.as_u256(), r.as_u256()) {
            (Some(a), Some(b)) => {
                if b.is_zero() {
                    return Err(anyhow!("modulo by zero"));
                }
                Ok(Value::BigUint(a % b))
            }
            _ => match (l.as_i256(), r.as_i256()) {
                (Some(a), Some(b)) => {
                    if b.is_zero() {
                        return Err(anyhow!("modulo by zero"));
                    }
                    a.checked_rem(b)
                        .map(exact_i256_value)
                        .ok_or_else(|| anyhow!("arithmetic overflow"))
                }
                _ => {
                    let li = l
                        .as_f64()
                        .ok_or_else(|| anyhow!("% on {}", l.type_name()))?
                        as i64;
                    let ri = r
                        .as_f64()
                        .ok_or_else(|| anyhow!("% on {}", r.type_name()))?
                        as i64;
                    if ri == 0 {
                        return Err(anyhow!("modulo by zero"));
                    }
                    Ok(Value::Int(li % ri))
                }
            },
        },
        ArithOp::Shl => {
            let shift = shift_amount(&r)?;
            Ok(Value::BigUint(to_u256_for_shift(&l)?.wrapping_shl(shift)))
        }
        ArithOp::Shr => {
            let shift = shift_amount(&r)?;
            Ok(Value::BigUint(to_u256_for_shift(&l)?.wrapping_shr(shift)))
        }
        // Exact I256 arithmetic for Add/Sub/Mul/Div whenever both operands are
        // integral. Avoids f64 precision loss on big uint256/int256 values.
        _ if l.as_i256().is_some() && r.as_i256().is_some() => {
            let a = l.as_i256().expect("checked above");
            let b = r.as_i256().expect("checked above");
            match op {
                ArithOp::Add => {
                    return a
                        .checked_add(b)
                        .map(exact_i256_value)
                        .ok_or_else(|| anyhow!("integer overflow"));
                }
                ArithOp::Sub => {
                    return a
                        .checked_sub(b)
                        .map(exact_i256_value)
                        .ok_or_else(|| anyhow!("integer overflow"));
                }
                ArithOp::Mul => {
                    return a
                        .checked_mul(b)
                        .map(exact_i256_value)
                        .ok_or_else(|| anyhow!("integer overflow"));
                }
                // Only use exact integer division when it divides evenly;
                // otherwise keep float semantics (`10 / 4 == 2.5`).
                // Everything else (div by zero, non-integer quotient, or float
                // operands) falls through to the float fallback below.
                ArithOp::Div if a.checked_rem(b).is_some_and(|r| r.is_zero()) => {
                    return a
                        .checked_div(b)
                        .map(exact_i256_value)
                        .ok_or_else(|| anyhow!("division overflow"));
                }
                _ => {}
            }
            eval_arith_float(op, l, r)
        }
        _ => eval_arith_float(op, l, r),
    }
}

fn eval_arith_float(op: &ArithOp, l: Value, r: Value) -> Result<Value> {
    let lf = l
        .as_f64()
        .ok_or_else(|| anyhow!("arithmetic on {}", l.type_name()))?;
    let rf = r
        .as_f64()
        .ok_or_else(|| anyhow!("arithmetic on {}", r.type_name()))?;
    let result = match op {
        ArithOp::Add => lf + rf,
        ArithOp::Sub => lf - rf,
        ArithOp::Mul => lf * rf,
        ArithOp::Div => {
            if rf == 0.0 {
                return Err(anyhow!("division by zero"));
            }
            lf / rf
        }
        _ => unreachable!(),
    };
    // No integer coercion here: integral Add/Sub/Mul/Div results are handled
    // exactly by `eval_arith` (see the I256 fast path). A float result is only
    // produced for genuinely non-integral quotients or float operands, where
    // an f64 → i64/u64 cast would silently lose precision again.
    Ok(Value::Float(result))
}

/// Narrow an exact I256 result into the tightest `Value` variant:
/// non-negative → `BigUint`, small negative → `Int`, large negative → `BigInt`.
fn exact_i256_value(v: I256) -> Value {
    match U256::try_from(v) {
        Ok(u) => Value::BigUint(u),
        Err(_) => match i64::try_from(v) {
            Ok(i) => Value::Int(i),
            Err(_) => Value::BigInt(v),
        },
    }
}

fn shift_amount(v: &Value) -> Result<usize> {
    match v {
        Value::Int(i) if *i >= 0 => Ok(*i as usize),
        Value::BigUint(u) => u.try_into().map_err(|_| anyhow!("shift amount too large")),
        _ => Err(anyhow!("shift amount must be a non-negative integer")),
    }
}

fn to_u256_for_shift(v: &Value) -> Result<U256> {
    match v {
        Value::BigUint(u) => Ok(*u),
        Value::Int(i) if *i >= 0 => Ok(U256::from(*i as u64)),
        _ => Err(anyhow!("shift base must be a non-negative integer")),
    }
}

/// Resolve an attribute/index path against the EvalContext.
///
/// Supports:
///   `from_address`, `to_address`, `chainId`, `value`, `gasPrice`, `gasLimit`
///   `args.field`               — top-level decoded arg
///   `args.tuple_field.nested`  — nested tuple field (decoded as JSON object)
///   `args.array_field[0]`      — array element by index
///   `args.field.length`        — length of an array field
///   Any combination, e.g. `args.swap.path[2].token`
pub fn resolve_attribute(parts: &[AttrSegment], ctx: &EvalContext) -> Value {
    // Single top-level names
    if parts.len() == 1 {
        return match parts[0].as_field() {
            Some("from_address") => Value::Str(ctx.from_address.clone()),
            Some("to_address") => Value::Str(ctx.to_address.clone()),
            Some("chainId") => chain_id_value(ctx),
            Some("network") => Value::Str(ctx.network.clone()),
            Some("value") => Value::BigUint(ctx.value),
            Some("gasPrice") => Value::Int(ctx.gas_price as i64),
            Some("gasLimit") => Value::Int(ctx.gas_limit as i64),
            other => match other.and_then(|name| ctx.chain_fields.get(name)) {
                Some(v) => Value::from(v.clone()),
                None => Value::Null,
            },
        };
    }

    // Family-specific context data (accounts, type_arguments, …) — full
    // attribute paths: `accounts[1]`, `accounts.length`, …
    if let Some(root) = parts[0].as_field() {
        if let Some(v) = ctx.chain_fields.get(root) {
            return traverse_json(v.clone(), &parts[1..]);
        }
    }

    // vars.<name>  — scalar lookup only; deeper paths (vars.FOO.bar) → Null
    if parts[0].as_field() == Some("vars") {
        if parts.len() > 2 {
            return Value::Null;
        }
        return match parts.get(1).and_then(|p| p.as_field()) {
            Some(name) => match ctx.vars.get(name) {
                Some(v) => Value::from(v.clone()),
                None => Value::Null,
            },
            None => Value::Null,
        };
    }

    // args.<path>
    if parts[0].as_field() == Some("args") && parts.len() >= 2 {
        let first_field = match &parts[1] {
            AttrSegment::Field(f) => f,
            AttrSegment::Index(_) => return Value::Null, // args[0] is invalid
        };
        let root = match ctx.args.get(first_field) {
            Some(v) => v.clone(),
            None => return Value::Null,
        };
        return traverse_json(root, &parts[2..]);
    }

    Value::Null
}

/// `chainId` resolution per family: EVM (numeric or legacy empty network) →
/// numeric EIP-155 id; `svm:`/`sui:` networks → the network name without the
/// family prefix (`"svm:mainnet-beta"` → `"mainnet-beta"`).
fn chain_id_value(ctx: &EvalContext) -> Value {
    if ctx.network.is_empty() || ctx.network.starts_with("eip155:") {
        return Value::Int(ctx.chain_id as i64);
    }
    match ctx.network.find(':') {
        Some(idx) => Value::Str(ctx.network[idx + 1..].to_string()),
        None => Value::Str(ctx.network.clone()),
    }
}

/// Traverse a serde_json::Value using remaining AttrSegments.
/// Handles: .field (object key), [n] (array index), .length (array length).
fn traverse_json(mut current: serde_json::Value, parts: &[AttrSegment]) -> Value {
    for part in parts {
        current = match part {
            AttrSegment::Field(key) => {
                // Special: .length on arrays returns the array length
                if key == "length" {
                    if let serde_json::Value::Array(arr) = &current {
                        return Value::Int(arr.len() as i64);
                    }
                }
                match current {
                    serde_json::Value::Object(mut map) => match map.remove(key) {
                        Some(v) => v,
                        None => return Value::Null,
                    },
                    _ => return Value::Null,
                }
            }
            AttrSegment::Index(idx) => match current {
                serde_json::Value::Array(arr) => match arr.into_iter().nth(*idx) {
                    Some(v) => v,
                    None => return Value::Null,
                },
                _ => return Value::Null,
            },
        };
    }
    Value::from(current)
}
