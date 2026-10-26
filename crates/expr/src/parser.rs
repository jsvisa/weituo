use anyhow::{anyhow, Result};
use pest::error::{Error as PestError, InputLocation};
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

use super::ast::{AttrSegment, *};

#[derive(Parser)]
#[grammar = "grammar.pest"]
pub struct RuleParser;

pub fn parse(input: &str) -> Result<Expr> {
    let cleaned = input.trim();
    let mut pairs = RuleParser::parse(Rule::expr, cleaned)
        .map_err(|e| anyhow!("{}", format_parse_error(cleaned, &e)))?;
    let expr_pair = pairs.next().ok_or_else(|| anyhow!("empty expression"))?;
    build_expr(
        expr_pair
            .into_inner()
            .next()
            .ok_or_else(|| anyhow!("empty"))?,
    )
}

fn build_expr(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::or_expr => {
            let mut exprs = pair
                .into_inner()
                .filter(|p| !is_keyword(p.as_rule()))
                .map(build_expr)
                .collect::<Result<Vec<_>>>()?;
            let mut iter = exprs.drain(..);
            let mut lhs = iter.next().unwrap();
            for rhs in iter {
                lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
            }
            Ok(lhs)
        }
        Rule::and_expr => {
            let mut exprs = pair
                .into_inner()
                .filter(|p| !is_keyword(p.as_rule()))
                .map(build_expr)
                .collect::<Result<Vec<_>>>()?;
            let mut iter = exprs.drain(..);
            let mut lhs = iter.next().unwrap();
            for rhs in iter {
                lhs = Expr::And(Box::new(lhs), Box::new(rhs));
            }
            Ok(lhs)
        }
        Rule::not_expr => {
            let mut inner = pair.into_inner();
            let first = inner.next().unwrap();
            if first.as_rule() == Rule::kw_not {
                // "not <not_expr>"
                let operand = inner.next().unwrap();
                Ok(Expr::Not(Box::new(build_expr(operand)?)))
            } else {
                // just <cmp_expr>
                build_expr(first)
            }
        }
        Rule::cmp_expr => {
            let mut inner = pair.into_inner();
            let lhs = build_expr(inner.next().unwrap())?;
            let op_pair = match inner.next() {
                Some(p) => p,
                None => return Ok(lhs),
            };
            match op_pair.as_rule() {
                Rule::cmp_op => {
                    let op = match op_pair.as_str() {
                        "==" => BinOp::Eq,
                        "!=" => BinOp::Ne,
                        "<" => BinOp::Lt,
                        "<=" => BinOp::Le,
                        ">" => BinOp::Gt,
                        ">=" => BinOp::Ge,
                        "=~" => BinOp::Regex,
                        s => return Err(anyhow!("unknown op: {s}")),
                    };
                    let rhs = build_expr(inner.next().unwrap())?;
                    Ok(Expr::BinOp {
                        op,
                        lhs: Box::new(lhs),
                        rhs: Box::new(rhs),
                    })
                }
                Rule::in_op => {
                    // in_op contains kw_not+kw_in (negated) or just kw_in
                    let negated = op_pair.into_inner().any(|p| p.as_rule() == Rule::kw_not);
                    let list_pair = inner.next().unwrap(); // this is array_lit
                    let list = list_pair
                        .into_inner() // yields array_element nodes
                        .map(|elem| {
                            // each array_element contains exactly one child: attribute or literal
                            let child = elem.into_inner().next().unwrap();
                            build_expr(child)
                        })
                        .collect::<Result<Vec<_>>>()?;
                    Ok(Expr::In {
                        val: Box::new(lhs),
                        list,
                        negated,
                    })
                }
                _ => Ok(lhs),
            }
        }
        Rule::add_expr => {
            let mut inner = pair.into_inner();
            let mut lhs = build_expr(inner.next().unwrap())?;
            while let (Some(op_pair), Some(rhs_pair)) = (inner.next(), inner.next()) {
                // op_pair is Rule::add_op, rhs_pair is Rule::mul_expr
                let op = if op_pair.as_str().trim() == "+" {
                    ArithOp::Add
                } else {
                    ArithOp::Sub
                };
                lhs = Expr::Arith {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(build_expr(rhs_pair)?),
                };
            }
            Ok(lhs)
        }
        Rule::shift_expr => {
            let mut inner = pair.into_inner();
            let mut lhs = build_expr(inner.next().unwrap())?;
            while let (Some(op_pair), Some(rhs_pair)) = (inner.next(), inner.next()) {
                let op = match op_pair.as_str().trim() {
                    "<<" => ArithOp::Shl,
                    ">>" => ArithOp::Shr,
                    s => return Err(anyhow!("unknown shift op: {s}")),
                };
                lhs = Expr::Arith {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(build_expr(rhs_pair)?),
                };
            }
            Ok(lhs)
        }
        Rule::mul_expr => {
            let mut inner = pair.into_inner();
            let mut lhs = build_expr(inner.next().unwrap())?;
            while let (Some(op_pair), Some(rhs_pair)) = (inner.next(), inner.next()) {
                let op = match op_pair.as_str().trim() {
                    "*" => ArithOp::Mul,
                    "/" => ArithOp::Div,
                    "%" => ArithOp::Mod,
                    s => return Err(anyhow!("unknown mul op: {s}")),
                };
                lhs = Expr::Arith {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(build_expr(rhs_pair)?),
                };
            }
            Ok(lhs)
        }
        Rule::add_op | Rule::mul_op | Rule::shift_op => {
            Err(anyhow!("op should not appear standalone"))
        }
        Rule::unary => {
            let mut inner = pair.into_inner();
            let first = inner.next().unwrap();
            if first.as_rule() == Rule::neg_op {
                Ok(Expr::Neg(Box::new(build_expr(inner.next().unwrap())?)))
            } else {
                build_expr(first)
            }
        }
        Rule::neg_op => Err(anyhow!("neg_op should not appear standalone")),
        Rule::primary => {
            let inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::bool_lit | Rule::null_lit | Rule::float | Rule::integer | Rule::string => {
                    build_literal(inner).map(Expr::Lit)
                }
                _ => build_expr(inner),
            }
        }
        Rule::builtin_call => {
            let mut inner = pair.into_inner();
            let name = inner.next().unwrap().as_str().to_string();
            let args = inner
                .next()
                .map(|p| p.into_inner().map(build_expr).collect::<Result<_>>())
                .transpose()?
                .unwrap_or_default();
            // collect trailing attr_tail* (e.g. .timestamp in $block().timestamp)
            let mut path = Vec::new();
            for tail in inner {
                let child = tail.into_inner().next().unwrap();
                match child.as_rule() {
                    Rule::attr_dot => {
                        let field = child.into_inner().next().unwrap().as_str().to_string();
                        path.push(AttrSegment::Field(field));
                    }
                    Rule::attr_index => {
                        let idx: usize = child
                            .into_inner()
                            .next()
                            .unwrap()
                            .as_str()
                            .parse()
                            .map_err(|e| anyhow!("invalid index: {e}"))?;
                        path.push(AttrSegment::Index(idx));
                    }
                    r => return Err(anyhow!("unexpected builtin attr child: {r:?}")),
                }
            }
            Ok(Expr::Builtin { name, args, path })
        }
        Rule::func_call => {
            let mut inner = pair.into_inner();
            let name = inner.next().unwrap().as_str().to_string();
            let args = inner
                .next()
                .map(|p| p.into_inner().map(build_expr).collect::<Result<_>>())
                .transpose()?
                .unwrap_or_default();
            Ok(Expr::FuncCall { name, args })
        }
        Rule::attribute => {
            let mut inner = pair.into_inner();
            // First token is the root ident
            let root = inner.next().unwrap().as_str().to_string();
            let mut segments = vec![AttrSegment::Field(root)];
            // Remaining tokens are attr_tail → attr_dot or attr_index
            for tail in inner {
                match tail.as_rule() {
                    Rule::attr_tail => {
                        let child = tail.into_inner().next().unwrap();
                        match child.as_rule() {
                            Rule::attr_dot => {
                                let field = child.into_inner().next().unwrap().as_str().to_string();
                                segments.push(AttrSegment::Field(field));
                            }
                            Rule::attr_index => {
                                let idx: usize = child
                                    .into_inner()
                                    .next()
                                    .unwrap()
                                    .as_str()
                                    .parse()
                                    .map_err(|e| anyhow!("invalid index: {e}"))?;
                                segments.push(AttrSegment::Index(idx));
                            }
                            r => return Err(anyhow!("unexpected attr_tail child: {r:?}")),
                        }
                    }
                    r => return Err(anyhow!("unexpected attribute child: {r:?}")),
                }
            }
            Ok(Expr::Attribute(segments))
        }
        Rule::literal => build_literal(pair.into_inner().next().unwrap()).map(Expr::Lit),
        Rule::bool_lit
        | Rule::null_lit
        | Rule::float
        | Rule::integer
        | Rule::string
        | Rule::kw_true
        | Rule::kw_false
        | Rule::kw_null => build_literal(pair).map(Expr::Lit),
        r => Err(anyhow!("unexpected rule: {r:?}")),
    }
}

fn build_literal(pair: Pair<Rule>) -> Result<Literal> {
    match pair.as_rule() {
        Rule::integer => {
            let s = pair.as_str();
            // Priority: exact i64, then exact U256, finally lossy f64
            if let Ok(i) = s.parse::<i64>() {
                Ok(Literal::Int(i))
            } else if let Ok(u) = s.parse::<alloy_primitives::U256>() {
                Ok(Literal::BigUint(u))
            } else {
                Ok(Literal::Float(s.parse::<f64>()?))
            }
        }
        Rule::float => Ok(Literal::Float(pair.as_str().parse()?)),
        Rule::string => {
            let s = pair.as_str();
            Ok(Literal::Str(s[1..s.len() - 1].to_string()))
        }
        Rule::bool_lit | Rule::kw_true | Rule::kw_false => {
            // inner is kw_true or kw_false; .as_str() gives the matched text
            let s = pair.as_str().trim();
            Ok(Literal::Bool(s == "true"))
        }
        Rule::null_lit | Rule::kw_null => Ok(Literal::Null),
        // Unwrap the outer literal wrapper when coming from array_lit
        Rule::literal => build_literal(pair.into_inner().next().unwrap()),
        r => Err(anyhow!("unexpected literal rule: {r:?}")),
    }
}

const fn is_keyword(r: Rule) -> bool {
    matches!(
        r,
        Rule::kw_and
            | Rule::kw_or
            | Rule::kw_not
            | Rule::kw_in
            | Rule::kw_true
            | Rule::kw_false
            | Rule::kw_null
    )
}

/// Keep pest's line/caret diagnostic but append an actionable hint for common
/// mistakes (bad builtin syntax, `&&`/`||`/`!`, single `=`, missing `)`, …).
fn format_parse_error(input: &str, err: &PestError<Rule>) -> String {
    let pos = match err.location {
        InputLocation::Pos(p) => p,
        InputLocation::Span((start, _)) => start,
    };
    let mut msg = err.to_string();
    if let Some(hint) = parse_hint(input, pos) {
        msg.push_str("\n\nhint: ");
        msg.push_str(&hint);
    }
    msg
}

/// Heuristic hints, inspected at the byte position where the parse failed.
fn parse_hint(input: &str, pos: usize) -> Option<String> {
    let rest = &input[pos.min(input.len())..];

    // `$block.timestamp()` → `$block().timestamp`: builtins take parens before
    // any `.field` / `[n]` access.
    if let Some(after) = rest.strip_prefix('$') {
        let name_len = after
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if name_len > 0 {
            let tail = &after[name_len..];
            if tail.starts_with('.') {
                let field = tail
                    .strip_prefix('.')?
                    .split(['(', ')'])
                    .next()
                    .unwrap_or("field");
                return Some(format!(
                    "builtins are called with parentheses before field access — write `${}().{field}`",
                    &after[..name_len],
                ));
            }
            if !tail.starts_with('(') {
                return Some(format!(
                    "builtins must be called with parentheses, e.g. `${}(...)`",
                    &after[..name_len],
                ));
            }
        }
    }

    // Single `=` is not a comparison operator.
    if rest.starts_with('=') && !rest.starts_with("==") {
        return Some("use `==` for equality; a single `=` is not a comparison operator".into());
    }

    // JS-style logical operators.
    if rest.starts_with("&&") {
        return Some("use the keyword `and` instead of `&&`".into());
    }
    if rest.starts_with("||") {
        return Some("use the keyword `or` instead of `||`".into());
    }
    if rest.starts_with('!') && !rest.starts_with("!=") {
        return Some("use the keyword `not` instead of `!`".into());
    }

    // Unbalanced parentheses.
    let opens = input.bytes().filter(|b| *b == b'(').count();
    let closes = input.bytes().filter(|b| *b == b')').count();
    if opens > closes {
        return Some("missing a closing `)`".into());
    }
    if closes > opens && rest.starts_with(')') {
        return Some("unexpected `)` — too many closing parentheses".into());
    }

    // Expression ends right after an operator.
    if pos >= input.len() {
        let before = input[..input.len()].trim_end();
        if let Some(last) = before.chars().last() {
            if matches!(
                last,
                '+' | '-' | '*' | '/' | '%' | '<' | '>' | '=' | '!' | '&' | '|' | '^' | '~'
            ) {
                return Some(
                    "the expression ends unexpectedly — a value/operand is missing after this \
                     operator"
                        .into(),
                );
            }
        }
    }

    None
}
