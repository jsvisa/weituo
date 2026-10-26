/// AST for the rule_engine expression DSL.

#[derive(Debug, Clone)]
pub enum Expr {
    // Boolean
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    // Comparison
    BinOp {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    // Membership
    In {
        val: Box<Expr>,
        list: Vec<Expr>,
        negated: bool,
    },
    // Arithmetic
    Arith {
        op: ArithOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Neg(Box<Expr>),
    // Terminals
    Builtin {
        name: String,
        args: Vec<Expr>,
        /// Field path chained after the call: `$block().timestamp` → `[Field("timestamp")]`
        path: Vec<AttrSegment>,
    },
    FuncCall {
        name: String,
        args: Vec<Expr>,
    },
    /// Attribute / index access path.
    /// e.g. `args.to`            → [Field("args"), Field("to")]
    ///      `args._amounts[0]`   → [Field("args"), Field("_amounts"), Index(0)]
    ///      `args.swap.path[2]`  → [Field("args"), Field("swap"), Field("path"), Index(2)]
    Attribute(Vec<AttrSegment>),
    Lit(Literal),
}

/// One step in an attribute access chain.
#[derive(Debug, Clone)]
pub enum AttrSegment {
    Field(String),
    Index(usize),
}

impl Expr {
    /// Render the AST back to a DSL source string. Used for diagnostics so a
    /// failing sub-expression can be shown to the caller verbatim.
    ///
    /// The output re-parses to the same AST: operands are parenthesised
    /// whenever the child's precedence is looser than the grammar requires.
    pub(crate) fn render(&self) -> String {
        self.render_prec(0)
    }

    /// Precedence ladder mirrors `grammar.pest` (loose → tight):
    ///   or < and < not < cmp < shift < add < mul < unary < atom
    const fn prec(&self) -> u8 {
        match self {
            Expr::Or(..) => 1,
            Expr::And(..) => 2,
            Expr::Not(..) => 3,
            Expr::BinOp { .. } | Expr::In { .. } => 4,
            Expr::Arith { op, .. } => match op {
                ArithOp::Shl | ArithOp::Shr => 5,
                ArithOp::Add | ArithOp::Sub => 6,
                ArithOp::Mul | ArithOp::Div | ArithOp::Mod => 7,
            },
            Expr::Neg(..) => 8,
            Expr::Builtin { .. } | Expr::FuncCall { .. } | Expr::Attribute(..) | Expr::Lit(..) => 9,
        }
    }

    fn render_prec(&self, min: u8) -> String {
        let body = match self {
            Expr::Or(l, r) => format!("{} or {}", l.render_prec(2), r.render_prec(2)),
            Expr::And(l, r) => format!("{} and {}", l.render_prec(3), r.render_prec(3)),
            Expr::Not(inner) => format!("not {}", inner.render_prec(3)),
            Expr::BinOp { op, lhs, rhs } => {
                let s = match op {
                    BinOp::Eq => "==",
                    BinOp::Ne => "!=",
                    BinOp::Lt => "<",
                    BinOp::Le => "<=",
                    BinOp::Gt => ">",
                    BinOp::Ge => ">=",
                    BinOp::Regex => "=~",
                };
                format!("{} {s} {}", lhs.render_prec(5), rhs.render_prec(5))
            }
            Expr::In { val, list, negated } => {
                let kw = if *negated { "not in" } else { "in" };
                let items: Vec<String> = list.iter().map(|e| e.render_prec(9)).collect();
                format!("{} {kw} [{}]", val.render_prec(5), items.join(", "))
            }
            Expr::Arith { op, lhs, rhs } => {
                let s = match op {
                    ArithOp::Add => "+",
                    ArithOp::Sub => "-",
                    ArithOp::Mul => "*",
                    ArithOp::Div => "/",
                    ArithOp::Mod => "%",
                    ArithOp::Shl => "<<",
                    ArithOp::Shr => ">>",
                };
                let prec = self.prec();
                format!(
                    "{} {s} {}",
                    lhs.render_prec(prec + 1),
                    rhs.render_prec(prec + 1)
                )
            }
            Expr::Neg(inner) => format!("-{}", inner.render_prec(8)),
            Expr::Builtin { name, args, path } => {
                let args_s: Vec<String> = args.iter().map(|a| a.render_prec(0)).collect();
                let mut s = format!("${name}({})", args_s.join(", "));
                for seg in path {
                    match seg {
                        AttrSegment::Field(f) => s.push_str(&format!(".{f}")),
                        AttrSegment::Index(i) => s.push_str(&format!("[{i}]")),
                    }
                }
                s
            }
            Expr::FuncCall { name, args } => {
                let args_s: Vec<String> = args.iter().map(|a| a.render_prec(0)).collect();
                format!("{name}({})", args_s.join(", "))
            }
            Expr::Attribute(parts) => {
                let mut s = String::new();
                for (i, seg) in parts.iter().enumerate() {
                    match seg {
                        AttrSegment::Field(f) => {
                            if i == 0 {
                                s.push_str(f);
                            } else {
                                s.push_str(&format!(".{f}"));
                            }
                        }
                        AttrSegment::Index(idx) => s.push_str(&format!("[{idx}]")),
                    }
                }
                s
            }
            Expr::Lit(lit) => match lit {
                Literal::Int(i) => i.to_string(),
                Literal::BigUint(u) => u.to_string(),
                Literal::Float(f) => f.to_string(),
                Literal::Str(s) => format!("'{s}'"),
                Literal::Bool(b) => b.to_string(),
                Literal::Null => "null".to_string(),
            },
        };
        if self.prec() < min {
            format!("({body})")
        } else {
            body
        }
    }
}

impl AttrSegment {
    pub fn as_field(&self) -> Option<&str> {
        if let AttrSegment::Field(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Regex,
}

#[derive(Debug, Clone)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Shl,
    Shr,
}

#[derive(Debug, Clone)]
pub enum Literal {
    Int(i64),
    /// Large non-negative integer literal (> i64::MAX) stored exactly.
    BigUint(alloy_primitives::U256),
    Float(f64),
    Str(String),
    Bool(bool),
    Null,
}

#[cfg(test)]
mod tests {
    use crate::parser::parse;

    /// `render` must re-parse to a string that renders identically (idempotent).
    fn assert_roundtrip(src: &str) {
        let ast = parse(src).unwrap();
        let once = ast.render();
        let twice = parse(&once).unwrap().render();
        assert_eq!(once, twice, "non-idempotent render for: {src}");
    }

    #[test]
    fn render_plain_condition() {
        assert_eq!(parse("args.a > 0").unwrap().render(), "args.a > 0");
        assert_eq!(
            parse("args.a == '0xabc' and args.b != 2").unwrap().render(),
            "args.a == '0xabc' and args.b != 2"
        );
    }

    #[test]
    fn render_preserves_grouping() {
        assert_eq!(
            parse("args.a > 0 and (args.b == 1 or args.c == 2)")
                .unwrap()
                .render(),
            "args.a > 0 and (args.b == 1 or args.c == 2)"
        );
        assert_eq!(
            parse("(args.a + args.b) * 3 > 10").unwrap().render(),
            "(args.a + args.b) * 3 > 10"
        );
    }

    #[test]
    fn render_in_chain() {
        assert_eq!(
            parse("args.token in ['0xaaa', '0xbbb']").unwrap().render(),
            "args.token in ['0xaaa', '0xbbb']"
        );
    }

    #[test]
    fn render_builtin_and_func() {
        assert_eq!(
            parse("$block().timestamp > 0").unwrap().render(),
            "$block().timestamp > 0"
        );
        assert_eq!(
            parse("len(args.s) > 3").unwrap().render(),
            "len(args.s) > 3"
        );
    }

    #[test]
    fn render_roundtrip_is_idempotent() {
        for src in [
            "args.a > 0 and args.b == 1 and args.c != 2",
            "args.x == 1 or args.y == 2",
            "not (args.a == 1)",
            "args.amount > $now_ts() - 60",
            "args.path[2].token == '0xweth'",
            "(args.a or args.b) and args.c > 0",
            "args.deadline > $now_ts() - 60 and args.minAmount > 0",
        ] {
            assert_roundtrip(src);
        }
    }
}
