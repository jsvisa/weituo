use weituo_expr::{
    ast::{Expr, Literal},
    parse,
};

#[test]
fn vars_in_array_literal_parses() {
    // vars.ETH inside an in-array should parse without error
    let ast = parse("x in [vars.ETH, 'hello']").unwrap();
    match ast {
        Expr::In { list, negated, .. } => {
            assert!(!negated);
            assert_eq!(list.len(), 2);
            // first element is Expr::Attribute([Field("vars"), Field("ETH")])
            match &list[0] {
                Expr::Attribute(parts) => {
                    assert_eq!(parts[0].as_field(), Some("vars"));
                    assert_eq!(parts[1].as_field(), Some("ETH"));
                }
                other => panic!("expected Attribute, got {other:?}"),
            }
            // second element is Expr::Lit(Literal::Str("hello"))
            assert!(matches!(&list[1], Expr::Lit(Literal::Str(s)) if s == "hello"));
        }
        other => panic!("expected In, got {other:?}"),
    }
}

#[test]
fn attribute_in_array_literal_parses() {
    // from_address in an in-array is also valid after the grammar change
    let ast = parse("x in [from_address, '0xdead']").unwrap();
    assert!(matches!(ast, Expr::In { .. }));
}

#[test]
fn plain_literal_array_still_parses() {
    // Regression: existing literal arrays must still work
    let ast = parse("x in ['0xabc', '0xdef', '0x123']").unwrap();
    match ast {
        Expr::In { list, .. } => assert_eq!(list.len(), 3),
        _ => panic!("expected In"),
    }
}
