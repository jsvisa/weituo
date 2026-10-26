use weituo_core::types::{expression_param_types, AbiInput};

#[test]
fn expression_param_types_flattens_nested_tuple_arrays() {
    let inputs = vec![AbiInput {
        name: "orders".to_string(),
        kind: "tuple[]".to_string(),
        components: vec![AbiInput {
            name: "recipient".to_string(),
            kind: "address".to_string(),
            components: vec![],
        }],
    }];

    let types = expression_param_types(&inputs);

    assert_eq!(types.get("orders").map(String::as_str), Some("tuple[]"));
    assert_eq!(
        types.get("orders.recipient").map(String::as_str),
        Some("address")
    );
}
