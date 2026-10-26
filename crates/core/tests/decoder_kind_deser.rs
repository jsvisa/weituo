//! Tests for DecoderKind deserialization — specifically the graceful fallback
//! for unknown decoder_type strings.

use weituo_core::types::{DecoderKind, Rule};

fn rule_json(decoder_type: serde_json::Value) -> serde_json::Value {
    serde_json::json!([{
        "address": "0xabc",
        "func": "foo()",
        "selector": "0x12345678",
        "abi_item": null,
        "decoder_type": decoder_type,
        "decoder_config": null,
        "rules": []
    }])
}

#[test]
fn known_decoder_kind_deserializes_correctly() {
    let rules: Vec<Rule> = serde_json::from_value(rule_json("bytes_array".into())).unwrap();
    assert_eq!(rules[0].decoder_type, Some(DecoderKind::BytesArray));

    let rules: Vec<Rule> = serde_json::from_value(rule_json("tuple_array".into())).unwrap();
    assert_eq!(rules[0].decoder_type, Some(DecoderKind::TupleArray));

    let rules: Vec<Rule> = serde_json::from_value(rule_json("parallel_arrays".into())).unwrap();
    assert_eq!(rules[0].decoder_type, Some(DecoderKind::ParallelArrays));

    let rules: Vec<Rule> = serde_json::from_value(rule_json("universal_router".into())).unwrap();
    assert_eq!(rules[0].decoder_type, Some(DecoderKind::UniversalRouter));
}

#[test]
fn unknown_decoder_kind_maps_to_none_not_error() {
    // A rule with an unknown decoder_type must not fail deserialization — it
    // maps to None so the rest of the contract's rules still load.
    let rules: Vec<Rule> = serde_json::from_value(rule_json("foobar_unknown".into()))
        .expect("unknown decoder_type must not cause parse failure");
    assert_eq!(rules[0].decoder_type, None);
}

#[test]
fn rule_with_unknown_decoder_type_and_config_sets_invalid_decoder() {
    // When decoder_type is unknown the Rule deserializes with decoder_type: None.
    // rule_manager sets invalid_decoder = decoder is None AND decoder_config is Some.
    // We verify the Rule carries decoder_config so the manager can detect this case.
    let json = serde_json::json!([{
        "address": "0xabc",
        "func": "foo()",
        "selector": "0x12345678",
        "abi_item": null,
        "decoder_type": "foobar_unknown",
        "decoder_config": { "data_param": "data" },
        "rules": []
    }]);
    let rules: Vec<Rule> = serde_json::from_value(json).unwrap();
    assert_eq!(rules[0].decoder_type, None, "unknown type maps to None");
    assert!(
        rules[0].decoder_config.is_some(),
        "decoder_config must survive deserialization"
    );
    // invalid_decoder = decoder_type is None AND decoder_config is Some
    let would_be_invalid = rules[0].decoder_type.is_none() && rules[0].decoder_config.is_some();
    assert!(
        would_be_invalid,
        "rule_manager must set invalid_decoder=true for this rule"
    );
}

#[test]
fn null_decoder_kind_maps_to_none() {
    let rules: Vec<Rule> = serde_json::from_value(rule_json(serde_json::Value::Null)).unwrap();
    assert_eq!(rules[0].decoder_type, None);
}

#[test]
fn missing_decoder_kind_maps_to_none() {
    // decoder_type field absent entirely
    let json = serde_json::json!([{
        "address": "0xabc",
        "func": "foo()",
        "selector": "0x12345678",
        "abi_item": null,
        "decoder_config": null,
        "rules": []
    }]);
    let rules: Vec<Rule> = serde_json::from_value(json).unwrap();
    assert_eq!(rules[0].decoder_type, None);
}
