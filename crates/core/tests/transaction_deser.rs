//! Regression tests for Transaction field deserialization:
//! chainId, gasLimit, gasPrice, and value all accept both JSON integers and "0x..." hex strings.
//! value additionally accepts large integers (> u64::MAX) as bare JSON numbers or strings.

use alloy_primitives::U256;
use weituo_core::types::Transaction;

fn parse(json: &str) -> Transaction {
    serde_json::from_str(json).expect(json)
}

/// Base JSON with a fixed value=0; use for gas field tests.
fn base_gas(extra: &str) -> String {
    format!(
        r#"{{"chainId":1,"to":"0xabc","from":"0xdef","data":"0xa9059cbb00000000","value":0,{extra}}}"#
    )
}

/// Base JSON without value field; use for value field tests.
fn base_value(value_json: &str) -> String {
    format!(
        r#"{{"chainId":1,"to":"0xabc","from":"0xdef","data":"0xa9059cbb00000000","value":{value_json}}}"#
    )
}

fn base_chain_id(chain_id_json: &str) -> String {
    format!(
        r#"{{"chainId":{chain_id_json},"to":"0xabc","from":"0xdef","data":"0xa9059cbb00000000","value":0}}"#
    )
}

#[test]
fn chain_id_integer() {
    let tx = parse(&base_chain_id("1"));
    assert_eq!(tx.chain_id, 1);
}

#[test]
fn chain_id_hex_string() {
    let tx = parse(&base_chain_id(r#""0x1""#));
    assert_eq!(tx.chain_id, 1);
}

// ── gasLimit ─────────────────────────────────────────────────────────────────

#[test]
fn gas_limit_integer() {
    let tx = parse(&base_gas(r#""gasLimit":21000"#));
    assert_eq!(tx.gas_limit, 21000);
}

#[test]
fn gas_limit_hex_string() {
    let tx = parse(&base_gas(r#""gasLimit":"0x5208""#)); // 0x5208 = 21000
    assert_eq!(tx.gas_limit, 21000);
}

#[test]
fn gas_limit_hex_string_uppercase() {
    let tx = parse(&base_gas(r#""gasLimit":"0X5208""#));
    assert_eq!(tx.gas_limit, 21000);
}

#[test]
fn gas_limit_decimal_string() {
    let tx = parse(&base_gas(r#""gasLimit":"21000""#));
    assert_eq!(tx.gas_limit, 21000);
}

#[test]
fn gas_limit_scientific_bare() {
    let tx = parse(&base_gas(r#""gasLimit":2.1e4"#));
    assert_eq!(tx.gas_limit, 21_000);
}

#[test]
fn gas_limit_scientific_string() {
    let tx = parse(&base_gas(r#""gasLimit":"2.1e4""#));
    assert_eq!(tx.gas_limit, 21_000);
}

#[test]
fn gas_limit_absent_defaults_to_zero() {
    let tx = parse(&base_gas(r#""gasPrice":0"#));
    assert_eq!(tx.gas_limit, 0);
}

#[test]
fn gas_limit_rejects_null() {
    let err = serde_json::from_str::<Transaction>(&base_gas(r#""gasLimit":null"#))
        .expect_err("null gasLimit must fail to parse");
    assert!(
        err.to_string().contains("expected integer or hex string"),
        "unexpected error: {err}"
    );
}

#[test]
fn gas_limit_rejects_overflow_integer() {
    let err = serde_json::from_str::<Transaction>(&base_gas(r#""gasLimit":18446744073709551616"#))
        .expect_err("overflowing gasLimit must fail to parse");
    assert!(
        err.to_string().contains("integer overflow for u64"),
        "unexpected error: {err}"
    );
}

// ── gasPrice ─────────────────────────────────────────────────────────────────

#[test]
fn gas_price_integer() {
    let tx = parse(&base_gas(r#""gasPrice":1000000000"#)); // 1 gwei
    assert_eq!(tx.gas_price, 1_000_000_000);
}

#[test]
fn gas_price_hex_string() {
    let tx = parse(&base_gas(r#""gasPrice":"0x3b9aca00""#)); // 0x3b9aca00 = 1_000_000_000
    assert_eq!(tx.gas_price, 1_000_000_000);
}

#[test]
fn gas_price_scientific_string() {
    let tx = parse(&base_gas(r#""gasPrice":"1e9""#));
    assert_eq!(tx.gas_price, 1_000_000_000);
}

#[test]
fn gas_price_scientific_bare() {
    let tx = parse(&base_gas(r#""gasPrice":1e9"#));
    assert_eq!(tx.gas_price, 1_000_000_000);
}

#[test]
fn gas_price_scientific_rejects_overflow() {
    let json = base_gas(r#""gasPrice":"1e20""#);
    assert!(serde_json::from_str::<Transaction>(&json).is_err());
}

#[test]
fn gas_price_absent_defaults_to_zero() {
    let tx = parse(&base_gas(r#""gasLimit":0"#));
    assert_eq!(tx.gas_price, 0);
}

#[test]
fn transaction_type_absent_is_none() {
    let tx = parse(&base_gas(r#""gasLimit":0"#));
    assert_eq!(tx.transaction_type, None);
}

#[test]
fn transaction_type_accepts_hex_type_field() {
    let tx = parse(&base_gas(r#""type":"0x2""#));
    assert_eq!(tx.transaction_type, Some(2));
}

#[test]
fn transaction_type_accepts_uppercase_hex_type_field() {
    let tx = parse(&base_gas(r#""type":"0X2""#));
    assert_eq!(tx.transaction_type, Some(2));
}

#[test]
fn transaction_type_accepts_decimal_transaction_type_field() {
    let tx = parse(&base_gas(r#""transactionType":"1""#));
    assert_eq!(tx.transaction_type, Some(1));
}

#[test]
fn transaction_type_accepts_snake_case_field() {
    let tx = parse(&base_gas(r#""transaction_type":2"#));
    assert_eq!(tx.transaction_type, Some(2));
}

#[test]
fn transaction_type_accepts_short_snake_case_field() {
    let tx = parse(&base_gas(r#""tx_type":2"#));
    assert_eq!(tx.transaction_type, Some(2));
}

#[test]
fn transaction_type_null_is_none() {
    let tx = parse(&base_gas(r#""type":null"#));
    assert_eq!(tx.transaction_type, None);
}

#[test]
fn transaction_type_rejects_malformed_string() {
    let err = serde_json::from_str::<Transaction>(&base_gas(r#""type":"bad""#))
        .expect_err("malformed transaction type must fail to parse");
    assert!(
        err.to_string().contains("invalid digit"),
        "unexpected error: {err}"
    );
}

#[test]
fn transaction_type_rejects_array() {
    let err = serde_json::from_str::<Transaction>(&base_gas(r#""type":[2]"#))
        .expect_err("array transaction type must fail to parse");
    assert!(
        err.to_string().contains("expected integer or hex string"),
        "unexpected error: {err}"
    );
}

#[test]
fn transaction_type_rejects_overflow_integer() {
    let err = serde_json::from_str::<Transaction>(&base_gas(r#""type":18446744073709551616"#))
        .expect_err("overflowing transaction type must fail to parse");
    assert!(
        err.to_string().contains("integer overflow for u64"),
        "unexpected error: {err}"
    );
}

// ── value ────────────────────────────────────────────────────────────────────

#[test]
fn value_zero_integer() {
    let tx = parse(&base_value("0"));
    assert_eq!(tx.value, U256::ZERO);
}

#[test]
fn value_small_integer() {
    let tx = parse(&base_value("1000"));
    assert_eq!(tx.value, U256::from(1000u64));
}

#[test]
fn value_hex_string() {
    // 0x6f05b59d3b20000 = 500_000_000_000_000_000 (0.5 ETH in wei)
    let tx = parse(&base_value(r#""0x6f05b59d3b20000""#));
    assert_eq!(tx.value, U256::from(500_000_000_000_000_000u64));
}

#[test]
fn value_decimal_string() {
    let tx = parse(&base_value(r#""499980000000000000000""#));
    let expected = "499980000000000000000".parse::<U256>().unwrap();
    assert_eq!(tx.value, expected);
}

#[test]
fn value_large_integer_bare() {
    // Bare JSON number larger than u64::MAX — requires serde_json/arbitrary_precision.
    // 499980000000000000000 ≈ 500 ETH in wei.
    let tx = parse(&base_value("499980000000000000000"));
    let expected = "499980000000000000000".parse::<U256>().unwrap();
    assert_eq!(tx.value, expected);
}

#[test]
fn value_large_hex_string() {
    // Same value as a hex string
    let hex = format!(r#""0x{:x}""#, 499980000000000000000u128);
    let tx = parse(&base_value(&hex));
    let expected = U256::from(499980000000000000000u128);
    assert_eq!(tx.value, expected);
}

#[test]
fn value_scientific_bare() {
    let tx = parse(&base_value("1e48"));
    let expected = format!("1{}", "0".repeat(48));
    assert_eq!(tx.value, expected.parse::<U256>().unwrap());
}

#[test]
fn value_scientific_string() {
    let tx = parse(&base_value(r#""1.25e21""#));
    let expected = "1250000000000000000000".parse::<U256>().unwrap();
    assert_eq!(tx.value, expected);
}

#[test]
fn value_scientific_fraction_truncates() {
    let tx = parse(&base_value(r#""1.9e-1""#));
    assert_eq!(tx.value, U256::ZERO);
}

#[test]
fn value_scientific_rejects_negative() {
    let json = base_value(r#""-1e3""#);
    assert!(serde_json::from_str::<Transaction>(&json).is_err());
}

#[test]
fn value_scientific_rejects_overflow() {
    let json = base_value(r#""1e78""#);
    assert!(serde_json::from_str::<Transaction>(&json).is_err());
}

#[test]
fn value_scientific_rejects_empty_mantissa() {
    let json = base_value(r#""e5""#);
    assert!(serde_json::from_str::<Transaction>(&json).is_err());
}

#[test]
fn value_scientific_leading_zero_truncates_to_zero() {
    let tx = parse(&base_value(r#""0000125e-7""#)); // 0.0000125 → 0
    assert_eq!(tx.value, U256::ZERO);
}
