use alloy_dyn_abi::{DynSolType, DynSolValue};
use anyhow::{anyhow, Result};
/// Decodes EVM calldata into a named argument map using the stored ABI item.
///
/// Uses alloy-dyn-abi for correct ABI v2 decoding (static + dynamic types,
/// tuples, nested arrays). Tuple fields are decoded into JSON objects keyed
/// by their component names from the ABI, so WAF rules can use
/// `args.swapList[0].pair` or `args.baseRequest.fromToken`.
use std::collections::HashMap;

use crate::types::{AbiInput, AbiItem};

/// Decode raw calldata hex into `{param_name → serde_json::Value}`.
/// The 4-byte selector is stripped automatically.
pub fn decode_calldata(
    abi_item: &AbiItem,
    data: &str,
) -> Result<HashMap<String, serde_json::Value>> {
    let hex = data.trim_start_matches("0x");
    if hex.len() < 8 {
        return Err(anyhow!(
            "calldata too short (need at least 4-byte selector)"
        ));
    }

    let params_bytes = hex::decode(&hex[8..]).map_err(|e| anyhow!("hex decode: {e}"))?;

    // Build a tuple type from all inputs, decode in one shot.
    let types: Vec<DynSolType> = abi_item
        .inputs
        .iter()
        .map(parse_type)
        .collect::<Result<_>>()?;

    // Use abi_decode_params (not abi_decode) — function parameters are encoded
    // as a params sequence, which differs from a standalone tuple value encoding.
    let decoded = DynSolType::Tuple(types)
        .abi_decode_params(&params_bytes)
        .map_err(|e| anyhow!("ABI decode failed: {e}"))?;

    let DynSolValue::Tuple(values) = decoded else {
        return Err(anyhow!("unexpected decoded shape"));
    };

    let mut result = HashMap::new();
    for (idx, (input, value)) in abi_item.inputs.iter().zip(values).enumerate() {
        // Unnamed parameters get __arg{idx} keys
        let key = if input.name.is_empty() {
            format!("__arg{idx}")
        } else {
            input.name.clone()
        };
        result.insert(key, value_to_json(value, input));
    }
    Ok(result)
}

/// Decode raw ABI-encoded params (no leading 4-byte selector) into a named argument map.
/// Used for command-dispatch patterns where inputs[i] contains only param bytes.
pub fn decode_args_only(
    inputs: &[AbiInput],
    hex: &str,
) -> Result<HashMap<String, serde_json::Value>> {
    let raw = hex::decode(hex.trim_start_matches("0x")).map_err(|e| anyhow!("hex decode: {e}"))?;

    let types: Vec<DynSolType> = inputs.iter().map(parse_type).collect::<Result<_>>()?;
    let decoded = DynSolType::Tuple(types)
        .abi_decode_params(&raw)
        .map_err(|e| anyhow!("ABI decode failed: {e}"))?;
    let DynSolValue::Tuple(values) = decoded else {
        return Err(anyhow!("unexpected decoded shape"));
    };

    let mut result = HashMap::new();
    for (idx, (input, value)) in inputs.iter().zip(values).enumerate() {
        let key = if input.name.is_empty() {
            format!("__arg{idx}")
        } else {
            input.name.clone()
        };
        result.insert(key, value_to_json(value, input));
    }
    Ok(result)
}

/// Recursively convert a decoded value to JSON, using the ABI input for
/// component names (so tuples become `{"field": value}` not `[value]`).
fn value_to_json(v: DynSolValue, input: &AbiInput) -> serde_json::Value {
    match v {
        DynSolValue::Address(a) => {
            // EIP-55 checksummed. The evaluator also normalises both sides to
            // lowercase, so rules with lowercase or any-case literals still
            // compare equal regardless.
            serde_json::Value::String(a.to_checksum(None))
        }
        DynSolValue::Bool(b) => serde_json::Value::Bool(b),

        // Integers as decimal strings to preserve uint256 precision
        DynSolValue::Uint(u, _) => serde_json::Value::String(u.to_string()),
        DynSolValue::Int(i, _) => serde_json::Value::String(i.to_string()),

        DynSolValue::FixedBytes(b, _) => serde_json::Value::String(format!("0x{}", hex::encode(b))),
        DynSolValue::Bytes(b) => serde_json::Value::String(format!("0x{}", hex::encode(b))),
        DynSolValue::String(s) => serde_json::Value::String(s),

        // Arrays/fixed-arrays: each element gets the same input (array element type).
        // Strip one [] suffix so elements get the correct component names.
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) => {
            let elem_input = strip_array_suffix(input);
            serde_json::Value::Array(
                items
                    .into_iter()
                    .map(|v| value_to_json(v, &elem_input))
                    .collect(),
            )
        }

        // Tuples: zip decoded fields with component names from the ABI.
        // Unnamed components get __arg{idx} keys.
        DynSolValue::Tuple(fields) => {
            if !input.components.is_empty() {
                let obj = input
                    .components
                    .iter()
                    .zip(fields)
                    .enumerate()
                    .map(|(idx, (comp, val))| {
                        let key = if comp.name.is_empty() {
                            format!("__arg{idx}")
                        } else {
                            comp.name.clone()
                        };
                        (key, value_to_json(val, comp))
                    })
                    .collect::<serde_json::Map<_, _>>();
                serde_json::Value::Object(obj)
            } else {
                serde_json::Value::Array(
                    fields
                        .into_iter()
                        .map(|v| value_to_json(v, &AbiInput::default()))
                        .collect(),
                )
            }
        }

        _ => serde_json::Value::Null,
    }
}

/// Build a synthetic AbiInput for array elements by stripping one `[]` suffix.
/// e.g. `tuple[]` → `tuple`, `address[][]` → `address[]`
/// Components are preserved so nested tuple arrays decode correctly.
fn strip_array_suffix(input: &AbiInput) -> AbiInput {
    // Strip the last [] or [N] suffix, e.g. "tuple[][]" → "tuple[]", "address[]" → "address"
    let kind = if let Some(s) = input.kind.strip_suffix("[]") {
        s.to_string()
    } else if let Some(i) = input.kind.rfind('[') {
        input.kind[..i].to_string()
    } else {
        input.kind.clone()
    };
    AbiInput {
        name: input.name.clone(),
        kind,
        components: input.components.clone(),
    }
}

/// Parse an AbiInput into a DynSolType.
fn parse_type(input: &AbiInput) -> Result<DynSolType> {
    if input.kind == "tuple" || input.kind.starts_with("tuple[") {
        let inner: Vec<DynSolType> = input
            .components
            .iter()
            .map(parse_type)
            .collect::<Result<_>>()?;
        let base = DynSolType::Tuple(inner);
        return apply_array_suffix(&input.kind, base);
    }
    input
        .kind
        .parse::<DynSolType>()
        .map_err(|e| anyhow!("unknown ABI type '{}': {e}", input.kind))
}

fn apply_array_suffix(kind: &str, base: DynSolType) -> Result<DynSolType> {
    // Strip "tuple" prefix, then apply each [] or [N] suffix left-to-right.
    // e.g. "tuple[][]" → Array(Array(Tuple(...))), "tuple[3][]" → Array(FixedArray(Tuple(...), 3))
    let mut remaining = kind.trim_start_matches("tuple");
    let mut current = base;
    while !remaining.is_empty() {
        if let Some(rest) = remaining.strip_prefix("[]") {
            current = DynSolType::Array(Box::new(current));
            remaining = rest;
        } else if remaining.starts_with('[') {
            let end = remaining
                .find(']')
                .ok_or_else(|| anyhow!("unclosed bracket in '{kind}'"))?;
            let n: usize = remaining[1..end]
                .parse()
                .map_err(|_| anyhow!("invalid fixed array size in '{kind}'"))?;
            current = DynSolType::FixedArray(Box::new(current), n);
            remaining = &remaining[end + 1..];
        } else {
            return Err(anyhow!("unrecognised tuple array suffix in '{kind}'"));
        }
    }
    Ok(current)
}

/// Build a [`MulticallDecoder`] from a rule's `decoder_type` + `decoder_config`
/// (raw JSON object). Returns `None` when either part is missing — the caller
/// decides whether that means "no multicall" or "invalid decoder".
pub fn build_decoder(
    kind: Option<crate::types::DecoderKind>,
    config: Option<&serde_json::Value>,
) -> Option<crate::types::MulticallDecoder> {
    use crate::types::{DecoderKind, MulticallDecoder};
    let kind = kind?;
    let cfg = config?;
    let s =
        |key: &str, default: &str| -> String { cfg[key].as_str().unwrap_or(default).to_string() };
    match kind {
        DecoderKind::BytesArray => Some(MulticallDecoder::BytesArray {
            data_param: s("data_param", "data"),
        }),
        DecoderKind::TupleArray => Some(MulticallDecoder::TupleArray {
            calls_param: s("calls_param", "calls"),
            data_field: s("data_field", "callData"),
            target_field: s("target_field", "target"),
        }),
        DecoderKind::ParallelArrays => Some(MulticallDecoder::ParallelArrays {
            data_param: s("data_param", "calldatas"),
            target_param: s("target_param", "targets"),
        }),
        DecoderKind::UniversalRouter => Some(MulticallDecoder::UniversalRouter {
            commands_param: s("commands_param", "commands"),
            inputs_param: s("inputs_param", "inputs"),
        }),
    }
}
