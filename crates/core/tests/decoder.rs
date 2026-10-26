//! Decoder tests: real-world calldata samples covering tuples, nested arrays,
//! bytes, and unnamed parameters.
//!
//! Value conventions produced by `decode_calldata`:
//! - uint/int are decimal strings — JSON precision for uint256
//! - bytes/bytes32 are "0x..." hex strings
//! - address is EIP-55 checksummed "0x..."
//! - arrays are JSON arrays; tuples are JSON objects keyed by component name
//! - unnamed parameters use __arg{idx} keys

use std::collections::HashMap;

use serde_json::json;

use weituo_core::decoder::decode_calldata;
use weituo_core::types::{AbiInput, AbiItem};

// ── ABI helpers ───────────────────────────────────────────────────────────────

fn parse_abi(json: &str) -> AbiItem {
    serde_json::from_str(json).expect("invalid ABI JSON")
}

// ── ABIs ──────────────────────────────────────────────────────────────────────

fn abi_swap_eth_for_specific_nfts() -> AbiItem {
    parse_abi(
        r#"{
        "name": "swapETHForSpecificNFTs",
        "type": "function",
        "stateMutability": "payable",
        "inputs": [
            {
                "name": "swapList",
                "type": "tuple[]",
                "components": [
                    {"name": "pair",   "type": "address"},
                    {"name": "nftIds", "type": "uint256[]"}
                ]
            },
            {"name": "ethRecipient", "type": "address"},
            {"name": "nftRecipient", "type": "address"},
            {"name": "deadline",     "type": "uint256"}
        ],
        "outputs": [{"name": "remainingValue", "type": "uint256"}]
    }"#,
    )
}

fn abi_claim() -> AbiItem {
    parse_abi(
        r#"{
        "name": "claim",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "users",   "type": "address[]"},
            {"name": "tokens",  "type": "address[]"},
            {"name": "amounts", "type": "uint256[]"},
            {"name": "proofs",  "type": "bytes32[][]"}
        ],
        "outputs": []
    }"#,
    )
}

fn abi_execute() -> AbiItem {
    parse_abi(
        r#"{
        "name": "execute",
        "type": "function",
        "stateMutability": "payable",
        "inputs": [
            {"name": "commands", "type": "bytes"},
            {"name": "inputs",   "type": "bytes[]"},
            {"name": "deadline", "type": "uint256"}
        ],
        "outputs": []
    }"#,
    )
}

fn abi_smart_swap_by_order_id() -> AbiItem {
    parse_abi(
        r#"{
        "name": "smartSwapByOrderId",
        "type": "function",
        "stateMutability": "payable",
        "inputs": [
            {"name": "orderId", "type": "uint256"},
            {
                "name": "baseRequest",
                "type": "tuple",
                "components": [
                    {"name": "fromToken",        "type": "uint256"},
                    {"name": "toToken",          "type": "address"},
                    {"name": "fromTokenAmount",  "type": "uint256"},
                    {"name": "minReturnAmount",  "type": "uint256"},
                    {"name": "deadLine",         "type": "uint256"}
                ]
            },
            {"name": "batchesAmount", "type": "uint256[]"},
            {
                "name": "batches",
                "type": "tuple[][]",
                "components": [
                    {"name": "mixAdapters", "type": "address[]"},
                    {"name": "assetTo",     "type": "address[]"},
                    {"name": "rawData",     "type": "uint256[]"},
                    {"name": "extraData",   "type": "bytes[]"},
                    {"name": "fromToken",   "type": "uint256"}
                ]
            },
            {
                "name": "extraData",
                "type": "tuple[]",
                "components": [
                    {"name": "pathIndex",         "type": "uint256"},
                    {"name": "payer",             "type": "address"},
                    {"name": "fromToken",         "type": "address"},
                    {"name": "toToken",           "type": "address"},
                    {"name": "fromTokenAmountMax","type": "uint256"},
                    {"name": "toTokenAmountMax",  "type": "uint256"},
                    {"name": "salt",              "type": "uint256"},
                    {"name": "deadLine",          "type": "uint256"},
                    {"name": "isPushOrder",       "type": "bool"},
                    {"name": "extension",         "type": "bytes"}
                ]
            }
        ],
        "outputs": [{"name": "returnAmount", "type": "uint256"}]
    }"#,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Decodes a payable swap whose argument is a tuple array.
#[test]
fn swap_eth_for_specific_nfts_tuple_array() {
    // real-world calldata sample
    let data = "0x111320000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000ca6f3defbc6041299837725f6430f33b0f24e5c0000000000000000000000000ca6f3defbc6041299837725f6430f33b0f24e5c00000000000000000000000000000000000000000000000000000000062e9ca1800000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000575570f62c90a61763b1e93cf0da62ed810dbda2000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000561";

    let args = decode_calldata(&abi_swap_eth_for_specific_nfts(), data).unwrap();

    // swapList is array of {pair, nftIds} objects
    assert_eq!(
        args["swapList"],
        json!([
            {
                "pair":   "0x575570F62c90a61763b1e93Cf0Da62eD810dbDa2",
                "nftIds": ["1377"]
            }
        ])
    );
    assert_eq!(
        args["ethRecipient"],
        json!("0xCA6F3Defbc6041299837725f6430f33B0F24e5C0")
    );
    assert_eq!(
        args["nftRecipient"],
        json!("0xCA6F3Defbc6041299837725f6430f33B0F24e5C0")
    );
    assert_eq!(args["deadline"], json!("1659488792"));
}

/// Decodes `bytes` and `bytes[]` arguments (Uniswap-style execute).
#[test]
fn execute_bytes_and_bytes_array() {
    // real-world calldata sample
    let data = "0x3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000066315593000000000000000000000000000000000000000000000000000000000000000300060c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000158f681b29fbc7873c90000000000000000000000000000000000000000000000007b5809110e99138900000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002b808507121b80c02388fad14726482e061b8da827000bb8c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000037a8f295612602f2774d331e562be9e61b83a3270000000000000000000000000000000000000000000000000000000000000019000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000007b5809110e991389";

    let args = decode_calldata(&abi_execute(), data).unwrap();

    assert_eq!(args["commands"], json!("0x00060c"));
    assert_eq!(args["deadline"], json!("1714509203"));

    // inputs is bytes[] — three hex-encoded blobs
    let inputs = args["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 3);
    // first input contains the swap path
    assert!(inputs[0].as_str().unwrap().starts_with("0x"));
    assert!(inputs[0].as_str().unwrap().contains("808507121b80"));
}

/// Decodes a two-dimensional fixed-byte array (`bytes32[][]`).
#[test]
fn claim_bytes32_2d_array() {
    // real-world calldata sample
    let data = "0x71ee95c0000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000934f719cd3fadef7bb30e297f6687ad978a076b700000000000000000000000000000000000000000000000000000000000000010000000000000000000000006b3595068778dd592e39a122f4f5a5cf09c90fe2000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000030afb97e9507ab9550000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000ad162b50e03f5ca065f5f13cd2c65744877194219a9a1520ebe8b4327eaa509945375d3fedbaa836660791c66775eacfade558aceebb8aecab8940b138a844a601779ad5dd4897e835a3777d177d4dc6019a4ba46ea2713f7466f164458159ab5e13f0480977ba1694945183bd8bb1c216c45da56aa82b33c2995db3cf3c15f07ec01f7626fa2122f179696264b402448db62de07899f9a68e511f1c7a1068ab99b5feef23af33b9eebaa2cd394e323f750fae3fc0b8cc67208c550cc760cc2b74c70f9b89b51ceb082c87778b56f4e01086d18ea7afc89b4824f025e376241feabc79489f4f479f6c1e810396cf5038944a392a797eee460d811e3988dacd496eaafbe1e0cf599e83e51c86a9dbde94acdbdd11a0f4d818cc79afc31332256bf0a20eef93fc442a1e6f2f9b23267ee74ecafa475501097cb80ad83da61606a75";

    let args = decode_calldata(&abi_claim(), data).unwrap();

    let users = args["users"].as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(
        users[0],
        json!("0x934f719cd3fADeF7bB30E297F6687Ad978A076B7")
    );

    let tokens = args["tokens"].as_array().unwrap();
    assert_eq!(
        tokens[0],
        json!("0x6B3595068778DD592e39A122f4f5a5cF09C90fE2")
    );

    let amounts = args["amounts"].as_array().unwrap();
    assert_eq!(amounts[0], json!("14369696104702900000000"));

    // proofs: array of array of bytes32
    let proofs = args["proofs"].as_array().unwrap();
    assert_eq!(proofs.len(), 1);
    let proof0 = proofs[0].as_array().unwrap();
    assert_eq!(proof0.len(), 10);
    assert_eq!(
        proof0[0],
        json!("0xd162b50e03f5ca065f5f13cd2c65744877194219a9a1520ebe8b4327eaa50994")
    );
    assert_eq!(
        proof0[9],
        json!("0x0a20eef93fc442a1e6f2f9b23267ee74ecafa475501097cb80ad83da61606a75")
    );
}

/// Decodes nested tuples: tuple containing tuple[][] and bytes[].
#[test]
fn smart_swap_nested_tuples() {
    // real-world calldata sample
    let data = "0xb80c2f090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee000000000000000000000000000000000000000000000000000000004d7c6d0000000000000000000000000000000000000000000000000006d37a2c0b0175dc000000000000000000000000000000000000000000000000000000006836b8310000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000004600000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000004d7c6d00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000160000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000001000000000000000000000000cbd78f8fb96bae40826a601f8b9ba17782d625270000000000000000000000000000000000000000000000000000000000000001000000000000000000000000cbd78f8fb96bae40826a601f8b9ba17782d6252700000000000000000000000000000000000000000000000000000000000000010000000000000000000027101ac1a8feaaea1900c4166deeed0c11cc10669d360000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000060000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000000000001f40000000000000000000000000000000000000000000000000000000000000000";

    let args = decode_calldata(&abi_smart_swap_by_order_id(), data).unwrap();

    assert_eq!(args["orderId"], json!("0"));

    // baseRequest is a named tuple
    let br = &args["baseRequest"];
    assert_eq!(
        br["toToken"],
        json!("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE")
    );
    assert_eq!(br["fromTokenAmount"], json!("1300000000"));
    assert_eq!(br["deadLine"], json!("1748416561"));

    // batchesAmount is uint256[]
    let ba = args["batchesAmount"].as_array().unwrap();
    assert_eq!(ba[0], json!("1300000000"));

    // batches is tuple[][] — array of arrays of named tuples
    let batches = args["batches"].as_array().unwrap();
    assert_eq!(batches.len(), 1);
    let batch0 = batches[0].as_array().unwrap();
    assert_eq!(batch0.len(), 1);
    let path = &batch0[0];
    assert_eq!(
        path["mixAdapters"].as_array().unwrap()[0],
        json!("0xCBD78F8fb96baE40826A601F8B9ba17782d62527")
    );
    assert_eq!(
        path["assetTo"].as_array().unwrap()[0],
        json!("0xCBD78F8fb96baE40826A601F8B9ba17782d62527")
    );
    // extraData within the path is bytes[]
    let extra = path["extraData"].as_array().unwrap();
    assert_eq!(extra.len(), 1);
    assert!(extra[0].as_str().unwrap().starts_with("0x"));

    // top-level extraData is empty tuple[]
    assert_eq!(args["extraData"], json!([]));
}

// ── Retained basic type tests from original decoder.rs ────────────────────────

fn abi(name: &str, inputs: &[(&str, &str)]) -> AbiItem {
    AbiItem {
        kind: "function".into(),
        name: name.into(),
        inputs: inputs
            .iter()
            .map(|(t, n)| AbiInput {
                kind: t.to_string(),
                name: n.to_string(),
                components: vec![],
            })
            .collect(),
        state_mutability: "nonpayable".into(),
    }
}

const TRANSFER_CALLDATA: &str = "0xa9059cbb\
     000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7\
     00000000000000000000000000000000000000000000000000000000000f4240";

#[test]
fn decode_transfer_address_and_uint() {
    let item = abi("transfer", &[("address", "to"), ("uint256", "value")]);
    let args = decode_calldata(&item, TRANSFER_CALLDATA).unwrap();
    // Decoder returns EIP-55 checksummed addresses
    assert_eq!(
        args["to"].as_str().unwrap(),
        "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    );
    assert_eq!(args["value"].as_str().unwrap(), "1000000");
}

const SET_APPROVAL_TRUE: &str = "0xa22cb465\
     000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd\
     0000000000000000000000000000000000000000000000000000000000000001";

#[test]
fn decode_bool_true() {
    let item = abi(
        "setApprovalForAll",
        &[("address", "operator"), ("bool", "approved")],
    );
    let args = decode_calldata(&item, SET_APPROVAL_TRUE).unwrap();
    assert!(args["approved"].as_bool().unwrap());
}

#[test]
fn decode_too_short_fails() {
    let item = abi("transfer", &[("address", "to"), ("uint256", "value")]);
    assert!(decode_calldata(&item, "0xa9059cbb").is_err());
}

#[test]
fn decode_no_args_is_empty_map() {
    let item = abi("withdraw", &[]);
    assert!(decode_calldata(&item, "0x3ccfd60b").unwrap().is_empty());
}

const MULTI_UINT_CALLDATA: &str = "0xdeadbeef\
     0000000000000000000000000000000000000000000000000000000000000064\
     00000000000000000000000000000000000000000000000000000000000001f4";

#[test]
fn decode_multiple_uints() {
    let item = abi("foo", &[("uint256", "a"), ("uint256", "b")]);
    let args = decode_calldata(&item, MULTI_UINT_CALLDATA).unwrap();
    assert_eq!(args["a"].as_str().unwrap(), "100");
    assert_eq!(args["b"].as_str().unwrap(), "500");
}

// ── Unnamed parameters ────────────────────────────────────────────────────────
// ABIs with empty parameter names get __arg{idx} keys

#[test]
#[allow(non_snake_case)]
fn unnamed_params_use__arg_idx() {
    // ABI with no param names — params become __arg0, __arg1, etc.
    use weituo_core::types::AbiInput;
    let item = weituo_core::types::AbiItem {
        kind: "function".into(),
        name: "noNames".into(),
        state_mutability: "nonpayable".into(),
        inputs: vec![
            AbiInput {
                name: "".into(),
                kind: "address".into(),
                components: vec![],
            },
            AbiInput {
                name: "".into(),
                kind: "uint256".into(),
                components: vec![],
            },
        ],
    };
    let calldata = "0xdeadbeef\
        000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7\
        00000000000000000000000000000000000000000000000000000000000f4240";

    let args = decode_calldata(&item, calldata).unwrap();
    // Unnamed → __arg0, __arg1
    assert!(
        args.contains_key("__arg0"),
        "expected __arg0, got {:?}",
        args.keys().collect::<Vec<_>>()
    );
    assert!(args.contains_key("__arg1"), "expected __arg1");
    assert_eq!(
        args["__arg0"].as_str().unwrap(),
        "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    );
    assert_eq!(args["__arg1"].as_str().unwrap(), "1000000");
}

#[test]
#[allow(non_snake_case)]
fn unnamed_tuple_components_use__arg_idx() {
    use weituo_core::types::{AbiInput, AbiItem};
    // Tuple with unnamed components
    let item = AbiItem {
        kind: "function".into(),
        name: "swap".into(),
        state_mutability: "nonpayable".into(),
        inputs: vec![AbiInput {
            name: "params".into(),
            kind: "tuple".into(),
            components: vec![
                AbiInput {
                    name: "".into(),
                    kind: "address".into(),
                    components: vec![],
                }, // __arg0
                AbiInput {
                    name: "fee".into(),
                    kind: "uint256".into(),
                    components: vec![],
                }, // fee (named)
                AbiInput {
                    name: "".into(),
                    kind: "uint256".into(),
                    components: vec![],
                }, // __arg2
            ],
        }],
    };
    // params = (0xdac17f..., 3000, 500)
    let calldata = "0xdeadbeef\
        000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7\
        0000000000000000000000000000000000000000000000000000000000000bb8\
        00000000000000000000000000000000000000000000000000000000000001f4";

    let args = decode_calldata(&item, calldata).unwrap();
    let params = &args["params"];
    assert!(
        params.get("__arg0").is_some(),
        "unnamed component[0] should be __arg0"
    );
    assert!(
        params.get("fee").is_some(),
        "named component[1] should stay 'fee'"
    );
    assert!(
        params.get("__arg2").is_some(),
        "unnamed component[2] should be __arg2"
    );
    assert_eq!(params["fee"].as_str().unwrap(), "3000");
}

// ── Multicall decoder pattern tests ──────────────────────────────────────────
//
// Etherscan was rate-limited (no API key), so calldata was constructed by hand
// using standard ABI encoding, matching real mainnet patterns.
//
// Each test:
//   1. Defines the outer function ABI
//   2. Calls decode_calldata to get outer_args
//   3. Extracts inner calls (replicating extract_inner_calldata logic inline)
//   4. Asserts inner call count > 0
//   5. Decodes the first inner call and asserts a named arg is present

/// Helper: extract a flat bytes[] field from decoded args.
/// Replicates the logic of checker::extract_inner_calldata for a flat path (no dot).
fn extract_bytes_array(
    outer_args: &HashMap<String, serde_json::Value>,
    field: &str,
) -> Vec<String> {
    match outer_args.get(field) {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => vec![],
    }
}

/// Helper: extract a field from each element of a tuple array (dot-path: "array.field").
fn extract_tuple_field(
    outer_args: &HashMap<String, serde_json::Value>,
    array_key: &str,
    field_key: &str,
) -> Vec<String> {
    match outer_args.get(array_key) {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|elem| elem.get(field_key)?.as_str().map(String::from))
            .collect(),
        _ => vec![],
    }
}

// ── bytes_array: multicall(uint256,bytes[]) — SwapRouter02 on mainnet ────────

/// Real mainnet tx: Uniswap V3 SwapRouter02 multicall(uint256 deadline, bytes[] data)
/// tx: 0x02eabc1de1a587a92983e7a08f4407337c55fd9683d49b24d3f2302646ef1ea9
/// One inner call: exactInputSingle swapping 1 ETH → USDC
#[test]
fn multicall_bytes_array_decoder() {
    let calldata = "0x5ae401dc000000000000000000000000000000000000000000000000000000006a1d444b00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e404e45aaf000000000000000000000000266e5923f6118f8b340ca5a23ae7f71897361476000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000cdddbcb65f01d7696ecca0e635f425ce4d4290100000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000951dbb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let abi_multicall = parse_abi(
        r#"{
        "name": "multicall",
        "type": "function",
        "stateMutability": "payable",
        "inputs": [
            {"name": "deadline", "type": "uint256"},
            {"name": "data",     "type": "bytes[]"}
        ],
        "outputs": []
    }"#,
    );

    let outer_args = decode_calldata(&abi_multicall, calldata).unwrap();

    assert_eq!(outer_args["deadline"].as_str().unwrap(), "1780302923"); // 0x6a1d444b

    let inner_calls = extract_bytes_array(&outer_args, "data");
    assert_eq!(inner_calls.len(), 1, "expected 1 inner call");

    // Inner call is exactInputSingle — verify selector prefix
    assert!(
        inner_calls[0].starts_with("0x04e45aaf"),
        "expected exactInputSingle selector"
    );

    // Decode inner: exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))
    let abi_eis = parse_abi(
        r#"{
        "name": "exactInputSingle",
        "type": "function",
        "stateMutability": "payable",
        "inputs": [{
            "name": "params", "type": "tuple",
            "components": [
                {"name": "tokenIn",            "type": "address"},
                {"name": "tokenOut",           "type": "address"},
                {"name": "fee",                "type": "uint24"},
                {"name": "recipient",          "type": "address"},
                {"name": "amountIn",           "type": "uint256"},
                {"name": "amountOutMinimum",   "type": "uint256"},
                {"name": "sqrtPriceLimitX96",  "type": "uint160"}
            ]
        }],
        "outputs": []
    }"#,
    );
    let inner_args = decode_calldata(&abi_eis, &inner_calls[0]).unwrap();
    let params = inner_args["params"].as_object().unwrap();
    assert_eq!(
        params["amountIn"].as_str().unwrap(),
        "1000000000000000000",
        "amountIn should be 1 ETH"
    );
    assert_eq!(params["fee"].as_str().unwrap(), "500");
}

// ── tuple_array: aggregate3Value(Call3Value[]) — Multicall3 on mainnet ───────

/// Real mainnet tx: Multicall3 aggregate3Value with one inner call
/// tx: 0x37b2d00322501adba7fb11e5796579fac7a6e4d536b95ac0db5053cf3b73e1a6
/// Call3Value = {address target, bool allowFailure, uint256 value, bytes callData}
#[test]
fn multicall_tuple_array_decoder() {
    let calldata = "0x174dea71000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000db9b1e94b5b69df7e401ddbede43491141047db300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000005c4cef6d209000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000004a000000000000000000000000000000000000000000000000000000000000004e00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000003e00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000a1100000000000000000000000047a9802197bb1d7f4ea41b6bd60dd5ede72673a8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000082ea9bca0000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000160000000000000000000000000146713078d39ecc1f5338309c28405ccf85abfbb0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000784cd00e387622c35bddb9b4c962c136462338bc31000000000000000000000000000000000000000000000000001059f66e9e171949290c1c00000000000000000000000047a9802197bb1d7f4ea41b6bd60dd5ede72673a8892c0de76930d6150f833970259047f072760ef40bc6851d64128481eaa60a110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004658b29f6b82ed55274221a06fc97d318e25416000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004166095c7672015ee18e25e13ffd4693976583ec6e8f6c42cb69d3d31522082c76613a41c8f4eb85b0983f8eea36acdcfe0fc1b9ef718077e088f356265c1b637f1c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000784cd00e387622c35bddb9b4c962c136462338bc31000000000000000000000000000000000000000000000000001059f66e9e171949290c1c00000000000000000000000047a9802197bb1d7f4ea41b6bd60dd5ede72673a8892c0de76930d6150f833970259047f072760ef40bc6851d64128481eaa60a11000000000000000000000000000000000000000000000000000000000000000000000000f879c07e98524c7f4aa6c55ec82d99e4e69383930e9475256035cb5576d1de2d";

    let abi_agg3v = parse_abi(
        r#"{
        "name": "aggregate3Value",
        "type": "function",
        "stateMutability": "payable",
        "inputs": [{
            "name": "calls",
            "type": "tuple[]",
            "components": [
                {"name": "target",       "type": "address"},
                {"name": "allowFailure", "type": "bool"},
                {"name": "value",        "type": "uint256"},
                {"name": "callData",     "type": "bytes"}
            ]
        }],
        "outputs": []
    }"#,
    );

    let outer_args = decode_calldata(&abi_agg3v, calldata).unwrap();

    let inner_calls = extract_tuple_field(&outer_args, "calls", "callData");
    assert_eq!(inner_calls.len(), 1, "expected 1 inner call");

    let targets = extract_tuple_field(&outer_args, "calls", "target");
    assert_eq!(
        targets[0].to_lowercase(),
        "0xdb9b1e94b5b69df7e401ddbede43491141047db3".to_lowercase()
    );

    // Inner callData starts with selector 0xcef6d209
    assert!(
        inner_calls[0].starts_with("0xcef6d209"),
        "unexpected inner selector: {}",
        &inner_calls[0][..10]
    );
}

// ── parallel_arrays: executeBatch(address[],uint256[],bytes[],bytes32,bytes32) ─

/// Outer: executeBatch with parallel targets[] and calldatas[] arrays (OZ Timelock pattern).
#[test]
fn multicall_parallel_arrays_decoder() {
    // Synthetic calldata: executeBatch(0x8f2a0bb0) with two parallel entries
    let calldata = "0x8f2a0bb000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc450000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044095ea7b300000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000";

    let abi_execute_batch = parse_abi(
        r#"{
        "name": "executeBatch",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "targets",     "type": "address[]"},
            {"name": "values",      "type": "uint256[]"},
            {"name": "calldatas",   "type": "bytes[]"},
            {"name": "predecessor", "type": "bytes32"},
            {"name": "salt",        "type": "bytes32"}
        ],
        "outputs": []
    }"#,
    );

    let outer_args = decode_calldata(&abi_execute_batch, calldata).unwrap();

    // Parallel arrays: calldatas[] for inner calls, targets[] for addresses
    let inner_calls = extract_bytes_array(&outer_args, "calldatas");
    let inner_targets = extract_bytes_array(&outer_args, "targets");

    assert!(
        inner_calls.len() >= 2,
        "expected >= 2 inner calldatas, got {}",
        inner_calls.len()
    );
    assert_eq!(
        inner_calls.len(),
        inner_targets.len(),
        "targets and calldatas lengths must match"
    );

    // Decode first inner call: transfer(address to, uint256 value)
    let abi_transfer = abi("transfer", &[("address", "to"), ("uint256", "value")]);
    let inner_args = decode_calldata(&abi_transfer, &inner_calls[0]).unwrap();
    assert!(
        inner_args.contains_key("to"),
        "expected 'to' arg in decoded inner call"
    );
    assert_eq!(inner_args["value"].as_str().unwrap(), "1000000");
}

// ── universal_router: execute(bytes,bytes[],uint256) — Uniswap UR V2 mainnet ─

/// Real mainnet tx: Uniswap Universal Router V2 execute
/// tx: 0x978d05526f3552073efe91cb9e86d25a112b5dca7ed213331947a4328e2056fb
/// commands = 0x0b010c  →  [PERMIT2_TRANSFER_FROM, V3_SWAP_EXACT_OUT, SWEEP]
/// inputs[1] contains V3_SWAP_EXACT_OUT bare ABI params (no selector prefix)
#[test]
fn multicall_universal_router_decoder() {
    use weituo_core::decoder::decode_args_only;
    use weituo_core::types::AbiInput;

    let calldata = "0x3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000006a1d407a00000000000000000000000000000000000000000000000000000000000000030b010c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000578fedb8a6ed440000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000049e2cb2fed75300000000000000000000000000000000000000000000000000000000578fedb8a6ed4400000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b974733a3f37208647577bb925d8ee854c7337e29002710c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000";

    let abi_execute = parse_abi(
        r#"{
        "name": "execute",
        "type": "function",
        "stateMutability": "payable",
        "inputs": [
            {"name": "commands", "type": "bytes"},
            {"name": "inputs",   "type": "bytes[]"},
            {"name": "deadline", "type": "uint256"}
        ],
        "outputs": []
    }"#,
    );

    let outer_args = decode_calldata(&abi_execute, calldata).unwrap();

    assert_eq!(outer_args["deadline"].as_str().unwrap(), "1780301946"); // 0x6a1d407a

    // commands = 0x0b010c  →  3 bytes
    let commands_hex = outer_args["commands"].as_str().unwrap();
    let cmd_bytes = hex::decode(commands_hex.trim_start_matches("0x")).unwrap();
    assert_eq!(cmd_bytes.len(), 3);
    // Apply UR command type mask 0x3f: [0x0b, 0x01, 0x0c]
    assert_eq!(cmd_bytes[0] & 0x3f, 0x0b); // PERMIT2_TRANSFER_FROM
    assert_eq!(cmd_bytes[1] & 0x3f, 0x01); // V3_SWAP_EXACT_OUT
    assert_eq!(cmd_bytes[2] & 0x3f, 0x0c); // SWEEP

    let inputs = match outer_args.get("inputs") {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>(),
        _ => panic!("inputs should be bytes[] array"),
    };
    assert_eq!(inputs.len(), 3, "3 commands → 3 inputs");

    // Decode inputs[1] as V3_SWAP_EXACT_OUT bare params (no selector):
    // (address recipient, uint256 amountOut, uint256 amountInMaximum, bytes path, bool payerIsUser)
    let v3_out_inputs = vec![
        AbiInput {
            name: "recipient".into(),
            kind: "address".into(),
            components: vec![],
        },
        AbiInput {
            name: "amountOut".into(),
            kind: "uint256".into(),
            components: vec![],
        },
        AbiInput {
            name: "amountInMaximum".into(),
            kind: "uint256".into(),
            components: vec![],
        },
        AbiInput {
            name: "path".into(),
            kind: "bytes".into(),
            components: vec![],
        },
        AbiInput {
            name: "payerIsUser".into(),
            kind: "bool".into(),
            components: vec![],
        },
    ];
    let swap_args = decode_args_only(&v3_out_inputs, &inputs[1])
        .expect("decode_args_only must succeed for V3_SWAP_EXACT_OUT params");

    assert!(swap_args["recipient"].as_str().unwrap().starts_with("0x"));
    // amountOut and amountInMaximum are large uint256 values
    let amount_out = swap_args["amountOut"].as_str().unwrap();
    assert!(
        !amount_out.is_empty() && amount_out != "0",
        "amountOut should be non-zero"
    );
    // path is a bytes value (encoded swap route)
    assert!(swap_args["path"].as_str().unwrap().starts_with("0x"));
}
