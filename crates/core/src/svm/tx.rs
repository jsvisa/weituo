//! `SvmTx` — the resolved SVM transaction payload (design §3.2).

use serde_json::Value as Json;

use super::{decode_data_field, parse_pubkey};

/// One instruction with **pre-resolved** accounts — core never sees address
/// lookup tables or indexes; an embedding that cannot resolve them does not
/// send the transaction here.
#[derive(Debug, Clone)]
pub struct SvmInstruction {
    pub program_id: String,
    pub accounts: Vec<String>,
    /// Instruction data (base58 or `0x`-hex on the wire, stored as bytes).
    pub data: Vec<u8>,
}

/// The unified SVM transaction input.
#[derive(Debug, Clone)]
pub struct SvmTx {
    /// Network name (`"mainnet-beta"`, `"devnet"`, …) — becomes the
    /// `svm:{network}` chain reference.
    pub network: String,
    /// Fee payer (first required signer).
    pub from: String,
    /// Full signer list; defaults to `[from]` (v1 does not model
    /// per-instruction authority).
    pub signers: Vec<String>,
    pub instructions: Vec<SvmInstruction>,
    /// Inline ABI fragment for test mode (mirrors `Transaction.abi`).
    pub abi: Option<crate::types::FamilyAbi>,
    /// Test-mode expression.
    pub expr: Option<String>,
    /// Test-mode vars.
    pub vars: Option<std::collections::HashMap<String, Json>>,
}

impl SvmTx {
    /// Parse the JSON wire form. A numeric `chainId` is rejected (SVM
    /// requires the network-name string; a numeric id means the caller sent
    /// an EVM-shaped payload with the wrong discriminator — fail closed).
    pub fn from_json(v: &Json) -> Result<Self, String> {
        let obj = v
            .as_object()
            .ok_or_else(|| "svm payload must be a JSON object".to_string())?;

        let network = match obj.get("chainId") {
            Some(Json::String(s)) if !s.is_empty() => s.clone(),
            Some(Json::Number(_)) => {
                return Err(
                    "svm payload requires a string chainId (network name); a numeric chainId is an EVM id"
                        .to_string(),
                );
            }
            _ => return Err("svm payload requires chainId (network name string)".to_string()),
        };

        let from = parse_pubkey(
            obj.get("from")
                .and_then(Json::as_str)
                .ok_or_else(|| "svm payload requires from (fee payer pubkey)".to_string())?,
        )?;

        let signers = match obj.get("signers") {
            Some(Json::Array(items)) => {
                let mut signers = Vec::with_capacity(items.len());
                for s in items {
                    signers
                        .push(parse_pubkey(s.as_str().ok_or_else(|| {
                            "signers entries must be strings".to_string()
                        })?)?);
                }
                if signers.is_empty() {
                    return Err("signers must not be empty when provided".to_string());
                }
                signers
            }
            Some(_) => return Err("signers must be an array of pubkeys".to_string()),
            None => vec![from.clone()],
        };

        let instructions_json = match obj.get("instructions") {
            Some(Json::Array(items)) if !items.is_empty() => items,
            Some(Json::Array(_)) => {
                return Err("svm payload requires at least one instruction".to_string())
            }
            _ => return Err("svm payload requires instructions (non-empty array)".to_string()),
        };
        let mut instructions = Vec::with_capacity(instructions_json.len());
        for (i, ins) in instructions_json.iter().enumerate() {
            let ins = ins
                .as_object()
                .ok_or_else(|| format!("instructions[{i}] must be an object"))?;
            let program_id = parse_pubkey(
                ins.get("programId")
                    .and_then(Json::as_str)
                    .ok_or_else(|| format!("instructions[{i}].programId is required"))?,
            )
            .map_err(|e| format!("instructions[{i}]: {e}"))?;
            let mut accounts = Vec::new();
            match ins.get("accounts") {
                Some(Json::Array(items)) => {
                    for a in items {
                        accounts.push(
                            parse_pubkey(a.as_str().ok_or_else(|| {
                                format!("instructions[{i}].accounts entries must be strings")
                            })?)
                            .map_err(|e| format!("instructions[{i}]: {e}"))?,
                        );
                    }
                }
                Some(_) => return Err(format!("instructions[{i}].accounts must be an array")),
                None => return Err(format!("instructions[{i}].accounts is required")),
            }
            let data = match ins.get("data") {
                Some(Json::String(s)) => {
                    decode_data_field(s).map_err(|e| format!("instructions[{i}].data: {e}"))?
                }
                Some(Json::Null) | None => Vec::new(),
                _ => return Err(format!("instructions[{i}].data must be a string")),
            };
            instructions.push(SvmInstruction {
                program_id,
                accounts,
                data,
            });
        }

        let abi = match obj.get("abi") {
            Some(a) => Some(
                crate::types::FamilyAbi::from_svm_json(a.clone())
                    .ok_or_else(|| "invalid svm abi fragment".to_string())?,
            ),
            None => None,
        };
        let expr = match obj.get("expr") {
            Some(Json::String(s)) => Some(s.clone()),
            Some(Json::Null) | None => None,
            _ => return Err("expr must be a string".to_string()),
        };
        let vars = match obj.get("vars") {
            Some(o @ Json::Object(_)) => Some(
                o.as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ),
            Some(Json::Null) | None => None,
            _ => return Err("vars must be an object".to_string()),
        };

        Ok(Self {
            network,
            from,
            signers,
            instructions,
            abi,
            expr,
            vars,
        })
    }
}
