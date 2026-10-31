//! `SuiTx` — the Sui PTB payload (design §3.3), pure-input BCS encoding,
//! and the MoveCall argument decoder (design §8.2).

use serde_json::{Map, Value as Json};

use crate::chain::normalize_sui_address;
use crate::types::{FamilyAbi, IdlArg};

use super::{normalize_move_type, param_consumes_argument, GAS_COIN_SENTINEL};

// ── Wire model ───────────────────────────────────────────────────────────────

/// One PTB input: pure (BCS bytes, encoded at parse time from the typed
/// JSON value or accepted as `0x`-hex raw BCS) or an object reference.
#[derive(Debug, Clone)]
pub enum SuiInput {
    Pure {
        value_type: String,
        bytes: Vec<u8>,
    },
    /// Object id in the full 64-nibble lowercase hex form.
    Object {
        object_id: String,
    },
}

/// One `MoveCall` argument reference.
#[derive(Debug, Clone)]
pub enum SuiArgument {
    GasCoin,
    Input(usize),
    Result(usize),
    NestedResult(usize, usize),
}

/// A `MoveCall` command: `target` is `package::module::function` on the
/// wire; the package is stored in full-hex form and `module::function`
/// becomes the rule-map selector.
#[derive(Debug, Clone)]
pub struct SuiMoveCall {
    /// Package address, full 64-nibble lowercase hex.
    pub package: String,
    pub module: String,
    pub function: String,
    /// Canonicalized (full-form) type argument strings.
    pub type_arguments: Vec<String>,
    pub arguments: Vec<SuiArgument>,
}

impl SuiMoveCall {
    /// The rule-map selector: `"module::function"` lowercase (design §5).
    pub fn selector(&self) -> String {
        format!("{}::{}", self.module, self.function).to_lowercase()
    }

    /// `module::function` for policy target matching.
    pub fn module_func(&self) -> String {
        format!("{}::{}", self.module, self.function).to_lowercase()
    }
}

/// One PTB command. Non-MoveCall commands carry no decoded payload — the
/// policy layer and the native-transfer dataflow pass consume them.
#[derive(Debug, Clone)]
pub enum SuiCommand {
    MoveCall(SuiMoveCall),
    SplitCoins {
        coin: SuiArgument,
        amounts: Vec<SuiArgument>,
    },
    TransferObjects {
        objects: Vec<SuiArgument>,
        address: SuiArgument,
    },
    Publish,
    Upgrade,
    MergeCoins,
    MakeMoveVec,
}

impl SuiCommand {
    /// The JSON command kind name (exposed as `chain_fields.command_kind`).
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::MoveCall(_) => "MoveCall",
            Self::SplitCoins { .. } => "SplitCoins",
            Self::TransferObjects { .. } => "TransferObjects",
            Self::Publish => "Publish",
            Self::Upgrade => "Upgrade",
            Self::MergeCoins { .. } => "MergeCoins",
            Self::MakeMoveVec => "MakeMoveVec",
        }
    }
}

/// The unified Sui transaction input (design §3.3).
#[derive(Debug, Clone)]
pub struct SuiTx {
    /// Network name (`"mainnet"`, `"testnet"`, …).
    pub network: String,
    /// Sender; `from_address` for rules (sponsorship is explicit via
    /// `gasOwner` and never changes `from_address`).
    pub from: String,
    /// Gas sponsor; defaults to `from`.
    pub gas_owner: String,
    pub gas_budget: u64,
    pub gas_price: u64,
    pub inputs: Vec<SuiInput>,
    pub commands: Vec<SuiCommand>,
    /// Inline Move signature for test mode (mirrors `Transaction.abi`).
    pub abi: Option<FamilyAbi>,
    /// Test-mode expression.
    pub expr: Option<String>,
    /// Test-mode vars.
    pub vars: Option<std::collections::HashMap<String, Json>>,
}

fn parse_u64_field(obj: &Map<String, Json>, key: &str) -> Result<u64, String> {
    match obj.get(key) {
        Some(Json::Number(n)) => n.as_u64().ok_or_else(|| format!("{key} must fit u64")),
        Some(Json::String(s)) => s
            .parse::<u64>()
            .map_err(|_| format!("{key} must be a decimal u64, got '{s}'")),
        Some(Json::Null) | None => Ok(0),
        Some(other) => Err(format!(
            "{key} must be a number or decimal string, got {other}"
        )),
    }
}

fn parse_argument(v: &Json) -> Result<SuiArgument, String> {
    match v {
        Json::String(s) if s == "GasCoin" => Ok(SuiArgument::GasCoin),
        Json::Object(o) => {
            if o.contains_key("GasCoin") {
                return Ok(SuiArgument::GasCoin);
            }
            if let Some(n) = o.get("Input").and_then(Json::as_u64) {
                return Ok(SuiArgument::Input(n as usize));
            }
            if let Some(n) = o.get("Result").and_then(Json::as_u64) {
                return Ok(SuiArgument::Result(n as usize));
            }
            if let Some(pair) = o.get("NestedResult").and_then(Json::as_array) {
                if pair.len() == 2 {
                    return Ok(SuiArgument::NestedResult(
                        pair[0].as_u64().unwrap_or(0) as usize,
                        pair[1].as_u64().unwrap_or(0) as usize,
                    ));
                }
                return Err("NestedResult must be [command, result]".to_string());
            }
            Err(format!("unrecognized argument {v}"))
        }
        _ => Err(format!(
            "argument must be GasCoin/Input/Result/NestedResult, got {v}"
        )),
    }
}

fn parse_input(v: &Json) -> Result<SuiInput, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| "inputs entries must be objects".to_string())?;
    match obj.get("kind").and_then(Json::as_str) {
        Some("pure") => {
            let value_type = normalize_move_type(
                obj.get("valueType")
                    .and_then(Json::as_str)
                    .ok_or_else(|| "pure input requires valueType".to_string())?,
            );
            let value = obj
                .get("value")
                .ok_or_else(|| "pure input requires value".to_string())?;
            let bytes = encode_pure_input(&value_type, value)?;
            Ok(SuiInput::Pure { value_type, bytes })
        }
        Some("object") => {
            let object_id = normalize_sui_address(
                obj.get("objectId")
                    .and_then(Json::as_str)
                    .ok_or_else(|| "object input requires objectId".to_string())?,
            )?;
            Ok(SuiInput::Object { object_id })
        }
        Some(other) => Err(format!(
            "unknown input kind '{other}' — expected pure or object"
        )),
        None => Err("input requires kind (pure|object)".to_string()),
    }
}

fn parse_command(v: &Json) -> Result<SuiCommand, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| "commands entries must be objects".to_string())?;
    if obj.len() != 1 {
        return Err(format!(
            "command must have exactly one kind key, got {} keys",
            obj.len()
        ));
    }
    let (kind, body) = obj.iter().next().unwrap();
    match kind.as_str() {
        "MoveCall" => {
            let b = body
                .as_object()
                .ok_or_else(|| "MoveCall must be an object".to_string())?;
            let target = b
                .get("target")
                .and_then(Json::as_str)
                .ok_or_else(|| "MoveCall requires target".to_string())?;
            let parts: Vec<&str> = target.split("::").collect();
            if parts.len() != 3 {
                return Err(format!(
                    "MoveCall target must be 'package::module::function', got '{target}'"
                ));
            }
            let package =
                normalize_sui_address(parts[0]).map_err(|e| format!("MoveCall target: {e}"))?;
            let type_arguments = match b.get("typeArguments") {
                Some(Json::Array(items)) => items
                    .iter()
                    .map(|t| {
                        t.as_str()
                            .map(normalize_move_type)
                            .ok_or_else(|| "typeArguments entries must be strings".to_string())
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                Some(Json::Null) | None => Vec::new(),
                _ => return Err("typeArguments must be an array of strings".to_string()),
            };
            let arguments = match b.get("arguments") {
                Some(Json::Array(items)) => items
                    .iter()
                    .map(parse_argument)
                    .collect::<Result<Vec<_>, String>>()?,
                Some(Json::Null) | None => Vec::new(),
                _ => return Err("arguments must be an array".to_string()),
            };
            Ok(SuiCommand::MoveCall(SuiMoveCall {
                package,
                module: parts[1].to_string(),
                function: parts[2].to_string(),
                type_arguments,
                arguments,
            }))
        }
        "SplitCoins" => {
            let b = body
                .as_object()
                .ok_or_else(|| "SplitCoins must be an object".to_string())?;
            let coin = parse_argument(
                b.get("coin")
                    .ok_or_else(|| "SplitCoins requires coin".to_string())?,
            )?;
            let amounts = match b.get("amounts") {
                Some(Json::Array(items)) => items
                    .iter()
                    .map(parse_argument)
                    .collect::<Result<Vec<_>, String>>()?,
                Some(Json::Null) | None => Vec::new(),
                _ => return Err("SplitCoins.amounts must be an array".to_string()),
            };
            Ok(SuiCommand::SplitCoins { coin, amounts })
        }
        "TransferObjects" => {
            let b = body
                .as_object()
                .ok_or_else(|| "TransferObjects must be an object".to_string())?;
            let objects = match b.get("objects") {
                Some(Json::Array(items)) => items
                    .iter()
                    .map(parse_argument)
                    .collect::<Result<Vec<_>, String>>()?,
                _ => return Err("TransferObjects requires objects (array)".to_string()),
            };
            let address = parse_argument(
                b.get("address")
                    .ok_or_else(|| "TransferObjects requires address".to_string())?,
            )?;
            Ok(SuiCommand::TransferObjects { objects, address })
        }
        "Publish" => Ok(SuiCommand::Publish),
        "Upgrade" => Ok(SuiCommand::Upgrade),
        "MergeCoins" => Ok(SuiCommand::MergeCoins),
        "MakeMoveVec" => Ok(SuiCommand::MakeMoveVec),
        other => Err(format!("unknown command kind '{other}'")),
    }
}

impl SuiTx {
    /// Parse the JSON wire form (design §3.3). A numeric `chainId` is
    /// rejected (Sui requires the network-name string).
    pub fn from_json(v: &Json) -> Result<Self, String> {
        let obj = v
            .as_object()
            .ok_or_else(|| "sui payload must be a JSON object".to_string())?;

        let network = match obj.get("chainId") {
            Some(Json::String(s)) if !s.is_empty() => s.clone(),
            Some(Json::Number(_)) => {
                return Err(
                    "sui payload requires a string chainId (network name); a numeric chainId is an EVM id"
                        .to_string(),
                );
            }
            _ => return Err("sui payload requires chainId (network name string)".to_string()),
        };

        let from = normalize_sui_address(
            obj.get("from")
                .and_then(Json::as_str)
                .ok_or_else(|| "sui payload requires from (sender address)".to_string())?,
        )?;
        let gas_owner = match obj.get("gasOwner") {
            Some(Json::String(s)) => normalize_sui_address(s)?,
            Some(Json::Null) | None => from.clone(),
            _ => return Err("gasOwner must be an address string".to_string()),
        };
        let gas_budget = parse_u64_field(obj, "gasBudget")?;
        let gas_price = parse_u64_field(obj, "gasPrice")?;

        let inputs = match obj.get("inputs") {
            Some(Json::Array(items)) => items
                .iter()
                .map(parse_input)
                .collect::<Result<Vec<_>, String>>()?,
            Some(Json::Null) | None => Vec::new(),
            _ => return Err("inputs must be an array".to_string()),
        };

        let commands = match obj.get("commands") {
            Some(Json::Array(items)) if !items.is_empty() => items
                .iter()
                .map(parse_command)
                .collect::<Result<Vec<_>, String>>()?,
            Some(Json::Array(_)) => {
                return Err("sui payload requires at least one command".to_string())
            }
            _ => return Err("sui payload requires commands (non-empty array)".to_string()),
        };

        let abi = match obj.get("abi") {
            Some(a) => Some(
                FamilyAbi::from_sui_json(a.clone())
                    .ok_or_else(|| "invalid sui abi fragment".to_string())?,
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
            gas_owner,
            gas_budget,
            gas_price,
            inputs,
            commands,
            abi,
            expr,
            vars,
        })
    }
}

// ── BCS: pure-input encoding (parse-time) ────────────────────────────────────

fn uleb128_encode(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out
}

fn uleb128_decode(r: &mut BcsReader<'_>) -> Result<usize, String> {
    let mut result = 0usize;
    let mut shift = 0;
    loop {
        let byte = r.take(1)?[0];
        result |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 35 {
            return Err("ULEB128 too long".to_string());
        }
    }
}

/// BCS-encode a typed JSON pure input. `0x`-hex string values are raw BCS
/// bytes (taken verbatim) — except for `address`, where the hex IS the
/// address. Ints arrive as decimal strings or JSON numbers.
pub(crate) fn encode_pure_input(value_type: &str, value: &Json) -> Result<Vec<u8>, String> {
    // Raw BCS pass-through (design §3.3): 0x-hex on a non-address pure input.
    if let Json::String(s) = value {
        if value_type != "address" {
            if let Some(hex_part) = s.strip_prefix("0x") {
                return hex::decode(hex_part).map_err(|e| format!("invalid raw BCS hex: {e}"));
            }
        }
    }
    match value_type {
        "bool" => match value {
            Json::Bool(true) => Ok(vec![1]),
            Json::Bool(false) => Ok(vec![0]),
            _ => Err("bool pure input requires a JSON boolean".to_string()),
        },
        "address" => {
            let s = value
                .as_str()
                .ok_or_else(|| "address pure input requires a 0x-hex string".to_string())?;
            let full = normalize_sui_address(s)?;
            let bytes = hex::decode(&full[2..]).map_err(|e| format!("address hex: {e}"))?;
            Ok(bytes)
        }
        "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| "string pure input requires a JSON string".to_string())?;
            let mut out = uleb128_encode(s.len());
            out.extend_from_slice(s.as_bytes());
            Ok(out)
        }
        "u8" | "u16" | "u32" | "u64" | "u128" | "u256" => {
            let width = int_width(value_type);
            let n = json_to_uint(value, value_type)?;
            let mut buf = [0u8; 32];
            buf[..32].copy_from_slice(&n.to_le_bytes::<32>());
            Ok(buf[..width].to_vec())
        }
        _ => {
            if let Some(inner) = value_type
                .strip_prefix("vector<")
                .and_then(|s| s.strip_suffix('>'))
            {
                let items = value
                    .as_array()
                    .ok_or_else(|| "vector pure input requires a JSON array".to_string())?;
                let mut out = uleb128_encode(items.len());
                for item in items {
                    out.extend(encode_pure_input(inner, item)?);
                }
                return Ok(out);
            }
            // Struct / other composite types cannot arrive as pure inputs.
            Err(format!(
                "unsupported pure valueType '{value_type}' — use an object input or raw BCS hex"
            ))
        }
    }
}

fn int_width(ty: &str) -> usize {
    match ty {
        "u8" => 1,
        "u16" => 2,
        "u32" => 4,
        "u64" => 8,
        "u128" => 16,
        _ => 32,
    }
}

fn json_to_uint(value: &Json, ty: &str) -> Result<alloy_primitives::U256, String> {
    match value {
        Json::Number(n) => {
            if let Some(i) = n.as_u64() {
                Ok(alloy_primitives::U256::from(i))
            } else {
                n.to_string()
                    .parse::<alloy_primitives::U256>()
                    .map_err(|_| format!("{ty} value out of range"))
            }
        }
        Json::String(s) => s
            .parse::<alloy_primitives::U256>()
            .map_err(|_| format!("invalid {ty} value '{s}'")),
        _ => Err(format!(
            "{ty} pure input requires a number or decimal string"
        )),
    }
}

// ── BCS: decode against a Move parameter type ────────────────────────────────

struct BcsReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BcsReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.data.len() {
            return Err(format!(
                "unexpected end of pure input: need {} byte(s) at offset {}, have {}",
                n,
                self.pos,
                self.data.len() - self.pos
            ));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
}

fn uint_to_json(b: &[u8]) -> Json {
    let mut buf = [0u8; 32];
    buf[..b.len()].copy_from_slice(b);
    Json::String(alloy_primitives::U256::from_le_bytes(buf).to_string())
}

fn int_to_json(b: &[u8]) -> Json {
    let mut buf = [0u8; 32];
    buf[..b.len()].copy_from_slice(b);
    if let Some(&last) = b.last() {
        if last & 0x80 != 0 {
            for byte in buf[b.len()..].iter_mut() {
                *byte = 0xff;
            }
        }
    }
    Json::String(alloy_primitives::I256::from_le_bytes(buf).to_string())
}

fn decode_bcs(ty: &str, r: &mut BcsReader<'_>) -> Result<Json, String> {
    match ty {
        "u8" => Ok(uint_to_json(r.take(1)?)),
        "u16" => Ok(uint_to_json(r.take(2)?)),
        "u32" => Ok(uint_to_json(r.take(4)?)),
        "u64" => Ok(uint_to_json(r.take(8)?)),
        "u128" => Ok(uint_to_json(r.take(16)?)),
        "u256" => Ok(uint_to_json(r.take(32)?)),
        "i8" => Ok(int_to_json(r.take(1)?)),
        "i16" => Ok(int_to_json(r.take(2)?)),
        "i32" => Ok(int_to_json(r.take(4)?)),
        "i64" => Ok(int_to_json(r.take(8)?)),
        "i128" => Ok(int_to_json(r.take(16)?)),
        "i256" => Ok(int_to_json(r.take(32)?)),
        "bool" => Ok(Json::Bool(r.take(1)?[0] != 0)),
        "address" => Ok(Json::String(format!("0x{}", hex::encode(r.take(32)?)))),
        "string" => {
            let len = uleb128_decode(r)?;
            let bytes = r.take(len)?;
            Ok(Json::String(
                std::str::from_utf8(bytes)
                    .map_err(|e| format!("invalid utf8 in string arg: {e}"))?
                    .to_string(),
            ))
        }
        _ => {
            if let Some(inner) = ty.strip_prefix("vector<").and_then(|s| s.strip_suffix('>')) {
                let len = uleb128_decode(r)?;
                let mut out = Vec::with_capacity(len.min(1024));
                for _ in 0..len {
                    out.push(decode_bcs(inner, r)?);
                }
                return Ok(Json::Array(out));
            }
            if let Some(inner) = ty.strip_prefix("Option<").and_then(|s| s.strip_suffix('>')) {
                return match r.take(1)?[0] {
                    0 => Ok(Json::Null),
                    1 => decode_bcs(inner, r),
                    other => Err(format!("invalid option tag {other}")),
                };
            }
            // Struct types cannot arrive as pure inputs.
            Err(format!(
                "cannot BCS-decode pure input for composite type '{ty}'"
            ))
        }
    }
}

// ── MoveCall argument decoding (design §8.2) ─────────────────────────────────

/// Decode `MoveCall` arguments positionally against the rule's Move
/// signature fragment, after filtering reference parameters (`&T`/`&mut T`,
/// always including the trailing `TxContext`).
///
/// `arguments` and `inputs` are the raw JSON renderings from the wire.
/// Mapping:
/// - `{"GasCoin": true}` → sentinel `"0x2::sui::SUI"`;
/// - `{"Input": i}` + pure input → BCS-decoded per the parameter's type;
/// - `{"Input": i}` + object input → the object id (full-hex);
/// - `{"Result": n}` / `{"NestedResult": …}` → `null` (unresolved in v1 —
///   fail-closed: expressions referencing such params error).
///
/// Errors (unknown type, truncated data, arity mismatch) fail closed.
pub fn decode_sui_args(
    abi: &FamilyAbi,
    arguments: &[Json],
    inputs: &[Json],
) -> Result<std::collections::HashMap<String, Json>, String> {
    let args = arguments
        .iter()
        .map(parse_argument)
        .collect::<Result<Vec<_>, String>>()?;
    let ins = inputs
        .iter()
        .map(parse_input)
        .collect::<Result<Vec<_>, String>>()?;
    decode_sui_args_typed(abi, &args, &ins)
}

/// Typed-core variant of [`decode_sui_args`]: takes already-parsed
/// arguments/inputs (what `SuiTx` carries after `from_json`).
pub fn decode_sui_args_typed(
    abi: &FamilyAbi,
    arguments: &[SuiArgument],
    inputs: &[SuiInput],
) -> Result<std::collections::HashMap<String, Json>, String> {
    let FamilyAbi::Sui { params } = abi else {
        return Err("not a Sui ABI fragment".to_string());
    };
    // Normalize types once, then filter non-argument params (refs/ctx).
    let normalized: Vec<(usize, &IdlArg, String)> = params
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let ty =
                p.ty.as_str()
                    .ok_or_else(|| format!("param {i}: type must be a Move type string"))?;
            Ok((i, p, normalize_move_type(ty)))
        })
        .collect::<Result<_, String>>()?;
    let consuming: Vec<(usize, &IdlArg, String)> = normalized
        .into_iter()
        .filter(|(i, _, ty)| param_consumes_argument(ty, *i + 1 == params.len()))
        .collect();

    if consuming.len() != arguments.len() {
        return Err(format!(
            "signature has {} argument slot(s) after reference filtering but the command passes {}",
            consuming.len(),
            arguments.len()
        ));
    }

    let mut out = std::collections::HashMap::with_capacity(consuming.len());
    for ((i, param, ty), arg) in consuming.iter().zip(arguments) {
        let name = if param.name.is_empty() {
            format!("__arg{i}")
        } else {
            param.name.clone()
        };
        let value = match arg {
            SuiArgument::GasCoin => Json::String(GAS_COIN_SENTINEL.to_string()),
            SuiArgument::Input(idx) => {
                let input = inputs
                    .get(*idx)
                    .ok_or_else(|| format!("argument references missing input {idx}"))?;
                match input {
                    SuiInput::Object { object_id } => Json::String(object_id.clone()),
                    SuiInput::Pure { bytes, .. } => {
                        let mut r = BcsReader::new(bytes);
                        decode_bcs(ty, &mut r)?
                    }
                }
            }
            SuiArgument::Result(_) | SuiArgument::NestedResult(..) => Json::Null,
        };
        out.insert(name, value);
    }
    Ok(out)
}

// ── Native-transfer dataflow helpers (design §8.3, used by the checker) ─────

/// Decode one `u64` pure input to its decimal string.
pub(crate) fn sui_pure_u64(inputs: &[SuiInput], idx: usize) -> Option<String> {
    let SuiInput::Pure { bytes, .. } = inputs.get(idx)? else {
        return None;
    };
    let mut r = BcsReader::new(bytes);
    match decode_bcs("u64", &mut r) {
        Ok(Json::String(s)) => Some(s),
        _ => None,
    }
}

/// Recipient of a `TransferObjects` command: `Input(i)` pointing at an
/// object input (the id) or an `address` pure input.
pub(crate) fn sui_recipient(inputs: &[SuiInput], cmd: &SuiCommand) -> Option<String> {
    let SuiCommand::TransferObjects {
        address: SuiArgument::Input(idx),
        ..
    } = cmd
    else {
        return None;
    };
    match inputs.get(*idx)? {
        SuiInput::Object { object_id } => Some(object_id.clone()),
        SuiInput::Pure { bytes, .. } => {
            let mut r = BcsReader::new(bytes);
            match decode_bcs("address", &mut r) {
                Ok(Json::String(s)) => Some(s),
                _ => None,
            }
        }
    }
}

/// Decode a `vector<u64>` / `vector<address>` pure input (the `pay_sui`
/// amounts / recipients arguments) to decimal strings / full-hex addresses.
pub(crate) fn sui_pure_vector(inputs: &[SuiInput], idx: usize, elem: &str) -> Option<Vec<String>> {
    let SuiInput::Pure { bytes, .. } = inputs.get(idx)? else {
        return None;
    };
    let mut r = BcsReader::new(bytes);
    match decode_bcs(&format!("vector<{elem}>"), &mut r) {
        Ok(Json::Array(items)) => items
            .into_iter()
            .map(|v| match v {
                Json::String(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}
