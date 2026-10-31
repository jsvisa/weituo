use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── JSON-RPC wire types ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub id: serde_json::Value,
    pub method: String,
    pub params: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    /// Structured error details (JSON-RPC 2.0 `data` member). Optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    pub fn ok(id: serde_json::Value, result: impl Serialize) -> Self {
        Self {
            id,
            result: Some(serde_json::to_value(result).unwrap_or(serde_json::Value::Null)),
            error: None,
        }
    }

    pub fn err(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self::err_with_data(id, code, message, None)
    }

    pub fn err_with_data(
        id: serde_json::Value,
        code: i32,
        message: impl Into<String>,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}

// ── Transaction (waf_checkRule / waf_testRule param) ─────────────────────────

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Transaction {
    #[serde(rename = "chainId", deserialize_with = "deser_u64_hex")]
    pub chain_id: u64,
    /// ETH value in wei. Accepts integer, decimal, scientific, and hex input.
    /// Uses alloy_primitives::U256 for full 256-bit precision.
    #[serde(deserialize_with = "deser_u256")]
    pub value: alloy_primitives::U256,
    pub to: String,
    /// Raw calldata hex (alias "input" also accepted)
    #[serde(alias = "input")]
    pub data: String,
    #[serde(rename = "from")]
    pub from: String,
    /// Accepts a JSON integer or a hex string ("0x...").
    #[serde(rename = "gasPrice", default, deserialize_with = "deser_u64_hex")]
    pub gas_price: u64,
    /// Accepts a JSON integer or a hex string ("0x...").
    #[serde(rename = "gasLimit", default, deserialize_with = "deser_u64_hex")]
    pub gas_limit: u64,
    #[serde(
        rename = "transactionType",
        alias = "type",
        alias = "tx_type",
        alias = "transaction_type",
        default,
        deserialize_with = "deser_opt_u64_hex"
    )]
    pub transaction_type: Option<u64>,
    /// Block number or "latest"
    #[serde(rename = "blkNumber", default = "default_block")]
    pub blk_number: String,
    /// Only present in waf_testRule: the expression to evaluate
    pub expr: Option<String>,
    /// Only present in waf_testRule: inline ABI for calldata decoding (overrides stored rule ABI)
    #[serde(default)]
    pub abi: Option<AbiItem>,
    /// Only present in waf_testRule: rule-level vars (overrides stored rule vars)
    #[serde(default)]
    pub vars: Option<HashMap<String, serde_json::Value>>,
    /// Only present in waf_testRule: multicall decoder type
    #[serde(
        rename = "decoder_type",
        default,
        deserialize_with = "deserialize_decoder_kind_opt"
    )]
    pub decoder_type: Option<DecoderKind>,
    /// Only present in waf_testRule: multicall decoder config overrides
    #[serde(rename = "decoder_config", default)]
    pub decoder_config: Option<serde_json::Value>,
    /// Only present in waf_testRule: per-selector ABIs for inner calls ("0xABCD1234" → AbiItem)
    #[serde(rename = "inner_abis", default)]
    pub inner_abis: Option<HashMap<String, AbiItem>>,
}

fn default_block() -> String {
    "latest".into()
}

fn has_scientific_exponent(value: &str) -> bool {
    let value = value.trim();
    !value.starts_with("0x") && !value.starts_with("0X") && value.contains(['e', 'E'])
}

/// Parse `1e18`, `"1.25e21"`, `2.1e4`, … into `U256`, truncating any fractional
/// part that falls right of the integer point. `Mantissa`e`Exponent` where
/// `Exponent` can be negative (→ truncates toward zero).
fn parse_scientific_u256(value: &str) -> Result<alloy_primitives::U256, String> {
    let value = value.trim();
    let (mantissa, exponent) = value
        .split_once(['e', 'E'])
        .ok_or_else(|| "missing exponent".to_string())?;
    let exponent: i64 = exponent
        .parse()
        .map_err(|_| "invalid exponent".to_string())?;
    if mantissa.starts_with('-') {
        return Err("negative integer is not supported".to_string());
    }
    let mantissa = mantissa.strip_prefix('+').unwrap_or(mantissa);
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits = format!("{whole}{fraction}");
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err("invalid scientific mantissa".to_string());
    }
    if digits.chars().all(|c| c == '0') {
        return Ok(alloy_primitives::U256::ZERO);
    }
    // Final value is `digits` with `Exponent - fraction_len` trailing zeros
    // (negative → drop rightmost digits, i.e. truncate toward zero).
    let integer_len = digits.len() as i64 + exponent - fraction.len() as i64;
    if integer_len <= 0 {
        return Ok(alloy_primitives::U256::ZERO);
    }
    if integer_len > 78 {
        return Err("integer overflow for U256".to_string());
    }
    let target = integer_len as usize;
    if target < digits.len() {
        digits.truncate(target);
    } else {
        digits.push_str(&"0".repeat(target - digits.len()));
    }
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(alloy_primitives::U256::ZERO);
    }
    digits
        .parse::<alloy_primitives::U256>()
        .map_err(|e| e.to_string())
}

fn parse_u256_value(value: &str) -> Result<alloy_primitives::U256, String> {
    let value = value.trim();
    if has_scientific_exponent(value) {
        parse_scientific_u256(value)
    } else {
        value
            .parse::<alloy_primitives::U256>()
            .map_err(|e| e.to_string())
    }
}

fn parse_u64_number(value: &serde_json::Number) -> Result<u64, String> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    let value = value.to_string();
    if has_scientific_exponent(&value) {
        parse_u64_string(&value)
    } else {
        Err("integer overflow for u64".to_string())
    }
}

pub(crate) fn parse_u64_string(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).map_err(|e| e.to_string());
    }
    if has_scientific_exponent(value) {
        return parse_scientific_u256(value)?
            .try_into()
            .map_err(|_| "integer overflow for u64".to_string());
    }
    value.parse::<u64>().map_err(|e| e.to_string())
}

/// Deserialize `value` into `U256`. Accepts:
/// - A JSON integer in the u64 range: `0`, `21000`, …
/// - A bare JSON integer > u64::MAX (requires `serde_json/arbitrary_precision`): `499980000000000000000`
/// - A hex string: `"0x1b1ae4d6e2ef500000"`
/// - A decimal string: `"499980000000000000000"`
/// - Scientific notation as a JSON number or string: `1e18`, `"1.25e21"`
///
/// Ruint's own `Deserialize` for `Uint<N, L>` handles strings and u64-range integers via
/// `deserialize_any`. The only gap is bare integers > u64::MAX: with `arbitrary_precision`
/// serde_json routes those to `visit_map` (the private Number sentinel), which we intercept
/// here and forward to `visit_str`.
fn deser_u256<'de, D>(d: D) -> Result<alloy_primitives::U256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use alloy_primitives::U256;
    use serde::de::{self, Error, MapAccess, Unexpected, Visitor};

    struct U256Visitor;

    impl<'de> Visitor<'de> for U256Visitor {
        type Value = U256;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "a U256 integer, decimal/scientific string, or 0x-prefixed hex string"
            )
        }

        fn visit_u64<E: Error>(self, v: u64) -> Result<U256, E> {
            Ok(U256::from(v))
        }

        fn visit_u128<E: Error>(self, v: u128) -> Result<U256, E> {
            Ok(U256::from(v))
        }

        fn visit_str<E: Error>(self, v: &str) -> Result<U256, E> {
            parse_u256_value(v).map_err(|_| E::invalid_value(Unexpected::Str(v), &self))
        }

        // serde_json with `arbitrary_precision` routes bare integers > u64::MAX through
        // visit_map using the internal "$serde_json::private::Number" sentinel.
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<U256, A::Error> {
            let key = map.next_key::<String>()?.unwrap_or_default();
            let raw: String = map.next_value()?;
            if key != "$serde_json::private::Number" {
                return Err(de::Error::custom(format!("unexpected map key: {key}")));
            }
            parse_u256_value(&raw).map_err(|_| de::Error::custom(format!("invalid U256: {raw}")))
        }
    }

    d.deserialize_any(U256Visitor)
}

/// Deserialize `gasPrice` / `gasLimit` from integer, scientific, or hex input.
pub fn deser_u64_hex<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(d)?;
    parse_u64_hex_value::<D>(&v)
}

fn deser_opt_u64_hex<'de, D>(d: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<serde_json::Value>::deserialize(d)?;
    match &v {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => parse_u64_hex_value::<D>(value).map(Some),
    }
}

fn parse_u64_hex_value<'de, D>(v: &serde_json::Value) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    match v {
        serde_json::Value::Number(value) => parse_u64_number(value).map_err(D::Error::custom),
        serde_json::Value::String(value) => parse_u64_string(value).map_err(D::Error::custom),
        _ => Err(D::Error::custom("expected integer or hex string")),
    }
}

/// Normalize an EIP-712 domain name for rule lookup.
/// `""`, `"'"`, and `'"'` are treated as empty (no domain name).
pub fn normalize_domain_name(name: &str) -> String {
    let s = name.trim();
    if s.is_empty() || s == "'" || s == "\"" {
        String::new()
    } else {
        s.to_string()
    }
}

// ── EIP-712 typed-data (waf_checkSign param) ──────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Eip712Domain {
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    pub name: String,
    /// Absent (or zero address) for purely off-chain auth signatures (e.g. ClobAuth). WAF skips those.
    #[serde(rename = "verifyingContract")]
    pub verifying_contract: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TypedDataRequest {
    pub from: String,
    #[serde(rename = "primaryType")]
    pub primary_type: String,
    pub domain: Eip712Domain,
    /// Single-message variant.
    pub message: Option<serde_json::Value>,
    /// Batch-message variant (e.g. batch-sign-orders).
    pub messages: Option<Vec<serde_json::Value>>,
}

// ── Rule feed types ──────────────────────────────────────────────────────────

/// One grouped entry from a rule-provider feed: every rule for one contract.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub address: String,
    pub func: String,
    pub selector: String,
    pub abi_item: Option<AbiItem>,
    #[serde(default, deserialize_with = "deserialize_decoder_kind_opt")]
    pub decoder_type: Option<DecoderKind>,
    pub decoder_config: Option<serde_json::Value>,
    pub rules: Vec<RuleClauseRaw>,
}

/// Minimal ABI function item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiItem {
    #[serde(rename = "type", default)]
    pub kind: String,
    pub name: String,
    pub inputs: Vec<AbiInput>,
    #[serde(rename = "stateMutability", default)]
    pub state_mutability: String,
}

/// Family-specific ABI fragment for non-EVM rules. Pure data — the
/// feature-gated decoders in `svm` / `sui` interpret it.
#[derive(Debug, Clone)]
pub enum FamilyAbi {
    /// Anchor-style IDL fragment: `{ name, args: [{name, type}], types? }`.
    /// `types` resolves `{defined: …}` references (same spirit as EVM tuple
    /// `components`).
    Svm {
        name: String,
        args: Vec<IdlArg>,
        types: HashMap<String, serde_json::Value>,
    },
    /// Move signature fragment: `{ params: [{name, type}] }`.
    Sui { params: Vec<IdlArg> },
}

/// One named, typed parameter of a non-EVM ABI fragment. `ty` keeps the raw
/// JSON rendering (string for primitives, object for `option`/`vec`/`array`/
/// `defined`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlArg {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: serde_json::Value,
}

impl FamilyAbi {
    /// Parse an SVM Anchor IDL fragment: `{ name, args: [{name, type}], types? }`.
    /// `args` and `name` are optional (argless programs / bare tag rules).
    pub fn from_svm_json(v: serde_json::Value) -> Option<Self> {
        #[derive(serde::Deserialize)]
        struct Frag {
            #[serde(default)]
            name: String,
            #[serde(default)]
            args: Vec<IdlArg>,
            #[serde(default)]
            types: HashMap<String, serde_json::Value>,
        }
        let f: Frag = serde_json::from_value(v).ok()?;
        Some(Self::Svm {
            name: f.name,
            args: f.args,
            types: f.types,
        })
    }

    /// Parse a Sui Move signature fragment: `{ params: [{name, type}] }`.
    pub fn from_sui_json(v: serde_json::Value) -> Option<Self> {
        #[derive(serde::Deserialize)]
        struct Frag {
            #[serde(default)]
            params: Vec<IdlArg>,
        }
        let f: Frag = serde_json::from_value(v).ok()?;
        Some(Self::Sui { params: f.params })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AbiInput {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    /// For tuple types
    #[serde(default)]
    pub components: Vec<AbiInput>,
}

pub fn expression_param_types(inputs: &[AbiInput]) -> HashMap<String, String> {
    let mut types = HashMap::new();
    for (idx, input) in inputs.iter().enumerate() {
        let name = expression_param_name(idx, input);
        collect_expression_param_types(&mut types, &name, input);
    }
    types
}

pub fn expression_param_names(inputs: &[AbiInput]) -> Vec<String> {
    inputs
        .iter()
        .enumerate()
        .map(|(idx, input)| expression_param_name(idx, input))
        .collect()
}

fn collect_expression_param_types(
    types: &mut HashMap<String, String>,
    path: &str,
    input: &AbiInput,
) {
    types.insert(path.to_string(), input.kind.clone());
    for (idx, component) in input.components.iter().enumerate() {
        let component_name = expression_param_name(idx, component);
        let component_path = format!("{path}.{component_name}");
        collect_expression_param_types(types, &component_path, component);
    }
}

fn expression_param_name(idx: usize, input: &AbiInput) -> String {
    if input.name.is_empty() {
        format!("__arg{idx}")
    } else {
        input.name.clone()
    }
}

// ── In-memory rule index ──────────────────────────────────────────────────────

/// Key: (chain_id, lowercase_address, func_selector_hex)
pub type RuleKey = (u64, String, String);

/// One (expr, vars) pair from a single project's rule.
#[derive(Debug, Clone)]
pub struct RuleClause {
    pub expr: ExprValue,
    pub vars: HashMap<String, serde_json::Value>,
}

/// Raw deserialized form from the API response.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleClauseRaw {
    pub expr: serde_json::Value,
    #[serde(default)]
    pub vars: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone)]
pub struct RuleEntry {
    pub clauses: Vec<RuleClause>,
    pub abi_item: Option<AbiItem>,
    /// Family-specific ABI fragment for non-EVM rules (SVM Anchor IDL, Sui
    /// Move signature). EVM rules keep `abi_item`; when `family_abi` is set
    /// the checker decodes with it and ignores `abi_item`.
    pub family_abi: Option<FamilyAbi>,
    pub multicall: Option<MulticallDecoder>,
    /// True when decoder_config was present but decoder_type was unrecognised.
    /// The checker must deny rather than silently skip inner-call inspection.
    pub invalid_decoder: bool,
}

// ── Listed rules (waf_listRules / waf_listSigns param & response) ─────────────

/// Param for `waf_listRules` / `waf_listSigns`.
/// `address` is optional: absent → list whatever the chain has loaded (cache only).
#[derive(Debug, Deserialize)]
pub struct ListRulesParam {
    #[serde(rename = "chainId", deserialize_with = "deser_u64_hex")]
    pub chain_id: u64,
    #[serde(default)]
    pub address: Option<String>,
}

/// One rule as returned by `waf_listRules` / `waf_listSigns`. Requires a
/// contract address for context.
#[derive(Debug, Clone, Serialize)]
pub struct ListedRule {
    pub selector: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clauses: Vec<ListedClause>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi: Option<AbiItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoder: Option<ListedDecoder>,
}

/// One (exprs, vars) clause of a listed rule. Clauses are OR'd together;
/// each clause's `exprs` are AND'd and reference that clause's own `vars`.
#[derive(Debug, Clone, Serialize)]
pub struct ListedClause {
    pub exprs: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub vars: HashMap<String, serde_json::Value>,
}

/// Multicall decoder descriptor for the listing API.
#[derive(Debug, Clone, Serialize)]
pub struct ListedDecoder {
    pub kind: &'static str,
    pub config: HashMap<String, String>,
}

// ── Decoder type metadata (returned by waf_decoderTypes) ─────────────────────

/// The canonical set of multicall decoder types.
/// Serializes to/from snake_case strings ("bytes_array", "tuple_array", …) in
/// JSON and YAML so all wire formats use the same identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoderKind {
    BytesArray,
    TupleArray,
    ParallelArrays,
    UniversalRouter,
}

/// Deserialize an `Option<DecoderKind>` from a string, mapping unknown values to
/// `None` rather than failing. This ensures a single rule with an unrecognised
/// decoder type doesn't prevent the rest of the contract's rules from loading.
pub fn deserialize_decoder_kind_opt<'de, D>(de: D) -> Result<Option<DecoderKind>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => {
            match serde_json::from_value::<DecoderKind>(serde_json::Value::String(s.to_owned())) {
                Ok(kind) => Ok(Some(kind)),
                Err(_) => {
                    tracing::warn!("unknown decoder_type {s:?}, treating as None");
                    Ok(None)
                }
            }
        }
    }
}

/// Input widget type used by the frontend to render this field.
/// All current decoder fields are plain strings; `kv_map` is reserved for
/// future fields that accept a key→value mapping.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    String,
    KvMap,
}

/// One configurable field in a decoder type (rendered as a form input by the frontend).
#[derive(Debug, Clone, Serialize)]
pub struct DecoderFieldMeta {
    /// Config key read by build_decoder (e.g. "data_param")
    pub name: &'static str,
    /// Human-readable label for the frontend form
    pub label: &'static str,
    /// Input widget type ("string" | "kv_map") — consumed by the frontend form renderer
    #[serde(rename = "type")]
    pub kind: FieldKind,
    /// Default value shown as placeholder; also the default used by build_decoder when absent
    pub placeholder: &'static str,
}

/// UI metadata for one decoder type variant.
#[derive(Debug, Clone, Serialize)]
pub struct DecoderTypeMeta {
    pub id: DecoderKind,
    pub label: &'static str,
    pub description: &'static str,
    pub fields: Vec<DecoderFieldMeta>,
}

// ── MulticallDecoder ──────────────────────────────────────────────────────────

/// How to extract and dispatch inner calls for a multicall function.
#[derive(Debug, Clone)]
pub enum MulticallDecoder {
    /// OZ Multicall, Uniswap V3, AAVE — each data[i] is full calldata targeting tx.to
    BytesArray { data_param: String },

    /// Multicall3 — each calls[i] has {target, callData} fields
    TupleArray {
        calls_param: String,
        data_field: String,
        target_field: String,
    },

    /// OZ Governor / Timelock — parallel targets[] and calldatas[] arrays
    ParallelArrays {
        data_param: String,
        target_param: String,
    },

    /// Uniswap Universal Router — commands[i] & 0x3f is command type,
    /// inputs[i] contains ABI params WITHOUT a selector prefix.
    /// Command dispatch is hardcoded from Dispatcher.sol (0x00–0x0c stable ABI).
    UniversalRouter {
        commands_param: String,
        inputs_param: String,
    },
}

impl MulticallDecoder {
    /// Return UI metadata for every supported decoder variant.
    /// Placeholders match the defaults used in build_decoder() — keep them in sync.
    pub fn all_meta() -> Vec<DecoderTypeMeta> {
        vec![
            DecoderTypeMeta {
                id: DecoderKind::BytesArray,
                label: "Standard (bytes[])",
                description: "OZ Multicall, Uniswap V3 SwapRouter, AAVE, Compound V3",
                fields: vec![DecoderFieldMeta {
                    name: "data_param",
                    label: "Data Param",
                    kind: FieldKind::String,
                    placeholder: "data",
                }],
            },
            DecoderTypeMeta {
                id: DecoderKind::TupleArray,
                label: "Tuple Array (Multicall3)",
                description: "aggregate((address target, bytes callData)[] calls)",
                fields: vec![
                    DecoderFieldMeta { name: "calls_param",  label: "Calls Param",  kind: FieldKind::String, placeholder: "calls" },
                    DecoderFieldMeta { name: "data_field",   label: "Data Field",   kind: FieldKind::String, placeholder: "callData" },
                    DecoderFieldMeta { name: "target_field", label: "Target Field", kind: FieldKind::String, placeholder: "target" },
                ],
            },
            DecoderTypeMeta {
                id: DecoderKind::ParallelArrays,
                label: "Parallel Arrays (Governor / Timelock)",
                description: "executeBatch(address[] targets, uint256[] values, bytes[] calldatas, ...)",
                fields: vec![
                    DecoderFieldMeta { name: "data_param",   label: "Data Param",   kind: FieldKind::String, placeholder: "calldatas" },
                    DecoderFieldMeta { name: "target_param", label: "Target Param", kind: FieldKind::String, placeholder: "targets" },
                ],
            },
            DecoderTypeMeta {
                id: DecoderKind::UniversalRouter,
                label: "Universal Router",
                description: "Uniswap Universal Router execute(bytes commands, bytes[] inputs, uint256 deadline)",
                fields: vec![
                    DecoderFieldMeta { name: "commands_param", label: "Commands Param", kind: FieldKind::String, placeholder: "commands" },
                    DecoderFieldMeta { name: "inputs_param",   label: "Inputs Param",   kind: FieldKind::String, placeholder: "inputs" },
                ],
            },
        ]
    }

    /// Serialize this decoder for `waf_listRules` / `waf_listSigns`.
    pub fn listed(&self) -> ListedDecoder {
        let mut config = HashMap::new();
        match self {
            Self::BytesArray { data_param } => {
                config.insert("data_param".to_string(), data_param.clone());
            }
            Self::TupleArray {
                calls_param,
                data_field,
                target_field,
            } => {
                config.insert("calls_param".to_string(), calls_param.clone());
                config.insert("data_field".to_string(), data_field.clone());
                config.insert("target_field".to_string(), target_field.clone());
            }
            Self::ParallelArrays {
                data_param,
                target_param,
            } => {
                config.insert("data_param".to_string(), data_param.clone());
                config.insert("target_param".to_string(), target_param.clone());
            }
            Self::UniversalRouter {
                commands_param,
                inputs_param,
            } => {
                config.insert("commands_param".to_string(), commands_param.clone());
                config.insert("inputs_param".to_string(), inputs_param.clone());
            }
        }
        ListedDecoder {
            kind: self.kind_str(),
            config,
        }
    }

    /// Wire-format identifier of this decoder variant.
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::BytesArray { .. } => "bytes_array",
            Self::TupleArray { .. } => "tuple_array",
            Self::ParallelArrays { .. } => "parallel_arrays",
            Self::UniversalRouter { .. } => "universal_router",
        }
    }

    /// Return the (data_path, target_path) dot-path strings for decoders
    /// that use the standard full-calldata extraction logic.
    /// Returns None for UniversalRouter which has its own extraction.
    pub fn standard_paths(&self) -> Option<(String, Option<String>)> {
        match self {
            Self::BytesArray { data_param } => Some((data_param.clone(), None)),
            Self::TupleArray {
                calls_param,
                data_field,
                target_field,
            } => Some((
                format!("{calls_param}.{data_field}"),
                Some(format!("{calls_param}.{target_field}")),
            )),
            Self::ParallelArrays {
                data_param,
                target_param,
            } => Some((data_param.clone(), Some(target_param.clone()))),
            Self::UniversalRouter { .. } => None,
        }
    }
}

/// expr can be a single string or an AND-list
#[derive(Debug, Clone)]
pub enum ExprValue {
    Single(String),
    And(Vec<String>),
}

impl ExprValue {
    pub fn exprs(&self) -> Vec<&str> {
        match self {
            ExprValue::Single(s) => vec![s.as_str()],
            ExprValue::And(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

impl TryFrom<serde_json::Value> for ExprValue {
    type Error = anyhow::Error;

    fn try_from(v: serde_json::Value) -> Result<Self, Self::Error> {
        match v {
            serde_json::Value::String(s) => Ok(ExprValue::Single(s)),
            serde_json::Value::Array(arr) => {
                let strs: Result<Vec<_>, _> = arr
                    .into_iter()
                    .map(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                            .ok_or_else(|| anyhow::anyhow!("non-string in expr array"))
                    })
                    .collect();
                Ok(ExprValue::And(strs?))
            }
            _ => Err(anyhow::anyhow!("expr must be string or array")),
        }
    }
}

pub use weituo_expr::EvalContext;
