//! Anchor IDL fragments + a hand-rolled borsh decoder (design §8.1).
//!
//! Runtime-type-driven: the rule's IDL fragment supplies the types, so no
//! `borsh` crate dependency is warranted for decode-only use. Unknown or
//! unresolvable types fail closed — the decoder errors, the checker sees
//! empty args, and any expression referencing `args.*` errors (deny).

use base58::ToBase58;
use serde_json::{Map, Value as Json};
use sha2::{Digest, Sha256};

use crate::types::{FamilyAbi, IdlArg};

/// Anchor instruction discriminator: `sha256("global:" + snake_case(name))[..8]`.
pub fn anchor_discriminator(name: &str) -> Vec<u8> {
    let preimage = format!("global:{}", snake_case(name));
    Sha256::digest(preimage.as_bytes())[..8].to_vec()
}

/// camelCase/PascalCase → snake_case (Anchor computes discriminators over the
/// snake_case function name).
pub(crate) fn snake_case(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            let prev_is_lower = i > 0 && (chars[i - 1].is_lowercase() || chars[i - 1].is_numeric());
            let next_is_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            let prev_is_upper = i > 0 && chars[i - 1].is_uppercase();
            // Boundary before an uppercase char when it starts a new word:
            // after a lowercase/digit ("swapExactIn"), or at the end of an
            // acronym run ("HTTPServer" → http_server).
            if i > 0 && (prev_is_lower || (prev_is_upper && next_is_lower)) {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Rule-map selector candidates for one instruction's data, longest prefix
/// first (design §5: full 8-byte key first, then shorter prefixes — covers
/// Anchor discriminators and SPL/System tag rules alike).
pub fn svm_selector_candidates(data: &[u8]) -> Vec<String> {
    let n = data.len().min(8);
    (1..=n)
        .rev()
        .map(|i| format!("0x{}", hex::encode(&data[..i])))
        .collect()
}

// ── Anchor type model ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) enum AnchorType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    I8,
    I16,
    I32,
    I64,
    I128,
    I256,
    Pubkey,
    Str,
    Option(Box<AnchorType>),
    Vec(Box<AnchorType>),
    Array(Box<AnchorType>, usize),
    /// Struct with named fields (resolved via the fragment's `types` map).
    Struct(Vec<(String, AnchorType)>),
}

/// Parse a type rendering. Accepts both IDL generations:
/// - primitive strings: `"u64"`, `"pubkey"` / `"publicKey"`, `"string"`, …
/// - objects: `{"option": T}`, `{"vec": T}`, `{"array": [T, N]}`,
///   `{"defined": {"name": N}}` (current) or `{"defined": "N"}` (legacy).
///
/// `types` resolves `defined` references (aliases or `{kind: "struct", …}`).
pub(crate) fn parse_anchor_type(
    ty: &Json,
    types: &std::collections::HashMap<String, Json>,
    depth: u32,
) -> Result<AnchorType, String> {
    if depth > 32 {
        return Err("IDL type nesting too deep (possible cycle)".to_string());
    }
    match ty {
        Json::String(s) => parse_primitive(s),
        Json::Object(o) => {
            if let Some(inner) = o.get("option") {
                return Ok(AnchorType::Option(Box::new(parse_anchor_type(
                    inner,
                    types,
                    depth + 1,
                )?)));
            }
            if let Some(inner) = o.get("vec") {
                return Ok(AnchorType::Vec(Box::new(parse_anchor_type(
                    inner,
                    types,
                    depth + 1,
                )?)));
            }
            if let Some(arr) = o.get("array").and_then(Json::as_array) {
                if arr.len() == 2 {
                    let elem = parse_anchor_type(&arr[0], types, depth + 1)?;
                    let len = match &arr[1] {
                        Json::Number(n) => n.as_u64().ok_or("array length must fit u64")?,
                        Json::String(s) => s
                            .parse::<u64>()
                            .map_err(|_| format!("invalid array length '{s}'"))?,
                        _ => return Err("array length must be a number".to_string()),
                    } as usize;
                    return Ok(AnchorType::Array(Box::new(elem), len));
                }
                return Err("array type must be [T, N]".to_string());
            }
            let defined_name = o
                .get("defined")
                .and_then(|d| match d {
                    Json::String(s) => Some(s.clone()),
                    Json::Object(d) => d.get("name").and_then(Json::as_str).map(String::from),
                    _ => None,
                })
                .ok_or_else(|| format!("unsupported IDL type rendering: {ty}"))?;
            resolve_defined(&defined_name, types, depth)
        }
        _ => Err(format!("unsupported IDL type rendering: {ty}")),
    }
}

fn parse_primitive(s: &str) -> Result<AnchorType, String> {
    Ok(match s {
        "bool" => AnchorType::Bool,
        "u8" => AnchorType::U8,
        "u16" => AnchorType::U16,
        "u32" => AnchorType::U32,
        "u64" => AnchorType::U64,
        "u128" => AnchorType::U128,
        "u256" => AnchorType::U256,
        "i8" => AnchorType::I8,
        "i16" => AnchorType::I16,
        "i32" => AnchorType::I32,
        "i64" => AnchorType::I64,
        "i128" => AnchorType::I128,
        "i256" => AnchorType::I256,
        "pubkey" | "publicKey" => AnchorType::Pubkey,
        "string" => AnchorType::Str,
        other => return Err(format!("unsupported IDL type '{other}'")),
    })
}

fn resolve_defined(
    name: &str,
    types: &std::collections::HashMap<String, Json>,
    depth: u32,
) -> Result<AnchorType, String> {
    let resolved = types.get(name).ok_or_else(|| {
        format!("unresolvable IDL type '{name}' (not in the fragment's types map)")
    })?;
    match resolved {
        // Alias to another type
        Json::String(_) => parse_anchor_type(resolved, types, depth + 1),
        Json::Object(o) => {
            match o.get("kind").and_then(Json::as_str) {
                Some("struct") => {
                    // Named fields: [{name, type}, …]; positional tuples
                    // (fields as [type, …] or name-less entries) are not
                    // exposed as args — fail closed.
                    let fields = o
                        .get("fields")
                        .and_then(Json::as_array)
                        .ok_or_else(|| format!("struct type '{name}' has no fields"))?;
                    let mut out = Vec::with_capacity(fields.len());
                    for f in fields {
                        let fname = f
                            .get("name")
                            .and_then(Json::as_str)
                            .ok_or_else(|| {
                                format!("struct type '{name}' has positional fields — unsupported")
                            })?
                            .to_string();
                        let fty = f
                            .get("type")
                            .ok_or_else(|| format!("struct field '{fname}' has no type"))?;
                        out.push((fname, parse_anchor_type(fty, types, depth + 1)?));
                    }
                    Ok(AnchorType::Struct(out))
                }
                // Type-object renderings ({vec: …}, {option: …}) with a kind
                // wrapper or not — delegate to the generic parser.
                _ => parse_anchor_type(resolved, types, depth + 1),
            }
        }
        _ => Err(format!("unsupported IDL type rendering for '{name}'")),
    }
}

// ── borsh reader ─────────────────────────────────────────────────────────────

struct BorshReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BorshReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.data.len() {
            return Err(format!(
                "unexpected end of instruction data: need {} byte(s) at offset {}, have {}",
                n,
                self.pos,
                self.data.len() - self.pos
            ));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u32_le(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    const fn remaining_is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
}

/// Unsigned little-endian integer of `len` bytes → decimal string (via U256;
/// matches the EVM decoder's string-args convention).
fn uint_to_json(b: &[u8]) -> Json {
    let mut buf = [0u8; 32];
    buf[..b.len()].copy_from_slice(b);
    Json::String(alloy_primitives::U256::from_le_bytes(buf).to_string())
}

/// Signed little-endian integer of `len` bytes (two's complement) → decimal
/// string (via I256).
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

fn decode_value(ty: &AnchorType, r: &mut BorshReader<'_>) -> Result<Json, String> {
    Ok(match ty {
        AnchorType::Bool => Json::Bool(r.take(1)?[0] != 0),
        AnchorType::U8 => uint_to_json(r.take(1)?),
        AnchorType::U16 => uint_to_json(r.take(2)?),
        AnchorType::U32 => uint_to_json(r.take(4)?),
        AnchorType::U64 => uint_to_json(r.take(8)?),
        AnchorType::U128 => uint_to_json(r.take(16)?),
        AnchorType::U256 => uint_to_json(r.take(32)?),
        AnchorType::I8 => int_to_json(r.take(1)?),
        AnchorType::I16 => int_to_json(r.take(2)?),
        AnchorType::I32 => int_to_json(r.take(4)?),
        AnchorType::I64 => int_to_json(r.take(8)?),
        AnchorType::I128 => int_to_json(r.take(16)?),
        AnchorType::I256 => int_to_json(r.take(32)?),
        AnchorType::Pubkey => Json::String(r.take(32)?.to_base58()),
        AnchorType::Str => {
            let len = r.u32_le()? as usize;
            let bytes = r.take(len)?;
            Json::String(
                std::str::from_utf8(bytes)
                    .map_err(|e| format!("invalid utf8 in string arg: {e}"))?
                    .to_string(),
            )
        }
        AnchorType::Option(inner) => {
            let tag = r.take(1)?[0];
            match tag {
                0 => Json::Null,
                1 => decode_value(inner, r)?,
                other => return Err(format!("invalid option tag {other}")),
            }
        }
        AnchorType::Vec(inner) => {
            let len = r.u32_le()? as usize;
            let mut out = Vec::with_capacity(len.min(1024));
            for _ in 0..len {
                out.push(decode_value(inner, r)?);
            }
            Json::Array(out)
        }
        AnchorType::Array(inner, len) => {
            let mut out = Vec::with_capacity(*len);
            for _ in 0..*len {
                out.push(decode_value(inner, r)?);
            }
            Json::Array(out)
        }
        AnchorType::Struct(fields) => {
            let mut obj = Map::new();
            for (name, fty) in fields {
                obj.insert(name.clone(), decode_value(fty, r)?);
            }
            Json::Object(obj)
        }
    })
}

/// Decode SVM instruction args against the rule's Anchor IDL fragment.
///
/// `selector` is the matched rule key — the decoder strips exactly its hex
/// bytes (Anchor discriminator = 8 bytes, SPL tag = 1 byte, System tag =
/// 4 bytes, per the YAML `func`) before decoding `args` positionally.
///
/// Any error (unknown type, truncated data) fails closed: the caller treats
/// args as unavailable, so expressions referencing `args.*` deny.
pub fn decode_svm_args(
    abi: &FamilyAbi,
    selector: &str,
    data: &[u8],
) -> Result<std::collections::HashMap<String, Json>, String> {
    let FamilyAbi::Svm { args, types, .. } = abi else {
        return Err("not an SVM ABI fragment".to_string());
    };
    let Some(hex_part) = selector.strip_prefix("0x") else {
        return Err(format!("svm selector '{selector}' is not a hex prefix"));
    };
    let strip_len = hex_part.len() / 2;
    if data.len() < strip_len {
        return Err(format!(
            "instruction data ({}) is shorter than the rule's tag prefix ({strip_len} bytes)",
            data.len()
        ));
    }
    let mut r = BorshReader::new(&data[strip_len..]);
    let mut out = std::collections::HashMap::with_capacity(args.len());
    for IdlArg { name, ty } in args {
        let parsed = parse_anchor_type(ty, types, 0)?;
        out.insert(name.clone(), decode_value(&parsed, &mut r)?);
    }
    // Trailing bytes after the declared args are common (padding, extra
    // Anchor fields) — not an error; the declared args are what rules see.
    let _ = r.remaining_is_empty();
    Ok(out)
}
