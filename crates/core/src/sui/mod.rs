//! Sui transaction support — feature `sui`.
//!
//! The transaction is a Programmable Transaction Block (PTB) in the JSON
//! shape of the Sui TypeScript SDK's `TransactionData` serialization with
//! `kind.programmableTransaction` flattened to top level (design §3.3).
//! Core decodes `MoveCall` arguments positionally against per-rule Move
//! signatures (BCS for pure inputs), recognizes the canonical native-SUI
//! transfer patterns, and checks every command against the rule set.

pub mod builtins;
pub mod tx;

pub use builtins::SuiBuiltins;
pub use tx::{
    decode_sui_args, decode_sui_args_typed, SuiArgument, SuiCommand, SuiInput, SuiMoveCall, SuiTx,
};

use crate::chain::normalize_sui_address;

/// The system package — home of `coin`, `pay`, `sui` modules and the
/// synthetic `native_transfer` rule target.
pub const SYSTEM_PACKAGE: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000002";
/// Sentinel for the `{"GasCoin": true}` argument: a gas coin *is* a SUI coin.
pub const GAS_COIN_SENTINEL: &str = "0x2::sui::SUI";
/// The SUI coin type (mist is the unit).
pub const SUI_COIN_TYPE: &str = "0x2::sui::SUI";

/// MoveCall targets that count as token operations for the token-op gate
/// (design §9). Targets are compared as `module::function` on the system
/// package.
pub const TOKEN_OP_TARGETS: &[&str] = &[
    "coin::transfer",
    "pay::pay",
    "pay::pay_sui",
    "pay::split",
    "pay::split_vec",
];

/// True when `module::function` is a token-op target on the system package.
pub fn is_token_op_target(module_func: &str) -> bool {
    TOKEN_OP_TARGETS.contains(&module_func)
}

/// Normalize a Move type string: canonicalize capitalized primitive
/// renderings (`U64` → `u64`, `Address` → `address`, `Bool` → `bool`,
/// `String` → `string`) at every generic position, expand addresses inside
/// generics to the full 64-nibble form, and collapse whitespace — so inline
/// rule fragments and `sui_getNormalizedMoveFunction` output decode
/// identically (design §8.2).
pub fn normalize_move_type(ty: &str) -> String {
    let trimmed = ty.trim();
    let mut out = String::with_capacity(trimmed.len() + 16);
    let mut seg = String::new();
    // Segment on delimiters; each segment is canonicalized independently so
    // primitives normalize at any generic depth (`vector<U64>` →
    // `vector<u64>`).
    for c in trimmed.chars() {
        match c {
            '<' | '>' | ',' | '&' => {
                flush_segment(&mut seg, &mut out);
                out.push(c);
            }
            c if c.is_whitespace() => flush_segment(&mut seg, &mut out),
            _ => seg.push(c),
        }
    }
    flush_segment(&mut seg, &mut out);
    out
}

fn flush_segment(seg: &mut String, out: &mut String) {
    if seg.is_empty() {
        return;
    }
    let s = std::mem::take(seg);
    out.push_str(&normalize_type_segment(&s));
}

/// Canonicalize one delimited segment: primitive map first, then expand any
/// `0x`-hex run (usually the leading address of a `0x2::module::Type` path).
fn normalize_type_segment(seg: &str) -> String {
    match seg {
        "U8" | "u8" => return "u8".into(),
        "U16" | "u16" => return "u16".into(),
        "U32" | "u32" => return "u32".into(),
        "U64" | "u64" => return "u64".into(),
        "U128" | "u128" => return "u128".into(),
        "U256" | "u256" => return "u256".into(),
        "Bool" | "bool" => return "bool".into(),
        "Address" | "address" => return "address".into(),
        "String" | "string" => return "string".into(),
        _ => {}
    }
    let bytes = seg.as_bytes();
    let mut out = String::with_capacity(seg.len() + 64);
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            // Collect the hex run.
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() && (bytes[end] as char).is_ascii_hexdigit() {
                end += 1;
            }
            if end > start {
                let full = normalize_sui_address(&seg[i..end])
                    .unwrap_or_else(|_| format!("0x{}", seg[start..end].to_lowercase()));
                out.push_str(&full);
                i = end;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// A rule ABI parameter after reference filtering decides whether it
/// consumes a PTB argument slot: `&T` / `&mut T` params — always including
/// the trailing `TxContext` — are implicit (design §8.2).
pub fn param_consumes_argument(normalized_ty: &str, is_last: bool) -> bool {
    if normalized_ty.starts_with('&') {
        return false;
    }
    if is_last && normalized_ty.contains("tx_context") {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_move_type_canonicalizes() {
        assert_eq!(normalize_move_type("U64"), "u64");
        assert_eq!(normalize_move_type("Address"), "address");
        assert_eq!(normalize_move_type(" Bool "), "bool");
        assert_eq!(normalize_move_type("vector<U64>"), "vector<u64>");
    }

    #[test]
    fn short_address_expands_in_generics() {
        assert_eq!(
            normalize_move_type("0x2::coin::Coin<0x2::sui::SUI>"),
            "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>"
        );
        // Non-hex segments pass through untouched.
        assert_eq!(
            normalize_move_type("0x2::coin::Coin<SUI>"),
            "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<SUI>"
        );
    }

    #[test]
    fn token_op_targets_match() {
        assert!(is_token_op_target("coin::transfer"));
        assert!(is_token_op_target("pay::pay_sui"));
        assert!(!is_token_op_target("sui::transfer_sui"));
    }

    #[test]
    fn ref_filtering() {
        assert!(!param_consumes_argument(
            "&mut 0x2::coin::Coin<0x2::sui::SUI>",
            false
        ));
        assert!(!param_consumes_argument("&address", false));
        assert!(!param_consumes_argument("0x2::tx_context::TxContext", true));
        assert!(param_consumes_argument("u64", true));
        assert!(param_consumes_argument("0x2::tx_context::TxContext", false));
    }
}
