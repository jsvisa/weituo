//! SVM (Solana) transaction support — feature `svm`.
//!
//! The transaction arrives as resolved JSON (§3.2 of the design): accounts
//! are pre-resolved by the embedding layer, and instruction data is base58
//! (wallet/RPC convention) or `0x`-hex (engine convention). Core decodes
//! Anchor/borsh payloads against per-rule IDL fragments and checks every
//! instruction against the rule set.

pub mod builtins;
pub mod idl;
pub mod tx;

pub use builtins::SvmBuiltins;
use hex::FromHex;
pub use idl::{anchor_discriminator, decode_svm_args, svm_selector_candidates};
pub use tx::{SvmInstruction, SvmTx};

/// The native System program — `System::Transfer` instructions (u32 LE tag 2)
/// are the SVM native-transfer gate's subject.
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// SPL Token / Token-2022 operation tags (first data byte). 3 = Transfer,
/// 4 = Approve, 12 = TransferChecked, 13 = ApproveChecked.
pub const SPL_TOKEN_OP_TAGS: &[u8] = &[3, 4, 12, 13];

/// True when `data` is a System program transfer (u32 little-endian tag 2).
pub const fn is_system_transfer(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 2 && data[1] == 0 && data[2] == 0 && data[3] == 0
}

/// True when `program` is one of the SPL token programs.
pub fn is_spl_token_program(program: &str) -> bool {
    program == TOKEN_PROGRAM || program == TOKEN_2022_PROGRAM
}

/// The SPL token-op tag of `data` (first byte), when it is one of the
/// policy-gated operations.
pub fn spl_token_op_tag(data: &[u8]) -> Option<u8> {
    let tag = *data.first()?;
    SPL_TOKEN_OP_TAGS.contains(&tag).then_some(tag)
}

/// Rule-map selector for an SVM `func` (design §5): an explicit hex prefix
/// (`"0x0c"`, `"0x02000000"`, up to 8 bytes) is used verbatim; anything else
/// is an Anchor function name → `sha256("global:" + snake_case(name))[..8]`.
pub fn func_selector(func: &str) -> String {
    let lower = func.to_lowercase();
    if let Some(hex_part) = lower.strip_prefix("0x") {
        if !hex_part.is_empty()
            && hex_part.len() % 2 == 0
            && hex_part.len() <= 16
            && hex_part.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return lower;
        }
    }
    format!("0x{}", hex::encode(anchor_discriminator(func)))
}

/// Selector for a rule's ABI fragment function name (test mode: the inline
/// ABI's `name` plays the role of the YAML `func`).
pub fn func_selector_from_abi_name(abi: &crate::types::FamilyAbi) -> String {
    match abi {
        crate::types::FamilyAbi::Svm { name, .. } => func_selector(name),
        crate::types::FamilyAbi::Sui { .. } => String::new(),
    }
}

/// Decode a wire data field: `0x`-hex or base58 → bytes. Errors fail closed
/// (the payload is malformed).
pub(crate) fn decode_data_field(s: &str) -> Result<Vec<u8>, String> {
    if let Some(hex_part) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return Vec::from_hex(hex_part).map_err(|e| format!("invalid hex data: {e}"));
    }
    if s.is_empty() {
        return Ok(Vec::new());
    }
    use base58::FromBase58;
    s.from_base58()
        .map_err(|e| format!("invalid base58 data: {e:?}"))
}

/// Validate + decode a base58 pubkey (must decode to exactly 32 bytes).
pub(crate) fn parse_pubkey(s: &str) -> Result<String, String> {
    use base58::FromBase58;
    let bytes = s
        .from_base58()
        .map_err(|e| format!("invalid base58 pubkey '{s}': {e:?}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "pubkey '{s}' must decode to 32 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_case_converts_camel() {
        assert_eq!(idl::snake_case("swap"), "swap");
        assert_eq!(idl::snake_case("swapExactIn"), "swap_exact_in");
        assert_eq!(idl::snake_case("getBALANCE"), "get_balance");
        assert_eq!(idl::snake_case("HTTPServer"), "http_server");
    }

    #[test]
    fn func_selector_hex_verbatim() {
        assert_eq!(func_selector("0x0c"), "0x0c");
        assert_eq!(func_selector("0x02000000"), "0x02000000");
        assert_eq!(func_selector("0xF8C69E91"), "0xf8c69e91");
    }

    #[test]
    fn func_selector_anchor_name() {
        assert_eq!(func_selector("swap"), "0xf8c69e91e17587c8");
    }

    #[test]
    fn selector_candidates_longest_first() {
        let data = [0x0cu8, 0x60, 0xe3, 0x16];
        assert_eq!(
            svm_selector_candidates(&data),
            vec!["0x0c60e316", "0x0c60e3", "0x0c60", "0x0c"]
        );
    }
}
