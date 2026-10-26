/// Loads WAF rules from a local waf.yaml + per-selector ABI files.
///
/// Used by static mode to populate `RuleManager` without contacting waf-admin.
use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::warn;

use crate::provider::ChainInfo;
use crate::rule_manager::build_decoder;
use crate::types::{
    normalize_domain_name, AbiItem, DecoderKind, ExprValue, MulticallDecoder, RuleClause, RuleEntry,
};

// ── YAML deserialization types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct WafYaml {
    global: Option<GlobalSection>,
    contracts: Option<Vec<ContractSection>>,
}

#[derive(Debug, Deserialize)]
struct GlobalSection {
    #[allow(dead_code)]
    rules: Vec<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct ContractSection {
    address: String,
    /// Optional — falls back to `default_chain_id` from StaticSettings.
    chain_id: Option<u64>,
    #[serde(default)]
    multicall: Vec<YamlMulticall>,
    allowlist: Vec<YamlRule>,
}

#[derive(Debug, Deserialize)]
struct YamlMulticall {
    func: String,
    #[serde(
        default,
        deserialize_with = "crate::types::deserialize_decoder_kind_opt"
    )]
    decoder_type: Option<DecoderKind>,
    #[serde(default)]
    decoder_config: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct YamlRule {
    func: String,
    expr: serde_yaml::Value,
    #[serde(default)]
    vars: Option<HashMap<String, serde_yaml::Value>>,
    /// Inline ABI / EIP-712 type schema. Takes precedence over the abi_dir file.
    #[serde(default)]
    abi: Option<serde_yaml::Value>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse `rules_path` (waf.yaml) and its companion `abi_dir` into data structures
/// ready to be loaded into `RuleManager::load_static()`.
///
/// Returns:
///   - `chains`: one `ChainInfo` per chain found in the file (rpc_url = "")
///   - `contracts`: (chain_id, lowercase_address) → (lowercase_selector → RuleEntry)
#[allow(clippy::type_complexity)]
pub fn load(
    rules_path: &str,
    abi_dir: &str,
    default_chain_id: u64,
) -> Result<(
    HashMap<u64, ChainInfo>,
    HashMap<(u64, String), HashMap<String, RuleEntry>>,
)> {
    let yaml_str = std::fs::read_to_string(rules_path)
        .map_err(|e| anyhow::anyhow!("cannot read {rules_path}: {e}"))?;
    let waf: WafYaml = serde_yaml::from_str(&yaml_str)
        .map_err(|e| anyhow::anyhow!("cannot parse {rules_path}: {e}"))?;

    let mut chains: HashMap<u64, ChainInfo> = HashMap::new();
    let mut contracts: HashMap<(u64, String), HashMap<String, RuleEntry>> = HashMap::new();

    if waf.global.is_some() {
        warn!("static mode: 'global' rules are not yet supported — ignoring");
    }

    for contract in waf.contracts.into_iter().flatten() {
        let address = contract.address.to_lowercase();
        let chain_id = contract.chain_id.unwrap_or(default_chain_id);

        chains.entry(chain_id).or_insert_with(|| ChainInfo {
            rpc_url: String::new(),
        });
        let slot = contracts.entry((chain_id, address)).or_default();

        // 1. Build selector → MulticallDecoder from the multicall: section
        let mut mc_map: HashMap<String, MulticallDecoder> = HashMap::new();
        for mc in &contract.multicall {
            let sel = if mc.func.contains("::") {
                mc.func.clone()
            } else {
                selector_for(&mc.func)
            };
            let cfg_json = mc.decoder_config.as_ref().map(|v| yaml_to_json(v.clone()));
            if let Some(decoder) = build_decoder(mc.decoder_type, cfg_json.as_ref()) {
                mc_map.insert(sel, decoder);
            } else {
                warn!(func = %mc.func, "multicall entry has no valid decoder_type — inner calls will not be checked");
            }
        }

        // 2. Process allowlist rules; attach decoder from mc_map where selector matches
        let mut allowlisted: HashSet<String> = HashSet::new();
        for rule in contract.allowlist {
            // EIP-712 typed-data rules use "domain.name::primaryType" as their selector;
            // check_sign() looks them up the same way as check() — no ABI decoding needed.
            // "*" / "fallback()"  → wildcard "any non-matching selector" (Solidity fallback semantics)
            // "receive()"         → "0x" sentinel for empty calldata (plain ETH send)
            // "X::Y"              → EIP-712: lowercased domain.name::primaryType
            // else                → 4-byte keccak selector
            let selector = if rule.func == "*" || rule.func == "fallback()" {
                "*".to_string()
            } else if rule.func == "receive()" {
                "0x".to_string()
            } else if rule.func.contains("::") {
                let (domain, rest) = rule.func.split_once("::").unwrap();
                format!("{}::{}", normalize_domain_name(domain), rest).to_lowercase()
            } else {
                selector_for(&rule.func)
            };
            let abi_item = rule
                .abi
                .as_ref()
                .and_then(|v| serde_json::from_value::<AbiItem>(yaml_to_json(v.clone())).ok())
                .or_else(|| load_abi(abi_dir, &selector));
            if abi_item.is_none() {
                warn!(func = %rule.func, selector, "no ABI found — args.* will be empty");
            }
            let expr_json = yaml_to_json(rule.expr);
            let expr = match ExprValue::try_from(expr_json) {
                Ok(e) => e,
                Err(e) => {
                    warn!(func = %rule.func, "skipping rule: {e}");
                    continue;
                }
            };
            let vars: HashMap<String, serde_json::Value> = rule
                .vars
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| (k, yaml_to_json(v)))
                .collect();
            let multicall = mc_map.get(&selector).cloned();
            allowlisted.insert(selector.clone());
            slot.insert(
                selector,
                RuleEntry {
                    clauses: vec![RuleClause { expr, vars }],
                    abi_item,
                    multicall,
                    invalid_decoder: false,
                },
            );
        }

        // 3. Multicall entries with no allowlist rule → implicit expr: "true" rule
        //    This handles contracts that declare a multicall decoder but don't add an
        //    explicit allowlist entry for the outer function.
        for (sel, decoder) in mc_map {
            if !allowlisted.contains(&sel) {
                let abi_item = load_abi(abi_dir, &sel);
                slot.insert(
                    sel,
                    RuleEntry {
                        clauses: vec![RuleClause {
                            expr: ExprValue::Single("true".into()),
                            vars: HashMap::new(),
                        }],
                        abi_item,
                        multicall: Some(decoder),
                        invalid_decoder: false,
                    },
                );
            }
        }
    }

    Ok((chains, contracts))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute the lowercase 4-byte selector hex (e.g. "0x095ea7b3") for a function signature.
pub fn selector_for(func_sig: &str) -> String {
    let sig = func_sig.replace(' ', "");
    let hash = alloy_primitives::keccak256(sig.as_bytes());
    format!("0x{}", hex::encode(&hash[..4]))
}

/// Load an ABI item from `{abi_dir}/{selector}.json`.
fn load_abi(abi_dir: &str, selector: &str) -> Option<AbiItem> {
    let path = Path::new(abi_dir).join(format!("{selector}.json"));
    let contents = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<AbiItem>(&contents) {
        Ok(item) => Some(item),
        Err(e) => {
            warn!(selector, "failed to parse ABI {}: {e}", path.display());
            None
        }
    }
}

/// Convert a `serde_yaml::Value` to `serde_json::Value`.
fn yaml_to_json(v: serde_yaml::Value) -> serde_json::Value {
    serde_json::to_value(&v).unwrap_or(serde_json::Value::Null)
}
