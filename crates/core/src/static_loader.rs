/// Loads WAF rules from a local waf.yaml + per-selector ABI files.
///
/// For embedders that ship rules as files instead of fetching them from a
/// rule provider.
use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::warn;

use crate::chain::ChainRef;
use crate::decoder::build_decoder;
use crate::provider::ChainInfo;
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
    /// Multi-chain files use `chain: "svm:mainnet-beta"` / `"sui:mainnet"`
    /// instead; both keys may not appear on the same contract.
    chain_id: Option<u64>,
    chain: Option<String>,
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
/// ready to build a `StaticResolver` or feed a custom rule cache.
///
/// Legacy EVM-only surface: contracts carrying `chain_id:` (or no chain key)
/// land under [`ChainRef::Evm`]; contracts carrying a non-EVM `chain:` key are
/// skipped with a warning because the returned maps are u64-keyed. Use
/// [`load_multi`] to load them.
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
    let (chains, contracts) = load_multi(rules_path, abi_dir, default_chain_id)?;
    let mut evm_chains = HashMap::new();
    let mut evm_contracts = HashMap::new();
    for (chain, info) in chains {
        match chain {
            ChainRef::Evm(n) => {
                evm_chains.insert(n, info);
            }
            other => warn!(
                chain = %other.to_family_network(),
                "legacy load() cannot represent non-EVM chains — skipped"
            ),
        }
    }
    for ((chain, address), rules) in contracts {
        match chain {
            ChainRef::Evm(n) => {
                evm_contracts.insert((n, address), rules);
            }
            other => warn!(
                chain = %other.to_family_network(),
                %address,
                "legacy load() cannot represent non-EVM contracts — skipped"
            ),
        }
    }
    Ok((evm_chains, evm_contracts))
}

/// Multi-chain [`load`]: same YAML surface, but the returned maps are keyed
/// by [`ChainRef`]. Contracts use `chain_id:` (implies EVM) or
/// `chain: "family:network"` (`"svm:mainnet-beta"`, `"sui:mainnet"`, …).
#[allow(clippy::type_complexity)]
pub fn load_multi(
    rules_path: &str,
    abi_dir: &str,
    default_chain_id: u64,
) -> Result<(
    HashMap<ChainRef, ChainInfo>,
    HashMap<(ChainRef, String), HashMap<String, RuleEntry>>,
)> {
    let yaml_str = std::fs::read_to_string(rules_path)
        .map_err(|e| anyhow::anyhow!("cannot read {rules_path}: {e}"))?;
    let waf: WafYaml = serde_yaml::from_str(&yaml_str)
        .map_err(|e| anyhow::anyhow!("cannot parse {rules_path}: {e}"))?;

    let mut chains: HashMap<ChainRef, ChainInfo> = HashMap::new();
    let mut contracts: HashMap<(ChainRef, String), HashMap<String, RuleEntry>> = HashMap::new();

    if waf.global.is_some() {
        warn!("static mode: 'global' rules are not yet supported — ignoring");
    }

    for contract in waf.contracts.into_iter().flatten() {
        let chain = match chain_ref_for(&contract, default_chain_id) {
            Ok(c) => c,
            Err(e) => {
                warn!(address = %contract.address, "skipping contract: {e}");
                continue;
            }
        };
        let address = chain.normalize_address(&contract.address);

        chains.entry(chain.clone()).or_insert_with(|| ChainInfo {
            rpc_url: String::new(),
        });
        let slot = contracts.entry((chain.clone(), address)).or_default();

        // 1. Build selector → MulticallDecoder from the multicall: section
        let mut mc_map: HashMap<String, MulticallDecoder> = HashMap::new();
        for mc in &contract.multicall {
            let sel = func_selector(&chain, &mc.func);
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
            let selector = func_selector(&chain, &rule.func);
            let abi_item = rule
                .abi
                .as_ref()
                .and_then(|v| serde_json::from_value::<AbiItem>(yaml_to_json(v.clone())).ok())
                .or_else(|| load_abi(abi_dir, &chain, &selector));
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
                let abi_item = load_abi(abi_dir, &chain, &sel);
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

/// Resolve the [`ChainRef`] for one contract section: `chain: "family:network"`
/// wins, `chain_id:` implies EVM, neither falls back to `default_chain_id`.
fn chain_ref_for(contract: &ContractSection, default_chain_id: u64) -> Result<ChainRef> {
    if contract.chain_id.is_some() && contract.chain.is_some() {
        anyhow::bail!("contract declares both chain_id and chain — pick one");
    }
    match &contract.chain {
        Some(spec) => parse_chain_ref(spec),
        None => Ok(ChainRef::Evm(contract.chain_id.unwrap_or(default_chain_id))),
    }
}

/// Parse a `"family:network"` chain spec. `"eip155:1"`-style specs are
/// accepted for symmetry; a bare numeric string is EVM (legacy default).
fn parse_chain_ref(spec: &str) -> Result<ChainRef> {
    let spec = spec.trim();
    if let Some((family, network)) = spec.split_once(':') {
        match family {
            "eip155" => network
                .parse::<u64>()
                .map(ChainRef::Evm)
                .map_err(|_| anyhow::anyhow!("invalid eip155 chain id '{network}'")),
            "svm" if !network.is_empty() => Ok(ChainRef::Svm(network.to_string())),
            "sui" if !network.is_empty() => Ok(ChainRef::Sui(network.to_string())),
            _ => anyhow::bail!("unknown chain family in '{spec}' — expected svm:, sui: or eip155:"),
        }
    } else {
        spec.parse::<u64>()
            .map(ChainRef::Evm)
            .map_err(|_| anyhow::anyhow!("invalid chain spec '{spec}' — use \"family:network\""))
    }
}

/// `func` → rule-map selector, per family:
/// - EVM: `*`/`fallback()` → wildcard, `receive()` → `"0x"`, `X::Y` →
///   EIP-712 `domain::primaryType`, else 4-byte keccak selector.
/// - Sui: `"module::function"` lowercased as written.
/// - SVM: hex funcs verbatim (non-Anchor tag prefixes); named funcs are
///   stored as-is until the `svm` feature adds Anchor discriminator
///   computation at load.
fn func_selector(chain: &ChainRef, func: &str) -> String {
    match chain {
        ChainRef::Evm(_) => {
            if func == "*" || func == "fallback()" {
                "*".to_string()
            } else if func == "receive()" {
                "0x".to_string()
            } else if func.contains("::") {
                let (domain, rest) = func.split_once("::").unwrap();
                format!("{}::{}", normalize_domain_name(domain), rest).to_lowercase()
            } else {
                selector_for(func)
            }
        }
        ChainRef::Sui(_) | ChainRef::Svm(_) => func.to_lowercase(),
    }
}

/// ABI file lookup: `{abi_dir}/{selector}.json`; non-EVM selectors containing
/// `::` map to `__` in file names (`pay::split` → `pay__split.json`).
fn load_abi(abi_dir: &str, chain: &ChainRef, selector: &str) -> Option<AbiItem> {
    let filename = if matches!(chain, ChainRef::Evm(_)) {
        format!("{selector}.json")
    } else {
        format!("{}.json", selector.replace("::", "__"))
    };
    let path = Path::new(abi_dir).join(filename);
    let contents = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<AbiItem>(&contents) {
        Ok(item) => Some(item),
        Err(e) => {
            warn!(selector, "failed to parse ABI {}: {e}", path.display());
            None
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute the lowercase 4-byte selector hex (e.g. "0x095ea7b3") for a function signature.
pub fn selector_for(func_sig: &str) -> String {
    let sig = func_sig.replace(' ', "");
    let hash = alloy_primitives::keccak256(sig.as_bytes());
    format!("0x{}", hex::encode(&hash[..4]))
}

/// Convert a `serde_yaml::Value` to `serde_json::Value`.
fn yaml_to_json(v: serde_yaml::Value) -> serde_json::Value {
    serde_json::to_value(&v).unwrap_or(serde_json::Value::Null)
}
