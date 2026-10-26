use anyhow::Result;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::ProviderSettings;
use crate::provider::{ChainInfo, RuleProvider};
use crate::types::{DecoderKind, MulticallDecoder, RuleEntry};

// ── Tier 2: per-contract rules ────────────────────────────────────────────────

struct ContractEntry {
    rules: HashMap<String, RuleEntry>,
    fetched_at: Instant,
    is_static: bool,
}

type ContractSlot = Arc<RwLock<Option<ContractEntry>>>;

/// Result of a rule lookup — distinguishes "contract has no rules configured"
/// from "contract is configured but this selector has no matching rule".
#[derive(Debug, Clone)]
pub enum RuleLookup {
    /// A matching rule (exact selector, or wildcard `"*"`) exists.
    Found(RuleEntry),
    /// The contract has rules configured, but none match this selector (no wildcard).
    NoSelector,
    /// No rules are configured for this contract at all.
    NoContract,
}

// ── Rule manager ──────────────────────────────────────────────────────────────

pub struct RuleManager {
    chain_info: Arc<ArcSwap<HashMap<u64, ChainInfo>>>,
    contract_cache: DashMap<(u64, String), ContractSlot>,
    provider: Arc<dyn RuleProvider>,
    settings: ProviderSettings,
}

impl RuleManager {
    pub fn new(provider: Arc<dyn RuleProvider>, settings: ProviderSettings) -> Self {
        Self {
            chain_info: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            contract_cache: DashMap::new(),
            provider,
            settings,
        }
    }

    // ── Tier 1 ────────────────────────────────────────────────────────────────

    pub async fn reload_chains(&self) -> Result<usize> {
        let mut new_info: HashMap<u64, ChainInfo> = HashMap::new();

        for &chain_id in &self.settings.chain_ids {
            let info = match self.provider.fetch_chain_info(chain_id).await {
                Ok(info) if !info.rpc_url.is_empty() => info,
                Ok(_) | Err(_) => match self.settings.default_chains.get(&chain_id) {
                    Some(url) => {
                        info!(chain_id, rpc_url = %url, "using provider.default_chains fallback");
                        ChainInfo {
                            rpc_url: url.clone(),
                        }
                    }
                    None => {
                        warn!(
                            chain_id,
                            "no rpc_url from provider and no default_chains entry, skipping"
                        );
                        continue;
                    }
                },
            };
            debug!(chain_id, rpc_url = %info.rpc_url, "chain info loaded");
            new_info.insert(chain_id, info);
        }

        let count = new_info.len();
        self.chain_info.store(Arc::new(new_info));
        Ok(count)
    }

    pub fn chain_info(&self, chain_id: u64) -> Option<ChainInfo> {
        self.chain_info.load().get(&chain_id).cloned()
    }

    /// Warm up Tier 1 metadata for a chain that isn't cached yet (e.g. one added
    /// to the backend after startup and absent from `provider.chain_ids`). Fetches
    /// once from the provider and merges it into the chain map; further calls for
    /// a known chain are no-ops. Failures fall back to `default_chains` and are
    /// otherwise ignored (best-effort warm-up). Used by `waf_listRules` so newly
    /// added chains load immediately instead of waiting for the next refresh.
    pub async fn ensure_chain_info(&self, chain_id: u64) {
        if self.chain_info(chain_id).is_some() {
            return;
        }
        let info = match self.provider.fetch_chain_info(chain_id).await {
            Ok(info) if !info.rpc_url.is_empty() => Some(info),
            Ok(_) | Err(_) => self
                .settings
                .default_chains
                .get(&chain_id)
                .map(|url| ChainInfo {
                    rpc_url: url.clone(),
                }),
        };
        let Some(info) = info else {
            warn!(chain_id, "no rpc_url for chain, not caching");
            return;
        };
        self.chain_info.rcu(|m| {
            let mut next = (**m).clone();
            next.insert(chain_id, info.clone());
            Arc::new(next)
        });
        info!(chain_id, rpc_url = %info.rpc_url, "chain info warmed up");
    }

    pub fn rpc_url(&self, chain_id: u64) -> Option<String> {
        self.chain_info
            .load()
            .get(&chain_id)
            .map(|i| i.rpc_url.clone())
    }

    // ── Tier 2 ────────────────────────────────────────────────────────────────

    pub async fn get(&self, chain_id: u64, address: &str, selector: &str) -> RuleLookup {
        let addr = address.to_lowercase();
        let sel = selector.to_lowercase();
        let ttl = std::time::Duration::from_secs(self.settings.contract_cache_ttl);
        let key = (chain_id, addr.clone());

        let slot: ContractSlot = self
            .contract_cache
            .entry(key)
            .or_insert_with(|| Arc::new(RwLock::new(None)))
            .clone();

        {
            let read = slot.read().await;
            if let Some(ref entry) = *read {
                if entry.is_static || entry.fetched_at.elapsed() < ttl {
                    return rule_or_wildcard(&entry.rules, &sel);
                }
            }
        }

        let mut write = slot.write().await;
        if let Some(ref entry) = *write {
            if entry.is_static || entry.fetched_at.elapsed() < ttl {
                return rule_or_wildcard(&entry.rules, &sel);
            }
        }

        match self.provider.fetch_contract_rules(chain_id, &addr).await {
            Ok(rules) => {
                let result = rule_or_wildcard(&rules, &sel);
                *write = Some(ContractEntry {
                    rules,
                    fetched_at: Instant::now(),
                    is_static: false,
                });
                // Drop the slot's write lock before evicting: eviction read-locks
                // every slot to find the stalest, including this one.
                drop(write);
                self.evict_over_capacity().await;
                result
            }
            Err(e) => {
                warn!(chain_id, address = %addr, "failed to fetch contract rules: {e}");
                match write.as_ref() {
                    Some(e) => rule_or_wildcard(&e.rules, &sel),
                    None => RuleLookup::NoContract,
                }
            }
        }
    }

    /// List the rules held for a chain.
    ///
    /// Returns `address → (selector → RuleEntry)`.
    ///
    /// - `address = None`: serve **only from cache** — whatever is already loaded
    ///   for the chain. Never contacts the provider (except Tier 1 chain warm-up
    ///   when the chain isn't known yet).
    /// - `address = Some(a)`: return the cached entry if still valid (static or
    ///   within `contract_cache_ttl`); otherwise fetch from the provider and
    ///   populate the cache (acts as a warm-up). On fetch error the stale cache
    ///   is served if present, else the error is returned.
    pub async fn list_rules(
        &self,
        chain_id: u64,
        address: Option<&str>,
    ) -> Result<HashMap<String, HashMap<String, RuleEntry>>> {
        // Warm up Tier 1 metadata for chains added after startup, so a
        // `waf_listRules` on a brand-new chain loads it without a restart.
        self.ensure_chain_info(chain_id).await;

        let mut out: HashMap<String, HashMap<String, RuleEntry>> = HashMap::new();

        let addr = match address.map(str::to_lowercase) {
            Some(addr) => addr,
            None => {
                for key in self.contract_cache.iter().map(|r| r.key().clone()) {
                    if key.0 != chain_id {
                        continue;
                    }
                    if let Some(slot) = self.contract_cache.get(&key) {
                        let read = slot.read().await;
                        if let Some(ref entry) = *read {
                            out.insert(key.1, entry.rules.clone());
                        }
                    }
                }
                return Ok(out);
            }
        };

        let ttl = std::time::Duration::from_secs(self.settings.contract_cache_ttl);
        let key = (chain_id, addr.clone());
        let slot: ContractSlot = self
            .contract_cache
            .entry(key)
            .or_insert_with(|| Arc::new(RwLock::new(None)))
            .clone();

        let mut write = slot.write().await;
        if let Some(ref entry) = *write {
            if entry.is_static || entry.fetched_at.elapsed() < ttl {
                out.insert(addr, entry.rules.clone());
                return Ok(out);
            }
        }

        match self.provider.fetch_contract_rules(chain_id, &addr).await {
            Ok(rules) => {
                let snapshot = rules.clone();
                *write = Some(ContractEntry {
                    rules,
                    fetched_at: Instant::now(),
                    is_static: false,
                });
                out.insert(addr, snapshot);
                Ok(out)
            }
            Err(e) => {
                warn!(chain_id, address = %addr, "failed to fetch contract rules: {e}");
                if let Some(ref entry) = *write {
                    out.insert(addr, entry.rules.clone());
                    Ok(out)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn invalidate_contract_cache(&self) {
        self.contract_cache.clear();
    }

    /// Enforce `settings.contract_cache_max`. When the number of cached contract
    /// entries exceeds the cap, evict the least-recently-fetched non-static
    /// entries until back under the cap. A cap of `0` means unlimited. Static
    /// entries (loaded from waf.yaml) are never evicted.
    async fn evict_over_capacity(&self) {
        let max = self.settings.contract_cache_max;
        if max == 0 {
            return;
        }
        let mut over = self.contract_cache.len().saturating_sub(max);
        if over == 0 {
            return;
        }

        // Collect (key, fetched_at) for every entry that is eligible for eviction.
        let keys: Vec<(u64, String)> = self
            .contract_cache
            .iter()
            .map(|r| r.key().clone())
            .collect();
        let mut candidates: Vec<((u64, String), Instant)> = Vec::new();
        for key in keys {
            let Some(slot) = self.contract_cache.get(&key) else {
                continue;
            };
            let read = slot.read().await;
            if let Some(entry) = read.as_ref() {
                if !entry.is_static {
                    candidates.push((key, entry.fetched_at));
                }
            }
        }

        // Order oldest first, then drop from the front until under the cap.
        candidates.sort_by_key(|(_, at)| *at);
        for (key, _) in candidates {
            if over == 0 {
                break;
            }
            if self.contract_cache.remove(&key).is_some() {
                over -= 1;
            }
        }
    }

    pub fn load_static(
        &self,
        contracts: HashMap<(u64, String), HashMap<String, RuleEntry>>,
        chains: HashMap<u64, ChainInfo>,
    ) {
        self.chain_info.store(Arc::new(chains));
        for ((chain_id, address), rules) in contracts {
            let slot: ContractSlot = Arc::new(RwLock::new(Some(ContractEntry {
                rules,
                fetched_at: Instant::now(),
                is_static: true,
            })));
            self.contract_cache.insert((chain_id, address), slot);
        }
    }

    // ── Background tasks ──────────────────────────────────────────────────────

    pub fn spawn_chain_refresher(self: Arc<Self>) {
        let interval = self.settings.chain_refresh_secs;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(interval));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match self.reload_chains().await {
                    Ok(n) => info!(chains = n, "chain info refreshed"),
                    Err(e) => warn!("chain refresh failed: {e}"),
                }
            }
        });
    }
}

pub(crate) fn build_decoder(
    kind: Option<DecoderKind>,
    config: Option<&serde_json::Value>,
) -> Option<MulticallDecoder> {
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

fn rule_or_wildcard(rules: &HashMap<String, RuleEntry>, sel: &str) -> RuleLookup {
    if let Some(e) = rules.get(sel).cloned() {
        return RuleLookup::Found(e);
    }
    if let Some(e) = rules.get("*").cloned() {
        return RuleLookup::Found(e);
    }
    if rules.is_empty() {
        RuleLookup::NoContract
    } else {
        RuleLookup::NoSelector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EmpApiSettings, ProviderKind, ProviderSettings, WafAdminSettings};
    use crate::provider::{ChainInfo, RuleProvider};
    use crate::types::{ExprValue, RuleClause, RuleEntry};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    fn make_settings(default_chains: HashMap<u64, String>) -> ProviderSettings {
        make_settings_cache(10, default_chains)
    }

    fn make_settings_cache(
        cache_ttl: u64,
        default_chains: HashMap<u64, String>,
    ) -> ProviderSettings {
        ProviderSettings {
            r#type: ProviderKind::EmpApi,
            chain_ids: vec![1],
            chain_refresh_secs: 3600,
            contract_cache_ttl: cache_ttl,
            contract_cache_max: 50_000,
            default_chains,
            emp_api: EmpApiSettings::default(),
            waf_admin: WafAdminSettings::default(),
        }
    }

    fn make_settings_max(
        cache_max: usize,
        default_chains: HashMap<u64, String>,
    ) -> ProviderSettings {
        ProviderSettings {
            r#type: ProviderKind::EmpApi,
            chain_ids: vec![1],
            chain_refresh_secs: 3600,
            contract_cache_ttl: 10,
            contract_cache_max: cache_max,
            default_chains,
            emp_api: EmpApiSettings::default(),
            waf_admin: WafAdminSettings::default(),
        }
    }

    struct EmptyRpcProvider;

    #[async_trait]
    impl RuleProvider for EmptyRpcProvider {
        async fn fetch_chain_info(&self, _: u64) -> anyhow::Result<ChainInfo> {
            Ok(ChainInfo {
                rpc_url: String::new(),
            })
        }
        async fn fetch_contract_rules(
            &self,
            _: u64,
            _: &str,
        ) -> anyhow::Result<HashMap<String, RuleEntry>> {
            Ok(HashMap::new())
        }
    }

    struct FailingProvider;

    #[async_trait]
    impl RuleProvider for FailingProvider {
        async fn fetch_chain_info(&self, _: u64) -> anyhow::Result<ChainInfo> {
            anyhow::bail!("network error")
        }
        async fn fetch_contract_rules(
            &self,
            _: u64,
            _: &str,
        ) -> anyhow::Result<HashMap<String, RuleEntry>> {
            Ok(HashMap::new())
        }
    }

    #[tokio::test]
    async fn reload_chains_uses_default_when_provider_returns_empty_rpc() {
        let mut defaults = HashMap::new();
        defaults.insert(1u64, "https://eth.llamarpc.com".to_string());
        let mgr = RuleManager::new(Arc::new(EmptyRpcProvider), make_settings(defaults));
        let count = mgr.reload_chains().await.unwrap();
        assert_eq!(count, 1);
        assert_eq!(mgr.rpc_url(1).as_deref(), Some("https://eth.llamarpc.com"));
    }

    #[tokio::test]
    async fn reload_chains_uses_default_when_provider_errors() {
        let mut defaults = HashMap::new();
        defaults.insert(1u64, "https://eth.llamarpc.com".to_string());
        let mgr = RuleManager::new(Arc::new(FailingProvider), make_settings(defaults));
        let count = mgr.reload_chains().await.unwrap();
        assert_eq!(count, 1);
        assert_eq!(mgr.rpc_url(1).as_deref(), Some("https://eth.llamarpc.com"));
    }

    #[tokio::test]
    async fn reload_chains_skips_chain_with_no_rpc_and_no_default() {
        let mgr = RuleManager::new(Arc::new(EmptyRpcProvider), make_settings(HashMap::new()));
        let count = mgr.reload_chains().await.unwrap();
        assert_eq!(count, 0);
        assert!(mgr.rpc_url(1).is_none());
    }

    /// Provider whose `fetch_chain_info` returns a fixed RPC URL and counts calls.
    struct CountingChainProvider {
        calls: Arc<AtomicUsize>,
        rpc: String,
    }

    #[async_trait]
    impl RuleProvider for CountingChainProvider {
        async fn fetch_chain_info(&self, _: u64) -> anyhow::Result<ChainInfo> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ChainInfo {
                rpc_url: self.rpc.clone(),
            })
        }
        async fn fetch_contract_rules(
            &self,
            _: u64,
            _: &str,
        ) -> anyhow::Result<HashMap<String, RuleEntry>> {
            Ok(HashMap::new())
        }
    }

    #[tokio::test]
    async fn ensure_chain_info_fetches_uncached_chain_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = CountingChainProvider {
            calls: Arc::clone(&calls),
            rpc: "https://polygon-rpc.com".to_string(),
        };
        let mgr = RuleManager::new(Arc::new(provider), make_settings(HashMap::new()));

        assert!(mgr.rpc_url(137).is_none());
        mgr.ensure_chain_info(137).await;
        assert_eq!(mgr.rpc_url(137).as_deref(), Some("https://polygon-rpc.com"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        mgr.ensure_chain_info(137).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "cached chain must not re-fetch"
        );
    }

    /// Provider with scripted rules, a call counter, and a fail switch.
    #[derive(Default)]
    struct ScriptedProvider {
        rules: HashMap<(u64, String), HashMap<String, RuleEntry>>,
        calls: Arc<AtomicUsize>,
        fail: AtomicBool,
    }

    #[async_trait]
    impl RuleProvider for ScriptedProvider {
        async fn fetch_chain_info(&self, _: u64) -> anyhow::Result<ChainInfo> {
            Ok(ChainInfo {
                rpc_url: String::new(),
            })
        }
        async fn fetch_contract_rules(
            &self,
            chain_id: u64,
            address: &str,
        ) -> anyhow::Result<HashMap<String, RuleEntry>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                anyhow::bail!("network error");
            }
            Ok(self
                .rules
                .get(&(chain_id, address.to_lowercase()))
                .cloned()
                .unwrap_or_default())
        }
    }

    fn tx_rule(expr: &str) -> RuleEntry {
        RuleEntry {
            clauses: vec![RuleClause {
                expr: ExprValue::Single(expr.to_string()),
                vars: HashMap::new(),
            }],
            abi_item: None,
            multicall: None,
            invalid_decoder: false,
        }
    }

    fn single_rule_contract() -> HashMap<String, RuleEntry> {
        let mut rules = HashMap::new();
        rules.insert("0x12345678".to_string(), tx_rule("args.amount > 0"));
        rules
    }

    #[tokio::test]
    async fn list_rules_with_address_fetches_once_then_serves_from_cache() {
        let provider = Arc::new(ScriptedProvider {
            rules: vec![((1, "0xabc".to_string()), single_rule_contract())]
                .into_iter()
                .collect(),
            ..Default::default()
        });
        let mgr = RuleManager::new(
            Arc::clone(&provider) as Arc<dyn RuleProvider>,
            make_settings(HashMap::new()),
        );

        let listed = mgr.list_rules(1, Some("0xABC")).await.unwrap();
        assert!(listed.get("0xabc").unwrap().contains_key("0x12345678"));
        assert_eq!(listed["0xabc"].len(), 1);

        let listed = mgr.list_rules(1, Some("0xabc")).await.unwrap();
        assert!(listed.get("0xabc").unwrap().contains_key("0x12345678"));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn list_rules_fetch_error_returns_error_when_nothing_cached() {
        let provider = Arc::new(ScriptedProvider {
            fail: AtomicBool::new(true),
            ..Default::default()
        });
        let mgr = RuleManager::new(
            Arc::clone(&provider) as Arc<dyn RuleProvider>,
            make_settings(HashMap::new()),
        );

        let err = mgr.list_rules(1, Some("0xabc")).await.unwrap_err();
        assert!(err.to_string().contains("network error"));
    }

    #[tokio::test]
    async fn list_rules_fetch_error_serves_stale_cache() {
        let provider = Arc::new(ScriptedProvider {
            rules: vec![((1, "0xabc".to_string()), single_rule_contract())]
                .into_iter()
                .collect(),
            ..Default::default()
        });
        let mgr = RuleManager::new(
            Arc::clone(&provider) as Arc<dyn RuleProvider>,
            make_settings_cache(0, HashMap::new()),
        );

        // cache_ttl = 0 means every listing re-checks upstream; warm once so a
        // stale entry exists, then fail upstream. The stale cache is served.
        mgr.list_rules(1, Some("0xabc")).await.unwrap();
        provider.fail.store(true, Ordering::SeqCst);
        let listed = mgr.list_rules(1, Some("0xabc")).await.unwrap();
        assert!(listed.get("0xabc").unwrap().contains_key("0x12345678"));
    }

    #[tokio::test]
    async fn list_rules_all_chain_serves_only_loaded_contracts_without_fetching() {
        let provider = Arc::new(ScriptedProvider {
            rules: vec![((1, "0xabc".to_string()), single_rule_contract())]
                .into_iter()
                .collect(),
            ..Default::default()
        });
        let mgr = RuleManager::new(
            Arc::clone(&provider) as Arc<dyn RuleProvider>,
            make_settings(HashMap::new()),
        );

        let listed = mgr.list_rules(1, None).await.unwrap();
        assert!(listed.is_empty());

        mgr.list_rules(1, Some("0xabc")).await.unwrap();
        let before = provider.calls.load(Ordering::SeqCst);
        let listed = mgr.list_rules(1, None).await.unwrap();
        assert!(listed.contains_key("0xabc"));
        assert_eq!(provider.calls.load(Ordering::SeqCst), before);
    }

    /// Provider that returns empty rules and counts upstream fetches, so a cache
    /// miss is observable.
    struct CountingProvider {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl RuleProvider for CountingProvider {
        async fn fetch_chain_info(&self, _: u64) -> anyhow::Result<ChainInfo> {
            Ok(ChainInfo {
                rpc_url: String::new(),
            })
        }
        async fn fetch_contract_rules(
            &self,
            _: u64,
            _: &str,
        ) -> anyhow::Result<HashMap<String, RuleEntry>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(HashMap::new())
        }
    }

    #[tokio::test]
    async fn cache_evicts_oldest_when_entries_exceed_cap() {
        let provider = Arc::new(CountingProvider {
            calls: AtomicUsize::new(0),
        });
        let mgr = RuleManager::new(
            Arc::clone(&provider) as Arc<dyn RuleProvider>,
            make_settings_max(2, HashMap::new()),
        );

        // Warm three distinct contracts; cap is 2 so the oldest (A) must be evicted.
        mgr.get(1, "0xaaa", "0x00000000").await;
        mgr.get(1, "0xbbb", "0x00000000").await;
        mgr.get(1, "0xccc", "0x00000000").await;
        assert_eq!(provider.calls.load(Ordering::SeqCst), 3);

        // B and C are cached → no refetch.
        mgr.get(1, "0xbbb", "0x00000000").await;
        mgr.get(1, "0xccc", "0x00000000").await;
        assert_eq!(provider.calls.load(Ordering::SeqCst), 3);

        // A was evicted → a cache miss that refetches.
        mgr.get(1, "0xaaa", "0x00000000").await;
        assert_eq!(provider.calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn cache_eviction_skips_static_entries() {
        let provider = Arc::new(CountingProvider {
            calls: AtomicUsize::new(0),
        });
        let mgr = RuleManager::new(
            Arc::clone(&provider) as Arc<dyn RuleProvider>,
            make_settings_max(1, HashMap::new()),
        );

        // Two static entries that must survive eviction.
        let mut contracts = HashMap::new();
        contracts.insert((1, "0xaaa".to_string()), HashMap::new());
        contracts.insert((1, "0xbbb".to_string()), HashMap::new());
        mgr.load_static(contracts, HashMap::new());

        // Warm a dynamic contract C. With cap=1 and only one non-static entry,
        // C evicts itself — static A/B are left intact.
        mgr.get(1, "0xccc", "0x00000000").await;
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

        // A is static → still cached, no fetch.
        mgr.get(1, "0xaaa", "0x00000000").await;
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

        // C was evicted → refetch now.
        mgr.get(1, "0xccc", "0x00000000").await;
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cache_cap_zero_means_unlimited() {
        let provider = Arc::new(CountingProvider {
            calls: AtomicUsize::new(0),
        });
        let mgr = RuleManager::new(
            Arc::clone(&provider) as Arc<dyn RuleProvider>,
            make_settings_max(0, HashMap::new()),
        );

        mgr.get(1, "0xaaa", "0x00000000").await;
        mgr.get(1, "0xbbb", "0x00000000").await;
        // Both still cached (cap = 0 = unlimited) → no refetch.
        mgr.get(1, "0xaaa", "0x00000000").await;
        mgr.get(1, "0xbbb", "0x00000000").await;
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }
}
