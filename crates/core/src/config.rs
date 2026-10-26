use serde::{Deserialize, Deserializer};
use std::collections::HashMap;

pub const EMP_API_ACCESS_TOKEN_ENV: &str = "ETH_WAF__PROVIDER__EMP_API__ACCESS_TOKEN";

pub fn emp_api_access_token_env_loaded() -> bool {
    std::env::var(EMP_API_ACCESS_TOKEN_ENV).is_ok_and(|value| !value.is_empty())
}

pub const WAF_ADMIN_API_KEY_ENV: &str = "ETH_WAF__PROVIDER__WAF_ADMIN__API_KEY";

pub fn waf_admin_api_key_env_loaded() -> bool {
    std::env::var(WAF_ADMIN_API_KEY_ENV).is_ok_and(|value| !value.is_empty())
}

#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    #[default]
    Dynamic,
    Static,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StaticSettings {
    /// Path to the waf.yaml rules file
    #[serde(default = "default_rules_path")]
    pub rules_path: String,
    /// Directory containing per-selector ABI JSON files (e.g. etc/abi/)
    #[serde(default = "default_abi_dir")]
    pub abi_dir: String,
    /// Fallback chain_id for contract entries that omit the field
    #[serde(default = "default_chain_id")]
    pub default_chain_id: u64,
}

impl Default for StaticSettings {
    fn default() -> Self {
        Self {
            rules_path: default_rules_path(),
            abi_dir: default_abi_dir(),
            default_chain_id: default_chain_id(),
        }
    }
}

fn default_rules_path() -> String {
    "etc/waf.yaml".into()
}
fn default_abi_dir() -> String {
    "etc/abi".into()
}
const fn default_chain_id() -> u64 {
    1
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerSettings,
    #[serde(default)]
    pub auth: AuthSettings,
    pub provider: ProviderSettings,
    pub rpc: RpcSettings,
    #[serde(default)]
    pub simulate: SimulateSettings,
    pub oracle: OracleSettings,
    #[serde(default)]
    pub allowlist: AllowlistSettings,
    #[serde(default)]
    pub scam_list: ScamListSettings,
    #[serde(default)]
    pub mode: RunMode,
    #[serde(default)]
    pub static_rules: StaticSettings,
    #[serde(default)]
    pub global_policy: GlobalPolicy,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuthSettings {
    #[serde(default)]
    pub google: GoogleAuthSettings,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAuthMode {
    #[default]
    Disabled,
    Required,
    Optional,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GoogleAuthSettings {
    #[serde(default)]
    pub mode: GoogleAuthMode,
    #[serde(default, deserialize_with = "deserialize_allowed_domains")]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub client_id: String,
    #[serde(default = "default_google_jwks_url")]
    pub jwks_url: String,
    #[serde(default = "default_google_jwks_cache_secs")]
    pub jwks_cache_secs: u64,
    /// Google account emails that should receive hard deny (instead of warn) when
    /// a rule check fails. Only checked when the user is authenticated via Google.
    /// Used by waf_checkRuleV2 / waf_checkSignV2 to differentiate deny vs warn
    /// responses.
    #[serde(default)]
    pub accounts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AllowedDomains {
    List(Vec<String>),
    CommaSeparated(String),
}

fn deserialize_allowed_domains<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    match AllowedDomains::deserialize(deserializer)? {
        AllowedDomains::List(domains) => Ok(domains),
        AllowedDomains::CommaSeparated(domains) => Ok(domains
            .split(',')
            .map(str::trim)
            .filter(|domain| !domain.is_empty())
            .map(str::to_owned)
            .collect()),
    }
}

impl Default for GoogleAuthSettings {
    fn default() -> Self {
        Self {
            mode: GoogleAuthMode::Disabled,
            allowed_domains: Vec::new(),
            client_id: String::new(),
            jwks_url: default_google_jwks_url(),
            jwks_cache_secs: default_google_jwks_cache_secs(),
            accounts: Vec::new(),
        }
    }
}

fn default_google_jwks_url() -> String {
    "https://www.googleapis.com/oauth2/v3/certs".into()
}

const fn default_google_jwks_cache_secs() -> u64 {
    3600
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerSettings {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

const fn default_metrics_port() -> u16 {
    8020
}

#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    #[default]
    EmpApi,
    WafAdmin,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct EmpApiSettings {
    #[serde(default)]
    pub api_url: String,
    #[serde(default)]
    pub access_token: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct WafAdminSettings {
    #[serde(default)]
    pub api_url: String,
    /// `X-API-Key` shortcut for `/waf/*` auth. Kept as a dedicated scalar so
    /// the env override stays a valid env-var name (`WAF_ADMIN_API_KEY_ENV`) —
    /// header names carry hyphens, which env vars cannot portably. An explicit
    /// `X-API-Key` entry in `headers` wins over this shortcut.
    #[serde(default)]
    pub api_key: String,
    /// Static headers injected on every request. Do not list multiple
    /// X-API-Key values here (the admin reads the first header only) — rotate
    /// by swapping `api_key` while the admin still accepts the old key.
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProviderSettings {
    #[serde(default)]
    pub r#type: ProviderKind,
    pub chain_ids: Vec<u64>,
    #[serde(default = "default_chain_refresh")]
    pub chain_refresh_secs: u64,
    #[serde(default = "default_contract_cache_ttl")]
    pub contract_cache_ttl: u64,
    /// Hard cap on the number of per-contract rule entries cached in memory.
    /// `0` disables the cap (unlimited). When the cap is reached the least
    /// recently fetched non-static entry is evicted before a new one is cached.
    #[serde(default = "default_contract_cache_max")]
    pub contract_cache_max: usize,
    #[serde(default)]
    pub default_chains: HashMap<u64, String>,
    #[serde(default)]
    pub emp_api: EmpApiSettings,
    #[serde(default)]
    pub waf_admin: WafAdminSettings,
}

impl ProviderSettings {
    /// Returns the active backend's base API URL.
    pub fn api_url(&self) -> &str {
        match self.r#type {
            ProviderKind::EmpApi => &self.emp_api.api_url,
            ProviderKind::WafAdmin => &self.waf_admin.api_url,
        }
    }
}

const fn default_chain_refresh() -> u64 {
    3600
}
const fn default_contract_cache_ttl() -> u64 {
    10
}
const fn default_contract_cache_max() -> usize {
    50_000
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RpcSettings {
    /// chain_id (as string) → RPC URL. Falls back to RPC URL fetched from admin API.
    #[serde(default)]
    pub providers: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SimulateSettings {
    #[serde(default = "default_simulate_url")]
    pub url: String,
    #[serde(default)]
    pub api_keys: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub rpc: RpcSettings,
    #[serde(default = "default_simulate_rpc_batch_size")]
    pub rpc_batch_size: u64,
    /// Per-request timeout in seconds for the decoder (simulate) HTTP request.
    #[serde(default = "default_simulate_timeout_secs")]
    pub timeout_secs: u64,
    /// Pro API key sent as x-pro-key header for premium RPC access.
    #[serde(default)]
    pub pro_api_key: String,
}

impl Default for SimulateSettings {
    fn default() -> Self {
        Self {
            url: default_simulate_url(),
            api_keys: HashMap::new(),
            rpc: RpcSettings::default(),
            rpc_batch_size: default_simulate_rpc_batch_size(),
            timeout_secs: default_simulate_timeout_secs(),
            pro_api_key: String::new(),
        }
    }
}

fn default_simulate_url() -> String {
    concat!("http://localhost:3000", "/api/simulate-tx").into()
}

const fn default_simulate_rpc_batch_size() -> u64 {
    20
}

const fn default_simulate_timeout_secs() -> u64 {
    30
}

#[derive(Debug, Deserialize, Clone)]
pub struct OracleSettings {
    /// Price providers tried in order. Supported: "coingecko", "defillama".
    #[serde(default = "default_oracle_providers")]
    pub providers: Vec<String>,
    pub cache_ttl_secs: u64,
    /// Optional API keys keyed by provider name (e.g. "coingecko" → "CG-xxxx").
    #[serde(default)]
    pub keys: HashMap<String, String>,
}

fn default_oracle_providers() -> Vec<String> {
    vec!["coingecko".to_string(), "defillama".to_string()]
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AllowlistSettings {
    #[serde(default)]
    pub addresses: Vec<String>,
}

/// Settings for the scam-address list used by `TokenOpPolicy::DenyScam`.
/// The list is a repo-committed JSON file (bot-updated daily) baked into the image;
/// the app only reads the local file at startup.
#[derive(Debug, Deserialize, Clone)]
pub struct ScamListSettings {
    /// Path to the JSON file containing a list of `0x…` scam addresses.
    #[serde(default = "default_scam_list_path")]
    pub path: String,
}

fn default_scam_list_path() -> String {
    "config/scam_addresses.json".into()
}

impl Default for ScamListSettings {
    fn default() -> Self {
        Self {
            path: default_scam_list_path(),
        }
    }
}

/// Policy for standard ERC20 transfer(address,uint256) and approve(address,uint256).
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenOpPolicy {
    /// Allow all transfer/approve without rule or whitelist check (default).
    #[default]
    AllowAll,
    /// Deny all transfer/approve unconditionally.
    DenyAll,
    /// Check against a dynamic address whitelist (placeholder — falls through to rule lookup).
    Whitelist,
    /// Require an explicit per-contract WAF rule; no rule = denied.
    RequireRule,
    /// For `approve(address,uint256)`, deny when the spender is on the scam list
    /// (`[scam_list]`). Transfer and clean spenders are allowed.
    DenyScam,
}

const fn default_true() -> bool {
    true
}

fn default_transaction_types() -> Vec<u64> {
    vec![0, 1, 2]
}

#[derive(Debug, Deserialize, Clone)]
pub struct GlobalPolicy {
    /// Allow contract deployment (tx.to is empty). Default: true.
    #[serde(default = "default_true")]
    pub allow_contract_creation: bool,
    /// Allow plain ETH sends with no calldata. Default: true.
    #[serde(default = "default_true")]
    pub allow_native_transfer: bool,
    /// Policy for ERC20 transfer and approve selectors. Default: AllowAll.
    #[serde(default)]
    pub token_op_policy: TokenOpPolicy,
    #[serde(default = "default_transaction_types")]
    pub transaction_types: Vec<u64>,
}

impl Default for GlobalPolicy {
    fn default() -> Self {
        Self {
            allow_contract_creation: true,
            allow_native_transfer: true,
            token_op_policy: TokenOpPolicy::default(),
            transaction_types: default_transaction_types(),
        }
    }
}

impl Settings {
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from("config/default.toml")
    }

    pub fn load_from(path: &str) -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name(path.trim_end_matches(".toml")).required(false))
            .add_source(
                config::Environment::with_prefix("ETH_WAF")
                    .separator("__")
                    .ignore_empty(true),
            )
            .build()?;
        Ok(cfg.try_deserialize()?)
    }

    pub fn rpc_url(&self, chain_id: u64) -> Option<&str> {
        self.rpc
            .providers
            .get(&chain_id.to_string())
            .map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn provider_settings_deserializes_from_toml() {
        let toml = r#"
            chain_ids = [1, 137]
            type = "emp_api"
            chain_refresh_secs = 600
            contract_cache_ttl = 5

            [emp_api]
            api_url = "http://localhost:3000"
            access_token = "secret"

            [waf_admin]
            api_url = "http://localhost:4000"

            [default_chains]
            1 = "https://eth.llamarpc.com"
        "#;
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap();
        let s: ProviderSettings = cfg.try_deserialize().unwrap();
        assert_eq!(s.chain_ids, vec![1, 137]);
        assert_eq!(s.r#type, ProviderKind::EmpApi);
        assert_eq!(s.chain_refresh_secs, 600);
        assert_eq!(s.contract_cache_ttl, 5);
        assert_eq!(s.contract_cache_max, 50_000);
        assert_eq!(s.emp_api.api_url, "http://localhost:3000");
        assert_eq!(s.emp_api.access_token, "secret");
        assert_eq!(s.waf_admin.api_url, "http://localhost:4000");
        assert_eq!(
            s.default_chains.get(&1).unwrap(),
            "https://eth.llamarpc.com"
        );
        assert_eq!(s.api_url(), "http://localhost:3000");
    }

    #[test]
    fn provider_contract_cache_max_overrides_default_when_set() {
        let toml = r#"
            chain_ids = [1]
            contract_cache_max = 1000
        "#;
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap();
        let s: ProviderSettings = cfg.try_deserialize().unwrap();
        assert_eq!(s.contract_cache_max, 1000);
    }

    #[test]
    fn provider_kind_defaults_to_emp_api() {
        let toml = "chain_ids = [1]\n[emp_api]\napi_url = \"http://x\"";
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap();
        let s: ProviderSettings = cfg.try_deserialize().unwrap();
        assert_eq!(s.r#type, ProviderKind::EmpApi);
    }

    #[test]
    fn waf_admin_settings_deserializes_auth_headers() {
        let toml = r#"
            api_url = "http://localhost:4000"
            api_key = "shortcut-secret"

            [headers]
            X-API-Key = "header-secret"
            X-Trace-Id = "trace-1"
        "#;
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap();
        let s: WafAdminSettings = cfg.try_deserialize().unwrap();
        assert_eq!(s.api_url, "http://localhost:4000");
        assert_eq!(s.api_key, "shortcut-secret");
        assert_eq!(
            s.headers.get("X-API-Key").map(String::as_str),
            Some("header-secret")
        );
        assert_eq!(
            s.headers.get("X-Trace-Id").map(String::as_str),
            Some("trace-1")
        );
    }

    #[test]
    fn waf_admin_settings_headers_default_to_empty() {
        let toml = "api_url = \"http://localhost:4000\"";
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap();
        let s: WafAdminSettings = cfg.try_deserialize().unwrap();
        assert!(s.headers.is_empty());
        assert!(s.api_key.is_empty());
    }

    #[test]
    fn waf_admin_api_key_env_overrides_toml_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = std::env::var(WAF_ADMIN_API_KEY_ENV).ok();
        std::env::set_var(WAF_ADMIN_API_KEY_ENV, "env-secret");

        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(
            file.path(),
            r#"
            [server]
            host = "127.0.0.1"
            port = 8010

            [provider]
            chain_ids = [1]
            type = "waf_admin"

            [provider.waf_admin]
            api_url = "http://localhost:4000"
            api_key = "toml-secret"

            [rpc]

            [oracle]
            cache_ttl_secs = 30
            "#,
        )
        .unwrap();

        let settings = Settings::load_from(file.path().to_str().unwrap()).unwrap();

        match old {
            Some(value) => std::env::set_var(WAF_ADMIN_API_KEY_ENV, value),
            None => std::env::remove_var(WAF_ADMIN_API_KEY_ENV),
        }
        assert_eq!(settings.provider.waf_admin.api_key, "env-secret");
    }

    #[test]
    fn waf_admin_api_key_env_is_loaded_only_when_non_empty() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = std::env::var(WAF_ADMIN_API_KEY_ENV).ok();

        std::env::remove_var(WAF_ADMIN_API_KEY_ENV);
        assert!(!waf_admin_api_key_env_loaded());

        std::env::set_var(WAF_ADMIN_API_KEY_ENV, "");
        assert!(!waf_admin_api_key_env_loaded());

        std::env::set_var(WAF_ADMIN_API_KEY_ENV, "env-secret");
        assert!(waf_admin_api_key_env_loaded());

        match old {
            Some(value) => std::env::set_var(WAF_ADMIN_API_KEY_ENV, value),
            None => std::env::remove_var(WAF_ADMIN_API_KEY_ENV),
        }
    }

    #[test]
    fn simulate_settings_deserializes_url_api_key_lists_and_batch_size() {
        let toml = r#"
            url = "http://localhost:3000/api/simulate-tx"
            rpc_batch_size = 50

            [api_keys]
            etherscan = ["etherscan-key-1", "etherscan-key-2"]
            routescan = ["routescan-key"]

            [rpc.providers]
            1 = "https://ethereum-rpc.publicnode.com"
        "#;
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap();
        let settings: SimulateSettings = cfg.try_deserialize().unwrap();

        assert_eq!(settings.url, "http://localhost:3000/api/simulate-tx");
        assert_eq!(settings.rpc_batch_size, 50);
        assert_eq!(settings.timeout_secs, 30);
        assert_eq!(
            settings.api_keys.get("etherscan").unwrap(),
            &vec!["etherscan-key-1".to_string(), "etherscan-key-2".to_string()]
        );
        assert_eq!(
            settings.api_keys.get("routescan").unwrap(),
            &vec!["routescan-key".to_string()]
        );
        assert_eq!(
            settings.rpc.providers.get("1").unwrap(),
            "https://ethereum-rpc.publicnode.com"
        );
    }

    #[test]
    fn simulate_timeout_secs_honors_explicit_value() {
        let toml = r#"
            url = "http://localhost:3000/api/simulate-tx"
            timeout_secs = 60
        "#;
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(toml, config::FileFormat::Toml))
            .build()
            .unwrap();
        let settings: SimulateSettings = cfg.try_deserialize().unwrap();
        assert_eq!(settings.timeout_secs, 60);
    }

    #[test]
    fn google_allowed_domains_accepts_a_comma_separated_string() {
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(
                r#"[google]
                allowed_domains = "foo.com, bar.com"
                "#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap();
        let settings: AuthSettings = cfg.try_deserialize().unwrap();
        assert_eq!(settings.google.allowed_domains, ["foo.com", "bar.com"]);
    }

    #[test]
    fn google_auth_optional_mode_allows_requests_without_an_authorization_header() {
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(
                r#"[google]
                mode = "optional"
                "#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap();
        let settings: AuthSettings = cfg.try_deserialize().unwrap();

        assert_eq!(settings.google.mode, GoogleAuthMode::Optional);
    }

    #[test]
    fn google_auth_mode_defaults_to_disabled() {
        let settings = GoogleAuthSettings::default();

        assert_eq!(settings.mode, GoogleAuthMode::Disabled);
        assert!(settings.client_id.is_empty());
    }

    #[test]
    fn global_policy_defaults_to_legacy_transaction_types() {
        let policy = GlobalPolicy::default();

        assert_eq!(policy.transaction_types, [0, 1, 2]);
    }

    #[test]
    fn global_policy_transaction_types_deserializes() {
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(
                r#"transaction_types = [0, 2]"#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap();
        let policy: GlobalPolicy = cfg.try_deserialize().unwrap();

        assert_eq!(policy.transaction_types, [0, 2]);
    }

    #[test]
    fn token_op_policy_deserializes_deny_scam() {
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(
                r#"token_op_policy = "deny_scam""#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap();
        let policy: GlobalPolicy = cfg.try_deserialize().unwrap();

        assert_eq!(policy.token_op_policy, TokenOpPolicy::DenyScam);
    }

    #[test]
    fn scam_list_settings_defaults_to_local_repo_path() {
        assert_eq!(
            ScamListSettings::default().path,
            "config/scam_addresses.json"
        );
    }

    #[test]
    fn scam_list_settings_deserializes_custom_path() {
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(
                r#"path = "/config/scam_addresses.json""#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap();
        let settings: ScamListSettings = cfg.try_deserialize().unwrap();

        assert_eq!(settings.path, "/config/scam_addresses.json");
    }

    #[test]
    fn google_auth_accounts_deserializes() {
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(
                r#"[google]
                accounts = ["admin@foo.com", "security@foo.com"]
                "#,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap();
        let settings: AuthSettings = cfg.try_deserialize().unwrap();

        assert_eq!(
            settings.google.accounts,
            vec!["admin@foo.com", "security@foo.com"]
        );
    }

    fn write_config(access_token: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(
            file.path(),
            format!(
                r#"
                [server]
                host = "127.0.0.1"
                port = 8010

                [provider]
                chain_ids = [1]

                [provider.emp_api]
                api_url = "http://localhost:3000"
                access_token = "{access_token}"

                [rpc]

                [oracle]
                cache_ttl_secs = 30
            "#
            ),
        )
        .unwrap();
        file
    }

    #[test]
    fn emp_access_token_env_overrides_toml_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = std::env::var(EMP_API_ACCESS_TOKEN_ENV).ok();
        std::env::set_var(EMP_API_ACCESS_TOKEN_ENV, "env-secret");

        let file = write_config("toml-secret");

        let settings = Settings::load_from(file.path().to_str().unwrap()).unwrap();

        match old {
            Some(value) => std::env::set_var(EMP_API_ACCESS_TOKEN_ENV, value),
            None => std::env::remove_var(EMP_API_ACCESS_TOKEN_ENV),
        }
        assert_eq!(settings.provider.emp_api.access_token, "env-secret");
    }

    #[test]
    fn empty_emp_access_token_env_does_not_override_toml_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = std::env::var(EMP_API_ACCESS_TOKEN_ENV).ok();
        std::env::set_var(EMP_API_ACCESS_TOKEN_ENV, "");

        let file = write_config("toml-secret");

        let settings = Settings::load_from(file.path().to_str().unwrap()).unwrap();

        match old {
            Some(value) => std::env::set_var(EMP_API_ACCESS_TOKEN_ENV, value),
            None => std::env::remove_var(EMP_API_ACCESS_TOKEN_ENV),
        }
        assert_eq!(settings.provider.emp_api.access_token, "toml-secret");
    }

    #[test]
    fn empty_emp_access_token_is_allowed_for_emp_api_provider() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = std::env::var(EMP_API_ACCESS_TOKEN_ENV).ok();
        std::env::remove_var(EMP_API_ACCESS_TOKEN_ENV);

        let file = write_config("");
        let settings = Settings::load_from(file.path().to_str().unwrap()).unwrap();

        match old {
            Some(value) => std::env::set_var(EMP_API_ACCESS_TOKEN_ENV, value),
            None => std::env::remove_var(EMP_API_ACCESS_TOKEN_ENV),
        }
        assert_eq!(settings.provider.r#type, ProviderKind::EmpApi);
        assert!(settings.provider.emp_api.access_token.is_empty());
    }

    #[test]
    fn emp_access_token_env_is_loaded_only_when_non_empty() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = std::env::var(EMP_API_ACCESS_TOKEN_ENV).ok();

        std::env::remove_var(EMP_API_ACCESS_TOKEN_ENV);
        assert!(!emp_api_access_token_env_loaded());

        std::env::set_var(EMP_API_ACCESS_TOKEN_ENV, "");
        assert!(!emp_api_access_token_env_loaded());

        std::env::set_var(EMP_API_ACCESS_TOKEN_ENV, "env-secret");
        assert!(emp_api_access_token_env_loaded());

        match old {
            Some(value) => std::env::set_var(EMP_API_ACCESS_TOKEN_ENV, value),
            None => std::env::remove_var(EMP_API_ACCESS_TOKEN_ENV),
        }
    }
}
