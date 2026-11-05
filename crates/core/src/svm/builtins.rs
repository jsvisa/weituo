//! `SvmBuiltins` — the `$`-builtin provider for SVM rules (design §7).
//!
//! Same JSON-RPC 2.0 transport as the EVM [`crate::builtins::Builtins`], but
//! Solana methods: `$balance_of` → `getBalance` (lamports), `$is_contract` /
//! `$is_eoa` → `getAccountInfo`, `$spl_balance_of` / `$spl_allowance` →
//! `getTokenAccountsByOwner` (jsonParsed). EVM-only builtins (`$erc20_*`,
//! `$block`, `$gas_price`, `$b32int2addr`) are not part of this provider —
//! expressions using them error (and are rejected at rule load).

use alloy_primitives::U256;
use anyhow::{anyhow, Result};
use weituo_expr::context::BuiltinProvider;
use weituo_expr::eval::Value;
use weituo_expr::EvalContext;

/// The SVM `$`-builtin provider, bound to one cluster's RPC endpoint.
pub struct SvmBuiltins {
    http: reqwest::Client,
    /// RPC endpoint for the bound cluster. `None` = unknown — RPC-backed
    /// builtins error when a rule uses them.
    rpc_url: Option<String>,
}

impl SvmBuiltins {
    pub const fn new(http: reqwest::Client, rpc_url: Option<String>) -> Self {
        Self { http, rpc_url }
    }

    async fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let url = self
            .rpc_url
            .as_deref()
            .ok_or_else(|| anyhow!("no RPC configured for the svm network"))?;
        let body =
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        Ok(self.http.post(url).json(&body).send().await?.json().await?)
    }

    /// `getBalance` → lamports as BigUint.
    async fn sol_balance(&self, args: &[Value]) -> Result<Value> {
        let owner = str_arg(args, 0, "balance_of")?;
        let resp = self
            .rpc_call("getBalance", serde_json::json!([owner]))
            .await?;
        let lamports = resp["value"]
            .as_u64()
            .ok_or_else(|| anyhow!("getBalance returned no value: {:?}", resp["error"]))?;
        Ok(Value::BigUint(U256::from(lamports)))
    }

    /// `getAccountInfo` → (exists, executable).
    async fn account_info(&self, addr: &str) -> Result<(bool, bool)> {
        let resp = self
            .rpc_call(
                "getAccountInfo",
                serde_json::json!([addr, { "encoding": "base64" }]),
            )
            .await?;
        match resp["value"].as_object() {
            Some(acc) => Ok((
                true,
                acc.get("executable")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            )),
            None => Ok((false, false)),
        }
    }

    /// All parsed token accounts of `owner` for `mint` (jsonParsed).
    async fn token_accounts(&self, mint: &str, owner: &str) -> Result<serde_json::Value> {
        self.rpc_call(
            "getTokenAccountsByOwner",
            serde_json::json!([owner, { "mint": mint, "encoding": "jsonParsed" }]),
        )
        .await
        .map(|resp| resp["value"].clone())
    }

    /// `$spl_balance_of(mint, owner)` — raw token amounts summed across all
    /// the owner's accounts for that mint.
    async fn spl_balance(&self, args: &[Value]) -> Result<Value> {
        let mint = str_arg(args, 0, "spl_balance_of")?;
        let owner = str_arg(args, 1, "spl_balance_of")?;
        let accounts = self.token_accounts(&mint, &owner).await?;
        let mut total = U256::ZERO;
        if let Some(list) = accounts.as_array() {
            for acc in list {
                if let Some(amount) = acc["account"]["data"]["parsed"]["info"]["tokenAmount"]
                    ["amount"]
                    .as_str()
                    .and_then(|s| s.parse::<U256>().ok())
                {
                    total += amount;
                }
            }
        }
        Ok(Value::BigUint(total))
    }

    /// `$spl_allowance(mint, owner, delegate)` — an owner may hold several
    /// accounts per mint; v1 scans them all and takes the max delegated
    /// amount matching the delegate.
    async fn spl_allowance(&self, args: &[Value]) -> Result<Value> {
        let mint = str_arg(args, 0, "spl_allowance")?;
        let owner = str_arg(args, 1, "spl_allowance")?;
        let delegate = str_arg(args, 2, "spl_allowance")?;
        let accounts = self.token_accounts(&mint, &owner).await?;
        let mut max = U256::ZERO;
        if let Some(list) = accounts.as_array() {
            for acc in list {
                let info = &acc["account"]["data"]["parsed"]["info"];
                if info["delegate"].as_str() != Some(delegate.as_str()) {
                    continue;
                }
                if let Some(amount) = info["delegatedAmount"]["amount"]
                    .as_str()
                    .and_then(|s| s.parse::<U256>().ok())
                {
                    if amount > max {
                        max = amount;
                    }
                }
            }
        }
        Ok(Value::BigUint(max))
    }
}

fn str_arg(args: &[Value], idx: usize, name: &str) -> Result<String> {
    match args.get(idx) {
        Some(Value::Str(s)) => Ok(s.clone()),
        _ => Err(anyhow!("${name}: arg {idx} must be string")),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[async_trait::async_trait]
impl BuiltinProvider for SvmBuiltins {
    async fn call(&self, name: &str, args: &[Value], _ctx: &EvalContext) -> Result<Value> {
        match name {
            "now_ts" => Ok(Value::Int(now_secs() as i64)),
            "pow" => {
                let base = args
                    .first()
                    .and_then(|v| v.as_f64())
                    .ok_or_else(|| anyhow!("$pow: missing base"))?;
                let exp = args
                    .get(1)
                    .and_then(|v| v.as_f64())
                    .ok_or_else(|| anyhow!("$pow: missing exp"))?;
                Ok(Value::Float(base.powf(exp)))
            }
            "balance_of" => self.sol_balance(args).await,
            "is_contract" => {
                let addr = str_arg(args, 0, "is_contract")?;
                let (exists, executable) = self.account_info(&addr).await?;
                Ok(Value::Bool(exists && executable))
            }
            "is_eoa" => {
                let addr = str_arg(args, 0, "is_eoa")?;
                let (exists, executable) = self.account_info(&addr).await?;
                Ok(Value::Bool(!(exists && executable)))
            }
            "spl_balance_of" => self.spl_balance(args).await,
            "spl_allowance" => self.spl_allowance(args).await,
            // Embedding-provided sentinels (same defaults as the EVM core)
            "is_approved_token" => Ok(Value::Bool(false)),
            "is_approved_spender" => Ok(Value::Bool(false)),
            "is_not_blocked_spender" => Ok(Value::Bool(true)),
            "price_of" | "is_scam" => Err(anyhow!(
                "${name} is embedding-provided and not available in core"
            )),
            _ => Err(anyhow!("unknown builtin: ${name}")),
        }
    }
}
