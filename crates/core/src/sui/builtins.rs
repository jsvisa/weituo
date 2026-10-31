//! `SuiBuiltins` — the `$`-builtin provider for Sui rules (design §7).
//!
//! Same JSON-RPC 2.0 transport as the other families, Sui methods:
//! `$balance_of` → `sui_getBalance` (SUI, mist), `$coin_balance` →
//! `sui_getBalance` with an explicit coin type, `$is_contract` / `$is_eoa`
//! → `sui_getObject` (a move package vs anything else). EVM-only builtins
//! (`$erc20_*`, `$block`, `$gas_price`, `$spl_*`, `$b32int2addr`) are not
//! part of this provider — expressions using them error (and are rejected
//! at rule load).

use alloy_primitives::U256;
use anyhow::{anyhow, Result};
use weituo_expr::context::BuiltinProvider;
use weituo_expr::eval::Value;
use weituo_expr::EvalContext;

use super::SUI_COIN_TYPE;

/// The Sui `$`-builtin provider, bound to one network's full-node endpoint.
pub struct SuiBuiltins {
    http: reqwest::Client,
    /// RPC endpoint for the bound network. `None` = unknown — RPC-backed
    /// builtins error when a rule uses them.
    rpc_url: Option<String>,
}

impl SuiBuiltins {
    pub const fn new(http: reqwest::Client, rpc_url: Option<String>) -> Self {
        Self { http, rpc_url }
    }

    async fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let url = self
            .rpc_url
            .as_deref()
            .ok_or_else(|| anyhow!("no RPC configured for the sui network"))?;
        let body =
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        Ok(self.http.post(url).json(&body).send().await?.json().await?)
    }

    /// `sui_getBalance(owner, {coinType})` → totalBalance (mist) as BigUint.
    async fn sui_balance(&self, owner: &str, coin_type: &str) -> Result<Value> {
        let resp = self
            .rpc_call(
                "sui_getBalance",
                serde_json::json!([owner, { "coinType": coin_type }]),
            )
            .await?;
        let total = resp["result"]["totalBalance"].as_str().ok_or_else(|| {
            anyhow!(
                "sui_getBalance returned no totalBalance: {:?}",
                resp["error"]
            )
        })?;
        let amount = total
            .parse::<U256>()
            .map_err(|_| anyhow!("sui_getBalance totalBalance '{total}' out of range"))?;
        Ok(Value::BigUint(amount))
    }

    /// `sui_getObject` → (exists, is_move_package).
    async fn object_info(&self, addr: &str) -> Result<(bool, bool)> {
        let resp = self
            .rpc_call(
                "sui_getObject",
                serde_json::json!([addr, { "options": { "showType": true } }]),
            )
            .await?;
        let data = &resp["result"]["data"];
        if !data.is_object() {
            return Ok((false, false));
        }
        let is_package = data["type"].as_str() == Some("package");
        Ok((true, is_package))
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
impl BuiltinProvider for SuiBuiltins {
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
            "balance_of" => {
                let owner = str_arg(args, 0, "balance_of")?;
                self.sui_balance(&owner, SUI_COIN_TYPE).await
            }
            "coin_balance" => {
                let owner = str_arg(args, 0, "coin_balance")?;
                let coin_type = str_arg(args, 1, "coin_balance")?;
                self.sui_balance(&owner, &coin_type).await
            }
            "is_contract" => {
                let addr = str_arg(args, 0, "is_contract")?;
                let (exists, is_package) = self.object_info(&addr).await?;
                Ok(Value::Bool(exists && is_package))
            }
            "is_eoa" => {
                let addr = str_arg(args, 0, "is_eoa")?;
                let (exists, is_package) = self.object_info(&addr).await?;
                Ok(Value::Bool(!(exists && is_package)))
            }
            // Embedding-provided sentinels (same defaults as the other cores)
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
