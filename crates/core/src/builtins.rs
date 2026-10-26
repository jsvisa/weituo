use anyhow::{anyhow, Result};
use weituo_expr::context::BuiltinProvider;

use crate::types::parse_u64_string;
use alloy_primitives::U256;
use serde_json::{json, Map, Value as Json};
use weituo_expr::eval::Value;
use weituo_expr::EvalContext;

/// Core engine builtins: generic chain-data helpers (`$block`, `$balance_of`,
/// `$erc20_*`, `$gas_price`, `$now_ts`, `$pow`, …).
///
/// External-data builtins (`$price_of`, `$is_scam`) are *not* part of core —
/// embeddings provide them via a composite
/// [`BuiltinProvider`](weituo_expr::context::BuiltinProvider) passed to
/// [`crate::checker::Checker::new_with_builtins`].
/// The engine's `$`-builtin provider: chain data read over JSON-RPC
/// (`$block`, `$gas_price`, `$balance_of`, `$erc20_*`, `$is_contract`,
/// `$is_eoa`) plus pure helpers (`$now_ts`, `$pow`, `$b32int2addr`,
/// `$is_approved_token`, …).
///
/// An instance is bound to one chain's RPC endpoint and holds no mutable
/// state — construct one per check (or reuse it freely; it is `Clone`-cheap:
/// only a [`reqwest::Client`] handle and an `Option<String>`).
///
/// There are deliberately no price-feed or scam builtins here: embeddings
/// provide them via a composite
/// [`BuiltinProvider`](weituo_expr::context::BuiltinProvider) passed to
/// [`crate::checker::Checker::with_builtins_factory`].
pub struct Builtins {
    http: reqwest::Client,
    /// RPC endpoint for the bound chain. `None` = unknown — RPC-backed
    /// builtins error when a rule uses them.
    rpc_url: Option<String>,
}

impl Builtins {
    pub const fn new(http: reqwest::Client, rpc_url: Option<String>) -> Self {
        Self { http, rpc_url }
    }

    pub async fn call(&self, name: &str, args: &[Value], ctx: &EvalContext) -> Result<Value> {
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
            "is_eoa" => self.is_eoa(args, ctx).await,
            "is_contract" => self.is_contract(args, ctx).await,
            "block" => self.block(args, ctx).await,
            "gas_price" => self.gas_price(ctx).await,
            "balance_of" => self.eth_balance(args, ctx).await,
            "erc20_balance_of" => self.erc20_call("balanceOf", args, ctx).await,
            "erc20_allowance" => self.erc20_call("allowance", args, ctx).await,
            "erc20_total_supply" => self.erc20_call("totalSupply", args, ctx).await,
            "erc20_decimals" => self.erc20_call("decimals", args, ctx).await,
            "is_approved_token" => Ok(Value::Bool(false)),
            "is_approved_spender" => Ok(Value::Bool(false)),
            "is_not_blocked_spender" => Ok(Value::Bool(true)),
            "b32int2addr" => {
                // Accept address encoded as: uint256 decimal → BigUint, hex string, or i64
                let hex = match args.first() {
                    Some(Value::BigUint(u)) => format!("{u:x}"),
                    Some(Value::Str(s)) if s.starts_with("0x") || s.starts_with("0X") => {
                        s[2..].to_string()
                    }
                    Some(Value::Str(s)) => {
                        // Decimal string — parse as U256 and convert to hex
                        if let Ok(u) = s.parse::<U256>() {
                            format!("{u:x}")
                        } else {
                            s.clone()
                        }
                    }
                    Some(Value::Int(i)) => format!("{i:x}"),
                    _ => return Err(anyhow!("$b32int2addr: expected uint256 or address string")),
                };
                let padded = format!("{:0>40}", hex);
                let addr_hex = &padded[padded.len().saturating_sub(40)..];
                Ok(Value::Str(format!("0x{addr_hex}")))
            }
            _ => Err(anyhow!("unknown builtin: ${name}")),
        }
    }

    /// The RPC endpoint this instance was constructed with. The caller
    /// resolves it (per chain) when building the checker's builtin provider.
    fn rpc_url(&self, _ctx: &EvalContext) -> Option<String> {
        self.rpc_url.clone()
    }

    /// POST a JSON-RPC `method` with `params` to the chain's RPC URL and return the
    /// parsed JSON response. Errors when no RPC URL is configured for the chain.
    async fn rpc_call(&self, ctx: &EvalContext, method: &str, params: Json) -> Result<Json> {
        let url = self
            .rpc_url(ctx)
            .ok_or_else(|| anyhow!("no RPC for chain {}", ctx.chain_id))?;
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        Ok(self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?)
    }

    async fn eth_call_raw(&self, ctx: &EvalContext, to: &str, data: &str) -> Result<String> {
        let resp = self
            .rpc_call(ctx, "eth_call", json!([{"to": to, "data": data}, "latest"]))
            .await?;
        resp["result"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("eth_call failed: {:?}", resp["error"]))
    }

    async fn is_contract(&self, args: &[Value], ctx: &EvalContext) -> Result<Value> {
        let addr = str_arg(args, 0, "is_contract")?;
        let resp = self
            .rpc_call(ctx, "eth_getCode", json!([addr, "latest"]))
            .await?;
        let code = resp["result"].as_str().unwrap_or("0x");
        Ok(Value::Bool(code.len() > 2))
    }

    async fn is_eoa(&self, args: &[Value], ctx: &EvalContext) -> Result<Value> {
        let v = self.is_contract(args, ctx).await?;
        Ok(Value::Bool(!v.as_bool()))
    }

    async fn block(&self, args: &[Value], ctx: &EvalContext) -> Result<Value> {
        let block_id = match args.first() {
            Some(Value::Str(s)) => s.clone(),
            _ => "latest".into(),
        };
        let resp = self
            .rpc_call(ctx, "eth_getBlockByNumber", json!([block_id, false]))
            .await?;
        Ok(Value::from(normalize_block_fields(resp["result"].clone())))
    }

    async fn gas_price(&self, ctx: &EvalContext) -> Result<Value> {
        let resp = self.rpc_call(ctx, "eth_gasPrice", json!([])).await?;
        let hex = resp["result"].as_str().unwrap_or("0x0");
        let v = parse_u64_string(hex).unwrap_or(0);
        Ok(Value::Int(v as i64))
    }

    async fn eth_balance(&self, args: &[Value], ctx: &EvalContext) -> Result<Value> {
        let addr = str_arg(args, 0, "balance_of")?;
        let resp = self
            .rpc_call(ctx, "eth_getBalance", json!([addr, "latest"]))
            .await?;
        let hex = resp["result"].as_str().unwrap_or("0x0");
        let v = U256::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or_default();
        Ok(Value::BigUint(v))
    }

    async fn erc20_call(&self, method: &str, args: &[Value], ctx: &EvalContext) -> Result<Value> {
        let (token, data) = match method {
            "decimals" => (str_arg(args, 0, method)?, "0x313ce567".to_string()),
            "totalSupply" => (str_arg(args, 0, method)?, "0x18160ddd".to_string()),
            "balanceOf" => {
                let token = str_arg(args, 0, method)?;
                let owner = format!(
                    "{:0>64}",
                    str_arg(args, 1, method)?
                        .trim_start_matches("0x")
                        .to_lowercase()
                );
                (token, format!("0x70a08231{owner}"))
            }
            "allowance" => {
                let token = str_arg(args, 0, method)?;
                let owner = format!(
                    "{:0>64}",
                    str_arg(args, 1, method)?
                        .trim_start_matches("0x")
                        .to_lowercase()
                );
                let spender = format!(
                    "{:0>64}",
                    str_arg(args, 2, method)?
                        .trim_start_matches("0x")
                        .to_lowercase()
                );
                (token, format!("0xdd62ed3e{owner}{spender}"))
            }
            _ => return Err(anyhow!("unknown erc20 method: {method}")),
        };
        let result = self.eth_call_raw(ctx, &token, &data).await?;
        let hex = result.trim_start_matches("0x");
        let v = U256::from_str_radix(
            if hex.len() > 64 {
                &hex[hex.len() - 64..]
            } else {
                hex
            },
            16,
        )
        .unwrap_or_default();
        if method == "decimals" {
            Ok(Value::Int(v.to_string().parse().unwrap_or(0)))
        } else {
            Ok(Value::BigUint(v))
        }
    }
}

fn str_arg(args: &[Value], idx: usize, name: &str) -> Result<String> {
    match args.get(idx) {
        Some(Value::Str(s)) => Ok(s.clone()),
        _ => Err(anyhow!("${name}: arg {idx} must be string")),
    }
}

/// Keep only the decimal `BLOCK_FIELDS` and convert their hex Quantity values to
/// JSON numbers, so arithmetic like `$block().timestamp + 86400` evaluates exactly.
fn normalize_block_fields(block: Json) -> Json {
    let Json::Object(map) = block else {
        return block;
    };
    let mut out = Map::new();
    for name in weituo_expr::analyze::BLOCK_FIELDS {
        let Some(value) = map.get(*name) else {
            continue;
        };
        if let Some(num) = hex_to_number(value) {
            out.insert(name.to_string(), num);
        }
    }
    Json::Object(out)
}

/// Convert a hex Quantity string (`"0x..."`) to a JSON number. Keeps numbers as-is
/// (mocks return plain numbers); returns None for unparseable values.
fn hex_to_number(value: &Json) -> Option<Json> {
    match value {
        Json::Number(n) => Some(Json::Number(n.clone())),
        Json::String(s) => parse_u64_string(s).ok().map(Json::from),
        _ => None,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[async_trait::async_trait]
impl BuiltinProvider for Builtins {
    async fn call(&self, name: &str, args: &[Value], ctx: &EvalContext) -> Result<Value> {
        self.call(name, args, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_block_fields, Builtins};
    use serde_json::{json, Value as Json};
    use weituo_expr::{eval::Value, EvalContext};

    fn builtins(rpc_url: Option<&str>) -> Builtins {
        Builtins::new(reqwest::Client::new(), rpc_url.map(str::to_string))
    }

    fn eval_context() -> EvalContext {
        EvalContext::new(1, "0x0", "0x0")
    }

    #[tokio::test]
    async fn price_of_is_no_longer_a_core_builtin() {
        // Price/scam data moved to the embedding layer; core must no longer
        // answer `$price_of` / `$is_scam`.
        for name in ["price_of", "is_scam", "is_scam_addr"] {
            let error = builtins(None)
                .call(name, &[Value::Str("0x0".into())], &eval_context())
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), format!("unknown builtin: ${name}"));
        }
    }

    #[tokio::test]
    async fn rpc_builtins_error_without_an_rpc_url() {
        let error = builtins(None)
            .call("is_contract", &[Value::Str("0x0".into())], &eval_context())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "no RPC for chain 1");
    }

    #[test]
    fn normalizes_hex_block_fields() {
        let block = json!({
            "number": "0x112a880",
            "timestamp": "0x6553f100",
            "gasUsed": "0x12d687",
            "gasLimit": "0x1c9c380",
            "baseFeePerGas": "0x4c4b40",
            "size": "0x9a1",
            "miner": "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5",
            "hash": "0x85f8c5b3a1d4e9f2b6c0a3e5d7f8b2a4c6d9e1f3a5b7c0d2e4f6a8b9c1d3e5f7",
            "parentHash": "0x85f8c5b3a1d4e9f2b6c0a3e5d7f8b2a4c6d9e1f3a5b7c0d2e4f6a8b9c1d3e5f7",
            "transactions": ["0xcc"],
            "excessBlobGas": "0x483ff4",
            "logsBloom": "0x00",
        });

        let block = normalize_block_fields(block);

        assert_eq!(block["number"], 18_000_000);
        assert_eq!(block["timestamp"], 1_700_000_000);
        assert_eq!(block["gasUsed"], 1_234_567);
        assert_eq!(block["gasLimit"], 30_000_000);
        assert_eq!(block["baseFeePerGas"], 5_000_000);
        assert!(block.get("size").is_none());
        assert!(block.get("miner").is_none());
        assert!(block.get("hash").is_none());
        assert!(block.get("parentHash").is_none());
        assert!(block.get("transactions").is_none());
        assert!(block.get("excessBlobGas").is_none());
        assert!(block.get("logsBloom").is_none());
        assert_eq!(block.as_object().unwrap().len(), 5);
    }

    #[test]
    fn keeps_plain_numbers_and_drops_non_integers() {
        let block = json!({
            "number": 18_000_000,
            "gasLimit": 30_000_000,
            "hash": "0x85f8c5b3a1d4e9f2b6c0a3e5d7f8b2a4c6d9e1f3a5b7c0d2e4f6a8b9c1d3e5f7",
            "transactions": ["0xcc"],
            "excessBlobGas": "0x483ff4",
        });

        let block = normalize_block_fields(block);

        assert_eq!(block["number"], 18_000_000);
        assert_eq!(block["gasLimit"], 30_000_000);
        assert!(block.get("hash").is_none());
        assert!(block.get("transactions").is_none());
        assert!(block.get("excessBlobGas").is_none());
        assert_eq!(block.as_object().unwrap().len(), 2);
    }

    #[test]
    fn null_result_stays_null() {
        let block = normalize_block_fields(Json::Null);
        assert!(block.is_null());
    }
}
