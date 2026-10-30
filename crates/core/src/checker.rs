/// WAF rule checker — a stateless decision engine.
///
/// Rules, the scam list and every cache live in the embedding layer: the
/// checker receives a [`RuleResolver`] per call and holds only immutable
/// parameters ([`Policy`], allowlist, HTTP client for the `$`-builtins).
use std::{collections::HashMap, sync::Arc};

use crate::builtins::Builtins;
use crate::chain::{ChainRef, ChainResolver, ChainTx, CompatResolver};
use crate::decoder::{build_decoder, decode_args_only, decode_calldata};
use crate::policy::{Policy, TokenOpPolicy};
use crate::provider::RuleResolver;
use crate::types::{
    normalize_domain_name, JsonRpcError, MulticallDecoder, RuleEntry, Transaction, TypedDataRequest,
};
use weituo_expr as expr;
use weituo_expr::EvalContext;

/// ERC20 transfer(address,uint256)
const TRANSFER_SELECTOR: &str = "0xa9059cbb";
/// ERC20 approve(address,uint256)
const APPROVE_SELECTOR: &str = "0x095ea7b3";

/// Typed reason for a transaction denial.
#[derive(Debug, thiserror::Error)]
pub enum DenyReason {
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("no rule configured for selector {selector} on {address}")]
    NoRule { address: String, selector: String },

    #[error("no rules configured for contract {address} on chain {chain_id}")]
    NoContract { address: String, chain_id: u64 },

    #[error("transaction denied by rule: {expr}")]
    ExpressionDenied {
        expr: String,
        /// The specific `and`-joined condition that failed, when the evaluator
        /// could narrow it down. Returned via the JSON-RPC `data` member.
        explain: Option<expr::Explain>,
    },

    #[error("expression evaluation error: {0}")]
    EvalError(String),

    #[error("calldata decode error: {0}")]
    DecodeError(String),

    #[error("test mode: expression not provided")]
    NoExprInTest,

    #[error("no EIP-712 rule configured for {domain}::{primary_type} on {address}")]
    NoSignRule {
        domain: String,
        primary_type: String,
        address: String,
    },

    #[error("contract creation not permitted by global policy")]
    ContractCreationDenied,

    #[error("token operation denied by global policy: {selector}")]
    TokenOpDenied { selector: String },

    #[error("rule has decoder_config but decoder_type is unrecognised — inner calls cannot be inspected")]
    InvalidDecoder,

    #[error("multiple inner calls denied")]
    Multiple(Vec<DenyReason>),
}

impl DenyReason {
    pub const fn code(&self) -> i32 {
        match self {
            DenyReason::InvalidRequest(_) => -32600,
            DenyReason::NoRule { .. } => -32601,
            DenyReason::NoContract { .. } => -32606,
            DenyReason::ExpressionDenied { .. } => -32603,
            DenyReason::EvalError(_) => -32500,
            DenyReason::DecodeError(_) => -32501,
            DenyReason::NoExprInTest => -32700,
            DenyReason::NoSignRule { .. } => -32601,
            DenyReason::ContractCreationDenied => -32602,
            DenyReason::TokenOpDenied { .. } => -32604,
            DenyReason::InvalidDecoder => -32605,
            DenyReason::Multiple(_) => -32603,
        }
    }

    /// The specific rule condition that failed, when the evaluator could narrow
    /// it down (e.g. one branch of an `and`-joined expression). `None` otherwise.
    pub fn cond(&self) -> Option<&str> {
        match self {
            DenyReason::ExpressionDenied {
                explain: Some(e), ..
            } => Some(&e.source),
            _ => None,
        }
    }

    /// The failing condition with its operands substituted for their runtime
    /// values (e.g. `"1024 > 1024"`), when the evaluator could compute them.
    pub fn data(&self) -> Option<&str> {
        match self {
            DenyReason::ExpressionDenied {
                explain: Some(e), ..
            } => e.values.as_deref(),
            _ => None,
        }
    }

    /// Construct a JSON array of inner errors for the `Multiple` variant, each
    /// entry containing `message`, `cond`, and optionally `data`. Returns `None`
    /// for non-`Multiple` variants.
    pub fn inner_errors_json(&self) -> Option<Vec<serde_json::Value>> {
        match self {
            DenyReason::Multiple(reasons) => {
                let arr: Vec<serde_json::Value> = reasons
                    .iter()
                    .map(|r| {
                        let mut obj = serde_json::Map::new();
                        obj.insert("cond".to_string(), serde_json::json!(r.cond()));
                        obj.insert("message".to_string(), serde_json::json!(r.to_string()));
                        if let Some(d) = r.data() {
                            obj.insert("data".to_string(), serde_json::json!(d));
                        }
                        serde_json::Value::Object(obj)
                    })
                    .collect();
                Some(arr)
            }
            _ => None,
        }
    }

    pub fn to_rpc_error(&self) -> JsonRpcError {
        let data = match self {
            DenyReason::Multiple(_) => self
                .inner_errors_json()
                .map(|arr| serde_json::json!({ "inner_errors": arr })),
            _ => self.cond().map(|c| {
                let mut obj = serde_json::Map::new();
                obj.insert("cond".to_string(), serde_json::json!(c));
                if let Some(d) = self.data() {
                    obj.insert("data".to_string(), serde_json::json!(d));
                }
                serde_json::Value::Object(obj)
            }),
        };
        JsonRpcError {
            code: self.code(),
            message: self.to_string(),
            data,
        }
    }
}

/// Factory producing the `$`-builtin provider for one check. Receives the
/// RPC URL resolved for the transaction's chain (`None` = unknown).
pub type BuiltinsFactory =
    Arc<dyn Fn(Option<String>) -> Arc<dyn weituo_expr::context::BuiltinProvider> + Send + Sync>;

/// EvalContext construction for the EVM pipeline: family network string
/// threaded through so rules can reference `network` (and, on non-EVM
/// families later, `chain_fields`).
fn evm_eval_ctx(
    tx: &Transaction,
    args: HashMap<String, serde_json::Value>,
    to_address: &str,
    vars: HashMap<String, serde_json::Value>,
) -> EvalContext {
    EvalContext {
        chain_id: tx.chain_id,
        value: tx.value,
        args,
        from_address: tx.from.to_lowercase(),
        to_address: to_address.to_lowercase(),
        gas_price: tx.gas_price,
        gas_limit: tx.gas_limit,
        vars,
        network: format!("eip155:{}", tx.chain_id),
        chain_fields: HashMap::new(),
    }
}

/// The decision engine. Holds only immutable parameters — construct it once
/// and call [`Checker::check`] with a [`RuleResolver`] per transaction.
fn lookup_rules(rules: &HashMap<String, RuleEntry>, selector: &str) -> RuleLookup {
    if let Some(e) = rules.get(selector) {
        return RuleLookup::Found(e.clone());
    }
    if let Some(e) = rules.get("*") {
        return RuleLookup::Found(e.clone());
    }
    if rules.is_empty() {
        RuleLookup::NoContract
    } else {
        RuleLookup::NoSelector
    }
}

pub struct Checker {
    http: reqwest::Client,
    /// Override for the default `$`-builtins; lets embeddings layer extra
    /// data sources (price feeds, …) on top of [`Builtins`].
    builtins_factory: Option<BuiltinsFactory>,
    /// Sender addresses that bypass all checks (lowercased).
    allowlist: Vec<String>,
    policy: Policy,
}

/// Result of a rule lookup in a contract's rule map.
enum RuleLookup {
    Found(RuleEntry),
    NoSelector,
    NoContract,
}

/// Per-check context threaded through the pipeline: where rules come from
/// and which `$`-builtin provider answers this check's expressions.
struct CheckCtx<'a> {
    resolver: &'a dyn ChainResolver,
    builtins: &'a Arc<dyn weituo_expr::context::BuiltinProvider>,
}

/// One inner call extracted from a multicall payload.
struct InnerCall<'a> {
    idx: usize,
    target: &'a str,
    selector: &'a str,
    calldata: &'a str,
    /// true = `calldata` starts with a 4-byte selector (decode_calldata);
    /// false = bare ABI params (decode_args_only).
    has_selector: bool,
}

pub enum CheckResult {
    Ok,
    Denied(DenyReason),
}

impl Checker {
    pub fn new(http: reqwest::Client, allowlist: Vec<String>, policy: Policy) -> Self {
        Self {
            http,
            builtins_factory: None,
            allowlist: allowlist.into_iter().map(|s| s.to_lowercase()).collect(),
            policy,
        }
    }

    /// Use a composite builtin provider (e.g. core [`Builtins`] wrapped with
    /// price feeds or other embedding-owned data sources) instead of the
    /// default one.
    pub fn with_builtins_factory(mut self, factory: BuiltinsFactory) -> Self {
        self.builtins_factory = Some(factory);
        self
    }

    /// Build the `$`-builtin provider for one check call.
    fn builtins_for(
        &self,
        resolver: &dyn ChainResolver,
        chain: ChainRef,
    ) -> Arc<dyn weituo_expr::context::BuiltinProvider> {
        self.builtins_for_opt(Some(resolver), chain)
    }

    fn builtins_for_opt(
        &self,
        resolver: Option<&dyn ChainResolver>,
        chain: ChainRef,
    ) -> Arc<dyn weituo_expr::context::BuiltinProvider> {
        let rpc_url = resolver.and_then(|r| r.chain_rpc_url(chain));
        match &self.builtins_factory {
            Some(factory) => factory(rpc_url),
            None => Arc::new(Builtins::new(self.http.clone(), rpc_url)),
        }
    }

    /// Unchanged EVM entry point — delegates to [`Checker::check_tx`] with
    /// the caller's resolver wrapped in [`CompatResolver`] (embedders never
    /// see the adapter).
    pub async fn check(&self, tx: &Transaction, resolver: &dyn RuleResolver) -> CheckResult {
        self.check_tx(&ChainTx::Evm(tx.clone()), &CompatResolver(resolver))
            .await
    }

    /// Unified entry point: policy gates → per-call rule lookup → eval.
    pub async fn check_tx(&self, tx: &ChainTx, resolver: &dyn ChainResolver) -> CheckResult {
        let ChainTx::Evm(tx) = tx;
        self.check_evm(tx, ChainRef::Evm(tx.chain_id), resolver)
            .await
    }

    async fn check_evm(
        &self,
        tx: &Transaction,
        chain: ChainRef,
        resolver: &dyn ChainResolver,
    ) -> CheckResult {
        let builtins = self.builtins_for(resolver, chain);
        let ctx = CheckCtx {
            resolver,
            builtins: &builtins,
        };
        if let Some(r) = self.step_transaction_type(tx) {
            return r;
        }
        if let Some(r) = self.step_allowlist(tx) {
            return r;
        }
        if let Some(r) = self.step_contract_creation(tx) {
            return r;
        }
        let selector = Self::derive_selector(tx);
        if let Some(r) = self.step_native_transfer(&selector, tx) {
            return r;
        }
        let entry = match self.step_rule_lookup(tx, &selector, resolver).await {
            Ok(e) => e,
            Err(reason) => {
                return self
                    .step_token_op(&selector)
                    .unwrap_or(CheckResult::Denied(reason))
            }
        };
        let args = Self::decode_args(&entry, tx);
        if let Some(r) = self.step_eval_clauses(&entry, &args, tx, &ctx).await {
            return r;
        }
        if let Some(r) = self.step_multicall(&entry, tx, &args, &ctx).await {
            return r;
        }
        CheckResult::Ok
    }

    fn step_transaction_type(&self, tx: &Transaction) -> Option<CheckResult> {
        let transaction_type = tx.transaction_type?;
        if self.policy.transaction_types.contains(&transaction_type) {
            None
        } else {
            Some(CheckResult::Denied(DenyReason::InvalidRequest(format!(
                "transaction type {transaction_type} is not configured"
            ))))
        }
    }

    fn step_allowlist(&self, tx: &Transaction) -> Option<CheckResult> {
        if self.allowlist.contains(&tx.from.to_lowercase()) {
            Some(CheckResult::Ok)
        } else {
            None
        }
    }

    const fn step_contract_creation(&self, tx: &Transaction) -> Option<CheckResult> {
        if tx.to.is_empty() {
            Some(if self.policy.allow_contract_creation {
                CheckResult::Ok
            } else {
                CheckResult::Denied(DenyReason::ContractCreationDenied)
            })
        } else {
            None
        }
    }

    // Empty/short calldata (< 4 bytes) means fallback() or receive() — use "0x" as the
    // sentinel selector so waf.yaml can configure those via `func: fallback()`.
    fn derive_selector(tx: &Transaction) -> String {
        if tx.data.len() >= 10 {
            tx.data[..10].to_lowercase()
        } else {
            "0x".to_string()
        }
    }

    // Native transfer gate — ONLY genuinely empty calldata is a native transfer.
    // Short but non-empty calldata (e.g. "0x1234") is NOT a native transfer: it
    // falls through to rule lookup as a receive()/fallback() call (synthetic
    // "0x" selector) and is denied unless a receive()/wildcard rule authorises
    // it. If allowed, bypass rule lookup entirely.
    fn step_native_transfer(&self, selector: &str, tx: &Transaction) -> Option<CheckResult> {
        let empty_calldata = tx.data.is_empty() || tx.data.eq_ignore_ascii_case("0x");
        if empty_calldata && selector == "0x" && self.policy.allow_native_transfer {
            Some(CheckResult::Ok)
        } else {
            None
        }
    }

    fn step_token_op(&self, selector: &str) -> Option<CheckResult> {
        if selector != TRANSFER_SELECTOR && selector != APPROVE_SELECTOR {
            return None;
        }
        match self.policy.token_op_policy {
            TokenOpPolicy::AllowAll => Some(CheckResult::Ok),
            TokenOpPolicy::DenyAll => Some(CheckResult::Denied(DenyReason::TokenOpDenied {
                selector: selector.to_string(),
            })),
            // RequireRule/Whitelist fall through to rule lookup; a missing
            // rule then denies with NoRule.
            TokenOpPolicy::Whitelist | TokenOpPolicy::RequireRule => None,
        }
    }

    async fn step_rule_lookup(
        &self,
        tx: &Transaction,
        selector: &str,
        resolver: &dyn ChainResolver,
    ) -> Result<RuleEntry, DenyReason> {
        let Some(rules) = resolver
            .contract_rules(ChainRef::Evm(tx.chain_id), &tx.to)
            .await
        else {
            return Err(DenyReason::NoContract {
                address: tx.to.clone(),
                chain_id: tx.chain_id,
            });
        };
        match lookup_rules(&rules, selector) {
            RuleLookup::Found(e) => Ok(e),
            RuleLookup::NoSelector => Err(DenyReason::NoRule {
                address: tx.to.clone(),
                selector: selector.to_string(),
            }),
            RuleLookup::NoContract => Err(DenyReason::NoContract {
                address: tx.to.clone(),
                chain_id: tx.chain_id,
            }),
        }
    }

    fn decode_args(entry: &RuleEntry, tx: &Transaction) -> HashMap<String, serde_json::Value> {
        entry
            .abi_item
            .as_ref()
            .and_then(|abi| decode_calldata(abi, &tx.data).ok())
            .unwrap_or_default()
    }

    async fn step_eval_clauses(
        &self,
        entry: &RuleEntry,
        args: &HashMap<String, serde_json::Value>,
        tx: &Transaction,
        cx: &CheckCtx<'_>,
    ) -> Option<CheckResult> {
        // A multicall-only entry (decoder present, no per-project clauses) defers
        // entirely to step_multicall — skip clause evaluation so it isn't denied here.
        if entry.clauses.is_empty() && entry.multicall.is_some() {
            return None;
        }
        let mut any_passed = false;
        let mut last_denied = String::new();
        let mut last_failing = None;
        'clauses: for clause in &entry.clauses {
            let ctx = evm_eval_ctx(tx, args.clone(), &tx.to, clause.vars.clone());
            for expr_str in clause.expr.exprs() {
                match expr::evaluate_explain(expr_str, &ctx, Arc::clone(cx.builtins)).await {
                    Ok((true, _)) => {}
                    Ok((false, explain)) => {
                        last_denied = expr_str.to_string();
                        last_failing = explain;
                        continue 'clauses;
                    }
                    Err(e) => {
                        return Some(CheckResult::Denied(DenyReason::EvalError(e.to_string())))
                    }
                }
            }
            any_passed = true;
            break;
        }
        if !any_passed {
            Some(CheckResult::Denied(DenyReason::ExpressionDenied {
                expr: last_denied,
                explain: last_failing,
            }))
        } else {
            None
        }
    }

    async fn step_multicall(
        &self,
        entry: &RuleEntry,
        tx: &Transaction,
        args: &HashMap<String, serde_json::Value>,
        cx: &CheckCtx<'_>,
    ) -> Option<CheckResult> {
        if entry.invalid_decoder {
            return Some(CheckResult::Denied(DenyReason::InvalidDecoder));
        }
        if let Some(mc) = &entry.multicall {
            if let Err(reason) = self.check_inner_calls(tx, args, mc, cx).await {
                return Some(CheckResult::Denied(reason));
            }
        }
        None
    }

    /// Route inner-call extraction and checking to the appropriate decoder variant.
    async fn check_inner_calls(
        &self,
        tx: &Transaction,
        outer_args: &HashMap<String, serde_json::Value>,
        decoder: &MulticallDecoder,
        cx: &CheckCtx<'_>,
    ) -> Result<(), DenyReason> {
        if let MulticallDecoder::UniversalRouter {
            commands_param,
            inputs_param,
        } = decoder
        {
            return self
                .check_universal_router_calls(tx, outer_args, commands_param, inputs_param)
                .await;
        }
        // All other decoders extract full-calldata inner calls via dot-path
        let (data_path, target_path) = decoder
            .standard_paths()
            .expect("non-UR decoder always has standard paths");
        let inner_calls = extract_inner_calldata(outer_args, &data_path);
        let inner_targets = target_path
            .as_deref()
            .map(|tp| extract_inner_targets(outer_args, tp))
            .unwrap_or_default();

        let mut errors = Vec::new();

        for (idx, inner_hex) in inner_calls.iter().enumerate() {
            if inner_hex.len() < 10 {
                continue;
            }
            let inner_sel = inner_hex[..10].to_lowercase();
            let inner_target = inner_targets
                .get(idx)
                .map(|s| s.to_lowercase())
                .unwrap_or_else(|| tx.to.to_lowercase());
            if let Err(e) = self
                .check_one_inner(
                    tx,
                    &InnerCall {
                        idx,
                        target: &inner_target,
                        selector: &inner_sel,
                        calldata: inner_hex,
                        has_selector: true,
                    },
                    cx,
                )
                .await
            {
                errors.push(e);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else if errors.len() == 1 {
            Err(errors.into_iter().next().unwrap())
        } else {
            Err(DenyReason::Multiple(errors))
        }
    }

    /// Universal Router: hardcoded dispatch from Dispatcher.sol (commands 0x00–0x0c).
    /// Checks recipient validity and slippage protection for swap commands.
    async fn check_universal_router_calls(
        &self,
        tx: &Transaction,
        outer_args: &HashMap<String, serde_json::Value>,
        commands_param: &str,
        inputs_param: &str,
    ) -> Result<(), DenyReason> {
        let commands_hex = outer_args
            .get(commands_param)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cmd_bytes = hex::decode(commands_hex.trim_start_matches("0x")).unwrap_or_default();
        let inputs = extract_inner_calldata(outer_args, inputs_param);

        let mut errors = Vec::new();

        for (idx, &cmd_byte) in cmd_bytes.iter().enumerate() {
            let cmd = cmd_byte & 0x3f;
            let inner_hex = inputs.get(idx).cloned().unwrap_or_default();
            match cmd {
                // V3_SWAP_EXACT_IN (0x00) / V3_SWAP_EXACT_OUT (0x01)
                // ABI: (address recipient, uint256 amountIn, uint256 amountOutMin,
                //        bytes path, bool payerIsUser)
                0x00 | 0x01 => {
                    let args =
                        decode_args_only(&ur_v3_swap_inputs(), &inner_hex).unwrap_or_default();
                    let recipient = args
                        .get("recipient")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if !is_valid_ur_recipient(&recipient, tx) {
                        errors.push(DenyReason::ExpressionDenied {
                            expr: format!("inner[{idx}] UR V3 swap: recipient {recipient} is not from_address or contract"),
                            explain: None,
                        });
                        continue;
                    }
                    if cmd == 0x00 {
                        let amount_out_min = args
                            .get("amountOutMin")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<u128>().ok())
                            .unwrap_or(0);
                        if amount_out_min == 0 {
                            errors.push(DenyReason::ExpressionDenied {
                                expr: format!("inner[{idx}] UR V3_SWAP_EXACT_IN: amountOutMin is 0 (no slippage protection)"),
                                explain: None,
                            });
                            continue;
                        }
                    }
                }
                // V2_SWAP_EXACT_IN (0x08) / V2_SWAP_EXACT_OUT (0x09)
                // ABI: (address recipient, uint256 amountIn, uint256 amountOutMin,
                //        address[] path, bool payerIsUser)
                0x08 | 0x09 => {
                    let args =
                        decode_args_only(&ur_v2_swap_inputs(), &inner_hex).unwrap_or_default();
                    let recipient = args
                        .get("recipient")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if !is_valid_ur_recipient(&recipient, tx) {
                        errors.push(DenyReason::ExpressionDenied {
                            expr: format!("inner[{idx}] UR V2 swap: recipient {recipient} is not from_address or contract"),
                            explain: None,
                        });
                        continue;
                    }
                    if cmd == 0x08 {
                        let amount_out_min = args
                            .get("amountOutMin")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<u128>().ok())
                            .unwrap_or(0);
                        if amount_out_min == 0 {
                            errors.push(DenyReason::ExpressionDenied {
                                expr: format!("inner[{idx}] UR V2_SWAP_EXACT_IN: amountOutMin is 0 (no slippage protection)"),
                                explain: None,
                            });
                            continue;
                        }
                    }
                }
                // SWEEP (0x04) / TRANSFER (0x05)
                // ABI: (address token, address recipient, uint256 amount)
                0x04 | 0x05 => {
                    let args =
                        decode_args_only(&ur_payment_inputs(), &inner_hex).unwrap_or_default();
                    let recipient = args
                        .get("recipient")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if !is_valid_ur_recipient(&recipient, tx) {
                        errors.push(DenyReason::ExpressionDenied {
                            expr: format!("inner[{idx}] UR SWEEP/TRANSFER: recipient {recipient} is not from_address or contract"),
                            explain: None,
                        });
                        continue;
                    }
                }
                // UNWRAP_WETH (0x0c)
                // ABI: (address recipient, uint256 amountMin)
                0x0c => {
                    let args = decode_args_only(&ur_wrap_inputs(), &inner_hex).unwrap_or_default();
                    let recipient = args
                        .get("recipient")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if !is_valid_ur_recipient(&recipient, tx) {
                        errors.push(DenyReason::ExpressionDenied {
                            expr: format!("inner[{idx}] UR UNWRAP_WETH: recipient {recipient} is not from_address or contract"),
                            explain: None,
                        });
                        continue;
                    }
                }
                // PERMIT2_TRANSFER_FROM (0x02), PERMIT2_PERMIT_BATCH (0x03),
                // PAY_PORTION (0x06/0x07), PERMIT2_PERMIT (0x0a), WRAP_ETH (0x0b),
                // V4_SWAP (0x10), all others → pass-through
                _ => {}
            }
        }
        if errors.is_empty() {
            Ok(())
        } else if errors.len() == 1 {
            Err(errors.into_iter().next().unwrap())
        } else {
            Err(DenyReason::Multiple(errors))
        }
    }

    /// Check a single inner call.
    /// `has_selector`: true = inner_hex starts with 4-byte selector (use decode_calldata),
    ///                 false = inner_hex is bare ABI params (use decode_args_only).
    async fn check_one_inner(
        &self,
        tx: &Transaction,
        inner: &InnerCall<'_>,
        cx: &CheckCtx<'_>,
    ) -> Result<(), DenyReason> {
        let idx = inner.idx;
        let selector = inner.selector;
        if let Some(result) = self.step_token_op(selector) {
            return match result {
                CheckResult::Ok => Ok(()),
                CheckResult::Denied(reason) => Err(reason),
            };
        }
        let inner_target = inner.target;
        let inner_address = format!("{inner_target} (inner[{idx}])");
        let Some(rules) = cx
            .resolver
            .contract_rules(ChainRef::Evm(tx.chain_id), inner_target)
            .await
        else {
            return Err(DenyReason::NoContract {
                address: inner_address,
                chain_id: tx.chain_id,
            });
        };
        let inner_entry = match lookup_rules(&rules, selector) {
            RuleLookup::Found(e) => e,
            RuleLookup::NoSelector => {
                return Err(DenyReason::NoRule {
                    address: inner_address,
                    selector: selector.to_string(),
                });
            }
            RuleLookup::NoContract => {
                return Err(DenyReason::NoContract {
                    address: inner_address,
                    chain_id: tx.chain_id,
                });
            }
        };

        let inner_args = if let Some(abi) = &inner_entry.abi_item {
            if inner.has_selector {
                decode_calldata(abi, inner.calldata).unwrap_or_default()
            } else {
                decode_args_only(&abi.inputs, inner.calldata).unwrap_or_default()
            }
        } else {
            Default::default()
        };

        // A multicall-only inner entry (decoder present, no clauses) passes
        // clause evaluation unconditionally — inner-call inspection is the caller's job.
        if inner_entry.clauses.is_empty() && inner_entry.multicall.is_some() {
            return Ok(());
        }

        let mut any_passed = false;
        let mut last_denied = String::new();
        let mut last_failing = None;
        'clauses: for clause in &inner_entry.clauses {
            let inner_ctx = evm_eval_ctx(tx, inner_args.clone(), inner_target, clause.vars.clone());
            for expr_str in clause.expr.exprs() {
                match expr::evaluate_explain(expr_str, &inner_ctx, Arc::clone(cx.builtins)).await {
                    Ok((true, _)) => {}
                    Ok((false, explain)) => {
                        last_denied = format!("inner[{idx}] {expr_str}");
                        last_failing = explain;
                        continue 'clauses;
                    }
                    Err(e) => return Err(DenyReason::EvalError(format!("inner[{idx}]: {e}"))),
                }
            }
            any_passed = true;
            break;
        }
        if !any_passed {
            return Err(DenyReason::ExpressionDenied {
                expr: last_denied,
                explain: last_failing,
            });
        }
        Ok(())
    }

    /// waf_checkSign: evaluate EIP-712 typed-data message(s) against configured rules.
    ///
    /// Rule lookup key: (domain.chainId, domain.verifyingContract, "domain.name::primaryType")
    /// The message fields map directly to `args` — no ABI decoding needed.
    /// If `verifyingContract` is absent (or the zero address) the request is
    /// allowed (off-chain auth only).
    pub async fn check_sign(
        &self,
        req: &TypedDataRequest,
        resolver: &dyn RuleResolver,
    ) -> CheckResult {
        // EIP-712 is EVM-only; adapt the caller's resolver for the internal
        // ChainResolver plumbing (same pattern as `check`).
        let resolver = &CompatResolver(resolver);

        // 1. No verifyingContract (or zero address) → off-chain auth, skip WAF
        let contract = match req.domain.verifying_contract.as_deref() {
            Some(c) if !is_missing_or_zero_address(c) => c.to_lowercase(),
            _ => return CheckResult::Ok,
        };

        // 2. Sender allowlist bypass
        if self.allowlist.contains(&req.from.to_lowercase()) {
            return CheckResult::Ok;
        }

        // 3. Rule lookup: "domain.name::primaryType" acts as the selector
        let domain_name = normalize_domain_name(&req.domain.name);
        let selector = format!("{}::{}", domain_name, req.primary_type);
        let builtins = self.builtins_for(resolver, ChainRef::Evm(req.domain.chain_id));
        let ctx = CheckCtx {
            resolver,
            builtins: &builtins,
        };
        let entry = match resolver
            .contract_rules(ChainRef::Evm(req.domain.chain_id), &contract)
            .await
            .map(|rules| lookup_rules(&rules, &selector))
        {
            Some(RuleLookup::Found(e)) => e,
            Some(RuleLookup::NoSelector) | Some(RuleLookup::NoContract) | None => {
                return CheckResult::Denied(DenyReason::NoSignRule {
                    domain: domain_name,
                    primary_type: req.primary_type.clone(),
                    address: contract,
                });
            }
        };

        // 4. Evaluate each message (single or batch)
        let messages: Vec<&serde_json::Value> = match (&req.message, &req.messages) {
            (Some(m), _) => vec![m],
            (_, Some(ms)) => ms.iter().collect(),
            (None, None) => vec![],
        };

        for (idx, msg) in messages.iter().enumerate() {
            if let CheckResult::Denied(reason) =
                self.eval_typed_message(msg, &entry, req, idx, &ctx).await
            {
                return CheckResult::Denied(reason);
            }
        }

        CheckResult::Ok
    }

    async fn eval_typed_message(
        &self,
        message: &serde_json::Value,
        entry: &crate::types::RuleEntry,
        req: &TypedDataRequest,
        idx: usize,
        cx: &CheckCtx<'_>,
    ) -> CheckResult {
        let args: HashMap<String, serde_json::Value> = match message.as_object() {
            Some(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            None => Default::default(),
        };

        let mut any_passed = false;
        let mut last_denied = String::new();
        let mut last_failing = None;
        'clauses: for clause in &entry.clauses {
            let ctx = EvalContext {
                chain_id: req.domain.chain_id,
                value: alloy_primitives::U256::ZERO,
                args: args.clone(),
                from_address: req.from.to_lowercase(),
                to_address: req
                    .domain
                    .verifying_contract
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase(),
                gas_price: 0,
                gas_limit: 0,
                vars: clause.vars.clone(),
                network: format!("eip155:{}", req.domain.chain_id),
                chain_fields: HashMap::new(),
            };
            for expr_str in clause.expr.exprs() {
                match expr::evaluate_explain(expr_str, &ctx, Arc::clone(cx.builtins)).await {
                    Ok((true, _)) => {}
                    Ok((false, explain)) => {
                        last_denied = if idx > 0 {
                            format!("message[{idx}] {expr_str}")
                        } else {
                            expr_str.to_string()
                        };
                        last_failing = explain;
                        continue 'clauses;
                    }
                    Err(e) => return CheckResult::Denied(DenyReason::EvalError(e.to_string())),
                }
            }
            any_passed = true;
            break;
        }
        if !any_passed {
            return CheckResult::Denied(DenyReason::ExpressionDenied {
                expr: last_denied,
                explain: last_failing,
            });
        }

        // 5. Check inner calls if a multicall decoder is configured on this EIP-712 rule.
        if entry.invalid_decoder {
            return CheckResult::Denied(DenyReason::InvalidDecoder);
        }
        if let Some(mc) = &entry.multicall {
            let tx = Transaction {
                chain_id: req.domain.chain_id,
                to: req
                    .domain
                    .verifying_contract
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase(),
                from: req.from.to_lowercase(),
                ..Default::default()
            };
            if let Err(reason) = self.check_inner_calls(&tx, &args, mc, cx).await {
                return CheckResult::Denied(reason);
            }
        }

        CheckResult::Ok
    }

    /// waf_testRule: evaluate the caller-supplied expr using the stored ABI for decoding.
    ///
    /// When the caller provides `abi` inline, the call is treated as fully
    /// self-contained: the resolver is NOT consulted at all. This keeps
    /// `waf_testRule` a pure preview API — no cache interaction, no provider
    /// fetch when previewing a rule for a contract that isn't yet loaded.
    ///
    /// When `abi` is omitted the engine falls back to the stored rule's ABI
    /// (via `resolver`) for calldata decoding.
    pub async fn test(&self, tx: &Transaction, resolver: Option<&dyn RuleResolver>) -> CheckResult {
        let compat = resolver.map(CompatResolver);
        self.test_tx(
            &ChainTx::Evm(tx.clone()),
            compat.as_ref().map(|c| c as &dyn ChainResolver),
        )
        .await
    }

    /// Unified test-mode preview (mirrors [`Checker::test`]): inline `abi` on
    /// the transaction plays the role of `Transaction.abi` today.
    pub async fn test_tx(&self, tx: &ChainTx, resolver: Option<&dyn ChainResolver>) -> CheckResult {
        let ChainTx::Evm(tx) = tx;
        if let Some(r) = self.step_transaction_type(tx) {
            return r;
        }
        let expr_str = match &tx.expr {
            Some(e) => e.clone(),
            None => return CheckResult::Denied(DenyReason::NoExprInTest),
        };
        let builtins = self.builtins_for_opt(resolver, ChainRef::Evm(tx.chain_id));

        let selector = if tx.data.len() >= 10 {
            tx.data[..10].to_lowercase()
        } else {
            "0x".to_string()
        };

        // Self-contained when the caller provided an inline ABI: skip the rule
        // lookup entirely. Otherwise fall back to the stored rule's ABI so
        // calldata can still be decoded.
        let (stored_abi, stored_vars, stored_mc) = if tx.abi.is_some() {
            (None, HashMap::new(), None)
        } else {
            let found = match resolver {
                Some(r) => r
                    .contract_rules(ChainRef::Evm(tx.chain_id), &tx.to)
                    .await
                    .map(|rules| lookup_rules(&rules, &selector)),
                None => None,
            };
            match found {
                Some(RuleLookup::Found(e)) => {
                    // Use the first clause's vars as the representative vars for test mode.
                    let vars = e
                        .clauses
                        .into_iter()
                        .next()
                        .map(|c| c.vars)
                        .unwrap_or_default();
                    (e.abi_item, vars, e.multicall)
                }
                _ => (None, HashMap::new(), None),
            }
        };
        let abi_item = tx.abi.as_ref().or(stored_abi.as_ref());
        let vars = tx.vars.clone().unwrap_or(stored_vars);

        // Build multicall decoder: inline decoder_type/decoder_config > stored rule
        let decoder = if tx.decoder_type.is_some() {
            build_decoder(tx.decoder_type, tx.decoder_config.as_ref())
        } else {
            stored_mc
        };

        let args = if let Some(item) = abi_item {
            decode_calldata(item, &tx.data).unwrap_or_default()
        } else {
            Default::default()
        };

        let ctx = evm_eval_ctx(tx, args, &tx.to, vars);

        // Evaluate the outer expression first
        let (outer_ok, explain) =
            match expr::evaluate_explain(&expr_str, &ctx, Arc::clone(&builtins)).await {
                Ok(passes) => passes,
                Err(e) => return CheckResult::Denied(DenyReason::EvalError(e.to_string())),
            };
        if !outer_ok {
            return CheckResult::Denied(DenyReason::ExpressionDenied {
                expr: expr_str,
                explain,
            });
        }

        // If a multicall decoder is configured, also check inner calls
        if let Some(ref mc) = decoder {
            if let Some((data_path, target_path)) = mc.standard_paths() {
                let inner_calldatas = extract_inner_calldata(&ctx.args, &data_path);
                let inner_targets = target_path
                    .as_ref()
                    .map(|tp| extract_inner_targets(&ctx.args, tp))
                    .unwrap_or_default();

                for (idx, inner_data) in inner_calldatas.iter().enumerate() {
                    if inner_data.len() < 10 {
                        continue;
                    }
                    let inner_sel = inner_data[..10].to_lowercase();
                    let inner_to = inner_targets
                        .get(idx)
                        .map(|s| s.to_lowercase())
                        .unwrap_or_else(|| tx.to.to_lowercase());

                    // Look up inner ABI from inline inner_abis map
                    let inner_args =
                        if let Some(abi) = tx.inner_abis.as_ref().and_then(|m| m.get(&inner_sel)) {
                            decode_calldata(abi, inner_data).unwrap_or_default()
                        } else {
                            Default::default()
                        };

                    let inner_ctx = EvalContext {
                        chain_id: tx.chain_id,
                        value: ctx.value,
                        args: inner_args,
                        from_address: ctx.from_address.clone(),
                        to_address: inner_to,
                        gas_price: ctx.gas_price,
                        gas_limit: ctx.gas_limit,
                        vars: ctx.vars.clone(),
                        network: ctx.network.clone(),
                        chain_fields: HashMap::new(),
                    };

                    match expr::evaluate_explain(&expr_str, &inner_ctx, Arc::clone(&builtins)).await
                    {
                        Ok((true, _)) => {}
                        Ok((false, explain)) => {
                            return CheckResult::Denied(DenyReason::ExpressionDenied {
                                expr: format!("inner[{idx}] {expr_str}"),
                                explain,
                            });
                        }
                        Err(e) => {
                            return CheckResult::Denied(DenyReason::EvalError(e.to_string()));
                        }
                    }
                }
            }
        }

        CheckResult::Ok
    }
}

// ── EIP-712 helpers ───────────────────────────────────────────────────────────

/// Zero address (0x0000…0000) — treated as an absent verifyingContract.
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// A verifyingContract that is empty or the zero address is effectively
/// absent — the signature is purely off-chain auth and WAF always allows it.
fn is_missing_or_zero_address(contract: &str) -> bool {
    contract.is_empty() || contract.to_lowercase() == ZERO_ADDRESS
}

// ── Universal Router helpers ──────────────────────────────────────────────────

/// UR ActionConstants: these sentinel addresses are mapped by the UR itself.
const UR_ADDR_MSG_SENDER: &str = "0x0000000000000000000000000000000000000001";
const UR_ADDR_ADDRESS_THIS: &str = "0x0000000000000000000000000000000000000002";

fn is_valid_ur_recipient(recipient: &str, tx: &Transaction) -> bool {
    let r = recipient.to_lowercase();
    r == tx.from.to_lowercase()
        || r == tx.to.to_lowercase()
        || r == UR_ADDR_MSG_SENDER
        || r == UR_ADDR_ADDRESS_THIS
}

fn mk_input(name: &str, kind: &str) -> crate::types::AbiInput {
    crate::types::AbiInput {
        name: name.to_string(),
        kind: kind.to_string(),
        components: vec![],
    }
}

/// V3 swap ABI inputs: (address recipient, uint256 amountIn, uint256 amountOutMin, bytes path, bool payerIsUser)
fn ur_v3_swap_inputs() -> Vec<crate::types::AbiInput> {
    vec![
        mk_input("recipient", "address"),
        mk_input("amountIn", "uint256"),
        mk_input("amountOutMin", "uint256"),
        mk_input("path", "bytes"),
        mk_input("payerIsUser", "bool"),
    ]
}

/// V2 swap ABI inputs: (address recipient, uint256 amountIn, uint256 amountOutMin, address[] path, bool payerIsUser)
fn ur_v2_swap_inputs() -> Vec<crate::types::AbiInput> {
    vec![
        mk_input("recipient", "address"),
        mk_input("amountIn", "uint256"),
        mk_input("amountOutMin", "uint256"),
        mk_input("path", "address[]"),
        mk_input("payerIsUser", "bool"),
    ]
}

/// Payment ABI inputs: (address token, address recipient, uint256 amount)
fn ur_payment_inputs() -> Vec<crate::types::AbiInput> {
    vec![
        mk_input("token", "address"),
        mk_input("recipient", "address"),
        mk_input("amount", "uint256"),
    ]
}

/// Wrap/Unwrap ABI inputs: (address recipient, uint256 amount)
fn ur_wrap_inputs() -> Vec<crate::types::AbiInput> {
    vec![
        mk_input("recipient", "address"),
        mk_input("amount", "uint256"),
    ]
}

// ── Multicall inner-call helpers ──────────────────────────────────────────────

/// Extract inner calldata hex strings from decoded multicall args.
///
/// `data_field` is a dot-separated path:
///   "data"           → outer_args["data"] is Vec<"0x..."> (bytes[])
///   "inputs"         → outer_args["inputs"] is Vec<"0x...">
///   "calls.callData" → outer_args["calls"] is Vec<{callData: "0x...", ...}>
///
/// Returns a Vec of "0x..." hex strings, one per inner call.
fn extract_inner_calldata(
    outer_args: &HashMap<String, serde_json::Value>,
    data_field: &str,
) -> Vec<String> {
    let mut parts = data_field.splitn(2, '.');

    let array_key = parts.next().unwrap_or("");
    let inner_key = parts.next(); // Some("callData") or None

    let arr = match outer_args.get(array_key) {
        Some(serde_json::Value::Array(a)) => a,
        _ => return vec![],
    };

    arr.iter()
        .filter_map(|elem| {
            match inner_key {
                // Flat bytes[] — each element is the calldata directly
                None => elem.as_str().map(|s| s.to_string()),
                // Tuple array — each element is an object; pick the named field
                Some(field) => elem.get(field)?.as_str().map(|s| s.to_string()),
            }
        })
        .collect()
}
/// Extract the target address for each inner call from decoded multicall args.
/// Mirrors extract_inner_calldata but for the address field.
/// Returns a Vec of lowercase address strings.
fn extract_inner_targets(
    outer_args: &HashMap<String, serde_json::Value>,
    target_field: &str,
) -> Vec<String> {
    let mut parts = target_field.splitn(2, '.');
    let array_key = parts.next().unwrap_or("");
    let inner_key = parts.next();

    let arr = match outer_args.get(array_key) {
        Some(serde_json::Value::Array(a)) => a,
        _ => return vec![],
    };

    arr.iter()
        .filter_map(|elem| match inner_key {
            None => elem.as_str().map(|s| s.to_lowercase()),
            Some(field) => elem.get(field)?.as_str().map(|s| s.to_lowercase()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::DenyReason;
    use crate::types::normalize_domain_name;
    use weituo_expr::Explain;
    #[test]
    fn normalize_empty_stays_empty() {
        assert_eq!(normalize_domain_name(""), "");
    }

    #[test]
    fn normalize_single_quote_stripped() {
        assert_eq!(normalize_domain_name("'"), "");
    }

    #[test]
    fn normalize_double_quote_stripped() {
        assert_eq!(normalize_domain_name("\""), "");
    }

    #[test]
    fn normalize_whitespace_stripped() {
        assert_eq!(normalize_domain_name("  '  "), "");
        assert_eq!(normalize_domain_name("  \"  "), "");
        assert_eq!(normalize_domain_name("  "), "");
    }

    #[test]
    fn normalize_normal_name_unchanged() {
        assert_eq!(
            normalize_domain_name("Polymarket CTF Exchange"),
            "Polymarket CTF Exchange"
        );
    }

    #[test]
    fn normalize_quoted_content_not_stripped() {
        assert_eq!(normalize_domain_name("''"), "''");
        assert_eq!(normalize_domain_name("\"\""), "\"\"");
        assert_eq!(normalize_domain_name("'foo'"), "'foo'");
        assert_eq!(normalize_domain_name("\"bar\""), "\"bar\"");
        assert_eq!(normalize_domain_name("'\""), "'\"");
    }

    #[test]
    fn expression_denied_data_carries_cond() {
        let reason = DenyReason::ExpressionDenied {
            expr: "a > 0 and b > 1".to_string(),
            explain: Some(Explain {
                source: "b > 1".to_string(),
                values: Some("0 > 1".to_string()),
            }),
        };
        let err = reason.to_rpc_error();
        assert_eq!(err.code, -32603);
        assert_eq!(err.message, "transaction denied by rule: a > 0 and b > 1");
        assert_eq!(
            err.data,
            Some(serde_json::json!({ "cond": "b > 1", "data": "0 > 1" }))
        );
    }

    #[test]
    fn expression_denied_without_condition_has_no_data() {
        let reason = DenyReason::ExpressionDenied {
            expr: "a > 0".to_string(),
            explain: None,
        };
        let err = reason.to_rpc_error();
        assert_eq!(err.message, "transaction denied by rule: a > 0");
        assert_eq!(err.data, None);
    }
}

/// Tests for the stateless check pipeline — rules enter through a
/// [`StaticResolver`], the checker holds only plain parameters.
#[cfg(test)]
mod stateless_tests {
    use super::{CheckResult, Checker};
    use crate::policy::{Policy, TokenOpPolicy};
    use crate::provider::{ChainInfo, StaticResolver};
    use crate::types::{ExprValue, RuleClause, RuleEntry, Transaction};
    use std::collections::HashMap;

    const TOKEN: &str = "0xdac17f958d2ee523a2206206994597c13d831ec7";
    const SENDER: &str = "0x1111111111111111111111111111111111111111";

    fn tx(data: &str) -> Transaction {
        serde_json::from_value(serde_json::json!({
            "chainId": 1, "from": SENDER, "to": TOKEN, "data": data, "value": 0,
        }))
        .unwrap()
    }

    fn entry(expr: &str) -> RuleEntry {
        RuleEntry {
            clauses: vec![RuleClause {
                expr: ExprValue::Single(expr.into()),
                vars: HashMap::new(),
            }],
            abi_item: None,
            multicall: None,
            invalid_decoder: false,
        }
    }

    fn resolver(rules: HashMap<(u64, String), HashMap<String, RuleEntry>>) -> StaticResolver {
        StaticResolver::new(
            rules,
            HashMap::from([(
                1u64,
                ChainInfo {
                    rpc_url: String::new(),
                },
            )]),
        )
    }

    fn checker(policy: Policy) -> Checker {
        Checker::new(reqwest::Client::new(), Vec::new(), policy)
    }

    #[tokio::test]
    async fn allowlisted_sender_bypasses_rules() {
        // Even DenyAll token policy can't deny an allowlisted sender.
        let policy = Policy {
            token_op_policy: TokenOpPolicy::DenyAll,
            ..Default::default()
        };
        let checker = Checker::new(reqwest::Client::new(), vec![SENDER.into()], policy);
        let resolver = resolver(HashMap::new());
        let result = checker.check(&tx("0x095ea7b3"), &resolver).await;
        assert!(matches!(result, CheckResult::Ok));
    }

    #[tokio::test]
    async fn unknown_contract_with_allow_all_token_policy_is_ok() {
        let resolver = resolver(HashMap::new());
        let result = checker(Policy::default())
            .check(&tx("0x095ea7b3"), &resolver)
            .await;
        assert!(matches!(result, CheckResult::Ok));
    }

    #[tokio::test]
    async fn unknown_contract_with_deny_all_token_policy_denies() {
        let policy = Policy {
            token_op_policy: TokenOpPolicy::DenyAll,
            ..Default::default()
        };
        let resolver = resolver(HashMap::new());
        let result = checker(policy).check(&tx("0x095ea7b3"), &resolver).await;
        match result {
            CheckResult::Denied(reason) => {
                assert_eq!(reason.code(), -32604); // TokenOpDenied
            }
            CheckResult::Ok => panic!("expected denial"),
        }
    }

    #[tokio::test]
    async fn non_token_op_unknown_contract_denies_even_with_allow_all() {
        let resolver = resolver(HashMap::new());
        let result = checker(Policy::default())
            .check(&tx("0xdeadbeef"), &resolver)
            .await;
        match result {
            CheckResult::Denied(reason) => {
                assert_eq!(reason.code(), -32606); // NoContract
            }
            CheckResult::Ok => panic!("expected denial"),
        }
    }

    #[tokio::test]
    async fn rule_expression_denies() {
        // approve(spender=0x2222…) with rule `args.spender == from` → denied.
        let spender = "2222222222222222222222222222222222222222";
        let amount = format!("{:0>64}", "1");
        let data = format!("0x095ea7b3{spender:0>64}{amount}");
        let abi: crate::types::AbiItem = serde_json::from_value(serde_json::json!({
            "type": "function", "name": "approve",
            "inputs": [
                { "name": "spender", "type": "address" },
                { "name": "amount", "type": "uint256" }
            ],
            "outputs": []
        }))
        .unwrap();
        let mut rule = entry("args.spender == from");
        rule.abi_item = Some(abi);
        let resolver = resolver(HashMap::from([(
            (1u64, TOKEN.to_string()),
            HashMap::from([("0x095ea7b3".to_string(), rule)]),
        )]));
        let result = checker(Policy::default())
            .check(&tx(&data), &resolver)
            .await;
        match result {
            CheckResult::Denied(reason) => {
                assert_eq!(reason.code(), -32603); // ExpressionDenied
            }
            CheckResult::Ok => panic!("expected denial"),
        }
    }
}
