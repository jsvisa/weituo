use alloy_primitives::U256;
use serde_json::Value as JsonValue;
use std::collections::HashMap;

/// The runtime context passed to every expression evaluation.
/// Field names are the identifiers rules can reference (`from_address`,
/// `to_address`, `chainId`, `value`, `args`, …).
#[derive(Debug, Clone)]
pub struct EvalContext {
    pub chain_id: u64,
    pub value: U256,
    /// Decoded calldata: param_name → json value
    pub args: HashMap<String, JsonValue>,
    pub from_address: String,
    pub to_address: String,
    pub gas_price: u64,
    pub gas_limit: u64,
    /// Rule-level named constants: var_name → json value
    pub vars: HashMap<String, JsonValue>,
}

impl Default for EvalContext {
    fn default() -> Self {
        Self {
            chain_id: 0,
            value: U256::ZERO,
            args: HashMap::new(),
            from_address: String::new(),
            to_address: String::new(),
            gas_price: 0,
            gas_limit: 0,
            vars: HashMap::new(),
        }
    }
}

impl EvalContext {
    pub fn new(chain_id: u64, from: &str, to: &str) -> Self {
        Self {
            chain_id,
            value: U256::ZERO,
            args: HashMap::new(),
            from_address: from.to_lowercase(),
            to_address: to.to_lowercase(),
            gas_price: 0,
            gas_limit: 0,
            vars: HashMap::new(),
        }
    }
}

/// Trait for providing $ builtin functions.
/// The main crate provides a real implementation; tests can use a mock.
#[async_trait::async_trait]
#[allow(clippy::double_must_use)]
pub trait BuiltinProvider: Send + Sync {
    async fn call(
        &self,
        name: &str,
        args: &[crate::eval::Value],
        ctx: &EvalContext,
    ) -> anyhow::Result<crate::eval::Value>;
}

#[cfg(test)]
mod tests {
    use super::EvalContext;
    use alloy_primitives::U256;

    #[test]
    fn default_uses_zero_for_transaction_numeric_fields() {
        let ctx = EvalContext::default();

        assert_eq!(ctx.value, U256::ZERO);
        assert_eq!(ctx.gas_price, 0);
        assert_eq!(ctx.gas_limit, 0);
    }
}
