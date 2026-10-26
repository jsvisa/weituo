# weituo-core

The reusable EVM WAF rule-check engine: it evaluates transactions and EIP-712
signatures against rules expressed in the [`weituo-expr`](../expr) DSL. No HTTP
server, no auth, no metrics — those belong to the embedding service.

```toml
[dependencies]
weituo-core = "0.2"
reqwest     = "0.12"   # used by Builtins for chain RPC helpers
tokio       = "1"
anyhow      = "1"
```

## Concepts

| Piece | Role |
| --- | --- |
| `provider::RuleProvider` | Trait for fetching rules: `fetch_chain_info` (RPC URL per chain) and `fetch_contract_rules` (per-selector rules). Implement it over HTTP, a database, or anything else. |
| `static_loader` | The local-file counterpart: load rules from YAML + ABI JSON files instead of a provider. |
| `rule_manager::RuleManager` | Caches rules per `(chain, address)`, refreshes chain metadata in the background, and knows the RPC URL fallback. |
| `decoder` | Decodes calldata against the rule's ABI (`alloy-dyn-abi`), including tuples and arrays. |
| `builtins::Builtins` | The engine's `$` builtins: chain data read over RPC (`$block`, `$gas_price`, `$balance_of`, `$erc20_*`, `$is_contract`, …) plus pure helpers (`$now_ts`, `$pow`, `$b32int2addr`). |
| `checker::Checker` | The state machine that decides allow/deny. |
| `checker::ScamOracle` | Injected contract for "is this address known-bad"; used by `TokenOpPolicy::DenyScam`. Fail-open when not provided. |
| `parse_rule` | Syntax + semantic validation of a single rule expression, for rule-authoring UIs. |

## The check pipeline

`Checker::check(&tx)` runs, in order:

1. **transaction type policy** — configured `global_policy.transaction_types`;
2. **allowlist** — `from` address allowlist;
3. **contract creation** — `to` empty ⇒ `allow_contract_creation`;
4. **native transfer** — empty calldata ⇒ `allow_native_transfer`;
5. **rule lookup** — the contract's rule for the derived selector, else the
   **token-op policy** (`AllowAll` / `DenyAll` / `DenyScam` / `RequireRule` /
   `Whitelist`), with `DenyScam` consulting the injected `ScamOracle`;
6. **clause evaluation** — the rule's expressions against the decoded args;
7. **multicall** — nested calls, when the rule declares a multicall decoder.

`Checker::check_sign(&typed_data)` is the EIP-712 counterpart.

Denials come back as a typed `DenyReason` (which renders to a JSON-RPC error
with `to_rpc_error()`), so callers can map them to their own protocol.

## Embedding

```rust
use std::{collections::HashMap, sync::Arc};

use weituo_core::{
    builtins::Builtins,
    checker::Checker,
    config::Settings,
    provider::{ChainInfo, RuleProvider},
    rule_manager::RuleManager,
    types::RuleEntry,
};

struct MyRules;

#[async_trait::async_trait]
impl RuleProvider for MyRules {
    async fn fetch_chain_info(&self, _chain_id: u64) -> anyhow::Result<ChainInfo> {
        Ok(ChainInfo { rpc_url: String::new() })
    }

    async fn fetch_contract_rules(
        &self,
        _chain_id: u64,
        _address: &str,
    ) -> anyhow::Result<HashMap<String, RuleEntry>> {
        Ok(HashMap::new())
    }
}

async fn run() -> anyhow::Result<()> {
let settings = Settings::load_from("config/default.toml")?;
let http = reqwest::Client::new();
let provider: Arc<dyn RuleProvider> = Arc::new(MyRules);

let builtins = Builtins::new(settings.clone(), http, Arc::clone(&provider));
let rules = Arc::new(RuleManager::new(provider, settings.provider.clone()));
let checker = Checker::new(rules, builtins, Vec::new(), None, settings.global_policy.clone());
Ok(())
}
```

A runnable version is in [`examples/embed_checker.rs`](examples/embed_checker.rs).

### Supplying extra data to the DSL

Rules can call any `$` builtin your embedding layer provides. Core deliberately
ships no external-data builtins: compose your own provider over the engine's
`Builtins` and hand it to `Checker::new_with_builtins`:

```rust
use weituo_core::{builtins::Builtins, checker::Checker};
use weituo_expr::{context::BuiltinProvider, eval::Value, EvalContext};

struct MyBuiltins {
    /// Fallback: everything the engine already knows.
    inner: std::sync::Arc<Builtins>,
}

#[async_trait::async_trait]
impl BuiltinProvider for MyBuiltins {
    async fn call(&self, name: &str, args: &[Value], ctx: &EvalContext) -> anyhow::Result<Value> {
        match name {
            "price_of" => { /* your price feed */ Ok(Value::Null) }
            _ => self.inner.call(name, args, ctx).await,
        }
    }
}
```

The same pattern supplies `ScamOracle`:

```rust
impl weituo_core::checker::ScamOracle for MyScamList {
    fn is_scam(&self, address: &str) -> bool { /* ... */ }
}
```

## State

All state (rule caches, RPC-URL cache) lives inside the instances you build and
is dropped with them: no globals, no background tasks except the optional
chain-metadata refresher you start explicitly via
`RuleManager::spawn_chain_refresher`.

## Tests

```sh
cargo test -p weituo-core
```

Some tests read the example config at `config/default.toml`.

## License

MIT — see [LICENSE](../../LICENSE).