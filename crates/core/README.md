# weituo-core

The reusable EVM WAF rule-check engine: it evaluates transactions and EIP-712
signatures against rules expressed in the [`weituo-expr`](../expr) DSL. No HTTP
server, no auth, no metrics, **no configuration, no state** — everything
stateful belongs to the embedding service.

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
| `provider::RuleProvider` | Trait for fetching rules from a backend: `fetch_chain_info` (RPC URL per chain) and `fetch_contract_rules` (per-selector rules). Implement it over HTTP, a database, or anything else — and cache it yourself. |
| `provider::RuleResolver` | What the checker consumes per call: `contract_rules(chain, address)` + `chain_rpc_url(chain)`. Typically a TTL cache sitting on a `RuleProvider`. `StaticResolver` is an in-memory implementation. |
| `static_loader` | Loads rules from local YAML + ABI JSON files (`waf.yaml` style) — one call, no daemon. |
| `decoder` | Decodes calldata against the rule's ABI (`alloy-dyn-abi`), including tuples and arrays; builds multicall decoders. |
| `builtins::Builtins` | The engine's `$` builtins: chain data read over JSON-RPC (`$block`, `$gas_price`, `$balance_of`, `$erc20_*`, `$is_contract`, …) plus pure helpers (`$now_ts`, `$pow`, `$b32int2addr`). Bound to one chain's RPC endpoint, no internal state. |
| `checker::Checker` | The decision engine. Holds only the `Policy`, the allowlist and an HTTP client — constructed once, called many times. |
| `policy::Policy` | Plain parameter struct: transaction-type allowlist, contract-creation / native-transfer gates, token-op policy. |
| `parse_rule` | Syntax + semantic validation of a single rule expression, for rule-authoring UIs. |

There is deliberately **no scam concept in core**: the embedding layer decodes
the `approve` spender itself, consults its own scam list and denies before
invoking the checker.

## The check pipeline

`Checker::check(&tx, &resolver)` runs, in order:

1. **transaction type policy** — `policy.transaction_types`;
2. **allowlist** — `from` address allowlist (handed to `Checker::new`);
3. **contract creation** — `to` empty ⇒ `policy.allow_contract_creation`;
4. **native transfer** — empty calldata ⇒ `policy.allow_native_transfer`;
5. **rule lookup** — `resolver.contract_rules(chain, to)` for the derived
   selector (`"*"` wildcard supported); unknown contract ⇒ `NoContract`,
   missing selector ⇒ token-op policy (`AllowAll` / `DenyAll` /
   `RequireRule` / `Whitelist`);
6. **clause evaluation** — the rule's expressions against the decoded args;
7. **multicall** — nested calls, when the rule declares a multicall decoder
   (inner calls are resolved through the same resolver).

`Checker::check_sign(&req, &resolver)` is the EIP-712 counterpart;
`Checker::test(&tx, resolver)` is the rule-preview entry point.

Denials come back as a typed `DenyReason` (which renders to a JSON-RPC error
with `to_rpc_error()`), so callers can map them to their own protocol.

## Embedding

```rust
use std::collections::HashMap;

use weituo_core::{
    checker::Checker,
    policy::Policy,
    provider::{ChainInfo, RuleResolver, StaticResolver},
    types::RuleEntry,
};

async fn run() -> anyhow::Result<()> {
// Rules pre-loaded from `static_loader::load` (or fetched from your backend):
let resolver = StaticResolver::new(rules, chains /* HashMap<u64, ChainInfo> */);

let checker = Checker::new(
    reqwest::Client::new(),
    Vec::new(),          // sender allowlist
    Policy::default(),   // or deserialized from your own config layer
);

let tx: weituo_core::types::Transaction = serde_json::from_value(tx_json)?;
match checker.check(&tx, &resolver).await {
    weituo_core::checker::CheckResult::Ok => println!("allowed"),
    weituo_core::checker::CheckResult::Denied(reason) => println!("denied: {reason}"),
}
Ok(())
}
```

A runnable version is in [`examples/embed_checker.rs`](examples/embed_checker.rs)
(`cargo run -p weituo-core --example embed_checker`).

### Caching rules from a backend

Implement `RuleResolver` over your own cache; `RuleProvider` is the fetch
contract the cache refreshes from:

```rust
use std::collections::HashMap;

use weituo_core::provider::RuleResolver;
use weituo_core::types::RuleEntry;

struct MyCache { /* e.g. moka/TTL map + a RuleProvider for refreshes */ }

#[async_trait::async_trait]
impl RuleResolver for MyCache {
    async fn contract_rules(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Option<HashMap<String, RuleEntry>> {
        None // `None` = contract unknown → NoContract; missing selector → NoRule
    }

    fn chain_rpc_url(&self, chain_id: u64) -> Option<String> {
        None // $-builtins error "no RPC for chain N" when None and used
    }
}
```

### Supplying extra data to the DSL

Rules can call any `$` builtin your embedding layer provides. Core ships no
external-data builtins: compose your own provider over the engine's `Builtins`
and install it with `Checker::with_builtins_factory`:

```rust
use weituo_core::builtins::Builtins;
use weituo_expr::{context::BuiltinProvider, eval::Value, EvalContext};
use std::sync::Arc;

struct MyBuiltins {
    /// Fallback: everything the engine already knows.
    inner: Builtins,
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

// let checker = Checker::new(http, allowlist, policy)
//     .with_builtins_factory(Arc::new(|rpc_url| {
//         Arc::new(MyBuiltins { inner: Builtins::new(http.clone(), rpc_url) })
//     }));
```

## Tests

```sh
cargo test -p weituo-core
```

## License

MIT — see [LICENSE](../../LICENSE).
