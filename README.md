# weituo

Reusable Rust libraries for **EVM transaction and signature rule checking**,
extracted from the weituo Web Application Firewall.

The service layer — HTTP JSON-RPC server, request authentication, metrics,
concrete rule providers, price oracles — is intentionally *not* part of this
repository. What is here is the part meant to be embedded in other services:

| Crate | What it does |
| --- | --- |
| [`weituo-expr`](crates/expr) | The rule DSL: a pest-based parser and an async evaluator (`Value`, `EvalContext`, `BuiltinProvider`) |
| [`weituo-core`](crates/core) | The engine: rules (`RuleProvider` trait / static YAML loader), calldata decoder, builtins, and the `Checker` state machine |

The dependency direction is strictly one-way — `weituo-core` depends on
`weituo-expr`, never the reverse — so `weituo-expr` can be used standalone for
any expression-evaluation need.

## Layout

```
crates/
  expr/           weituo-expr — DSL parser + evaluator
  core/           weituo-core — rule-check engine (no HTTP)
config/
  default.toml    example configuration used by the tests
```

## Quick start

```toml
[dependencies]
weituo-core = "0.2"
reqwest     = "0.12"   # used by Builtins for chain RPC helpers
tokio       = "1"
anyhow      = "1"
```

```rust
use std::{collections::HashMap, sync::Arc};

use weituo_core::{
    builtins::Builtins,
    checker::{CheckResult, Checker},
    config::Settings,
    provider::{ChainInfo, RuleProvider},
    rule_manager::RuleManager,
    types::{RuleEntry, Transaction},
};

/// Supply rules from wherever they live (HTTP API, database, files…).
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
let checker = Checker::new(
    rules,
    builtins,
    Vec::new(), // address allowlist
    None,       // no scam oracle injected
    settings.global_policy.clone(),
);

let tx: Transaction = serde_json::from_value(serde_json::json!({
    "chainId": 1,
    "from": "0x1111111111111111111111111111111111111111",
    "to": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "data": "0x",
    "value": 0,
}))?;

match checker.check(&tx).await {
    CheckResult::Ok => println!("allowed"),
    CheckResult::Denied(reason) => println!("denied: {reason}"),
}
Ok(())
}
```

A compiling version of this lives in
[`crates/core/examples/embed_checker.rs`](crates/core/examples/embed_checker.rs)
(`cargo run -p weituo-core --example embed_checker`).

All engine state (rule caches) lives inside the instances you construct — no
globals, no background tasks, no listeners. The caller owns the lifetime.

## Development

```sh
cargo +nightly fmt --all                                              # rustfmt runs on nightly
cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Publishing

Publish in dependency order; run each dry run first:

```sh
cargo publish --dry-run -p weituo-expr
cargo publish           -p weituo-expr
cargo publish --dry-run -p weituo-core
cargo publish           -p weituo-core
```

`weituo-core` declares `weituo-expr` with both `path` (local development) and
`version` (required by crates.io), so the two must be released together.

## License

MIT — see [LICENSE](LICENSE).