# weituo

Reusable Rust libraries for **EVM transaction and signature rule checking**,
extracted from the weituo Web Application Firewall.

The service layer — HTTP JSON-RPC server, request authentication, metrics,
concrete rule providers and their caches, price oracles, scam lists — is
intentionally *not* part of this repository. What is here is the stateless
part meant to be embedded in other services:

| Crate | What it does |
| --- | --- |
| [`weituo-expr`](crates/expr) | The rule DSL: a pest-based parser and an async evaluator (`Value`, `EvalContext`, `BuiltinProvider`) |
| [`weituo-core`](crates/core) | The engine: calldata decoder, chain-data RPC builtins, and the stateless `Checker` (`check(tx, rules) → allow/deny`) |

The dependency direction is strictly one-way — `weituo-core` depends on
`weituo-expr`, never the reverse — so `weituo-expr` can be used standalone for
any expression-evaluation need.

Both crates are **stateless**: no config files, no global state, no background
tasks. Rule caches, configuration, and external data (prices, scam lists)
belong to the embedding layer.

## Layout

```
crates/
  expr/           weituo-expr — DSL parser + evaluator
  core/           weituo-core — rule-check engine (no HTTP server, no config)
```

## Quick start

```toml
[dependencies]
weituo-core = "0.2"
reqwest     = "0.12"   # used by the engine's $-builtins for chain RPC
tokio       = "1"
anyhow      = "1"
```

```rust
use std::collections::HashMap;

use weituo_core::{
    checker::{CheckResult, Checker},
    policy::Policy,
    provider::{ChainInfo, RuleResolver, StaticResolver},
    types::{RuleEntry, Transaction},
};

/// Rules come from wherever they live — a cached HTTP backend
/// (`RuleProvider`), local YAML (`static_loader`), a database. Here: memory.
struct MyRules;

#[async_trait::async_trait]
impl RuleResolver for MyRules {
    async fn contract_rules(
        &self,
        _chain_id: u64,
        _address: &str,
    ) -> Option<HashMap<String, RuleEntry>> {
        None // contract unknown → the checker denies with NoContract
    }

    fn chain_rpc_url(&self, _chain_id: u64) -> Option<String> {
        None // $-builtins that need the chain will error if a rule uses them
    }
}

async fn run() -> anyhow::Result<()> {
let checker = Checker::new(reqwest::Client::new(), Vec::new(), Policy::default());
let tx: Transaction = serde_json::from_str(r#"{
    "chainId": 1, "from": "0x…", "to": "0x…", "data": "0x…", "value": 0
}"#)?;

match checker.check(&tx, &MyRules).await {
    CheckResult::Ok => println!("allowed"),
    CheckResult::Denied(reason) => println!("denied: {reason}"),
}
Ok(())
}
```

A compiling version lives in
[`crates/core/examples/embed_checker.rs`](crates/core/examples/embed_checker.rs)
(`cargo run -p weituo-core --example embed_checker`).

## Architecture

```
embedding layer (yours)                     weituo-core
┌─────────────────────────────┐            ┌──────────────────────────┐
│ config files, env, CLI      │  Policy    │                          │
│ rule backend + TTL cache    │─(resolver)→│ Checker::check(tx, rules)│
│ scam list, price feeds      │  builtins  │  decoder · expr · policy │
│ HTTP server, auth, metrics  │  (factory) │  $-builtins (chain RPC)  │
└─────────────────────────────┘            └──────────────────────────┘
```

The engine holds no caches and reads no configuration: every check receives
its rules through a [`RuleResolver`](crates/core/src/provider/mod.rs), and
every decision parameter is handed to `Checker::new`. Scam screening is an
embedding concern — decode the approve spender in your layer, consult your
own list, deny before calling the checker.

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
