# weituo-expr

The rule DSL for [weituo](../..): a pest-based parser and an async evaluator.
No WAF concepts, no I/O — just expressions over a context.

```toml
[dependencies]
weituo-expr = "0.2"
```

## The language

```text
args.amount > 0 and args.to != "0x0000000000000000000000000000000000000000"
$pow(10, 18) <= args.amount
args.maker in ["0xaaa...", "0xbbb..."]
args.nonce not in [0]
$block("latest").timestamp + 86400 > $now_ts()
```

- **Literals** — integers (`10`), floats (`1e9`, `0.5`), strings (`"a"` / `'a'`),
  `true` / `false`, `null` (also `None`), and array literals `[1, 2, 3]`.
- **Operators** — `and`, `or`, `not`, `in` / `not in`, `==`, `!=`, `<`, `<=`,
  `>`, `>=`, `=~` (regex match), `<<`, `>>`, `+`, `-`, `*`, `/`, `%`, unary `-`,
  and parentheses.
- **Attribute access** — `args.to`, `args.orders[0].recipient`,
  `args.path.length`.
- **Calls** — `$name(...)` resolves through the injected
  [`BuiltinProvider`](src/context.rs); bare `name(...)` calls registered
  functions.

Arithmetic on decoded `uint256` values is exact (backed by
`alloy_primitives::U256`), not floating point.

## API

```rust
use weituo_expr::{evaluate, parse, validate_syntax, EvalContext, Value};

assert_eq!(validate_syntax("args.amount > 0"), None);

let ast = parse("args.amount > 1e9").unwrap();
let ctx = EvalContext::new(1, "0xfrom", "0xto");
let value = evaluate(&ast, &ctx, builtins).await?;   // -> Value::Bool(..)
```

- `parse` / `validate_syntax` / `validate_full` — parsing and static checks
  (unknown `args.*` fields, `$` builtin arity, …).
- `evaluate` / `evaluate_explain` — async evaluation; the `_explain` variant
  returns the `Explain` trace used for error messages.
- `Value` — `Bool`, `Int(i64)`, `BigUint(U256)`, `BigInt(I256)`, `Float(f64)`,
  `Str`, `Null`, `Json`.
- `BuiltinProvider` — implement it to expose `$` functions to expressions; it is
  the only extension point the evaluator needs.

## Tests

```sh
cargo test -p weituo-expr
```

## License

MIT — see [LICENSE](../../LICENSE).