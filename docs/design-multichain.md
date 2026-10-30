# Design: Multi-Chain Rule Checking (EVM / SVM / Sui)

Status: draft for review — not yet implemented.

Extends `weituo-expr` + `weituo-core` so the same DSL and check pipeline can
validate transactions from three chain families, while keeping the existing
EVM API and wire format **byte-compatible**.

| Family | Networks (examples) | Tx model | Naming in this repo |
| --- | --- | --- | --- |
| `evm` | 1, 137, 8453, … | calldata call to a contract | existing types, unchanged |
| `svm` | `mainnet-beta`, `devnet`, … | list of instructions to programs | new `Svm*` types |
| `sui` | `mainnet`, `testnet`, … | Programmable Transaction Block (PTB) | new `Sui*` types |

We name families after the **VM**, not the flagship network — `svm`, not
`solana` — mirroring how the repo already says `evm`, not `ethereum`.

## 1. Goals / non-goals

Goals:

1. One DSL (`weituo-expr`) and one check pipeline for all three families.
2. Zero breaking change for existing EVM embedders: same `Transaction`
   struct, same `Checker::check/test/check_sign` signatures, same JSON-RPC
   payloads, same YAML rule files, same `RuleResolver` impls.
3. Fail-closed everywhere a chain detail is under-specified.

Non-goals (deferred, §12):

- Signature-message checking for SVM (SIW) and Sui (personal-message
  intents) — `check_sign` stays EIP-712 only for now.
- On-chain simulation of SVM/Sui calls (no `eth_call` equivalent).
- Program/package-wide static policy beyond the per-rule model.

## 2. Compatibility strategy (the part existing callers care about)

Everything is **additive**. Existing types are wrapped, never mutated:

```rust
// 2.1 ChainRef — EVM keeps numeric ids, so today's keys still work
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChainRef {
    Evm(u64),          // 1, 137, 8453, …
    Svm(String),       // "mainnet-beta"
    Sui(String),       // "mainnet"
}

impl From<u64> for ChainRef {
    fn from(n: u64) -> Self { Self::Evm(n) }
}

impl ChainRef {
    /// CAIP-2-style rendering: "eip155:1" / "svm:mainnet-beta" / "sui:mainnet".
    pub fn to_family_network(&self) -> String;
}

// 2.2 Unified input — wraps the existing Transaction
pub enum ChainTx {
    Evm(Transaction),   // same struct as today, no field changes
    Svm(SvmTx),         // new
    Sui(SuiTx),         // new
}
```

```rust
// 2.3 Checker — additive methods, old ones become thin delegators
impl Checker {
    /// Unchanged signature and behavior for EVM.
    pub async fn check(&self, tx: &Transaction, r: &dyn RuleResolver) -> CheckResult;
    /// New unified entry point.
    pub async fn check_tx(&self, tx: &ChainTx, r: &dyn ChainResolver) -> CheckResult;
    /// Unified test-mode preview (mirrors `test`): inline `abi` on `SvmTx` /
    /// `SuiTx` plays the role of `Transaction.abi` today.
    pub async fn test_tx(&self, tx: &ChainTx, r: Option<&dyn ChainResolver>) -> CheckResult;
}

// 2.4 New resolver trait. NOT a blanket impl (that would forbid a type from
// implementing both); instead a zero-cost adapter struct:
pub struct CompatResolver<'a, R: RuleResolver>(pub &'a R);
// answers ChainRef::Evm(n) by delegating with n; Svm/Sui → None (fail-closed)

#[async_trait]
pub trait ChainResolver: Send + Sync {
    async fn contract_rules(
        &self,
        chain: ChainRef,
        address: &str,
    ) -> Option<HashMap<String, RuleEntry>>;
    fn chain_rpc_url(&self, chain: ChainRef) -> Option<String>;
}
```

`Checker::check` wraps the caller's `RuleResolver` in `CompatResolver`
internally, so **embedders never see the adapter**.

### What existing EVM callers change: nothing

| Surface | Impact |
| --- | --- |
| `Transaction` struct + serde format | untouched |
| `Checker::new/check/test/check_sign` signatures | untouched (`check` delegates) |
| `RuleResolver` / `RuleProvider` impls | untouched |
| `StaticResolver::new(HashMap<(u64, String), …>)` | untouched |
| EVM YAML rule files (`chain_id:` key) | untouched |
| Their HTTP `waf_*` service code for EVM txs | untouched |
| `EvalContext` literal construction | **two fields added** (`network`, `chain_fields` — §6) — minor-break, ships with constructors + `0.3.0` |
| `with_builtins_factory` | kept; new `with_chain_builtins_factory` added alongside (§7) |

Versioning: ships as `0.3.0` of both crates.

## 3. JSON wire format

A top-level `"chain"` discriminator selects the family. Parsing rules:

- **Absent `chain` → legacy EVM parse** (strict `chainId`/`to`/`data`
  requirements as today) — today's payloads are byte-identical. An
  `instructions`-shaped payload *without* `chain` therefore fails the EVM
  parser's missing-field checks: fail-closed.
- SVM and Sui payloads **require** an explicit `chain` value and a string
  `chainId` (network name); a numeric `chainId` combined with
  `chain: "svm" | "sui"` is rejected.

### 3.1 EVM (unchanged)

```json
{"chainId": 1, "from": "0x…", "to": "0x…", "data": "0x…", "value": 0}
```

### 3.2 SVM

```json
{
  "chain": "svm",
  "chainId": "mainnet-beta",
  "from": "<base58 fee payer>",
  "instructions": [
    {
      "programId": "<base58 program>",
      "accounts": ["<base58>", "…"],
      "data": "<base58 or 0x-hex bytes>"
    }
  ]
}
```

Design decisions:

- **Accounts arrive pre-resolved.** Versioned-tx address-lookup-table (ALT)
  resolution needs RPC and is an embedding-layer concern (it owns the
  resolver's RPC URL). Core v1 requires `accounts` to be the final, fully
  resolved key list per instruction. Anything that would need a lookup core
  cannot verify is fail-closed: an instruction whose program or accounts
  reference unresolved ALT indexes is rejected as `InvalidRequest`.
- `data` accepts base58 (wallet/RPC convention) and `0x`-hex (engine
  convention); decoders normalize internally.
- `from` is the fee payer (first required signer).
- Optional `raw` (base64 `VersionedTransaction`) may be accepted later for
  embedding-side convenience; core still only consumes the decoded form.

### 3.3 Sui

```json
{
  "chain": "sui",
  "chainId": "mainnet",
  "from": "0x…sender",
  "gasOwner": "0x…optional sponsor, defaults to from",
  "gasBudget": "100000000",
  "gasPrice": "750",
  "inputs": [
    {"kind": "pure", "valueType": "u64", "value": "1000000000"},
    {"kind": "pure", "valueType": "address", "value": "0xrecipient…"},
    {"kind": "object", "objectId": "0x…"}
  ],
  "commands": [
    {"MoveCall": {"target": "0x2::pay::split", "typeArguments": ["0x2::sui::SUI"],
                  "arguments": [{"GasCoin"}, {"Input": 0}]}},
    {"TransferObjects": {"objects": [{"Result": 0}], "address": {"Input": 1}}}
  ]
}
```

- Shape mirrors the Sui TypeScript SDK's `TransactionData` JSON
  serialization (`kind.programmableTransaction` is flattened to top level).
  Pure inputs additionally accept a typed JSON `value` (we BCS-encode it
  internally) or `0x`-hex raw BCS bytes.
- Sui addresses are variable-length hex (`0x2` == full 32-byte address).
  **All rule keys and comparisons normalize to the full 64-nibble lowercase
  hex** before matching; display keeps the caller's form.
- `chainId` here is the network name string; `chain: "sui"` disambiguates it
  from a hex-ish EVM id.

## 4. Normalized pipeline

Every family normalizes to the same internal unit before rule matching:

```rust
struct Call<'a> {
    target: &'a str,      // EVM contract / SVM program id / Sui package address
    selector: String,     // 4-byte hex / discriminator or tag-prefix hex / "module::function"
    args: HashMap<String, serde_json::Value>,  // decoded call arguments
    meta: CallMeta,       // family-specific context → EvalContext.chain_fields
}
```

`check_tx` then runs one loop: policy gates → per-call rule lookup → eval →
result. Per-call denials are reported with the existing
`NoRule`/`NoContract`/`ExpressionDenied` reasons; the call's index appears in
the message (`instruction[2] …` / `command[1] …`), matching the existing
`inner[i]` style.

Family-specific normalization:

| Family | `Vec<Call>` construction |
| --- | --- |
| EVM | exactly today: 1 call; multicall expands via `MulticallDecoder` only when the rule configures one (semantics preserved) |
| SVM | one call per instruction; every instruction is checked (a tx *is* a multicall) |
| Sui | one call per command; non-MoveCall commands handled by the policy layer or the native-transfer dataflow pass (§8.3) |

This collapses the existing `step_multicall` / `check_one_inner` machinery
and the new families into a single path. EVM multicall semantics (per-inner
rule lookup, `invalid_decoder`, Universal Router dispatch) are preserved
exactly — phase 1 captures characterization tests for those paths *before*
the refactor (§10).

## 5. Rules: YAML format and rule keys

`static_loader` gains an optional string form of the chain key; numeric is
EVM and stays the default:

```yaml
contracts:
  # legacy — unchanged, implies family evm
  - chain_id: 1
    address: "0xdac17f95…"
    allowlist:
      - func: "transfer(address,uint256)"
        expr: "args.value <= vars.max_usd"

  # svm — chain is a "family:network" string; func is the snake_case Anchor name
  - chain: "svm:mainnet-beta"
    address: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"   # program id
    allowlist:
      - func: "swap"
        abi: { name: "swap", args: [{name: "amount", type: "u64"}, …] }  # Anchor IDL fragment
        expr: "args.amount <= vars.max_notional"

  # sui — func is "module::function" (lowercase), abi is a named Move signature
  - chain: "sui:mainnet"
    address: "0x…package…"
    allowlist:
      - func: "pay::split"
        abi: { params: [{name: "coin", type: "0x2::coin::Coin<0x2::sui::SUI>"},
                        {name: "split_at", type: "u64"}] }
        expr: "args.split_at <= vars.max_sui"
```

Selector keys per family:

| Family | selector key | how computed |
| --- | --- | --- |
| EVM | `0x` + 4-byte keccak hex | `selector_for` (today) |
| SVM | `0x` + discriminator bytes | Anchor: `sha256("global:" + snake_case(func))[..8]`; non-Anchor: `func` as a hex **prefix** (1–8 bytes) matched against the instruction-data prefix (covers SPL tags like `0x0c`); lookup tries the full 8-byte key first, then shorter prefixes |
| Sui | `"module::function"` lowercase | as written in YAML |

Notes:

- EIP-712 sign rules already use `"domain::PrimaryType"` selectors. No
  collision: that namespace is only consumed by `check_sign` (EVM), while
  `"module::function"` is only consumed by the Sui call path.
- ABI files: `{abi_dir}/{selector}.json` keeps working for EVM. For SVM/Sui
  the same convention applies with `::` → `__` in file names
  (`pay__split.json`); inline `abi:` in YAML remains the primary path, as it
  already is for most EVM rules.
- `RuleKey` internally becomes `(ChainRef, address, selector)`.
  `static_loader::load` keeps its exact signature and delegates to a new
  `load_multi` (same YAML surface, `ChainRef`-keyed maps); the legacy
  `StaticResolver::new(HashMap<(u64, String), …>)` constructor is retained
  and routes to `ChainRef::Evm`.
- **Sui upgradeability**: publishing an upgrade mints a *new* package id, so
  rules keyed by package address are silently orphaned. Rule authors should
  target immutable packages (or pin versions) — the engine cannot detect the
  drift.

### 5.1 Authoring rules per family (examples)

The expression language is identical on every family — same operators, same
`vars`, same `in`/indexing. Only the `args.*` namespace and context
identifiers differ.

**EVM** — `args` = decoded calldata params (today, unchanged):

```yaml
- func: "transfer(address,uint256)"
  expr: "args.to in vars.my_wallets and args.value <= vars.max_usdt"
```

**SVM** — `args` = borsh-decoded Anchor params, exclusively. The
instruction's resolved account list is a separate context identifier
`accounts` (never an arg, so an IDL arg named `accounts` cannot collide).
The key difference from EVM: for SPL token transfers the recipient/mint
live in the *accounts*, not in borsh args.

```yaml
# Anchor program: borsh args by param name; to_address == program id
- func: "swap"
  expr: "args.amount <= vars.max_notional"

# Non-Anchor program (SPL Token TransferChecked): the `func` hex is a
# prefix of the instruction data, and the decoder strips exactly those
# bytes before decoding args (SPL token tags are u8). TransferChecked
# accounts = [source, mint, destination, owner]:
- func: "0x0c"
  abi: { args: [{name: "amount", type: "u64"}, {name: "decimals", type: "u8"}] }
  expr: "accounts[1] == vars.usdc_mint
         and accounts[2] in vars.my_wallets
         and args.amount <= vars.max_usdc"

# Native SOL transfer (System::Transfer): the System program tags are
# u32 LE, so the func prefix is 4 bytes — the decoder strips exactly those
# bytes before decoding args. Recipient is accounts[1].
- func: "0x02000000"
  abi: { args: [{name: "lamports", type: "u64"}] }
  expr: "accounts[1] in vars.my_wallets and args.lamports <= vars.max_sol"
```

**Sui** — `args` = BCS-decoded pure inputs by param name; object params
become object-id strings; reference params (`&mut TxContext` etc.) are
filtered before positional mapping. Generic functions expose their type
arguments as a separate context identifier `type_arguments` (also never an
arg):

```yaml
# pay::split<T>(coin: Coin<T>, split_at: u64, ctx) — refs filtered, so
# args = {coin: "<object id>", split_at: <u64>} + type_arguments
- func: "pay::split"
  abi: { params: [{name: "coin", type: "0x2::coin::Coin<T>"},
                  {name: "split_at", type: "u64"}] }
  expr: "type_arguments[0] == '0x5d4b…::usdc::USDC'
         and args.split_at <= vars.max_usdc"
```

The **native SUI transfer** (SplitCoins+TransferObjects, or `pay_sui`) is
normalized to a synthetic call under the system package with selector
`native_transfer`, so recipient allowlists work exactly like EVM `receive()`
rules:

```yaml
- chain: "sui:mainnet"
  address: "0x2"
  allowlist:
    - func: "native_transfer"
      expr: "args.recipient in vars.my_wallets and args.amount <= vars.max_sui"
```

Context identifiers available on every family: `from_address` (fee payer /
sender), `to_address` (program id / package), `chainId`, `network`; per-call
synthetic data lives in family context identifiers too — `accounts` (SVM)
and `type_arguments` (Sui) — **not** in `args`. `args.*` therefore contains
only IDL-decoded parameters, which makes the namespace collision-free by
construction. `vars` are rule-level constants, unchanged.

## 6. `EvalContext` and DSL changes

```rust
pub struct EvalContext {
    // existing fields, unchanged semantics for EVM:
    pub chain_id: u64,        // Evm(n) → n; Svm/Sui → 0 (use `network` instead)
    pub value: U256,          // EVM wei; SVM/Sui → 0 (native amounts live in args)
    pub args, from_address, to_address, gas_price, gas_limit, vars
    // new:
    pub network: String,      // family-prefixed, == ChainRef::to_family_network():
                              // "eip155:1" / "svm:mainnet-beta" / "sui:mainnet"
    pub chain_fields: HashMap<String, serde_json::Value>,  // family-specific extras
}
```

Context identifiers per family (`analyze::KNOWN_CONTEXT_FIELDS` becomes a
per-family profile):

| identifier | evm | svm | sui |
| --- | --- | --- | --- |
| `from_address` | sender | fee payer | sender |
| `to_address` | contract | **program id of the current instruction** | **package of the current MoveCall** |
| `chainId` | num (EIP-155) | str (network name) | str (network name) |
| `network` | str, family-prefixed | str, family-prefixed | str, family-prefixed |
| `value`, `gasPrice`, `gasLimit` | num | n/a (0) — SVM exposes `lamports` per-arg; Sui exposes `gasBudget`/`gasPrice` via chain_fields | n/a (0) |
| family extras via `chain_fields` | — | `instruction_index`, `num_instructions`, `signers` (str list), `accounts` (str list) | `command_index`, `num_commands`, `command_kind`, `gas_budget`, `gas_price`, `type_arguments` (str list) |

`chain_fields` is a new `EvalContext` field; bare identifiers resolve through
the family profile first, then `chain_fields` — through the same attribute
machinery as `args`, so `accounts[1]`, `accounts.length`,
`type_arguments[0]` all work. Rule-load-time validation (`analyze`) rejects
references to fields the family does not define — a rule using `$erc20_*`
on an SVM contract fails at load, not at check time, and a bare `accounts`
on an EVM rule is rejected the same way.
Sponsored flows: SVM `from_address` is the fee payer, which on a sponsored
tx differs from the instruction authority — `chain_fields.signers` exposes
the full signer list (v1 does not model per-instruction authority). Sui
sponsorship is explicit in the payload (`gasOwner`); `from_address` stays
the sender.

Address literal validation per family: EVM 20-byte hex (alloy, today);
SVM base58-decodable, 32 bytes, length ≤ 44; Sui variable-length hex parsing
to exactly 32 bytes.

Sui addresses compare as **full 64-nibble lowercase hex**. Args are
normalized at decode time; rule `vars` and expression string literals must
use the same full form — a literal `'0x2'` will not match the system
package (`0x0000…0002`). The engine cannot rewrite embedding-owned `vars`,
so this is a documented convention, and the rule-load validator warns on
short Sui address literals.

## 7. Builtin sets

`KnownBuiltins` becomes a per-family registry, while generic names
stay stable across families so simple rules port unchanged:

| builtin | evm (today) | svm | sui |
| --- | --- | --- | --- |
| `$now_ts`, `$pow` | ✓ | ✓ | ✓ |
| `$balance_of(owner)` | eth_getBalance | getBalance (lamports) | sui_getBalance SUI (mist) |
| `$is_contract(a)` / `$is_eoa(a)` | eth_getCode | account exists & executable | object is a move package |
| `$block()` / `$gas_price` | ✓ | — (fail at load) | — (fail at load) |
| `$erc20_*` | ✓ | — (fail at load) | — |
| `$spl_balance_of(token_mint, owner)` | — | getTokenAccountsByOwner (jsonParsed), summed across the owner's accounts for that mint | — |
| `$spl_allowance(mint, owner, delegate)` | — | token-account `delegate`/`delegated_amount`; an owner may hold several accounts per mint, so v1 scans all of the owner's accounts for that mint and takes the max match | — |
| `$coin_balance(owner, coin_type)` | — | — | sui_getBalance(coinType) |
| `$b32int2addr` | ✓ | — | — |
| `$price_of`, `$is_scam`, `$is_approved_token/spender`, `$is_not_blocked_spender` | embedding-provided | embedding-provided | embedding-provided |

`Builtins` (EVM) keeps its name; new `SvmBuiltins`, `SuiBuiltins` structs
implement the same `BuiltinProvider` trait. The builtins factory becomes
family-aware additively:

```rust
pub type ChainBuiltinsFactory = Arc<
    dyn Fn(ChainRef, Option<String>) -> Arc<dyn BuiltinProvider> + Send + Sync
>;
// with_builtins_factory (EVM-only signature) stays for compat;
// with_chain_builtins_factory is the new hook; default = per-family core builtins
```

All three families speak JSON-RPC 2.0 over POST, so the transport code in
`builtins.rs` is shared; only methods/param shapes differ. Sui amounts: u64
(`mist`), SVM: u64 (`lamports`) — both fit `Value::BigUint(U256)` exactly.

## 8. Decoders

Both new decoders are runtime-type-driven (the type info comes from the
rule's IDL fragment), so both are **hand-rolled byte-slice decoders** — no
`borsh`/`bcs` crate dependency is warranted for decode-only use.

### 8.1 SVM: Anchor IDL + borsh

- Rule ABI fragment: `{ name, args: [{name, type}] }` with Anchor types:
  primitives (`u8`/`u16`/`u32`/`u64`/`u128`/`u256` and signed, `bool`,
  `pubkey`), `{option: T}`, `{vec: T}`, `{array: [T, N]}`, `{defined: {name}}`
  resolved via an optional `types:` map on the same fragment (same spirit as
  EVM tuple `components`). Both legacy and current Anchor IDL type
  renderings are accepted.
- Unknown/unresolvable type at load → rule loads with args unavailable and
  **the rule is treated as fail-closed**: expressions referencing `args.*`
  error at check time (deny), never silently pass.
- Encoding: little-endian fixed ints, `bool` 1 byte, `pubkey` 32 bytes,
  string/vec = u32 LE length prefix, option = 1-byte tag.
- Discriminator: `sha256("global:" + snake_case(name))[..8]` computed at
  rule load (new dep `sha2`). When a rule's `func` is already hex, it is used
  verbatim (covers non-Anchor programs and hand-written rules).
- The decoder strips **exactly the `func` hex bytes** before decoding args:
  Anchor = 8 bytes; non-Anchor programs use their native tag width (SPL
  token: u8 → `"0x0c"`; System: u32 LE → `"0x02000000"`). Rule authors must
  supply the program's full tag — a shorter prefix strips too few bytes and
  misaligns the decode.
- Synthetic context (NOT an arg): every SVM call exposes the instruction's
  resolved account keys as the context identifier `accounts`
  (`Vec<base58>`, indexable, `.length` works). Because it lives outside the
  `args` namespace, an IDL declaring a borsh argument literally named
  `accounts` cannot collide — `args.*` is exclusively decoded parameters.

### 8.2 Sui: Move signatures + BCS

- Rule ABI fragment: `{ params: [{name, type}] }` (§5) using normalized Move
  type syntax (`u64`, `address`, `bool`, `vector<T>`, `0x2::coin::Coin<T>`,
  `Option<T>`, `string`). Bare type strings are accepted for quick rules and
  map to `__arg{i}` keys.
- Decoding `MoveCall` arguments positionally against the function signature,
  **after filtering out reference parameters**: `&T` / `&mut T` params —
  always including the trailing `&mut 0x2::tx_context::TxContext` — are
  implicit in PTB arguments and consume no argument slot. Skipping this
  filter misaligns every subsequent argument. Parameter names come from the
  rule's ABI fragment; unnamed params fall back to `__arg{i}` (as in EVM).
  - `{"Input": i}` + pure input → BCS-decode with the parameter's type:
    LE ints, `address` = 32 raw bytes (rendered full-hex), `vector<T>` =
    ULEB128 length prefix, `string` = `vector<u8>`, option = tag byte.
  - `{"Input": i}` + object input → the object id string (type `address`).
  - `{"GasCoin"}` → sentinel string `"0x2::sui::SUI"` (a gas coin *is* a SUI
    coin).
  - `{"Result": n}` / `{"NestedResult": …}` → unresolved in v1: the arg is
    `null`, and the rule-load validator **rejects rules that reference a
    parameter receiving an inter-command result** unless the command pair is
    recognized by the native-transfer pass (§8.3). Fail-closed.
- Generic functions expose their type arguments as the context identifier
  `type_arguments` (canonicalized full-form type strings, outside `args`
  for the same collision-free reason as SVM `accounts`), so rules can pin
  the coin type: `type_arguments[0] == '0x5d4b…::usdc::USDC'`.
- Move type strings arrive in two renderings (inline rule fragments like
  `u64`; normalized-function output like `U64`). A small normalizer
  canonicalizes primitives, addresses inside generics, and whitespace so
  both sources produce identical selectors and decode identically.
- Move signature source: inline in the rule (primary), or fetched via
  `sui_getNormalizedMoveFunction` by the embedding layer and fed inline.

### 8.3 Sui native-transfer dataflow (v1 pragmatic pass)

The canonical wallet SUI transfer is a two-command pattern:

```
SplitCoins(GasCoin, [amount]) → TransferObjects([Result(0)], recipient)
```

The normalizer recognizes this (and the single `0x2::pay::pay_sui` form),
resolves `amount` and `recipient` from the pure inputs, and produces one
synthetic call per transfer with `args.amount` / `args.recipient` — so rules
like `args.amount <= vars.max_sui and args.recipient in vars.my_wallets`
work without general dataflow. All other inter-command references fall back
to the fail-closed rule of §8.2. General dataflow is future work.

## 9. Policy mapping

`Policy` fields map per family. **Gate order is identical on every family**:
allowlist → creation gate → native-transfer gate → token-op gate (only when
rule lookup fails) → rule lookup. On Sui, `pay_sui` / `split` over the gas
coin are consumed by the native-transfer gate first (§8.3); the same targets
over a non-gas coin fall through to the token-op gate.

| Policy field | evm (today) | svm | sui |
| --- | --- | --- | --- |
| `allow_contract_creation` | `tx.to == ""` | n/a (deploy = BPF-loader upgrade, rare; treat as normal rule path) | `Publish` / `Upgrade` command present → deny unless allowed |
| `allow_native_transfer` | empty calldata | **all** instructions are `System::Transfer` (program `1111…1111`, u32 LE tag 2) | PTB matches the §8.3 native-transfer pattern |
| `token_op_policy` | selectors `0xa9059cbb` / `0x095ea7b3` | SPL token programs (`Tokenkeg…`, `TokenzQd…` = Token-2022) first byte `3` transfer, `12` transferChecked, `4` approve, `13` approveChecked | MoveCall targets: `0x2::coin::transfer`, `0x2::pay::{pay, pay_sui, split, split_vec}` |
| `transaction_types` | EIP-2718 types | n/a (ignored) | n/a (ignored) |

Allowlist bypass (`Checker.allowlist`) applies to `from_address` on all
families unchanged.

## 10. Testing plan

- **EVM regression is the gate for phase 1**: characterization tests for the
  Multicall3 / BytesArray / ParallelArrays / UniversalRouter paths are
  captured *before* the refactor; afterwards the full existing suite must
  pass unchanged, plus new tests proving `check` ≡ `check_tx(Evm(tx))`.
- SVM golden vectors: real mainnet fixtures (System::Transfer, SPL
  TransferChecked/ApproveChecked, an Anchor call with the discriminator
  computed via `sha2` in-test) with accounts **pre-resolved in the fixture**
  — core never sees indexes or ALTs, so tests pin the resolved-list
  contract, not index-order semantics.
- Sui golden vectors: the §3.3 PTB (SplitCoins + TransferObjects with
  `Result(0)` dataflow), a plain `coin::transfer` MoveCall, a `Publish`
  policy denial, variable-length addresses (`0x2`) normalized against
  full-hex rule keys.
- Fail-closed tests: SVM instruction whose borsh payload runs out of bytes
  mid-argument or whose IDL references an unresolvable `defined` type, Sui
  rule referencing an unresolvable `Result`, unknown builtin per family
  rejected at load.

## 11. Phases

Workflow is test-first (TDD): every phase lands as failing golden-vector /
characterization tests before the implementation that turns them green.

1. **Foundations** — `ChainRef`, `ChainTx`, `ChainResolver` + `CompatResolver`,
   normalized `Call` model refactor behind `check`/`check_tx`, `EvalContext`
   fields, per-family analyze profiles (EVM = today), YAML `chain:` key.
   EVM-only, fully green.
2. **SVM** (feature `svm`) — `SvmTx` + JSON deser, discriminator computation,
   hand-rolled borsh decoder + IDL plumbing, `SvmBuiltins`, policy mapping,
   `test_tx` with inline ABI, golden vectors.
3. **Sui** (feature `sui`) — `SuiTx` + JSON deser, hand-rolled BCS decoder,
   native-transfer dataflow pass, `SuiBuiltins`, policy mapping, `test_tx`
   with inline Move signatures, golden vectors.
4. **Polish** — README + `embed_checker` multi-chain example, `0.3.0` bump,
   CI matrix (EVM-only build with `--no-default-features`).

New dependencies: `sha2`, `base58` (both tiny, pure Rust). The `svm` / `sui`
features are enabled by default; EVM-only embedders build with
`default-features = false`.

## 12. Deferred (explicitly out of scope for `0.3.0`)

- `check_sign` equivalents: Sign-In-With-Solana off-chain messages; Sui
  personal-message / intent messages. Both need a normalized sign-request
  model — separate design when needed.
- `raw` base64 SVM tx input + in-core ALT resolution.
- General Sui command dataflow (arbitrary `Result`/`NestedResult` graphs).
- SVM on-chain reads beyond balance/program checks (e.g. `simulateTransaction`
  as an `$svm_simulate` escape hatch).
- Sui checkpoint-based `$block()` analog.
- Cross-instruction / cross-command aggregate constraints (e.g. "total SVM
  lamports out across all instructions", "total SUI out across the PTB") —
  v1 checks each call independently.
- Sui object-input metadata (type/owner of referenced objects) for rules —
  v1 exposes only the object id string.
