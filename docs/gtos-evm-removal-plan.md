# GTOS EVM Removal Plan

## Background

GTOS uses fixed system contract addresses with direct Go execution for all on-chain logic
(agent registration, staking, delegation, reward distribution). No user-deployed smart
contracts are supported. This makes the full EVM interpreter unnecessary dead weight.

However, `core/vm/contracts.go` contains cryptographic primitives (precompiled contracts)
that are used independently of the EVM interpreter and must be retained.

---

## Decision: Partial Removal of `core/vm/`

We do **not** delete the entire `core/vm/` directory. Instead:

- **Keep**: precompiled contracts and their support types
- **Delete**: EVM interpreter, opcode table, memory/stack engine, gas table

---

## What to Keep

### `core/vm/contracts.go` — Cryptographic Precompiles

These are pure Go functions, independent of the EVM interpreter. Used for signature
verification, hashing, and elliptic curve operations throughout the chain core.

| Address | Name | Purpose |
|---------|------|---------|
| 0x01 | `ecrecover` | Transaction signature recovery — **critical** |
| 0x02 | `sha256` | SHA-256 hash |
| 0x03 | `ripemd160` | Legacy hash |
| 0x04 | `identity` | Data copy |
| 0x05 | `modexp` | Big integer modular exponentiation |
| 0x06–0x08 | `bn256Add/Mul/Pairing` | zkSNARK elliptic curve ops |
| 0x09 | `blake2f` | BLAKE2 compression (Schnorr support) |
| 0x0a–0x12 | `bls12-381` | BLS signature operations |

### Other `core/vm/` files to keep

- `core/vm/common.go` — shared utility types
- `core/vm/contracts_test.go` — precompile unit tests
- `core/vm/gas.go` — base gas constants (still used for tx intrinsic gas)

---

## What to Delete

### EVM Interpreter (inside `core/vm/`)

| File | Description | Size |
|------|-------------|------|
| `evm.go` | EVM main executor | ~20 KB |
| `interpreter.go` | Bytecode interpreter loop | ~8 KB |
| `instructions.go` | All opcode implementations | ~29 KB |
| `jump_table.go` | Opcode dispatch table | ~27 KB |
| `memory.go` | EVM memory model | ~4 KB |
| `stack.go` | EVM stack | ~3 KB |
| `gas_table.go` | Per-opcode gas costs | ~15 KB |
| `operations_acl.go` | Access list gas ops | ~6 KB |
| `runtime/` | Standalone EVM test runner | ~5 KB |

### Smart Contract Toolchain

| Path | Description |
|------|-------------|
| `accounts/abi/` | Solidity ABI encode/decode (25 files) |
| `accounts/abi/bind/` | Contract binding code generator (9 files) |
| `contracts/checkpointoracle/` | Light client checkpoint contract |
| `cmd/abigen/` | ABI code generation CLI tool |
| `cmd/evm/` | Command-line EVM execution tool |
| `tos/tracers/` | EVM execution tracers (debug only) |
| `graphql/` | GraphQL API (depends on EVM tracer APIs) |

---

## Core Refactor: `core/state_transition.go`

### Current call chain

```
BlockChain.insertChain()
└─ StateProcessor.Process()
   └─ applyTransaction()
      └─ ApplyMessage()                 ← core/state_transition.go
         └─ StateTransition.TransitionDb()
            ├─ preCheck()
            ├─ IntrinsicGas()
            ├─ evm.Call() / evm.Create() ← EVM interpreter invoked here
            └─ refundGas()
```

### New call chain (post-removal)

```
StateProcessor.Process()
└─ applyTransaction()
   ├─ [tx.To == SystemActionAddress] → sysaction.Execute(msg, statedb, header)
   ├─ [plain transfer: no data, no contract code] → statedb.Transfer(from, to, value)
   └─ [anything else] → return error: "contract execution not supported"
```

### Changes to `core/state_transition.go`

Remove:
- `evm.Call()` / `evm.Create()` invocations
- All `vm.EVM` struct references
- Gas refund logic tied to EVM execution
- Contract creation path

Keep:
- `preCheck()` — nonce and balance validation
- `IntrinsicGas()` — base gas for tx fee deduction
- `buyGas()` / `refundGas()` — fee mechanics
- Balance transfer for plain value transfers

---

## Implementation Steps

1. **Create branch** `feature/remove-evm` from `main`

2. **Delete EVM interpreter files** from `core/vm/`:
   - `evm.go`, `interpreter.go`, `instructions.go`, `jump_table.go`
   - `memory.go`, `stack.go`, `gas_table.go`, `operations_acl.go`
   - `runtime/` directory

3. **Delete smart contract toolchain**:
   - `accounts/abi/`
   - `accounts/abi/bind/`
   - `contracts/checkpointoracle/`
   - `cmd/abigen/`
   - `cmd/evm/`
   - `tos/tracers/`
   - `graphql/`

4. **Rewrite `core/state_transition.go`**:
   - Remove `vm.EVM` dependency
   - Replace `evm.Call()` with direct `statedb.Transfer()`
   - Add system action dispatch before transfer logic

5. **Rewrite `core/state_processor.go`**:
   - Remove `vm.NewEVM()` call
   - Remove `vm.Config` parameter threading
   - Simplify `applyTransaction()` to the two-path model

6. **Remove `core/evm.go`**:
   - This file only sets up `vm.BlockContext` and `vm.TxContext`
   - Replace with minimal context struct for system action executor

7. **Fix compilation errors** across all packages that imported removed modules:
   - `tos/api_backend.go` — remove tracer/EVM config references
   - `tos/state_accessor.go` — remove EVM state replay
   - `les/` — remove EVM references in light client
   - `internal/tosapi/api.go` — remove `CallArgs`, `EstimateGas`, `Call` RPC methods
   - `cmd/gtos/` — remove EVM-related CLI flags

8. **Remove EVM-dependent RPC methods** from `internal/tosapi/api.go`:
   - `eth_call` → remove
   - `eth_estimateGas` → remove
   - `debug_traceTransaction` → remove
   - `debug_traceCall` → remove

9. **Run `go build ./...`** and fix all remaining errors

10. **Run tests**: `go test ./core/... ./tos/... ./consensus/...`

---

## RPC Methods Removed

The following JSON-RPC methods will no longer be available (they require EVM):

| Method | Reason removed |
|--------|---------------|
| `tos_call` | EVM contract call |
| `tos_estimateGas` | EVM gas estimation |
| `debug_traceTransaction` | EVM tracer |
| `debug_traceCall` | EVM tracer |
| `debug_traceBlockByHash/Number` | EVM tracer |

All other standard methods remain:
`tos_getBalance`, `tos_sendRawTransaction`, `tos_getTransactionByHash`,
`tos_getBlockByNumber`, `tos_blockNumber`, `net_version`, etc.

---

## Code Size Reduction (Estimate)

| Removed component | Estimated lines |
|-------------------|----------------|
| EVM interpreter (core/vm) | ~12,000 |
| accounts/abi + bind | ~8,000 |
| tos/tracers | ~5,000 |
| graphql | ~3,000 |
| cmd/abigen + cmd/evm | ~1,500 |
| contracts/checkpointoracle | ~500 |
| **Total** | **~30,000 lines** |

---

## Non-Goals

- Removing `core/vm/contracts.go` (precompiles are kept and used)
- Removing gas fee mechanics (tx fees still apply)
- Removing `core/state/` (StateDB is the foundation of all on-chain state)
- Removing consensus engine (Clique or new TOS consensus still needed)
