# Lua VM Integration — Standard CREATE/CALL Semantics

## Overview

GTOS uses Lua as its smart contract execution engine. The external interface is
fully aligned with standard Ethereum JSON-RPC: contract deployment uses CREATE
semantics (`To == nil`), and contract calls use standard CALL semantics
(`To != nil` with code at the destination).

---

## Ethereum Standard Flow (go-ethereum v1.10.25 baseline)

### DEPLOY (CREATE)

```
To == nil → applyCreate()
  ├─ addr = keccak256(RLP(sender, nonce))[12:]   (crypto.CreateAddress)
  ├─ collision check (nonce != 0 || code != empty)
  ├─ CreateAccount(addr), SetNonce(addr, 1)      (EIP-158)
  ├─ Transfer(sender → addr, value)              (optional)
  ├─ charge 200 gas/byte for code storage
  ├─ SetCode(addr, tx.Data)                      (Lua source stored directly)
  └─ receipt.ContractAddress = addr              (DeriveFields auto-computes)
```

### CALL

```
To != nil, code at dest → applyLua(code)
  ├─ snapshot
  ├─ Transfer value
  ├─ code = StateDB.GetCode(addr)
  └─ executeLuaVM(ctx, code, gas, calldata)
```

---

## Lua VM vs EVM: Key Differences

| Point | EVM | Lua VM |
|---|---|---|
| initcode vs runtime | two distinct bytecodes | **same code** |
| constructor execution | runs at deploy time | **not run at deploy** |
| address derivation | `keccak256(RLP(sender, nonce))` | **same** |
| code lifetime | permanent | **permanent** (TTL removed) |

**Key design decision: deployment does not execute code.** Contract source is
stored verbatim at the derived address. The `tos.oncreate(fn)` pattern handles
initialization: the registered function runs automatically on the first CALL.

---

## Deployment Flow (before vs after)

### Before (setCode — removed)

```
Client → eth_sendTransaction({to: null, data: RLP{v=1, ttl=86400, code=...}})
GTOS:  applySetCode() → TTL check → store code at sender address
addr:  msg.From()  (sender's own address — non-standard)
```

### After (CREATE — standard)

```
Client → eth_sendTransaction({to: null, data: <lua source>})
GTOS:  applyCreate() → derive addr → collision check → SetCode
addr:  crypto.CreateAddress(sender, nonce)
receipt.contractAddress = CreateAddress(sender, nonce)  (auto via DeriveFields)
```

---

## Call Flow (unchanged)

```
Client → eth_sendTransaction({to: contractAddr, data: selector+args})
GTOS:  applyLua(code) → executeLuaVM(ctx, code, gas)
```

### staticcall (unchanged)

```
tos.staticcall(addr, calldata)  →  readonly=true propagates to all sub-calls
```

### delegatecall (unchanged)

```
tos.delegatecall(addr, calldata)  →  caller's from+value inherited
```

---

## Gas Model

| Operation | Gas |
|---|---|
| Intrinsic (CREATE) | `params.TxGasContractCreation` |
| Code storage | 200 gas / byte |
| Lua execution | charged against remaining gas |
| Value transfer | standard balance check, no extra gas |

---

## Removed APIs

The following non-standard RPCs have been removed:

- `tos_setCode(from, code, ttl)` → use `eth_sendTransaction({to: null, data: luaCode})`
- `tos_estimateSetCodeGas(code, ttl)` → use standard gas estimation with `to: null`
- `tos_getCodeMeta(addr, block)` → TTL metadata no longer relevant; code is permanent

---

## Affected Files

| File | Change |
|---|---|
| `core/state_transition.go` | Added `applyCreate()`, removed `applySetCode()` and `ErrCodeAlreadyActive` |
| `core/setcode_payload.go` | Deleted |
| `core/setcode_payload_test.go` | Deleted |
| `params/protocol_params.go` | Removed `SetCodeTTLBlockGas` |
| `internal/tosapi/transaction_args.go` | Removed `allowSetCodeCreation`; `To==nil` now uses CREATE gas |
| `internal/tosapi/api.go` | Removed `SetCode`, `EstimateSetCodeGas`, `RPCSetCodeArgs`, `GetCodeMeta`, `RPCCodeMetaResult` |
| `internal/tosapi/api_putcode_test.go` | Deleted |

**Not modified:** `core/lua_contract.go`, `core/lua_abi.go`, `core/lua_stdlib.go`,
`core/lua_contract_test.go`, `core/parallel/`, `core/state_processor.go`,
`core/types/receipt.go`.
