# Atomic Execution v1

**Status: IMPLEMENTED (2026-03-21)**

## Purpose

This document defines cross-contract atomicity and nested-call rollback
semantics in GTOS / LVM.

The core question: when agent-native flows span multiple contracts, what
rollback guarantees does the system make, and at what boundary?

---

## 1. Current Semantics (per-contract atomicity)

Every call path in the LVM takes a `StateDB.Snapshot()` before child execution
and calls `RevertToSnapshot()` on child failure:

| Call path | Snapshot line | Revert line | Covers |
|-----------|-------------|-------------|--------|
| `LVM.Call` | 222 | 238, 252, 263 | Top-level transaction |
| `tos.call` | 2967 | 3012 | Nested call to another contract |
| `tos.staticcall` | 3087 | 3122, 3137 | Readonly nested call (reverts even on success) |
| `tos.delegatecall` | 3216 | 3247 | Implementation call using caller's storage |
| `tos.package_call` | 4551 | 4574 | Package-dispatched call |
| `deployRawContract` | 3300 | 3320 | Contract creation |

**Guarantee:** Each individual call is atomic — if a callee fails, its storage
mutations and value transfers are rolled back. The caller's state before the
call is preserved.

**Not guaranteed:** If a caller makes call A (succeeds) then call B (fails),
call A's mutations persist. There is no automatic rollback of earlier
successful calls.

---

## 2. The Gap

Agent-native commerce requires multi-contract atomic flows:

- `finalizeReceipt()` + `releaseEscrow()` — both must succeed or both revert
- `chargeSponsor()` + `executeMerchant()` — sponsor budget and merchant payment
  must be atomic
- `completeAgreement()` + `emitEvidence()` + `recordReceipt()` — settlement
  trace must be all-or-nothing

Without cross-contract atomicity, coordinators must manually check return
values and undo earlier calls — error-prone and not auditable.

---

## 3. Chosen Primitive: `tos.atomic_multicall`

### API

```lua
local ok, results = tos.atomic_multicall({
  { addr = receipt_addr, data = finalize_calldata },
  { addr = escrow_addr, data = release_calldata, value = 0, gas = 100000 },
})
```

### Semantics

- Takes a **single outer** `stateDB.Snapshot()` before the first child call
- Executes N child calls **sequentially**
- If **ANY** child fails → `stateDB.RevertToSnapshot(outerSnap)` — all calls
  rolled back, return `(false, revertDataHex | nil)`
- If **ALL** succeed → snapshot abandoned (committed), return
  `(true, {ret1, ret2, ...})`

### Parameters (per entry)

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `addr` | hex string | Yes | — |
| `data` | hex string | No | empty |
| `value` | uint256 | No | 0 |
| `gas` | uint64 | No | remaining / 64 |

### Return values

| Outcome | Return 1 | Return 2 |
|---------|----------|----------|
| All succeed | `true` | Lua table of hex return data per call |
| Any fails | `false` | Hex revert data from failing call (or nil) |
| Empty input | `true` | Empty table |

### Guards

- **Readonly:** raises error if `ctx.Readonly` (staticcall context)
- **Depth:** raises error if `ctx.Depth >= maxCallDepth`
- **Gas:** per-child gas computed identically to `tos.call`

---

## 4. Gas Model

Gas accounting is identical to `tos.call`:

- Each child's consumed gas is added to `totalChildGas`
- After each child, parent's gas limit is adjusted via `L.SetGasLimit()`
- If gas is exhausted mid-batch, the outer snapshot is reverted and consumed
  gas is still deducted
- Explicit per-child gas caps are supported via the `gas` field

---

## 5. Value Transfer

- Value transfers happen inside the outer snapshot
- If any child fails, `RevertToSnapshot` rolls back all value transfers
  (including earlier successful ones)
- This is correct because `StateDB.RevertToSnapshot` reverts balance changes

---

## 6. Revert Data Propagation

- When a child fails with structured revert data (e.g.,
  `tos.revert("InsufficientFunds", "uint256", 42)`), the revert data is
  returned as the second value of `atomic_multicall`
- Only the failing child's revert data is returned (not earlier calls')

---

## 7. Nesting and Depth

- `atomic_multicall` itself does not consume a depth level
- Each child call increments depth by 1 from the caller's depth
- `atomic_multicall` inside a `tos.call` child works correctly because
  `StateDB.Snapshot()` is nestable

---

## 8. Backward Compatibility

- **No change** to existing `tos.call`, `tos.staticcall`, `tos.delegatecall`,
  `tos.package_call` behavior
- `atomic_multicall` is a new, opt-in primitive
- Contracts that don't use it behave exactly as before

---

## 9. Test Matrix

### GTOS tests (`core/vm/lvm_rollback_test.go`)

| Test | Scenario | Status |
|------|----------|--------|
| `TestAtomicMulticallAllSucceed` | 2 calls succeed, both mutations visible | PASS |
| `TestAtomicMulticallSecondFailsFirstRolledBack` | A writes, B fails → A rolled back | PASS |
| `TestAtomicMulticallMiddleFailsAllRolledBack` | 3 calls, middle fails → all rolled back | PASS |
| `TestAtomicMulticallValueTransferRollback` | A receives value, B fails → value returned | PASS |
| `TestAtomicMulticallInStaticCallRejected` | Readonly context → error | PASS |
| `TestAtomicMulticallEmptyTable` | Empty input → (true, {}) | PASS |
| `TestAtomicMulticallRevertDataPropagation` | Typed revert data propagated | PASS |

### Tolang tests (`stdlib_composed_runtime_test.go`)

| Test | Scenario | Status |
|------|----------|--------|
| `TestAtomicMulticallReceiptEscrowAtomicity` | A succeeds, B fails → both rolled back; retry both succeed | PASS |

---

## 10. Implementation Files

| File | Change |
|------|--------|
| `core/vm/lvm.go` | `tos.atomic_multicall` host function (~200 lines) |
| `core/vm/lvm_rollback_test.go` | 7 test cases |
| `tolang/stdlib_composed_runtime_test.go` | `invokeAtomicMulticall` helper + 1 test |

---

## Related Documents

- `/home/tomi/tolang/docs/AGENT_NATIVE_STDLIB_2046.md`
- `/home/tomi/tolang/docs/TOLANG_SHORTCOMINGS.md`
- `/home/tomi/tolang/docs/STDLIB_THREAT_MODEL_MATRIX.md`
