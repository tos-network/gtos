# GTOS Security Audit — Divergence Review

**Date**: 2026-03-05
**Scope**: gtos vs reference codebase — security and fork-risk review
**Modules**: `core/state_transition.go`, `core/parallel/`, `core/lvm/lvm.go`, `consensus/dpos/`

---

## Background

GTOS is derived from a reference Go blockchain implementation with two major architectural changes:

1. **EVM → LVM**: The EVM interpreter is removed; Lua VM (LVM) replaces smart contract execution.
2. **Serial → Parallel**: Single-threaded tx application is replaced by a DAG-based parallel executor.

This audit ran four parallel review agents (one per module), then cross-validated all findings to eliminate false positives.

---

## False Positives (Verified Correct)

The following were initially flagged and subsequently confirmed to be correct or harmless implementations:

| Flagged issue | Verification conclusion |
|---------------|------------------------|
| Parallel executor: nonce `Merge` uses absolute `SetNonce` | Correct. Same-sender txs are always in different levels (Write-Write conflict detected by DAG). Absolute assignment is safe. |
| `LVM.Create()` missing caller nonce increment | Correct. `state_transition.go:245` increments the sender nonce for all tx types before calling `LVM.Create`. The `nonce` parameter to `Create` is the pre-tx nonce used solely for address derivation. |
| Receipt missing `PostState` field | Correct. Status-byte encoding chains do not use `PostState`. `Status` is set correctly. |
| `VerifyFinalizedState` called after txs, not before | Correct. Both `FinalizeAndAssemble` (block production) and `Process` (block verification) read the post-tx statedb. Both see the same state. |
| `tos.send` skips `primGas` in readonly mode | Correct. The Lua opcode counter still advances gas for every instruction. `primGas` is an additional fine-grained primitive charge on top of opcode gas. |
| `sigcache` shallow copy across `Snapshot.copy()` | Harmless. `sigcache` is a read-only LRU; the same `(hash → signer)` pair always produces the same result. Safe across forks. |

---

## Fixed Issues

The following were confirmed as real bugs or alignment gaps. All fixes were implemented and committed.

---

### D-1 — Gas refund cap too permissive

**File**: `core/state_transition.go`, `params/protocol_params.go`

#### Problem

GTOS unconditionally used `RefundQuotient = 2`, giving refund caps up to `gasUsed / 2`.
A stricter cap of `gasUsed / 5` exists to prevent gas-refund griefing. GTOS was not
applying it.

```go
// Before — permissive cap
st.refundGas(params.RefundQuotient) // cap = gasUsed/2
```

#### Fix

GTOS now uses the strict cap unconditionally:

```go
// params/protocol_params.go
RefundQuotient       uint64 = 2 // legacy cap: gasUsed/2 (kept for reference)
RefundQuotientStrict uint64 = 5 // strict cap: gasUsed/5 — GTOS default

// core/state_transition.go
st.refundGas(params.RefundQuotientStrict)
```

---

### D-2 — Access list entries not warmed before execution

**File**: `core/state_transition.go`

#### Problem

When a transaction carries an explicit access list, GTOS charged intrinsic gas for
the list entries but never registered them as warm in the statedb. Any subsequent
storage operation against those addresses/slots would behave as if they were cold,
producing inconsistent gas semantics.

#### Fix

`PrepareAccessList` is called once per transaction in `TransitionDb`, immediately
after the nonce increment, warming sender, recipient, and all access-list entries:

```go
// Warm sender, recipient, and any explicit access-list entries for this transaction.
// GTOS has no precompiles, so the precompile slice is nil.
st.state.PrepareAccessList(msg.From(), msg.To(), nil, msg.AccessList())
```

---

### D-3 — `ExecutionResult.ReturnData` always nil

**File**: `core/state_transition.go`

#### Problem

The `ret` variable returned by `lvm.Call` was declared as a block-local variable and
immediately discarded (`_ = ret`). `ExecutionResult.ReturnData` was hardcoded to `nil`.
This made it impossible for callers (e.g. internal tooling, `tos_call` simulation) to
read the LVM contract's return value.

```go
// Before — ret was block-scoped and discarded
var ret []byte
ret, st.gas, vmerr = st.lvm.Call(...)
_ = ret
// ...
return &ExecutionResult{ReturnData: nil}, nil
```

#### Fix

`ret` is declared in the outer `var` block and propagated through `ExecutionResult`:

```go
var (
    msg              = st.msg
    contractCreation = msg.To() == nil
    ret              []byte // return data from LVM call
)
// ...
ret, st.gas, vmerr = st.lvm.Call(...)
// ...
return &ExecutionResult{UsedGas: st.gasUsed(), Err: vmerr, ReturnData: ret}, nil
```

---

### D-4 — Dispatch tag collision not detected at package deployment

**File**: `core/lvm/lvm.go` (`LVM.CreatePackage`)

#### Problem

Package dispatch uses `keccak256("pkg:" + contractName)[:4]` as a 4-byte selector.
If two contracts in the same `.tor` package share the same 4-byte prefix, the second
is silently unreachable — no deployment-time check existed.

#### Fix

`LVM.CreatePackage` now decodes the package manifest before storing code and rejects
any package containing a selector collision:

```go
seenTags := make(map[[4]byte]string, len(manifest.Contracts))
for _, c := range manifest.Contracts {
    var tag [4]byte
    copy(tag[:], crypto.Keccak256([]byte("pkg:"+c.Name))[:4])
    if prev, conflict := seenTags[tag]; conflict {
        return common.Address{}, gas, fmt.Errorf(
            "lvm: dispatch tag collision between %q and %q in package", prev, c.Name)
    }
    seenTags[tag] = c.Name
}
```

---

### D-5 — Epoch Extra verification via ad-hoc local interface

**Files**: `consensus/consensus.go`, `consensus/dpos/dpos.go`, `core/state_processor.go`, `consensus/dpos/snapshot.go`

#### Problem

`state_processor.go` defined a local `epochExtraVerifier` interface to call back into
DPoS-specific validation logic. This is an anti-pattern: a consumer package defining
its own one-off interface to reach into an implementation detail of a provider package.
The correct pattern is to define optional capability interfaces in the `consensus`
package itself, so that all engine extensions are defined in one place and any engine
can implement them.

Additionally, `snapshot.apply()` carried a lengthy "MVP limitation" comment explaining
that Extra could not be verified at snapshot time. This is superseded by the proper
`FinalizedStateVerifier` hook.

#### Fix

**1. `FinalizedStateVerifier` added to the `consensus` package:**

```go
// consensus/consensus.go
type FinalizedStateVerifier interface {
    // VerifyFinalizedState checks engine-specific invariants against the post-tx
    // statedb. Called by StateProcessor.Process after engine.Finalize().
    VerifyFinalizedState(header *types.Header, state *state.StateDB) error
}
```

**2. DPoS implements the interface** by delegating to the existing `VerifyEpochExtra`:

```go
// consensus/dpos/dpos.go
func (d *DPoS) VerifyFinalizedState(header *types.Header, st *state.StateDB) error {
    return d.VerifyEpochExtra(header, st)
}
```

**3. `state_processor.go` uses the canonical interface:**

```go
// Before — ad-hoc local interface
type epochExtraVerifier interface { VerifyEpochExtra(...) error }
if ev, ok := p.engine.(epochExtraVerifier); ok { ... }

// After — consensus package interface
if fsv, ok := p.engine.(consensus.FinalizedStateVerifier); ok {
    if err := fsv.VerifyFinalizedState(header, statedb); err != nil {
        return nil, nil, 0, err
    }
}
```

---


### HIGH-1 — Sysaction executes state changes when remaining gas is insufficient

**File**: `core/state_transition.go`

#### Problem

The sysaction handler was called unconditionally. If the remaining gas after intrinsic
deduction was below `params.SysActionGas`, the handler still executed and committed its
state changes, with the gas balance silently clamped to zero. This violates the principle
that insufficient gas must prevent execution.

#### Fix

The handler is now guarded by a pre-execution gas check:

```go
if st.gas < params.SysActionGas {
    st.gas = 0
    vmerr = vm.ErrOutOfGas
} else {
    gasUsed, execErr := sysaction.Execute(msg, st.state, st.blockCtx.BlockNumber, st.chainConfig)
    st.gas -= gasUsed
    vmerr = execErr
}
```

---

### HIGH-2 — EOA check skipped for contract-creation transactions

**File**: `core/state_transition.go`

#### Problem

The sender EOA check was wrapped in `if st.msg.To() != nil`, meaning a `To == nil`
transaction originating from a contract address was accepted without error. While
contract addresses have no associated private key (making this path practically
unreachable), it represents a protocol-level gap.

#### Fix

The `if st.msg.To() != nil` guard is removed; the EOA check is now unconditional:

```go
// Sender must always be an EOA — contract addresses have no private key.
if codeHash := st.state.GetCodeHash(st.msg.From()); codeHash != emptyCodeHash && codeHash != (common.Hash{}) {
    return fmt.Errorf("%w: address %v, codehash: %s", ErrSenderNoEOA, ...)
}
```

---

### MEDIUM-1 — `tos.arrPush` array length overflow at `math.MaxUint64`

**File**: `core/lvm/lvm.go`

#### Problem

`arrPush` read the array length as `uint64`, then computed `length + 1` without an
overflow guard. If `length == math.MaxUint64`, the addition wraps to 0, silently
corrupting the stored length. Gas cost makes this unreachable via normal operations,
but the missing guard is a latent defect.

#### Fix

```go
if length == math.MaxUint64 {
    L.RaiseError("tos.arrPush: array length overflow")
    return 0
}
```

---

### MEDIUM-2 — Unchecked integer cast in `tos.bytes.slice` / `tos.bytes.fromUint256`

**File**: `core/lvm/lvm.go`

#### Problem

`tos.bytes.slice` and `tos.bytes.fromUint256` called `.Int64()` on the parsed big.Int
without first verifying the value fits in int64. A value above `math.MaxInt64` wraps to
a negative integer; the subsequent bounds check still rejected it, but with a misleading
error message and latent memory-safety risk for future callers.

#### Fix

All three call sites now use `IsInt64()` + `Sign() >= 0` before casting:

```go
v := parseBigInt(L, 2)
if !v.IsInt64() || v.Sign() < 0 {
    L.RaiseError("tos.bytes.slice: offset out of range")
    return 0
}
offset := int(v.Int64())
```

---

### MEDIUM-3 — DPoS `gasLimit` missing lower bound and parent-relative constraint

**File**: `consensus/dpos/dpos.go`

#### Problem

`verifyHeader` only checked `header.GasLimit > params.MaxGasLimit`. A block with
`gasLimit == 0` passed validation but caused every transaction to fail immediately.
There was also no bound on how rapidly the gas limit could change between consecutive
blocks, allowing disruptive oscillation.

#### Fix

Two additional checks are inserted before the existing upper-bound check:

```go
if header.GasLimit == 0 {
    return errors.New("invalid gasLimit: zero")
}
// ... upper bound check ...
// Parent-relative change bound
diff := int64(parent.GasLimit) - int64(header.GasLimit)
if diff < 0 { diff = -diff }
if uint64(diff) >= parent.GasLimit/params.GasLimitBoundDivisor {
    return fmt.Errorf("invalid gas limit: have %d, want %d ±%d", ...)
}
```

---

## Previously Fixed (commit `6ed98f1`)

| Issue | Location | Fix |
|-------|----------|-----|
| `tos.call` orphaned snapshot on balance-check failure | `lvm.go` | Guard moved before `Snapshot()`; no snapshot taken on balance failure |
| Sub-call gas: missing 63/64 reservation rule | `lvm.go` (4 sites) | `childGasLimit = available - available/64` |
| `tos.create` nonce written before balance guard | `lvm.go` | Balance check hoisted before any state mutation |
| `LVM.Create` / `LVM.CreatePackage` no snapshot | `lvm.go` | `Snapshot()` inserted after guards, before first state write |

---

## All Issues Resolved

All findings from this audit have been fixed and committed. No open issues remain.
