# GTOS Security Audit — go-ethereum Divergence Review

**Date**: 2026-03-05
**Scope**: gtos vs go-ethereum v1.10.25 — security and fork-risk review
**Modules**: `core/state_transition.go`, `core/parallel/`, `core/lvm/lvm.go`, `consensus/dpos/`

---

## Background

GTOS is forked from go-ethereum with two major architectural changes:

1. **EVM → LVM**: The EVM interpreter is removed; Lua VM (LVM) replaces smart contract execution.
2. **Serial → Parallel**: `ApplyTransaction` is replaced by a DAG-based parallel executor.

This audit ran four parallel review agents (one per module), then cross-validated all findings to eliminate false positives.

---

## False Positives (Verified Correct)

The following were initially flagged and subsequently confirmed to be correct or harmless implementations:

| Flagged issue | Verification conclusion |
|---------------|------------------------|
| Parallel executor: nonce `Merge` uses absolute `SetNonce` | Correct. Same-sender txs are always in different levels (Write-Write conflict detected by DAG). Absolute assignment is safe. |
| `LVM.Create()` missing caller nonce increment | Correct. `state_transition.go:245` increments the sender nonce for all tx types before calling `LVM.Create`. The `nonce` parameter to `Create` is the pre-tx nonce used solely for address derivation. |
| Receipt missing `PostState` field | Correct. Post-Byzantium chains use the `Status` byte, not `PostState`. `Status` is set correctly. |
| `VerifyFinalizedState` called after txs, not before | Correct. Both `FinalizeAndAssemble` (block production) and `Process` (block verification) read the post-tx statedb. Both see the same state. |
| `tos.send` skips `primGas` in readonly mode | Correct. The Lua opcode counter still advances gas for every instruction. `primGas` is an additional fine-grained primitive charge on top of opcode gas. |
| `sigcache` shallow copy across `Snapshot.copy()` | Harmless. `sigcache` is a read-only LRU; the same `(hash → signer)` pair always produces the same result. Safe across forks. |

---

## Fixed Issues

The following were confirmed as real bugs or alignment gaps. All fixes were implemented and committed.

---

### D-1 — Gas refund quotient fixed at 2 (pre-EIP-3529)

**File**: `core/state_transition.go`, `params/protocol_params.go`
**Commit**: this PR

#### Problem

GTOS unconditionally used `RefundQuotient = 2` (pre-London), giving refund caps up to `gasUsed / 2`.
EIP-3529 (London) reduced the cap to `gasUsed / 5` (`RefundQuotientEIP3529 = 5`) to eliminate
gas-token griefing. go-ethereum switches based on `rules.IsLondon`.

```go
// go-ethereum — conditional
if rules.IsLondon {
    st.refundGas(params.RefundQuotientEIP3529) // 5
} else {
    st.refundGas(params.RefundQuotient)         // 2
}
```

#### Fix

GTOS adopts the post-London value unconditionally, which is the correct target for a new chain:

```go
// params/protocol_params.go
RefundQuotient        uint64 = 2 // pre-London (kept for reference)
RefundQuotientEIP3529 uint64 = 5 // post-London — GTOS uses this

// core/state_transition.go
st.refundGas(params.RefundQuotientEIP3529)
```

---

### D-2 — `PrepareAccessList` not called (EIP-2929/EIP-2930)

**File**: `core/state_transition.go`
**Commit**: this PR

#### Problem

go-ethereum calls `state.PrepareAccessList` in `TransitionDb` after the nonce check:

```go
// go-ethereum
if rules.IsBerlin {
    st.state.PrepareAccessList(msg.From(), msg.To(),
        vm.ActivePrecompiles(rules), msg.AccessList())
}
```

This warms the sender address, recipient address, and any explicit access-list entries
(EIP-2930) in the statedb's access-list tracker. Without this call, any EIP-2930 access
list fields in the transaction are paid for in `IntrinsicGas` but the corresponding slots
are never actually warmed — a semantically inconsistent state.

#### Fix

GTOS adds the call unconditionally (no `IsBerlin` guard, since GTOS is always post-Berlin).
Because the EVM and its precompiles are removed, `nil` is passed for the precompile list:

```go
// Warm sender, recipient, and explicit access-list entries (EIP-2929/2930).
// GTOS has no EVM precompiles, so the precompile slice is nil.
st.state.PrepareAccessList(msg.From(), msg.To(), nil, msg.AccessList())
```

---

### D-3 — `ExecutionResult.ReturnData` always nil

**File**: `core/state_transition.go`
**Commit**: this PR

#### Problem

The `ret` variable returned by `lvm.Call` was declared as a block-local variable and
immediately discarded (`_ = ret`). `ExecutionResult.ReturnData` was hardcoded to `nil`.
This made it impossible for callers (e.g. `eth_call` simulation, internal tooling) to
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

Aligns with go-ethereum's pattern of propagating return data through `ExecutionResult`:

```go
// After — ret declared in outer var block, returned to caller
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

### D-4 — 4-byte dispatch tag collision in package calls

**File**: `core/lvm/lvm.go` (`LVM.CreatePackage`)
**Commit**: this PR

#### Problem

Package dispatch uses `keccak256("pkg:" + contractName)[:4]` as a 4-byte selector,
identical in structure to Solidity's ABI function selectors. Collisions are possible
if two contracts in the same `.tor` package happen to share the same 4-byte prefix
(birthday bound ≈ 65 536 names for 50% collision probability). A collision silently
makes the second contract unreachable.

go-ethereum enforces ABI selector uniqueness at compile time. GTOS previously had no
equivalent deployment-time check.

#### Fix

`LVM.CreatePackage` now decodes the package manifest before storing code and rejects
any package containing a tag collision, mirroring go-ethereum's compile-time guarantee:

```go
// Validate dispatch tag uniqueness at deployment time.
pkg, decErr := lua.DecodePackage(torBytes)
// ... decode manifest ...
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
**Commit**: this PR

#### Problem

`state_processor.go` defined a local `epochExtraVerifier` interface to call back into
DPoS-specific validation logic. This pattern — a consumer package defining its own
one-off interface to reach into an implementation detail of a provider package — is
not how go-ethereum structures engine extensions.

go-ethereum uses the consensus package itself to define optional capability interfaces
(e.g. `consensus.PoW`). Core packages use type-assert against those interfaces, keeping
coupling in the right direction.

Additionally, `snapshot.apply()` carried a lengthy "R2-H1 MVP limitation" comment
explaining that Extra could not be verified at snapshot time. This is now superseded by
the proper `VerifyFinalizedState` hook.

#### Fix

**1. Add `FinalizedStateVerifier` to the `consensus` package** (the go-ethereum-aligned pattern):

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

**3. `state_processor.go` uses the canonical interface** instead of a local one:

```go
// Before
type epochExtraVerifier interface {
    VerifyEpochExtra(header *types.Header, statedb *state.StateDB) error
}
if ev, ok := p.engine.(epochExtraVerifier); ok { ... }

// After
if fsv, ok := p.engine.(consensus.FinalizedStateVerifier); ok {
    if err := fsv.VerifyFinalizedState(header, statedb); err != nil {
        return nil, nil, 0, err
    }
}
```

**4. `snapshot.apply()` comment updated** — replaces the "MVP limitation" note with a
description of the actual verification path now in place.

---

## Open Issues (Not Yet Fixed)

### HIGH-1 — Sysaction executes state changes when remaining gas is insufficient

**File**: `core/state_transition.go:267–275`

```go
gasUsed, execErr := sysaction.Execute(msg, st.state, ...)
// handler has already run — state changes (e.g. VALIDATOR_REGISTER) are committed
if st.gas >= gasUsed {
    st.gas -= gasUsed
} else {
    st.gas = 0   // silent clamp; no ErrOutOfGas returned
}
vmerr = execErr
```

If the remaining gas after intrinsic deduction is below `params.SysActionGas`, the handler
still executes and commits its state changes. The caller only sees `st.gas = 0` with no
error. This violates the principle that insufficient gas must prevent execution.

**Recommended fix** (go-ethereum aligned — pre-check before execution):

```go
if st.gas < params.SysActionGas {
    st.gas = 0
    vmerr = ErrOutOfGas
} else {
    gasUsed, execErr := sysaction.Execute(msg, st.state, ...)
    st.gas -= gasUsed
    vmerr = execErr
}
```

---

### HIGH-2 — EOA check skipped for contract-creation transactions

**File**: `core/state_transition.go:212–219`

```go
// GTOS — guarded by To != nil
if st.msg.To() != nil {
    if codeHash := st.state.GetCodeHash(st.msg.From()); ... { return ErrSenderNoEOA }
}

// go-ethereum — unconditional
if codeHash := st.state.GetCodeHash(st.msg.From()); ... { return ErrSenderNoEOA }
```

A `To == nil` transaction from an address that has deployed code is not rejected.
In practice, Lua contract addresses have no associated private key, so this path is
unreachable — but it represents a protocol-level divergence from go-ethereum semantics.

**Recommended fix**: Remove the `if st.msg.To() != nil` wrapper; always check EOA.

---

### MEDIUM-1 — `tos.arrPush` uint64 length overflow

**File**: `core/lvm/lvm.go:1221`

```go
length := new(big.Int).SetBytes(raw[:]).Uint64()
// ...
new(big.Int).SetUint64(length + 1).FillBytes(...)  // wraps to 0 if length == MaxUint64
```

If a storage slot is written to `math.MaxUint64` directly, the next `arrPush` wraps the
length to 0. Gas cost makes this unreachable via normal array operations, but a guard is
good defensive practice.

**Recommended fix**:

```go
if length == math.MaxUint64 {
    L.RaiseError("tos.arrPush: array length overflow")
    return 0
}
```

---

### MEDIUM-2 — `tos.bytes.slice` / `tos.bytes.fromUint256` unchecked `Int64` cast

**File**: `core/lvm/lvm.go:934, 941, 970`

```go
offset := int(parseBigInt(L, 2).Int64())  // silently truncates if > 2^63-1
```

A value above `math.MaxInt64` wraps to a negative integer. The subsequent bounds check
still rejects it, but the error message ("index out of range") is misleading. A future
code change that removes the bounds check would expose real memory-safety risk.

**Recommended fix**:

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

**File**: `consensus/dpos/dpos.go:398–400`

```go
if header.GasLimit > params.MaxGasLimit { return error }
// Missing: lower bound (gasLimit > 0)
// Missing: parent-relative bound (|cur - parent| < parent / GasLimitBoundDivisor)
```

A block with `gasLimit == 0` passes header validation but causes every transaction to fail
immediately. An attacker could also rapidly oscillate the gas limit across blocks, disrupting
miner transaction selection. go-ethereum's Clique enforces the parent-relative bound from
`misc.VerifyGaslimit`.

**Recommended fix**:

```go
if header.GasLimit == 0 {
    return errors.New("invalid gasLimit: zero")
}
diff := int64(parent.GasLimit) - int64(header.GasLimit)
if diff < 0 { diff = -diff }
if uint64(diff) >= parent.GasLimit/params.GasLimitBoundDivisor {
    return fmt.Errorf("invalid gas limit: have %d, want %d ±%d",
        header.GasLimit, parent.GasLimit, parent.GasLimit/params.GasLimitBoundDivisor-1)
}
```

---

## Previously Fixed (commit `6ed98f1`)

| Issue | Location | Fix |
|-------|----------|-----|
| `tos.call` orphaned snapshot on `CanTransfer` failure | `lvm.go` | Guard moved before `Snapshot()`; no snapshot taken on balance failure |
| EIP-150 63/64 gas rule missing in sub-calls | `lvm.go` (4 sites) | `childGasLimit = available - available/64` |
| `tos.deploy` `SetNonce` before `CanTransfer` guard | `lvm.go` | `CanTransfer` check hoisted before any state mutation |
| `LVM.Create` / `LVM.CreatePackage` no snapshot | `lvm.go` | `Snapshot()` inserted after guards, before first state write |

---

## Fix Priority

| Priority | ID | File | Description |
|----------|----|------|-------------|
| P1 | HIGH-1 | `state_transition.go:267` | Sysaction executes despite insufficient gas |
| P1 | HIGH-2 | `state_transition.go:214` | EOA check skipped for Create txs |
| P2 | MEDIUM-1 | `lvm.go:1221` | `arrPush` uint64 overflow guard |
| P2 | MEDIUM-2 | `lvm.go:934,941,970` | `Int64` cast requires `IsInt64()` pre-check |
| P2 | MEDIUM-3 | `dpos.go:398` | `gasLimit` lower bound + parent-relative constraint |
