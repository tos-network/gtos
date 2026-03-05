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

## All Previous Issues Resolved

All findings from the initial audit have been fixed and committed.

---

# Second Audit — 2026-03-05

**Scope:** Three major divergences from go-ethereum reviewed in depth:
1. Parallel execution (`core/parallel/`)
2. EVM → LVM replacement (`core/lvm/lvm.go`, tolang)
3. `.tor` package deployment format

**Reviewed files:** `core/parallel/analyze.go`, `core/parallel/executor.go`, `core/parallel/writebuf.go`, `core/lvm/lvm.go`, `core/state_processor.go`, `core/state_transition.go`, tolang `tol_tor.go`, `linit.go`, `stringlib.go`.

---

## Open Issues

---

### SEC-1 — CRITICAL: LVM Cross-Contract Storage Conflict Undetected (Double-Spend)

**File:** `core/parallel/analyze.go:28-40`, `core/parallel/writebuf.go:93-99`

#### Problem

`AnalyzeTx` only marks the **top-level `to` address** in the static access set:

```go
default:
    // Comment says "Plain TOS transfer" but LVM calls also hit this branch.
    as.WriteAddrs[*to] = struct{}{}
    as.ReadAddrs[*to] = struct{}{}
```

LVM contracts can write to **arbitrary third-party storage slots** via `tos.call`, `tos.transfer`, and `tos.delegatecall`. When two parallel transactions call different top-level contracts (A and B) that both internally write the same storage slot of a shared contract T (e.g., a TOS-20 token), the conflict detector sees no overlap and places both in the same execution level.

`WriteBufStateDB.Merge` applies storage writes as **absolute overwrites**, not deltas:

```go
// core/parallel/writebuf.go:93-99
for addr, slots := range b.storage {
    for slot, val := range slots {
        dst.SetState(addr, slot, val)  // absolute write — last merge wins
    }
}
```

**Attack scenario:**

- Parent state: `T.slot[X] = 600` (user X holds 600 token units)
- Tx1 calls Contract A → A internally calls `T.transferFrom(X, Y, 100)` → WriteBuf1: `T.slot[X] = 500`
- Tx2 calls Contract B → B internally calls `T.transferFrom(X, Z, 50)` → WriteBuf2: `T.slot[X] = 550`
- Conflict check: `{sender1, A}` vs `{sender2, B}` → **no conflict detected** → same level
- Merge Tx1: `T.slot[X] = 500` ✓
- Merge Tx2: `T.slot[X] = 550` — **overwrites Tx1; 100-unit deduction vanishes**

X is debited only 50 instead of 150. The attacker receives 100 tokens for free.

#### Fix

**Option A (Recommended — serialize all LVM calls):**

Add a `StateReader` parameter to `AnalyzeTx` and fall back to a global conflict sentinel whenever the destination address has contract code. This forces all LVM-call transactions to be serialized against each other.

```go
// core/parallel/analyze.go

// lvmSerialSentinel is written to the access set of every LVM contract call
// so that all such calls conflict with each other and execute serially.
var lvmSerialSentinel = params.LVMSerialAddress // a fixed reserved address

func AnalyzeTx(msg types.Message, statedb StateReader) AccessSet {
    // ... existing setup ...
    switch *to {
    case params.SystemActionAddress:
        as.WriteAddrs[params.ValidatorRegistryAddress] = struct{}{}
    case params.PrivacyRouterAddress:
        as.WriteAddrs[params.PrivacyRouterAddress] = struct{}{}
    default:
        as.WriteAddrs[*to] = struct{}{}
        as.ReadAddrs[*to] = struct{}{}
        // If the destination has LVM code it may write to arbitrary addresses.
        // Force serialization by marking a global sentinel address.
        if statedb.HasCode(*to) {
            as.WriteAddrs[lvmSerialSentinel] = struct{}{}
        }
    }
    return as
}
```

**Option B (Future — dynamic write-set tracking):**

Record which slots are actually written during parallel execution. After the goroutine phase, check for overlap between write sets from transactions in the same level. Re-execute overlapping transactions serially. This preserves parallelism for non-conflicting LVM calls at the cost of occasional re-execution.

**Option C (Not sufficient alone — storage delta merge):**

Change storage Merge to apply slot-level deltas instead of absolute values. This is correct only for purely additive semantics (token balances) and cannot be applied to general state (flags, counters reset to zero, enums). Do not use this as the sole fix.

---

### SEC-2 — HIGH: `string.rep` + Ungassed Hash Functions → Memory/CPU DoS

**File:** `core/lvm/lvm.go:999-1026`, tolang `stringlib.go:strRep`

#### Problem

`string.rep(s, n)` is a Go function call that costs **1 Lua VM opcode** regardless of output size. The tolang fork has no maximum-length guard:

```go
// tolang stringlib.go
func strRep(L *LState) int {
    str := L.CheckString(1)
    n   := L.CheckInt(2)
    L.Push(LString(strings.Repeat(str, n)))  // no size limit
```

The following LVM primitives do **not charge per-byte gas** on their input:

| Primitive | Missing charge |
|---|---|
| `tos.keccak256(data)` | No `len(data)` gas |
| `tos.sha256(data)` | No `len(data)` gas |
| `tos.ripemd160(data)` | No `len(data)` gas |
| `tos.bytes.fromhex(hex)` | No `len(hex)/2` gas |
| `tos.bytes.slice(bin, off, len)` | No `len` gas |
| `string.find(s, pat)` | Complex regex, O(N) CPU |
| `string.gsub(s, pat, repl)` | Complex regex, O(N) CPU |

A malicious contract can construct a gigabyte-scale string in a handful of opcodes and pass it to any of the above:

```lua
-- ~4 Lua opcodes; attempts to allocate 1 GB and hash it
tos.keccak256(string.rep("x", 1000000000))
```

#### Impact

A single on-chain transaction can cause an out-of-memory crash or a multi-second CPU stall on every validator node simultaneously, halting block production.

#### Fix

**Step 1 — Add per-byte gas to hash and binary primitives (`core/lvm/lvm.go`):**

```go
// tos.keccak256
L.SetField(tosTable, "keccak256", L.NewFunction(func(L *lua.LState) int {
    data := L.CheckString(1)
    chargePrimGas(1 + uint64(len(data)))  // 1 base + 1 per byte
    h := crypto.Keccak256Hash([]byte(data))
    L.Push(lua.LString(h.Hex()))
    return 1
}))
// Apply the same pattern to tos.sha256, tos.ripemd160,
// tos.bytes.fromhex, tos.bytes.slice, tos.bytes.tohex.
```

**Step 2 — Add a hard maximum-length guard in tolang `stringlib.go`:**

```go
const maxStringBytes = 1 << 20 // 1 MB hard cap

func strRep(L *LState) int {
    str := L.CheckString(1)
    n   := L.CheckInt(2)
    sep := L.OptString(3, "")
    if n > 0 && int64(len(str)+len(sep))*int64(n) > maxStringBytes {
        L.RaiseError("string.rep: result exceeds maximum string size (%d bytes)", maxStringBytes)
        return 0
    }
    // ... existing logic
```

**Step 3 — Cap `string.gsub` accumulated output size** in tolang `stringlib.go`: track total bytes produced by replacements and raise an error once the cap is exceeded.

---

### SEC-3 — HIGH: ZIP Bomb in `.tor` Package Decode

**File:** tolang `tol_tor.go:241`

#### Problem

`DecodePackage` reads each ZIP entry with no decompressed-size limit:

```go
rc, err := f.Open()
body, err := io.ReadAll(rc)  // no size cap on decompressed content
```

`MaxCodeSize = 512 KB` is enforced on the **compressed** `.tor` bytes (`core/lvm/lvm.go:272`). ZIP DEFLATE compression can achieve ratios of 1000:1 or higher. A valid 512 KB `.tor` file can decompress to 500 MB or more.

`DecodePackage` is called **twice per deployment** (once in `SplitDeployDataAndConstructorArgs` and once in `Create`) and once per call via `executePackage`. Every validator invokes it on every transaction that targets an LVM contract.

#### Impact

A single deployment transaction causes out-of-memory crashes on all validator nodes. The compressed file passes the `MaxCodeSize` check; the decompressed expansion exhausts available memory before the check can reject it.

#### Fix

Apply `io.LimitReader` per-entry and accumulate a total-size counter in `DecodePackage` (tolang `tol_tor.go`):

```go
const maxDecompressedEntry = 2 * 1024 * 1024  // 2 MB per entry
const maxDecompressedTotal = 8 * 1024 * 1024  // 8 MB total package

func DecodePackage(data []byte) (*Package, error) {
    zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
    if err != nil {
        return nil, fmt.Errorf("invalid tor zip: %w", err)
    }
    var totalBytes int64
    for _, f := range zr.File {
        // ...
        rc, err := f.Open()
        if err != nil {
            return nil, err
        }
        lr := io.LimitReader(rc, maxDecompressedEntry+1)
        body, err := io.ReadAll(lr)
        _ = rc.Close()
        if err != nil {
            return nil, err
        }
        if int64(len(body)) > maxDecompressedEntry {
            return nil, fmt.Errorf("tor entry %q exceeds decompressed size limit", f.Name)
        }
        totalBytes += int64(len(body))
        if totalBytes > maxDecompressedTotal {
            return nil, fmt.Errorf("tor package total decompressed size exceeds limit")
        }
        // ... existing logic
    }
```

Additionally, cache the decoded `*Package` in the StateDB keyed by code hash so that repeated calls to the same contract do not re-decompress the archive on every invocation.

---

### SEC-4 — MEDIUM: Block-Level Gas Check Deferred to Merge Phase

**File:** `core/parallel/executor.go:168-173`

#### Problem

In go-ethereum's serial execution, `buyGas()` is called **before** a transaction executes. If the transaction's declared gas exceeds the remaining block gas, execution is skipped with no CPU cost.

In GTOS's parallel executor, all transactions in a level execute first against individual per-tx gas pools, and the block-level gas check happens **after execution** during the serial merge phase:

```go
// Checked after parallel execution completes — too late
if msgs[txIdx].Gas() > gp.Gas() {
    return nil, nil, 0, ErrGasLimitReached
}
```

A malicious block proposer can include transactions whose total declared gas exceeds the block gas limit. All validators execute every transaction in parallel (doing real CPU work), then reject the block at merge time. The proposer forfeits the block reward; the validators waste a full block slot of compute.

#### Fix

Pre-filter each level before spawning goroutines: if the level's total declared gas exceeds remaining block gas, return `ErrGasLimitReached` immediately without executing any transaction.

```go
// core/parallel/executor.go — before the goroutine launch loop
for _, level := range levels {
    var levelGas uint64
    for _, txIdx := range level {
        g := msgs[txIdx].Gas()
        if levelGas+g < levelGas { // overflow guard
            levelGas = math.MaxUint64
            break
        }
        levelGas += g
    }
    if levelGas > gp.Gas() {
        return nil, nil, 0, ErrGasLimitReached
    }
    // ... existing goroutine launch
}
```

A stronger mitigation is to validate total block gas usage during `VerifyHeader` so that nodes can reject over-gas blocks before executing any transactions at all.

---

### SEC-5 — MEDIUM: LVM Contract Reentrancy — No Protocol-Level Guard

**File:** `core/lvm/lvm.go:1951-1956`

#### Problem

`tos.call` transfers value to the callee **before** executing callee code — identical to EVM `CALL` ordering:

```go
// Transfer happens before callee execution
if callValue.Sign() > 0 {
    blockCtx.Transfer(stateDB, contractAddr, calleeAddr, callValue)
}
// Callee runs here and can call back into the caller before its state is updated
childGasUsed, ... := Execute(stateDB, blockCtx, chainConfig, childCtx, calleeCode, childGasLimit)
```

A malicious callee can re-enter the caller before the caller updates its own state, enabling classic reentrancy attacks (e.g., repeatedly draining a contract's balance before the internal balance mapping is decremented).

#### Fix

No single protocol-level fix is appropriate because it would break legitimate re-entrancy patterns. The correct approach is defense-in-depth via documentation and standard library primitives.

**Add a `reentrancy_guard` built-in module** to `core/lvm/stdlib.go`:

```lua
-- reentrancy_guard standard library (pseudo-code)
local M = {}
local _lock_key = "_reentrancy_lock"

function M.nonReentrant()
    if tos.get(_lock_key) ~= 0 then
        tos.revert("ReentrancyGuard: reentrant call")
    end
    tos.set(_lock_key, 1)
end

function M.exit()
    tos.set(_lock_key, 0)
end
return M
```

**Enforce checks-effects-interactions in all standard library contracts** (`tos20`, `tos721`, etc.): update state before making any external calls or value transfers.

**Document the pattern prominently** in the contract development guide, with explicit warnings on `tos.call` and `tos.transfer`.

---

### SEC-6 — MEDIUM: Internal Sentinel Strings Detectable by Contract Code

**File:** `core/lvm/lvm.go:51-57`

#### Problem

`Execute` distinguishes clean returns and structured reverts from true errors by matching sentinel strings in the error message:

```go
const resultSignal    = "__tos_internal_result__"
const revertDataSignal = "__tos_revert_data__"

if hasResult && strings.Contains(err.Error(), resultSignal) { ... }
if hasRevertData && strings.Contains(err.Error(), revertDataSignal) { ... }
```

Boolean gates (`hasResult`, `hasRevertData`) prevent direct spoofing today. However, if a future code path sets `hasResult = true` prematurely before an attacker-controlled error string containing the sentinel is raised, the LVM would misclassify an error as a clean return — committing state and returning fabricated data.

#### Fix

Replace string-based detection with unexported Go error types that are structurally impossible to produce from Lua:

```go
// Unexported — cannot be constructed by contract code
type lvmResultSignal  struct{ data []byte }
type lvmRevertSignal  struct{ data []byte }

func (e *lvmResultSignal) Error() string { return "lvm: result signal (internal)" }
func (e *lvmRevertSignal) Error() string { return "lvm: revert signal (internal)" }
```

`tos.result()` and `tos.revert()` store data in these typed values. `Execute` detects them with `errors.As` rather than `strings.Contains`:

```go
var resultSig *lvmResultSignal
if errors.As(err, &resultSig) {
    return total, resultSig.data, nil, nil
}
var revertSig *lvmRevertSignal
if errors.As(err, &revertSig) {
    return total, nil, revertSig.data, fmt.Errorf("revert with data")
}
```

This eliminates the string-matching surface entirely, regardless of what strings Lua code raises.

---

### SEC-7 — LOW: `tos.keccak256` Accepts Raw Bytes, Not Hex

**File:** `core/lvm/lvm.go:999-1005`

#### Problem

`tos.keccak256` hashes the raw UTF-8 bytes of its argument, not decoded hex bytes:

```lua
tos.keccak256("0xdeadbeef")
-- hashes the 10 ASCII characters "0xdeadbeef", NOT the 4 bytes 0xde 0xad 0xbe 0xef
```

This is inconsistent with other hex-aware primitives (`tos.abi.encode`, `tos.bytes.fromhex`) and produces silent bugs when computing Solidity-compatible message hashes or EIP-712 digests.

#### Fix

Update the `tos.keccak256` docstring with an explicit warning and correct usage example:

```go
// tos.keccak256(data) → "0x..." hex (32 bytes)
//
// WARNING: `data` is treated as raw bytes, NOT as a hex string.
// To hash hex-encoded input, decode it first:
//
//   correct:   tos.keccak256(tos.bytes.fromhex("0xdeadbeef"))  -- hashes 4 bytes
//   incorrect: tos.keccak256("0xdeadbeef")                     -- hashes 10 ASCII chars
```

Consider adding a `tos.keccak256hex(hexStr)` convenience wrapper that calls `tos.bytes.fromhex` internally, making the common Solidity-compatible pattern safe by default.

---

### SEC-8 — LOW: On-Chain Runtime Package Diverges from Published `.tor`

**Status: Fixed**

**File:** `core/lvm/lvm.go` (`LVM.Create`)

#### Problem (original)

The former `buildRuntimePackage` function stripped `init_code`, `signature`, and
`publisher_key` fields before calling `SetCode`. The bytes stored on-chain did not
match any file the developer published, making signature verification impossible
after deployment.

#### Fix

`buildRuntimePackage` has been removed. `LVM.Create` now calls
`SetCode(contractAddr, pkgBytes)` with the original, unmodified deploy package bytes.
The full `.tor` archive — including `init_code` artifact, `signature`, and
`publisher_key` — is stored on-chain verbatim.

Consequences:
- `stateDB.GetCode(contractAddr)` returns the exact bytes the deployer submitted.
- Auditors and block explorers can verify the Ed25519 publisher signature directly
  from on-chain data without consulting any external store.
- `init_code` is stored but never dispatched: `Execute` / `executePackage` only
  routes calls to contracts listed in `manifest.contracts`; the `init_code` path
  is only reachable when `IsCreate=true`, which is set exclusively inside `Create`.

---

## Issues Summary

| ID | Severity | Area | Title | Status |
|----|----------|------|-------|--------|
| SEC-1 | CRITICAL | Parallel | LVM cross-contract storage conflict → double-spend | **Fixed** |
| SEC-2 | HIGH | LVM | `string.rep` + ungassed hashes → OOM/CPU DoS | **Fixed** |
| SEC-3 | HIGH | .tor | ZIP bomb in `DecodePackage` — no decompressed-size limit | **Fixed** |
| SEC-4 | MEDIUM | Parallel | Block gas check deferred to merge phase | **Fixed** |
| SEC-5 | MEDIUM | LVM | Reentrancy: no protocol-level guard | **Fixed** |
| SEC-6 | MEDIUM | LVM | Sentinel strings detectable by contract code | **Fixed** |
| SEC-7 | LOW | LVM | `tos.keccak256` raw-bytes vs hex inconsistency | **Fixed** |
| SEC-8 | LOW | .tor | On-chain runtime diverges from published `.tor` | **Fixed** |

### Fix Summary (2026-03-05)

| ID | Fix location | Key change |
|----|-------------|------------|
| SEC-1 | `params/tos_params.go`, `core/parallel/analyze.go`, `executor.go` | Added `LVMSerialAddress` sentinel; `AnalyzeTx` accepts `StateReader`, injects sentinel for any call to code-bearing address → all LVM calls serialized |
| SEC-2 | `core/lvm/lvm.go`, `tolang/stringlib.go` | Per-byte `chargePrimGas` on keccak256/sha256/ripemd160/bytes.fromhex/tohex/slice; `string.rep` output cap (1 MiB, int64 arithmetic); `string.gsub` output cap |
| SEC-3 | `tolang/tol_package.go` | `io.LimitReader` per entry (4 MiB) + total size limit (16 MiB) in `DecodePackage` |
| SEC-4 | `core/parallel/executor.go` | Pre-level gas-sum check before goroutine launch; returns `ErrGasLimitReached` without executing if sum exceeds pool |
| SEC-5 | `core/lvm/stdlib.go` | Added `reentrancy_guard` built-in module with `nonReentrant/exit/entered` named-guard helpers |
| SEC-6 | `core/lvm/lvm.go` | Replaced string sentinels with unexported LUserData typed sentinels; `isResultSignal`/`isRevertSignal` use `errors.As` + pointer comparison |
| SEC-7 | `core/lvm/lvm.go` | Added warning docstring to `tos.keccak256`; added `tos.keccak256hex` convenience wrapper |
| SEC-8 | `core/lvm/lvm.go` | `buildRuntimePackage` removed; `SetCode(contractAddr, pkgBytes)` stores full original package |

---

# Third Audit — 2026-03-05

**Scope:** Broader security and fork-risk review across the three major architectural changes vs. go-ethereum:
1. Parallel execution (`core/parallel/`)
2. EVM → LVM replacement (`core/lvm/lvm.go`)
3. `.tor` package smart contracts with package-based call routing

**Reviewed files:** `core/state_transition.go`, `core/parallel/executor.go`, `core/parallel/writebuf.go`, `core/parallel/dag.go`, `core/parallel/analyze.go`, `core/lvm/lvm.go` (full), `core/lvm/stdlib.go`.

---

## Verified Correct (No Issue)

| Topic | Verdict |
|-------|---------|
| `WriteBufStateDB.Merge` balance uses delta (overlay − parent) | Correct. Each tx's WriteBuf is backed by the same frozen parent copy. Delta = `overlay − parent` is the net contribution of this tx; multiple serial merges compose correctly. |
| `statedb.Copy()` called serially before goroutine launch | Correct. The `for _, txIdx := range level { txBufs[txIdx] = NewWriteBufStateDB(statedb.Copy()) }` loop is sequential, so no concurrent access to the live statedb. |
| SEC-4 pre-level gas: no uint64 underflow in `gp.Gas()-levelGasSum` | Correct. The check passes only when `txGas <= gp.Gas()-levelGasSum`; accumulating `txGas` afterward keeps `levelGasSum <= gp.Gas()`, so no underflow on the next iteration. |
| `tos.call` gas: 1/64 reserve mirrors EIP-150 | Correct. `childGasLimit = available - available/64` is semantically identical to the go-ethereum EIP-150 stipend rule. |
| `tos.delegatecall` storage context | Correct. `childCtx.To = contractAddr` (the calling contract's address) so `tos.set/get` inside the callee operates on the caller's storage slots — matching EVM DELEGATECALL semantics. |
| `tos.delegatecall` msg.sender and msg.value preservation | Correct. `childCtx.From = ctx.From`, `childCtx.Value = ctx.Value` — both preserved from the outer call frame. |
| `tos.create` / `tos.create2` address derivation | Correct. Uses `crypto.CreateAddress(contractAddr, nonce)` and `crypto.CreateAddress2(...)` — same as EVM. Nonce is incremented before child Deploy so successive calls get distinct addresses. |
| Parallel merge order determinism | Correct. `sortedInts(level)` sorts merge order by ascending tx index; all nodes apply the same order regardless of goroutine scheduling. |
| `tos.bytes.fromUint256` / `tos.bytes.toUint256` — no per-byte gas | Acceptable. Output is bounded at 32 bytes; these functions are O(32) and not a DoS vector under SEC-2 criteria. |
| UNO serialization via `PrivacyRouterAddress` sentinel | Correct. All UNO txs write `PrivacyRouterAddress`; the DAG forces them serial. This protects multi-account UNO state (sender + receiver ciphertext) from parallel conflict. |
| `lvm.Call` depth counter (`l.depth`) vs `ctx.Depth` | Correct. Two orthogonal counters: `l.depth` (Go-level LVM recursion, limit 1024 — dead in practice) and `ctx.Depth` (Lua-level `tos.call` nesting, limit 8). The Lua limit of 8 is the effective constraint. |
| UNO Unshield sends to arbitrary `payload.To` | By design. Self-custodial: the sender can withdraw to any address. The proof binds the withdrawal address via transcript context. |

---

## New Findings

---

### PAR-1 — MEDIUM: SEC-1 Sentinel Bypassed for Same-Block Deployed Contracts

**File:** `core/parallel/analyze.go:56-58`, `core/parallel/executor.go:99-103`

#### Problem

`AnalyzeTx` (and thus the `LVMSerialAddress` injection) is computed **once, before any transactions execute**, using the statedb at the start of the block:

```go
accessSets := make([]AccessSet, len(txs))
for i, msg := range msgs {
    accessSets[i] = AnalyzeTx(msg, statedb)  // statedb = pre-block state
}
levels := BuildLevels(accessSets)
```

If tx_A (level 0) deploys contract X (`To == nil`) and tx_B (a later level) calls X, then at analysis time `statedb.GetCodeSize(X) == 0` — X does not yet exist. `AnalyzeTx` does **not** inject `LVMSerialAddress` into tx_B's write set.

At runtime, tx_B's `WriteBufStateDB` is backed by the post-level-0 statedb (which now has X's code). So tx_B actually executes X as an LVM contract. If X internally calls a third contract T via `tos.call`, and another tx_C (in the same level as tx_B) also writes to T, both tx_B and tx_C execute concurrently — the DAG placed them in the same level because neither had `LVMSerialAddress` in the write set for T.

**Concrete scenario:**
```
Level 0: tx_A deploys contract X at address 0xX (To=nil)
Level 1: tx_B calls 0xX (X internally calls token T: T.slot[user] -= 100)
         tx_C calls T directly:              T.slot[user] -= 50
         Both run in parallel — slot[user] written independently
Merge:   tx_B: T.slot[user] = 900  (was 1000)
         tx_C: T.slot[user] = 950  (overwrites tx_B — 100-unit debit erased)
```

#### Conditions for exploitation

1. An external deployment tx (To=nil) in level 0
2. A level-1 tx calling the newly deployed contract
3. That contract internally calling an established LVM contract T
4. Another level-1 tx also writing to T

This chain of conditions is uncommon in practice (fresh deployment + same-block cross-call to shared token), but constitutes a correctness gap in the SEC-1 fix for the specific case of same-block deployment.

#### Note on Determinism

Both nodes compute the **same** merged state (merge order is deterministic by tx index). There is no fork risk — just semantic incorrectness (wrong balance deducted). The attacker cannot gain tokens; the victim contract's debit is silently lost.

#### Fix

Re-compute access sets for each level's successors using the post-level statedb, rather than computing all access sets upfront:

```go
// In ExecuteParallel: rebuild access sets after each level merge
for levelIdx, level := range levels {
    // ... execute level, merge ...
    // Refresh access sets for remaining txs
    if levelIdx+1 < len(levels) {
        for _, txIdx := range levels[levelIdx+1] {
            accessSets[txIdx] = AnalyzeTx(msgs[txIdx], statedb)
        }
        // Rebuild levels from levelIdx+1 onward if access sets changed
    }
}
```

Alternatively, always inject `LVMSerialAddress` for any call to an address that has **either** existing code **or** was the destination of a To==nil tx earlier in the same block.

---

### LVM-1 — LOW: `tos.create` Missing Address Collision Check

**File:** `core/lvm/lvm.go` (tos.create implementation, ~line 2296–2311)

#### Problem

`LVM.Create()` (called for external deployment transactions, `To == nil`) correctly validates address uniqueness before writing:

```go
codeHash := l.StateDB.GetCodeHash(contractAddr)
emptyCodeHash := crypto.Keccak256Hash(nil)
if l.StateDB.GetNonce(contractAddr) != 0 ||
    (codeHash != (common.Hash{}) && codeHash != emptyCodeHash) {
    return common.Address{}, gas, vm.ErrContractAddressCollision
}
```

`tos.create` (called from within a Lua contract) does **not** perform this check:

```go
nonce := stateDB.GetNonce(contractAddr)
newAddr := crypto.CreateAddress(contractAddr, nonce)
stateDB.SetNonce(contractAddr, nonce+1)
// No collision check — overwrites any existing code at newAddr
stateDB.SetCode(newAddr, []byte(code))
```

#### Exploitability

Exploiting this requires delivering a non-zero nonce or non-empty code to `newAddr` before `tos.create` runs. Since `newAddr = keccak256(RLP(contractAddr, nonce))[:20]`, a collision requires breaking keccak256 — computationally infeasible. Practical risk is negligible; the issue is a code-consistency gap with EVM CREATE semantics and `LVM.Create`.

#### Fix

Add the same collision guard as `LVM.Create` before the `SetCode` call in tos.create:

```go
existingCode := stateDB.GetCode(newAddr)
existingNonce := stateDB.GetNonce(newAddr)
if existingNonce != 0 || len(existingCode) != 0 {
    L.RaiseError("tos.create: address collision at %s", newAddr.Hex())
    return 0
}
```

The same fix applies to `tos.create2`.

---

### LVM-2 — LOW: `tos.create` Missing Nonce Overflow Guard

**File:** `core/lvm/lvm.go` (tos.create implementation, ~line 2305)

#### Problem

`LVM.Create()` guards against nonce overflow before computing the contract address:

```go
if nonce+1 < nonce {
    return common.Address{}, gas, ErrNonceUintOverflow
}
```

`tos.create` does not:

```go
nonce := stateDB.GetNonce(contractAddr)
newAddr := crypto.CreateAddress(contractAddr, nonce)
stateDB.SetNonce(contractAddr, nonce+1)   // wraps to 0 if nonce == MaxUint64
```

If `nonce == math.MaxUint64`, `nonce+1` silently wraps to 0. Subsequent `tos.create` calls from the same contract would reuse nonce 0, producing the same `newAddr`. The collision check (if added per LVM-1) would then block further deployments. Without the collision check the code at the derived address would be silently overwritten.

#### Reach

`gasDeploy = 32 000` gas per create; block gas limits make reaching `MaxUint64` nonces across even billions of blocks impossible in practice. This is a latent correctness gap, not a practical threat.

#### Fix

Add overflow check before the nonce increment in `tos.create` (and `tos.create2`):

```go
nonce := stateDB.GetNonce(contractAddr)
if nonce+1 < nonce {
    L.RaiseError("tos.create: deployer nonce overflow")
    return 0
}
newAddr := crypto.CreateAddress(contractAddr, nonce)
stateDB.SetNonce(contractAddr, nonce+1)
```

---

### LVM-3 — LOW: `strings.Contains` for OOG Error Classification (SEC-6 Partial Regression)

**File:** `core/lvm/lvm.go:159-162`, `core/lvm/lvm.go:379-382`

#### Problem

SEC-6 replaced string-based signal detection for `tos.result` and `tos.revert` with unexported typed sentinels. However, OOG detection in `LVM.Call()` and `LVM.Create()` still uses `strings.Contains`:

```go
// lvm.go — LVM.Call()
if strings.Contains(execErr.Error(), "gas limit exceeded") {
    return nil, 0, ErrGasLimitExceeded
}

// lvm.go — LVM.Create()
if strings.Contains(ctorErr.Error(), "gas limit exceeded") {
    return contractAddr, 0, ErrGasLimitExceeded
}
```

A Lua contract that executes `error("lua: gas limit exceeded")` at the top level will cause `LVM.Call()` to:
1. Revert all state changes (correct — snapshot is restored before the check)
2. Return `leftOverGas = 0` — consuming **all** remaining gas as if OOG

This is a gas-griefing vector: a contract designed to raise this string always appears to have exhausted the gas limit, even with ample gas remaining. The attacker cannot preserve state changes (the snapshot is always restored), but the caller loses all gas.

**Note:** This only affects the **top-level** call from `state_transition.go`. Nested calls via `tos.call` go through `Execute()` directly (not `LVM.Call()`), so inner contracts cannot trigger this path against the outer contract.

#### Fix

Export a typed OOG error from the LVM gas-tracking path, or detect the existing typed error (`chargePrimGas` raises via `L.RaiseError` which produces a `*lua.ApiError`):

```go
// Option A: check the Lua GasLimit state directly
if gasUsed > gas {
    l.StateDB.RevertToSnapshot(snapshot)
    return nil, 0, ErrGasLimitExceeded
}

// Option B: guard with a typed OOG sentinel (same approach as SEC-6)
// Define: var lvmOOGSentinel = new(lvmOOGSentinelType)
// chargePrimGas raises it on OOG; isOOGSignal() detects it in Execute()
// LVM.Call() checks isOOGSignal(execErr) instead of strings.Contains
```

---

## Third-Audit Summary

| ID | Severity | Area | Title | Status |
|----|----------|------|-------|--------|
| PAR-1 | MEDIUM | Parallel | SEC-1 sentinel bypassed for same-block deployed contracts | Open (known limitation) |
| LVM-1 | LOW | LVM | `tos.create` / `tos.create2` missing address collision check | **Fixed** |
| LVM-2 | LOW | LVM | `tos.create` missing nonce overflow guard | **Fixed** |
| LVM-3 | LOW | LVM | `strings.Contains` OOG classification is a SEC-6 partial regression | **Fixed** |

### Fix Summary (2026-03-05, third audit)

| ID | Fix location | Key change |
|----|-------------|------------|
| LVM-1 | `core/lvm/lvm.go` (tos.create + tos.create2) | Added nonce != 0 ∥ len(code) != 0 collision guard before `SetCode` to match `LVM.Create` and EVM CREATE semantics |
| LVM-2 | `core/lvm/lvm.go` (tos.create) | Added `nonce+1 < nonce` overflow guard before `crypto.CreateAddress`; mirrors existing `LVM.Create` check |
| LVM-3 | `core/lvm/lvm.go` (LVM.Call + LVM.Create constructor) | Removed `strings.Contains(err.Error(), "gas limit exceeded")` branch; rely on `gasUsed > gas` post-error check only. Eliminates string-forging gas-griefing vector |
