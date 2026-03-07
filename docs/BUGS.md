# gtos Security Bug Tracker

Audit date: 2026-03-07
Baseline: go-ethereum v1.10.25
Status values: `CONFIRMED` · `FALSE_POSITIVE` · `BY_DESIGN` · `FIXED`

---

## Critical

### C-1 uint64 overflow in LVM gas accounting
**File**: `core/vm/lvm.go:630`
**Status**: CONFIRMED

```go
if vmUsed+totalChildGas+primGasCharged+cost > gasLimit {
```
All operands are `uint64`. If the three accumulated values are near `math.MaxUint64`,
adding `cost` wraps to zero, the comparison evaluates to false, and the gas cap is
silently bypassed — allowing unbounded computation at no cost.

**Fix**:
```go
remaining := gasLimit - vmUsed - totalChildGas - primGasCharged
if cost > remaining {
    L.RaiseError("lua: gas limit exceeded")
    return
}
```

---

### C-2 Consensus layer missing `GasUsed ≤ GasLimit` header check
**File**: `consensus/dpos/dpos.go:431–469` — `verifyCascadingFields`
**Status**: CONFIRMED

`verifyCascadingFields` only validates the timestamp, slot advancement, and seal.
It does **not** check `header.GasUsed <= header.GasLimit`. The reference Clique
implementation (`clique.go:332`) performs this check in `verifyCascadingFields`.
In gtos the check is deferred to `core/block_validator.go:83` (after full state
execution), so a header with `GasUsed > GasLimit` can briefly enter the header
chain before being rejected — creating a short fork window.

**Fix**: Add to `verifyCascadingFields`:
```go
if header.GasUsed > header.GasLimit {
    return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d",
        header.GasUsed, header.GasLimit)
}
```

---

### C-3 Incomplete `GasLimit` lower-bound validation
**File**: `consensus/dpos/dpos.go:398–403` — `verifyHeader`
**Status**: CONFIRMED

```go
if header.GasLimit == 0 { return errors.New("invalid gasLimit: zero") }
if header.GasLimit > params.MaxGasLimit { ... }
```
`params.MinGasLimit = 5000`. The current check only rejects `0`; values `1–4999`
pass undetected. geth uses `misc.VerifyGaslimit(parent.GasLimit, header.GasLimit)`
which enforces both the lower bound and the maximum parent-relative change rate.

**Fix**: Replace the manual checks with:
```go
if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
    return err
}
```
(Move to after `parent` is resolved; remove the redundant `== 0` guard.)

---

### C-4 `Receipt.EncodeIndex` silently writes nothing for non-SignerTxType
**File**: `core/types/receipt.go:365–373`
**Status**: CONFIRMED

```go
func (rs Receipts) EncodeIndex(i int, w *bytes.Buffer) {
    r := rs[i]
    if r.Type != SignerTxType {
        return   // writes nothing — corrupts DeriveSha output
    }
    ...
}
```
`EncodeIndex` is called by `DeriveSha()` to build the receipts-root Merkle trie.
A receipt of any unexpected type causes its leaf to be empty, producing a
completely wrong receipts root and breaking block validation.
Although gtos currently only produces `SignerTxType` receipts, a defensive
invariant violation should not silently succeed.

**Fix**: Replace the silent `return` with an explicit `panic` or assertion so
unexpected types surface immediately in tests.

---

### C-5 `ContractAddress` never set in parallel executor receipts
**File**: `core/parallel/executor.go:206–223`
**Status**: CONFIRMED

The receipt struct constructed in the parallel executor has no `ContractAddress`
field assignment. geth's `state_processor.go:127` sets it for every contract
creation:
```go
if msg.To() == nil {
    receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
}
```
Without this, contract deployment receipts always report a zero address, breaking
contract-creation tracking and block-explorer indexing.

**Fix**: After building each receipt in the executor, add:
```go
if tx.To() == nil && !result.Failed() {
    receipt.ContractAddress = crypto.CreateAddress(msgs[txIdx].From(), tx.Nonce())
}
```

---

## High

### H-1 Non-secp256k1 sender cannot be verified via `accessListSigner.Sender`
**File**: `core/types/transaction_signing.go:474–476`
**Status**: FALSE_POSITIVE

`accessListSigner.Sender()` returns `ErrTxTypeNotSupported` for any
`signerType != "secp256k1"`, but this is intentional design. Every caller that
actually needs sender resolution — the txpool, `state_transition.go`,
`state_processor.go` — uses `core.ResolveSender()` (`core/accountsigner_sender.go`),
which calls `accountsigner.VerifyRawSignature()` for all non-secp256k1 types.
Non-secp256k1 signatures are cryptographically verified; there is no vulnerability.

---

### H-2 RPC `DoCall` missing context-cancellation goroutine
**File**: `internal/tosapi/api.go:1017–1044`
**Status**: FALSE_POSITIVE

gtos handles DoCall timeout through the LVM's Lua interrupt mechanism, which is
the functional equivalent of geth's `goroutine + evm.Cancel()` pattern:
```go
// core/vm/lvm.go:609–610
if ctx.GoCtx != nil {
    L.SetInterrupt(ctx.GoCtx.Done()) // fires immediately when context times out
}
```
`DoCall` creates a `context.WithTimeout`, which propagates through
`ApplyMessage → GoCtx → L.SetInterrupt`. When the deadline fires, `ctx.Done()`
closes and Lua raises an interrupt at the next opcode checkpoint.
The source comment at `lvm.go:138` explicitly notes: *"Analogous to the goroutine
+ evm.Cancel() pattern in go-ethereum."*

---

### H-3 UNO proof shape validation in txpool critical path
**File**: `core/tx_pool.go:603, 675, 690`
**Status**: CONFIRMED

Every UNO transaction admission calls:
```go
extraGas, err := validateUNOTxPrecheck(tx, from, pool.currentState)
```
which performs:
1. `uno.DecodeEnvelope(data)` — full parse of up to `UNOMaxPayloadBytes`
2. `uno.ValidateShieldProofBundleShape(payload.ProofBundle)` — structural
   validation of up to 96 KB proof bundles
3. `uno.RequireElgamalSigner(statedb, from)` — state lookup

All of this runs in the txpool hot path with no gas pre-charge. An attacker can
flood the pool with size-valid but structurally invalid UNO transactions, forcing
expensive parsing per admission without paying any gas.

**Fix**: Move proof shape validation to the block-execution path. In the txpool,
keep only the envelope size check (`len(data) > params.UNOMaxPayloadBytes`) and
the `DecodeEnvelope` format check.

---

### H-4 `CumulativeGasUsed` two-phase assignment in parallel executor
**File**: `core/parallel/executor.go:208, 226–234`
**Status**: CONFIRMED (reclassified Medium)

```go
receipt := &types.Receipt{
    CumulativeGasUsed: 0, // phase 1: always zero
    ...
}
receipt.Bloom = types.CreateBloom(types.Receipts{receipt}) // Bloom is correct (logs only)
// ... later ...
receipt.CumulativeGasUsed = cumulativeGasUsed             // phase 2: back-fill
```
No external code reads the receipts between the two phases, so there is no current
runtime error. However, the structure is fragile: any future code inserted between
phase 1 and phase 2 will observe incorrect `CumulativeGasUsed` values.

**Fix**: Accumulate and assign `CumulativeGasUsed` inline during the serial merge
loop instead of in a second pass.

---

### H-5 `verifyCascadingFields` does not validate `BaseFee`
**File**: `consensus/dpos/dpos.go:431–469`
**Status**: BY_DESIGN (current), FUTURE RISK CONFIRMED

gtos currently uses a fixed `TxPrice` and has no London/EIP-1559 fork scheduled.
All block headers have `BaseFee == nil`, so no validation is needed today.
If EIP-1559 compatibility is ever enabled, `verifyCascadingFields` must call
`misc.VerifyEip1559Header()` before the fork boundary, or nodes will accept
diverging blocks at the fork.

---

## Medium

### M-1 Signature malleability — high-s values accepted for secp256k1
**File**: `core/types/transaction.go:188`
**Status**: CONFIRMED

```go
if !crypto.ValidateSignatureValues(plainV, r, s, false) { // strict=false
```
Passing `strict=false` accepts high-s signatures. Two valid signatures (one
low-s, one high-s) produce different txids for the same transaction. This breaks
idempotency assumptions in exchange deposit monitoring and similar systems.
For non-secp256k1 types (`sanityCheckSignerTxSignature`), only bit-length is
checked — no curve-specific low-s constraint is enforced.

**Fix**: Pass `strict=true` for secp256k1; add appropriate range constraints for
other curve types.

---

### M-2 No per-field size limits on `SignerTx` fields
**File**: `core/types/signer_tx.go`
**Status**: FALSE_POSITIVE

The txpool enforces a global `txMaxSize = 128 KB` limit at `tx_pool.go:575`
(`if uint64(tx.Size()) > txMaxSize`). Individual field size limits are not needed
given this total-size cap. No OOM risk.

---

### M-3 `DoCall` `StateOverride` has no account or storage-slot count limit
**File**: `internal/tosapi/api.go:917–949`
**Status**: CONFIRMED

`StateOverride.Apply()` iterates all provided accounts and storage slots without
any count validation. A caller can supply thousands of accounts with millions of
storage slots, forcing the node to perform large allocations and writes.
Nodes typically gate RPC access, but a hard limit is required as a defence in depth.

**Fix**: Limit to at most N accounts (e.g. 100) and M storage slots per account
(e.g. 1 000) before calling `Apply()`.

---

### M-4 Epoch `Extra` validator set validated after transaction execution
**File**: `consensus/dpos/dpos.go:661–685`
**Status**: CONFIRMED

The validator set encoded in an epoch block's `Extra` field is not checked during
header verification. It is validated by `VerifyEpochExtra()` only after all
transactions in the block have been executed. A malicious block proposer can
submit an epoch block with a wrong validator set that passes header verification
and enters the header chain, only to be rejected during full block processing —
causing a brief reorg window.

---

### M-5 `ResolveSender` called twice per transaction in txpool
**File**: `core/tx_pool.go:599, 741`
**Status**: CONFIRMED

`validateTx()` (line 599) and `add()` (line 741) each call `ResolveSender`
independently. Each call includes signature recovery plus at least one SLOAD
(`accountsigner.Get`). Under high throughput the doubled work is measurable.

**Fix**: Resolve the sender once in `add()` and pass the result into `validateTx`.

---

### M-6 ABI revert reason not decoded in RPC responses
**File**: `internal/tosapi/api.go:1046–1050`
**Status**: CONFIRMED

```go
func newRevertError(result *core.ExecutionResult) *revertError {
    return &revertError{
        error:  errors.New("execution reverted"),
        reason: hexutil.Encode(result.Revert()), // raw hex only
    }
}
```
geth calls `abi.UnpackRevert()` to decode `Error(string)`-encoded revert reasons
into human-readable text. gtos returns only the raw hex, making debugging harder
for API consumers.

---

## Low

### L-1 `ChainID = 0` transactions are not rejected in `SignatureValues`
**File**: `core/types/transaction_signing.go:502`
**Status**: CONFIRMED

```go
if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
    return nil, nil, nil, ErrInvalidChainId
}
```
A transaction with `ChainID = 0` bypasses the chain-ID check and is accepted,
enabling cross-chain replay. (The txpool's `ResolveSender` does verify the chain
ID, but this gap exists at the signer layer.)

---

### L-2 `Hash()` silently returns zero hash for empty `signerType`
**File**: `core/types/transaction_signing.go:522–524`
**Status**: CONFIRMED (code smell)

```go
signerType, ok := tx.SignerType()
if !ok {
    return common.Hash{} // silent zero — wrong input to any verifier
}
```
An empty `signerType` should produce an explicit error rather than a silent zero
value. Upstream `sanityCheckSignerTxSignature` will reject it, but returning
`common.Hash{}` from a hash function is a dangerous implicit convention.

---

### L-3 `LastElement()` panic risk on empty pending list
**File**: `core/tx_pool.go:1260`
**Status**: CONFIRMED (currently safe, latent risk)

```go
for addr, list := range pool.pending {
    highestPending := list.LastElement() // panics if list is empty
    nonces[addr] = highestPending.Nonce() + 1
}
```
Currently safe because `demoteUnexecutables()` (line 1628–1629) deletes empty
pending lists before this loop runs. However, this ordering invariant is
undocumented — a future refactor that reorders or short-circuits these calls
could introduce a panic.

**Fix**: Add an explicit guard:
```go
if list.Len() == 0 { continue }
```

---

### L-4 `VerifyForkHashes` hook not called in `verifyHeader`
**File**: `consensus/dpos/dpos.go` — `verifyHeader`
**Status**: FALSE_POSITIVE

`misc.VerifyForkHashes()` is a no-op stub in gtos (`consensus/misc/forks.go`).
Calling or not calling it makes no difference. Address when actual fork-hash
enforcement is needed.

---

## Verification Summary

| ID | Finding | Result | Priority |
|----|---------|--------|----------|
| C-1 | LVM gas uint64 overflow | **CONFIRMED** | Immediate |
| C-2 | GasUsed ≤ GasLimit missing from header | **CONFIRMED** | Immediate |
| C-3 | GasLimit lower bound incomplete | **CONFIRMED** | Immediate |
| C-4 | EncodeIndex silent empty write | **CONFIRMED** | Immediate |
| C-5 | ContractAddress never set | **CONFIRMED** | Immediate |
| H-1 | Non-secp256k1 sender unverified | **FALSE_POSITIVE** | — |
| H-2 | DoCall missing cancellation goroutine | **FALSE_POSITIVE** | — |
| H-3 | UNO proof validation in txpool path | **CONFIRMED** | This sprint |
| H-4 | CumulativeGasUsed two-phase | **CONFIRMED** (→ Medium) | This sprint |
| H-5 | BaseFee validation missing | **BY_DESIGN** (future risk) | Planned |
| M-1 | secp256k1 signature malleability | **CONFIRMED** | Next sprint |
| M-2 | No per-field tx size limits | **FALSE_POSITIVE** | — |
| M-3 | StateOverride no count limit | **CONFIRMED** | Next sprint |
| M-4 | EpochExtra timing window | **CONFIRMED** | Next sprint |
| M-5 | ResolveSender called twice | **CONFIRMED** | Next sprint |
| M-6 | Revert reason not decoded | **CONFIRMED** | Next sprint |
| L-1 | ChainID=0 not rejected | **CONFIRMED** | Next sprint |
| L-2 | Hash silently returns zero | **CONFIRMED** | Next sprint |
| L-3 | LastElement empty-list panic | **CONFIRMED** (safe now) | Next sprint |
| L-4 | VerifyForkHashes not called | **FALSE_POSITIVE** | — |

**Confirmed bugs**: 14 (5 Critical · 2 High · 4 Medium · 3 Low)
**False positives / By design**: 6 (H-1, H-2, M-2, L-4 = false positive; H-5 = by design)
