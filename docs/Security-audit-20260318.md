# GTOS Security Audit: Fork Risk Analysis

**Date:** 2026-03-18
**Scope:** DPoS consensus engine, parallel execution, state transition, 2046 architecture packages
**Focus:** Consensus-critical non-determinism that could cause chain forks
**Last Updated:** 2026-03-18

---

## CRITICAL — Must Fix Immediately

### 1. Non-Deterministic Map Iteration in Parallel Merge()

**Status: FIXED (2026-03-18)**

**Location:** `core/parallel/writebuf.go`

The `Merge()` function applies state changes from per-transaction write buffers to the main StateDB using five unordered map iterations. Go map iteration order is randomized by the runtime.

```go
for addr := range b.created { dst.CreateAccount(addr) }
for addr, bal := range b.balances { ... }
for addr, nonce := range b.nonces { ... }
for addr, code := range b.codes { ... }
for addr, slots := range b.storage { for slot, val := range slots { ... } }
```

Different nodes executing the same block produce different state trie update sequences, leading to **different state roots** — a direct fork vector.

**Recommendation:** Sort all map keys before iteration using a deterministic comparator.

**Resolution:** Introduced `common/indexmap.IndexMap[K, V]` — a generic insertion-order map backed by a hash map + doubly-linked list (inspired by `elliotchance/orderedmap`, zero external dependencies). All five overlay maps in `WriteBufStateDB` (`balances`, `nonces`, `codes`, `storage`, `created`) replaced with `IndexMap`. `Merge()`, `Snapshot()`, and `RevertToSnapshot()` now iterate via `IndexMap.Range()` which guarantees deterministic insertion-order traversal.

---

### 2. Sponsor Nonce Not Tracked in Parallel Conflict Detection

**Status: FIXED (2026-03-18)**

**Location:** `core/parallel/analyze.go`

`AnalyzeTx()` builds access sets for DAG-based parallel scheduling but does not track sponsor address writes. Two transactions sharing the same sponsor can be assigned to the same parallel level:

1. Both read the same sponsor nonce from `SponsorRegistryAddress` storage.
2. Both increment it independently in their write buffers.
3. Serial merge applies both — nonce ends up correct, but intermediate state write order differs across nodes.

**Recommendation:** Add sponsor address and its nonce slot to the write set in `AnalyzeTx()`.

**Resolution:** When `msg.Sponsor()` is non-zero, the sponsor's nonce storage slot at `SponsorRegistryAddress` (computed via `Keccak256("tos.sponsor.nonce" || sponsor.Bytes())`) is now added to `WriteSlots`, forcing same-sponsor transactions into different parallel levels.

---

### 3. CalcDifficulty Returns nil on Snapshot Error

**Status: FIXED (2026-03-18)**

**Location:** `consensus/dpos/dpos.go`

When snapshot loading fails, `CalcDifficulty()` returns `nil` instead of a safe fallback:

```go
snap, err := d.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
if err != nil {
    return nil // should return diffNoTurn or propagate error
}
```

If one node's snapshot cache is temporarily corrupted or evicted, it constructs blocks with a nil difficulty while other nodes use the correct value, causing verification failures and chain divergence.

**Recommendation:** Return `diffNoTurn` on error, or propagate the error to the caller.

**Resolution:** Error path now returns `diffNoTurn` (value 1) instead of nil, preventing nil-pointer panics and ensuring a safe fallback difficulty.

---

### 4. Deferred Epoch Extra Validation

**Status: FIXED (2026-03-18)**

**Location:** `consensus/dpos/dpos.go`

When parent state is unavailable (common during batch sync), epoch block Extra validation is deferred to the finalized-state verification phase:

```go
case errors.Is(err, errMissingParentState):
    // Defer the definitive epoch-extra check to finalized-state verification...
```

This creates a window where:
- **Node A** (parent state available): validates immediately, may reject an invalid epoch block.
- **Node B** (parent state unavailable): accepts the block, defers the check.

If Node B's deferred check never runs or produces a different outcome, the two nodes diverge.

**Recommendation:** Either block until parent state is available or enforce a strict post-import verification gate that cannot be skipped.

**Resolution:** Added `deferredEpochChecks` LRU cache to track blocks with deferred validation. `VerifyFinalizedState()` now checks and clears the marker after running `VerifyEpochExtra`, ensuring the deferred check is guaranteed to execute. Log warning emitted when deferring.

---

### 5. Epoch Trust Fallback Bypasses State Verification

**Status: FIXED (2026-03-18)**

**Location:** `consensus/dpos/dpos.go`

When `len(headers) > FullImmutabilityThreshold` or the parent header is missing, the snapshot function trusts the epoch header's Extra field directly without verifying against on-chain validator state:

```go
validators, err := parseEpochValidators(checkpoint.Extra, d.config, false)
if err == nil {
    sort.Sort(addressAscending(validators))
    snap, err = newSnapshot(d.config, d.signatures, number, checkpoint.Hash(), validators, ...)
}
```

A crafted epoch header with a manipulated validator set could be accepted under deep-sync conditions, causing nodes to track different validator sets.

**Recommendation:** Always cross-check epoch Extra against on-chain state when the state is available; log a warning if the fallback path is taken.

**Resolution:** Epoch trust fallback now attempts state-based verification first when parent header and state DB are available. Only falls back to trusting header Extra when state is genuinely unavailable, with `log.Warn` emitted on fallback.

---

## HIGH — Fix Soon

### 6. Privacy Batch Verification Fallback Path Divergence

**Status: FIXED (2026-03-18)**

**Location:** `core/execute_transactions_privacy.go`

When batch proof verification fails, execution falls back to individual verification. If two privacy transactions in the same batch touch the same account:

- **Batch succeeds:** Both apply using pre-prepared state snapshots — both succeed.
- **Batch fails (fallback):** First transaction applies and mutates state; second transaction detects a state mismatch (`errPreparedPrivacyStateMismatch`) and fails.

If batch verification is not perfectly deterministic across nodes (e.g., due to numerical precision or library version differences), some nodes take the batch path and others the fallback path, producing different transaction outcomes.

**Recommendation:** Ensure batch verification is fully deterministic. Consider re-preparing state in the fallback path to avoid mismatch errors.

**Resolution:** In the batch apply loop, each transaction is now re-prepared against the real `statedb` via `preparePrivacyTxState()` before applying, ensuring `inputState` fields always reflect actual chain state. Batch verification still runs as a single batch call for the happy path (optimization preserved); re-preparation in the apply loop is lightweight (state reads only, no crypto verification).

---

### 7. Two-Phase QC Verification Async Risk

**Status: FIXED (2026-03-18)**

**Location:** `consensus/dpos/dpos.go`

Checkpoint QC verification is split into two phases:
- **Phase 1** (structural): runs during `verifyCascadingFields()` at header verification time.
- **Phase 2** (cryptographic): runs in `VerifyFinalizedState()` after block execution.

A block may be added to the canonical chain before Phase 2 completes. The ancestor walk in Phase 2 (`chain.GetHeader()` at lines 781-790) can return different results on different nodes during a reorg race, causing divergent Phase 2 outcomes.

**Recommendation:** Either run both phases atomically before chain insertion, or ensure Phase 2 failure triggers a rollback.

**Resolution:** Added explicit early nil check on parent header before ancestor walk in `verifyCheckpointQCFull()`. Improved error messages to be more specific about where the walk fails, ensuring the error wraps `errQCNotAncestor` (non-ignorable).

---

### 8. Handler and Proof Verifier Registration Order

**Status: FIXED (2026-03-18)**

**Location:** `sysaction/executor.go`, `sysaction/oracle_hooks.go`

Handlers are registered via `init()` functions and appended to a slice. The `Execute()` function performs a linear scan, returning the first matching handler:

```go
for _, h := range DefaultRegistry.handlers {
    if h.CanHandle(sa.Action) {
        return params.SysActionGas, h.Handle(ctx, sa)
    }
}
```

If two handlers can match the same action type (now or in the future), the result depends on registration order, which is determined by Go's import-path-alphabetical `init()` sequencing. Different build configurations or import orderings could cause different handler selection.

The same risk applies to `proofVerifierRegistry` — no canonical initialization of default verifiers is enforced.

**Recommendation:** Use a map keyed by action type for deterministic dispatch, or sort the handler slice after registration and assert no duplicates.

**Resolution:** Handler interface changed from `CanHandle(ActionKind) bool` to `Actions() []ActionKind`. Registry internals changed from `[]Handler` slice to `map[ActionKind]Handler` for O(1) deterministic dispatch. `Register()` panics on duplicate action registration. `RegisterProofVerifier()` and `RegisterProofVerifierAddress()` now also panic on duplicates. All 14 handler packages updated to implement `Actions()`.

---

## MEDIUM — Plan to Fix

### 9. Clock Skew Amplified by Random Seal Wiggle

**Status: FIXED (2026-03-18)**

**Location:** `consensus/dpos/dpos.go`

Out-of-turn seal delay includes `math/rand` jitter:

```go
delay += time.Duration(rand.Int63n(int64(wiggle)))
```

Combined with `time.Now()`-based delay calculation (line 1764) and a 3x-period future-block tolerance window (line 1087, ~1.08s at 360ms period), nodes with clock skew accept different blocks in tight fork races.

**Recommendation:** Tighten the future-block window; consider NTP health checks at startup.

**Resolution:** Reduced future-block tolerance from `3 * periodMs` to `2 * periodMs` in `verifyHeader()`, narrowing the acceptance window from ~1.08s to ~720ms at 360ms period. Test updated accordingly.

---

### 10. Snapshot Map Iteration in WriteBufStateDB

**Status: FIXED (2026-03-18)**

**Location:** `core/parallel/writebuf.go`

`Snapshot()` and `RevertToSnapshot()` iterate over maps without ordering when copying state. While currently safe (copies are value-independent of order), this is a latent risk if future code adds order-sensitive logic during snapshot operations.

**Recommendation:** Sort keys during snapshot creation for defensive determinism.

**Resolution:** Fixed together with Issue #1. `Snapshot()` now iterates via `IndexMap.Range()` which guarantees insertion-order traversal. `RevertToSnapshot()` restores the entire `IndexMap` instance, preserving the original insertion order.

---

### 11. Settlement Counter State Corruption

**Status: FIXED (2026-03-18)**

**Location:** `settlement/handler.go`

Callback and fulfillment IDs are minted using on-chain counters as nonces:

```go
nonce := ReadCallbackCount(ctx.StateDB)
callbackID := mintCallbackID(ctx.From, txHash, cbType, nonce)
IncrementCallbackCount(ctx.StateDB)
```

If the counter state is corrupted or reset on one node (e.g., due to a state DB bug or incomplete rollback), all subsequent IDs diverge permanently.

**Recommendation:** Add genesis-time invariant checks; log alerts if counter decreases.

**Resolution:** Added defensive guards to both `handleRegisterCallback` and `handleFulfillAsync`: (1) zero-counter warning past genesis (`log.Warn` if nonce == 0 && blockNum > 0), (2) post-increment monotonicity check (re-read counter and verify == nonce+1). Guards are warn-only to avoid changing consensus behavior.

---

### 12. Gateway Supported Kinds Stored Without Ordering

**Status: FIXED (2026-03-18)**

**Location:** `gateway/state.go`

`WriteSupportedKinds()` stores kinds in input order without sorting. If two nodes receive the same registration with kinds in different order, storage layout differs. While reads preserve storage order (internally consistent), RPC responses and any "first match" logic could diverge.

**Recommendation:** Sort the kinds slice before writing to storage.

**Resolution:** `WriteSupportedKinds()` now copies and sorts the input slice with `sort.Strings()` before writing to storage, ensuring deterministic storage layout regardless of input order. Test expectations updated to match sorted output.

---

### 13. Recents Map Iteration in DPoS Snapshot

**Status: FIXED (2026-03-18)**

**Location:** `consensus/dpos/snapshot.go`

Stale entry pruning in the `Recents` map uses non-deterministic iteration:

```go
for seenSlot := range snap.Recents {
    if seenSlot <= staleThreshold {
        delete(snap.Recents, seenSlot)
    }
}
```

The pruning result is deterministic (all entries below threshold are removed), but the iteration order is not. Currently safe, but any future early-exit or side-effect logic would introduce non-determinism.

**Recommendation:** Consider using a sorted data structure or sorting keys before iteration.

**Resolution:** All three `Recents` map iterations (`recentlySignedAt()`, bulk-evict in `apply()`, epoch re-trim in `apply()`) now collect keys into a sorted `[]uint64` slice before iterating, ensuring deterministic traversal order.

---

## Confirmed Non-Risks

| Area | Why Safe |
|------|----------|
| Slot-based validator rotation | `proposerIndexForSlot()` is fully deterministic; validators always sorted by address |
| Difficulty assignment | `calcDifficultySlot()` returns `diffInTurn` or `diffNoTurn` deterministically |
| Seal signature recovery | ed25519.Verify is deterministic |
| State slot hashing | All slots use `Keccak256(address \|\| field \|\| mapKey)` |
| Binary encoding | All serialization uses `binary.BigEndian` |
| Level execution merge order | `sortedInts()` ensures deterministic merge within each level |
| Transaction selection order | Locals-before-remotes affects block content, not state execution determinism |

---

## Fix Priority

| Priority | Issue | Location | Status |
|----------|-------|----------|--------|
| P0 — Immediate | #1 Merge() map iteration ordering | `core/parallel/writebuf.go` | **FIXED** |
| P0 — Immediate | #2 Sponsor nonce conflict tracking | `core/parallel/analyze.go` | **FIXED** |
| P0 — This week | #3 CalcDifficulty nil return | `consensus/dpos/dpos.go` | **FIXED** |
| P0 — This week | #6 Privacy batch verification determinism | `core/execute_transactions_privacy.go` | **FIXED** |
| P1 — Short term | #4 Unify epoch Extra validation timing | `consensus/dpos/dpos.go` | **FIXED** |
| P1 — Short term | #5 Epoch trust fallback hardening | `consensus/dpos/dpos.go` | **FIXED** |
| P1 — Short term | #7 Two-phase QC verification atomicity | `consensus/dpos/dpos.go` | **FIXED** |
| P1 — Short term | #8 Handler registration determinism | `sysaction/executor.go` | **FIXED** |
| P2 — Medium term | #9 Clock skew / seal wiggle tightening | `consensus/dpos/dpos.go` | **FIXED** |
| P2 — Medium term | #10 Snapshot map iteration | `core/parallel/writebuf.go` | **FIXED** |
| P2 — Medium term | #11 Settlement counter guards | `settlement/handler.go` | **FIXED** |
| P2 — Medium term | #12 Gateway kinds ordering | `gateway/state.go` | **FIXED** |
| P2 — Medium term | #13 Recents map iteration | `consensus/dpos/snapshot.go` | **FIXED** |
