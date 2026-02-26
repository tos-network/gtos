# GTOS DPoS Slot Design

Status: `PROPOSED`

---

## 1. Background

GTOS DPoS is derived from go-ethereum's Clique PoA engine. The current in-turn
validator selection uses block number as the rotation index:

```go
// snapshot.go — inturn()
return number % uint64(len(s.Validators)) == uint64(i)
```

There is no explicit slot concept. Consequences:

- Block height and rotation index are always identical: block N is assigned to
  `validators[N % count]`, even if produced out-of-turn.
- Monitoring can only track block production frequency, not missed turns.
- With slot-based `periodMs` timing already in use, the `Recents` window is
  measured in blocks rather than slots — a validator can be blocked from sealing
  even when legitimately scheduled after a slot skip.

This document specifies the slot-based design that addresses these issues.

---

## 2. Slot Number

### 2.1 Formula

A slot is a fixed-duration time window of `periodMs` milliseconds. The slot
number for any header is derived from the existing `header.Time` field (uint64
Unix milliseconds) without adding a new header field:

```
slot(header) = (header.Time − genesis.Time) / periodMs
```

With `periodMs = 360`:
- slot 0 → `[genesis.Time, genesis.Time + 360ms)`
- slot N → `[genesis.Time + N×360ms, genesis.Time + (N+1)×360ms)`

### 2.2 headerSlot() helper

```go
// headerSlot returns the slot number for a header timestamp.
// Returns (slot, true) on success; (0, false) if inputs are invalid.
func headerSlot(headerTime, genesisTime, periodMs uint64) (uint64, bool) {
    if periodMs == 0 || headerTime < genesisTime {
        return 0, false  // guard against underflow and division by zero
    }
    return (headerTime - genesisTime) / periodMs, true
}
```

All slot computations in the engine go through this helper.

### 2.3 Block height vs slot number

After introducing slots, block height and slot number diverge whenever a slot is
skipped. Both values are meaningful:

| Value | Meaning | How obtained |
|---|---|---|
| `header.Number` | block height (chain length) | existing field |
| `slot` | time-based rotation index | `headerSlot(header.Time, genesis.Time, periodMs)` |

`slot ≥ block_height` always holds once any slot is skipped.

---

## 3. Slot-Based Validator Rotation

### 3.1 inturnSlot()

Replace the block-number-based rotation with slot-based rotation in `snapshot.go`:

```go
// inturnSlot returns true if validator is the expected proposer for the given slot.
func (s *Snapshot) inturnSlot(slot uint64, validator common.Address) bool {
    if len(s.Validators) == 0 {
        return false
    }
    for i, v := range s.Validators {
        if v == validator {
            return slot%uint64(len(s.Validators)) == uint64(i)
        }
    }
    return false
}
```

The validator list is sorted by address (ascending) by `ReadActiveValidators`.
Equal slot-based allocation provides fair round-robin rotation among all
registered validators.

The old `inturn(number, validator)` is retained for the faker path only and is
**not used** in production consensus paths after this change.

### 3.2 Rotation at epoch boundary

When the validator set changes at an epoch boundary, `apply()` replaces the
set atomically. The new `inturnSlot` computation uses the updated set
immediately for subsequent slots. The same validator can appear at the last
slot of epoch N and the first slot of epoch N+1 — this is expected and correct.

---

## 4. Difficulty Computation

### 4.1 calcDifficultySlot()

```go
// calcDifficultySlot computes header difficulty using slot-based in-turn check.
func calcDifficultySlot(snap *Snapshot, headerTime, genesisTime, periodMs uint64,
    v common.Address) *big.Int {
    slot, ok := headerSlot(headerTime, genesisTime, periodMs)
    if !ok {
        return new(big.Int).Set(diffNoTurn)
    }
    if snap.inturnSlot(slot, v) {
        return new(big.Int).Set(diffInTurn)
    }
    return new(big.Int).Set(diffNoTurn)
}
```

### 4.2 Call sites

| Function | Current call | Updated call |
|---|---|---|
| `Prepare()` (`dpos.go:589`) | `calcDifficulty(snap, v)` | `calcDifficultySlot(snap, header.Time, genesisTime, periodMs, v)` |
| `CalcDifficulty()` (`dpos.go:764`) | `calcDifficulty(snap, v)` | `calcDifficultySlot(snap, parent.Time+periodMs, genesisTime, periodMs, v)` |
| `verifySeal()` (`dpos.go:449`) | `snap.inturn(number, signer)` | `snap.inturnSlot(slot, signer)` |

`CalcDifficulty()` uses `parent.Time + periodMs` (not the caller-supplied `time`
argument, which is unused dead code). This is deterministic and does not affect
consensus.

There is no circular dependency: `Prepare()` sets `header.Time` from the wall
clock first, then derives difficulty from that frozen timestamp.

---

## 5. Prepare() and Seal()

### 5.1 Prepare() — unchanged

```go
// Prepare() — no change from current code:
header.Time = parent.Time + d.config.TargetBlockPeriodMs()
if now := uint64(time.Now().UnixMilli()); header.Time < now {
    header.Time = now   // wall-clock already past expected slot → natural slot advance
}
```

The slot is determined at `Prepare()` time from the wall clock. No re-stamping
or re-signing is needed after the wiggle delay fires.

### 5.2 Seal() — no change required

The wiggle delay in `Seal()` is a **broadcast-only delay**. It does not modify
`header.Time`. The slot claimed by a block is fixed at `Prepare()` time.

### 5.3 Slot behaviour under this model

| Scenario | `header.Time` at Prepare | Slot |
|---|---|---|
| In-turn on time | `parent.Time + 360ms` | `parentSlot + 1` |
| Out-of-turn (wiggle delay, system on time) | `parent.Time + 360ms` | `parentSlot + 1` (same slot, `diffNoTurn`) |
| Both slow (system lagging ≥ 720ms) | `now ≥ parent.Time + 2×periodMs` | `parentSlot + 2` or more (genuine skip) |

In the common case, in-turn and out-of-turn validators both claim slot
`parentSlot + 1`. Fork resolution via total difficulty (`diffInTurn` >
`diffNoTurn`) handles convergence. Genuine slot skipping occurs only when
`now > parent.Time + 2×periodMs` at `Prepare()` time.

---

## 6. Header Verification

### 6.1 verifyHeader() — admissibility gate (existing, unchanged)

The existing `ErrFutureBlock` check in `verifyHeader()` provides the upper
admissibility bound:

```go
if header.Time > uint64(time.Now().UnixMilli()) + 3*d.config.TargetBlockPeriodMs() {
    return consensus.ErrFutureBlock
}
```

This limits any proposer to claiming a slot within `~3 slots` of wall-clock
time. No additional slot-admissibility check is added to `verifyCascadingFields`;
a stricter local-clock slot check would create reject/accept divergence between
validators with typical NTP skew (50ms skew ÷ 360ms period = 14% disagreement
probability at slot boundaries).

`ErrFutureBlock` always fires before `verifyCascadingFields()`. Exact execution
order for a non-genesis, non-faker block:

1. `ErrFutureBlock` check — admissibility gate
2. Faker early return — skips all subsequent checks in faker mode
3. Structural checks: UncleHash, MixDigest, difficulty, Extra format
4. Genesis early return
5. `verifyCascadingFields()` → M2 guard → Rule 1 → snapshot → `verifySeal()`

### 6.2 verifyCascadingFields() — two consensus rules

```go
func (d *DPoS) verifyCascadingFields(...) error {
    // ... existing parent lookup and minimum-interval check (unchanged):
    if header.Time < parent.Time + d.config.TargetBlockPeriodMs() {
        return errInvalidTimestamp
    }

    genesisTime, err := d.getGenesisTime(chain)  // cached helper; see §9
    if err != nil {
        return err
    }
    periodMs := d.config.TargetBlockPeriodMs()

    // Rule M2: guard against uint64 underflow before computing slots.
    if header.Time < genesisTime || parent.Time < genesisTime {
        return errInvalidTimestamp
    }

    parentSlot := (parent.Time - genesisTime) / periodMs
    headerSlot := (header.Time - genesisTime) / periodMs

    // Rule 1: slot must strictly advance (parent/child).
    if headerSlot <= parentSlot {
        return errInvalidSlot
    }

    // ... snapshot load and verifySeal as before
}
```

**Rule 1 is mathematically redundant** given that `header.Time ≥ parent.Time +
periodMs` (existing check) combined with the M2 guard implies
`headerSlot ≥ parentSlot + 1`. It is kept as a defence-in-depth assertion:
if the minimum-interval check is ever relaxed, Rule 1 remains load-bearing;
it also makes the slot invariant explicit in the code.

**Rule 1 scope**: it prevents a child block from claiming the same slot as its
parent. Two validators on competing fork branches can still produce same-slot
blocks — fork resolution via TD handles this.

---

## 7. verifySeal() — Slot-Based Checks

```go
func (d *DPoS) verifySeal(snap *Snapshot, header *types.Header,
    genesisTime, periodMs uint64) error {
    // ... signer recovery, coinbase check, validator membership — unchanged

    // Compute slot; validate timestamp.
    slot, ok := headerSlot(header.Time, genesisTime, periodMs)
    if !ok {
        return errInvalidTimestamp
    }

    // Recents check — slot-keyed (see §8).
    limit := snap.config.RecentSignerWindowSize(len(snap.Validators))
    for seenSlot, recent := range snap.Recents {
        if recent == signer {
            if slot < limit || seenSlot > slot-limit {
                return errRecentlySigned
            }
        }
    }

    // Difficulty check — slot-based inturn.
    if !d.fakeDiff {
        inturn := snap.inturnSlot(slot, signer)
        if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
            return errWrongDifficulty
        }
        if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
            return errWrongDifficulty
        }
    }
    return nil
}
```

---

## 8. Recents Window — Slot-Keyed

### 8.1 Problem with block-count Recents

The current `Recents` map uses block number as the key: `map[blockNumber]address`.
Eviction fires after `N/3 + 1` consecutive *blocks*. With slot-based rotation, a
validator can be legitimately scheduled after a single skipped slot (~720ms) while
fewer than `N/3 + 1` blocks have been produced. The eviction hasn't fired, so the
validator is falsely blocked with `errRecentlySigned`.

### 8.2 Fix: slot-keyed Recents with bulk eviction

Change the `Recents` key from block number to slot number. In `Snapshot`:

```go
Recents map[uint64]common.Address `json:"recents"` // slot → signer (was: blockNum → signer)
```

In `apply()`:

```go
slot, _ := headerSlot(header.Time, snap.GenesisTime, snap.PeriodMs)

// Bulk evict all stale slots (prevents unbounded map growth on slot jumps).
limit := snap.config.RecentSignerWindowSize(len(snap.Validators))
if slot >= limit {
    staleThreshold := slot - limit
    for seenSlot := range snap.Recents {
        if seenSlot <= staleThreshold {
            delete(snap.Recents, seenSlot)
        }
    }
}

// Record signer at this slot.
snap.Recents[slot] = signer
```

### 8.3 Window size and liveness

The recency window is `N/3 + 1` *slots*:

- For N=15 validators: window = 6 slots × 360ms = **2.16 seconds**
- For N=21 validators: window = 8 slots × 360ms = **2.88 seconds**

At most `N/3` validators can be in the recent window at any time, leaving at
least `2N/3` validators available — **liveness is guaranteed**.

The bulk-evict loop is O(window size) ≤ O(8) per block for N=21, negligible.

### 8.4 Epoch boundary re-trim

`apply()` evicts in two passes at epoch boundaries:

1. Normal per-block eviction using current N (before validator set replacement).
2. Epoch re-trim using new N (after validator set replacement).

Both validator-set growth and shrinkage are handled correctly.

### 8.5 Genesis era

At `slot < limit`, the condition `slot < limit || seenSlot > slot-limit` fires
unconditionally for any Recents entry — correct Clique-heritage behaviour.
Block 0 is initialised via `snapshot()`, not `apply()`, so Recents starts empty
and the genesis era guard is sound.

### 8.6 Migration of existing Recents entries

DB-loaded snapshots may have Recents entries with block-number keys (old format).
These are safely self-evicting: block numbers are much smaller than slot numbers
at the time of the upgrade. Old entries fall below `staleThreshold` on the first
`apply()` call and are bulk-evicted. No explicit migration step is needed for
Recents.

---

## 9. Genesis Time Caching

### 9.1 Requirement

All slot computations require `genesisTime = genesis.header.Time`. `DPoS.New()`
has no chain reader argument, so genesis time must be fetched lazily on the
first chain-aware call.

### 9.2 Retryable atomic pattern

Use an atomic `uint64` rather than `sync.Once`. `sync.Once` permanently caches
errors — if `chain.GetHeaderByNumber(0)` returns `nil` during genesis block
import (before the block is persisted), the error becomes frozen for the
lifetime of the engine. The retryable pattern avoids this:

```go
type DPoS struct {
    // ...
    genesisTime uint64  // atomic; 0 = not yet cached
}

// getGenesisTime returns the genesis block timestamp, caching it on first success.
// It retries on each call if a previous call found genesis not yet available.
func (d *DPoS) getGenesisTime(chain consensus.ChainHeaderReader) (uint64, error) {
    if t := atomic.LoadUint64(&d.genesisTime); t != 0 {
        return t, nil
    }
    g := chain.GetHeaderByNumber(0)
    if g == nil {
        return 0, errors.New("dpos: genesis block not available")
    }
    atomic.StoreUint64(&d.genesisTime, g.Time)
    return g.Time, nil
}
```

Since `g.Time` is immutable once written, concurrent calls are idempotent and safe.

All call sites that previously read `chain.GetHeaderByNumber(0).Time` inline now
call `getGenesisTime(chain)`.

---

## 10. Snapshot Changes

### 10.1 New struct fields

Add to `Snapshot` in `snapshot.go`:

```go
type Snapshot struct {
    // ... existing fields ...
    GenesisTime uint64 `json:"genesisTime"` // genesis block timestamp (ms)
    PeriodMs    uint64 `json:"periodMs"`    // target block period (ms)
}
```

These fields are used by `apply()` for slot computation and by `verifySeal()`
through the snapshot.

### 10.2 newSnapshot() — updated signature

```go
func newSnapshot(config *params.DPoSConfig, sigcache *lru.ARCCache,
    number uint64, hash common.Hash, validators []common.Address,
    genesisTime, periodMs uint64) (*Snapshot, error) {
    snap := &Snapshot{
        // ... existing fields ...
        GenesisTime: genesisTime,
        PeriodMs:    periodMs,
    }
    // ...
}
```

Genesis call site at `dpos.go:493` must become:

```go
snap, err = newSnapshot(d.config, d.signatures, 0, genesis.Hash(), validators,
    genesisTime, config.TargetBlockPeriodMs())
```

**All five steps below must be in the same commit** to avoid a division-by-zero
panic in `apply()`:

1. Add `GenesisTime` and `PeriodMs` fields to `Snapshot` struct.
2. Update `newSnapshot()` signature and populate new fields.
3. Update `copy()` to propagate both new fields.
4. Update all `newSnapshot()` call sites.
5. Update `apply()` to use `snap.GenesisTime` / `snap.PeriodMs`.

### 10.3 copy() — propagate new fields

```go
func (s *Snapshot) copy() *Snapshot {
    cpy := &Snapshot{
        // ... existing fields ...
        GenesisTime: s.GenesisTime,
        PeriodMs:    s.PeriodMs,
    }
    // ...
    return cpy
}
```

### 10.4 loadSnapshot() — patch pre-migration snapshots

Snapshots loaded from an existing DB (written before this change) will have
`GenesisTime = 0` and `PeriodMs = 0` (Go zero-value defaults). Without patching,
the first `apply()` will divide by zero or compute wrong slots.

```go
func loadSnapshot(config *params.DPoSConfig, sigcache *lru.ARCCache,
    db ethdb.KeyValueStore, hash common.Hash,
    genesisTime uint64) (*Snapshot, error) {
    // ... existing DB read + JSON unmarshal ...

    // Patch fields absent from pre-migration snapshots.
    if snap.GenesisTime == 0 {
        snap.GenesisTime = genesisTime
    }
    if snap.PeriodMs == 0 {
        snap.PeriodMs = config.TargetBlockPeriodMs()
    }
    return snap, nil
}
```

The `genesisTime` argument is supplied by the caller via `getGenesisTime(chain)`.
The `snapshot()` function already has `chain consensus.ChainHeaderReader` as an
argument, so `getGenesisTime(chain)` is callable there:

```go
genesisTime, err := d.getGenesisTime(chain)
if err != nil { return nil, err }
if s, err := loadSnapshot(d.config, d.signatures, d.db, hash, genesisTime); err == nil {
    // use cached snapshot
}
```

---

## 11. Complete List of Changes

| File | Change | Reason |
|---|---|---|
| `consensus/dpos/snapshot.go` | Add `inturnSlot(slot, addr)` | Slot-based rotation |
| `consensus/dpos/snapshot.go` | Change `Recents` key to slot number | M3: block-count eviction breaks after slot skip |
| `consensus/dpos/snapshot.go` | Add `GenesisTime uint64`, `PeriodMs uint64` fields to struct | Required by `apply()` and `verifySeal()` |
| `consensus/dpos/snapshot.go` | Update `newSnapshot()` signature to accept `genesisTime, periodMs` | Atomically required with `apply()` change |
| `consensus/dpos/snapshot.go` | Update `copy()` to propagate new fields | Snapshot consistency |
| `consensus/dpos/snapshot.go` | Update `apply()` eviction to slot-based bulk evict | M3 fix |
| `consensus/dpos/snapshot.go` | Update `loadSnapshot()` to accept `genesisTime`; patch zero-valued fields | DB migration safety |
| `consensus/dpos/dpos.go` | Add `headerSlot()` helper with underflow guard | M2: prevent uint64 underflow |
| `consensus/dpos/dpos.go` | Add `calcDifficultySlot()` replacing `calcDifficulty()` | H1: block-number inturn is wrong |
| `consensus/dpos/dpos.go` | `Prepare()`: call `calcDifficultySlot(header.Time, ...)` | H1 |
| `consensus/dpos/dpos.go` | `CalcDifficulty()`: call `calcDifficultySlot(parent.Time+periodMs, ...)` | H1 |
| `consensus/dpos/dpos.go` | `Seal()`: **no change** — wiggle stays broadcast-only | C1: re-stamp unnecessary |
| `consensus/dpos/dpos.go` | `verifyCascadingFields()`: M2 guard + Rule 1 (strict slot increase) | M2, defence-in-depth |
| `consensus/dpos/dpos.go` | `verifyHeader()`: keep existing `ErrFutureBlock` (`now + 3×period`) | C2 admissibility bound |
| `consensus/dpos/dpos.go` | `verifySeal()`: use `inturnSlot`, slot-keyed Recents lookup | H1, M3 |
| `consensus/dpos/dpos.go` | Add `getGenesisTime()` retryable atomic helper; add `genesisTime uint64` field to `DPoS` struct | Genesis caching |
| Tests | New cases: same-slot siblings, +2 slot jump, clock skew, Recents with slot gaps | Coverage |

---

## 12. Invariants

| Invariant | Mechanism |
|---|---|
| `slot(header) > slot(parent)` | Rule 1 in `verifyCascadingFields` (redundant with interval check; kept for defence-in-depth) |
| `header.Time ≤ now + 3×periodMs` | Existing `ErrFutureBlock` in `verifyHeader` |
| `header.Time ≥ genesisTime` | M2 guard before any slot computation |
| `parent.Time ≥ genesisTime` | M2 guard before any slot computation |
| Difficulty consistent with slot-based inturn across all code paths | `calcDifficultySlot()` used in `Prepare()`, `CalcDifficulty()`, and `verifySeal()` |
| Recents window measured in slots not blocks | Slot-keyed map + bulk eviction in `apply()` and lookup in `verifySeal()` |
| Recents map bounded in size | Bulk evict on every `apply()`: map size ≤ O(N/3+1) ≤ O(8) for N=21 |
| Liveness: ≥ 2N/3 validators always available | At most N/3 in Recents window at any time |
| Genesis block bypasses slot checks | `verifyHeader()` returns nil for `header.Number == 0` before cascading calls |
| Miner requires no changes | `Prepare()` already uses `max(parent.Time + periodMs, now)` |

---

## 13. Known Limitations

### 13.1 Slot-gaming within the admitted window

A proposer controls `header.Time` and therefore which slot they claim. Within
the admitted window (`[parent.Time + periodMs, now + 3×periodMs]`) a proposer
can scan for a slot where they are in-turn and set `header.Time` accordingly to
earn `diffInTurn`.

Complete elimination of slot-gaming requires a pre-committed leader schedule
(where the leader for each slot is fixed in advance). GTOS computes `inturnSlot`
on demand with no pre-committed schedule. This residual risk is accepted for
≤ 21 validators where fork convergence via TD is reliable.

### 13.2 Same-slot siblings on competing forks

Rule 1 prevents a child block from claiming the same slot as its parent. It does
not prevent two validators on competing fork branches from producing same-slot
blocks. Fork resolution uses total difficulty (`diffInTurn` > `diffNoTurn`)
as before.

---

## 14. Open Questions

1. **Genesis time implementation**: implement and deploy the `getGenesisTime()`
   retryable atomic helper; switch all inline `chain.GetHeaderByNumber(0).Time`
   usages to it.

2. **Stake-weighted schedule (future)**: once validators hold meaningfully
   different stake amounts, replace round-robin with stake-proportional slot
   allocation. The rotation algorithm would then allocate more slots to
   higher-stake validators proportionally.

3. **Equivocation evidence (future)**: same-slot conflicting blocks are provable
   equivocation. GTOS currently relies on TD fork resolution. Slashing on
   equivocation is a future feature.

4. **On-chain slot sysvar (future)**: deferred until TOS has contract execution.
   Once available, an on-chain `SLOT` sysvar can expose `(header.Time − genesis.Time) / periodMs`
   to contracts without a new header field.

5. **Snapshot DB migration**: required before shipping to any node with an
   existing chain DB. The `loadSnapshot()` patch (§10.4) handles pre-migration
   snapshots transparently. Verify this path in integration tests with an
   existing DB.
