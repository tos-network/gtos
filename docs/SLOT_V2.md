# GTOS DPoS Slot Design V2

Status: `PROPOSED`
Supersedes: `docs/SLOT.md` (V1)
Review: Codex (`gpt-5.3-codex`) — findings incorporated below.

---

## 1. Changes from V1

V1 had six issues identified by Codex review. V2 fixes all of them:

| V1 issue | Fix in V2 |
|---|---|
| C1: wiggle delays broadcast, not `header.Time` — slot doesn't advance | Fix `Seal()` to re-stamp and re-sign out-of-turn headers after wiggle fires |
| C2: proposer can pick any slot via `header.Time` → multi-diffInTurn forks | Add slot admissibility rule in `verifyCascadingFields` |
| H1: `Prepare()` and `calcDifficulty()` use block-number `inturn()` | Both must use slot-based `inturn()` with genesis time |
| M1: strict slot increase overstated | Documented correctly: prevents parent/child only, not fork siblings |
| M2: uint64 underflow if `header.Time < genesis.Time` | Explicit guard in slot helper |
| M3: Recents window in block-count, not slot-count | Change Recents key from block number to slot number |

---

## 2. Slot Formula

```go
// headerSlot returns the slot number for a header.
// Returns (slot, true) on success; (0, false) if header.Time < genesisTime.
func headerSlot(headerTime, genesisTime, periodMs uint64) (uint64, bool) {
    if periodMs == 0 || headerTime < genesisTime {
        return 0, false          // M2 guard: no underflow
    }
    return (headerTime - genesisTime) / periodMs, true
}
```

`genesisTime` is always `chain.GetHeaderByNumber(0).Time` — the canonical source.
No new header field is needed; the slot is derived from the existing `header.Time` (uint64 ms).

With `periodMs = 360`:
- slot 0 → `[genesis.Time, genesis.Time + 360ms)`
- slot N → `[genesis.Time + N×360ms, genesis.Time + (N+1)×360ms)`

---

## 3. inturn() — Slot-Based

Replace the block-number-based rotation with slot-based rotation:

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

The old `inturn(number, validator)` is kept for the faker path only and is
**not** used in production consensus paths after this change.

---

## 4. Prepare() — Timestamp and Difficulty

Current `Prepare()` sets `header.Time = max(parent.Time + periodMs, now)`.
This is **correct and unchanged** for in-turn validators — the timestamp naturally
reflects wall-clock time, and the slot derived from it is accurate.

What changes is the difficulty computation. Currently `calcDifficulty` calls
`snap.inturn(snap.Number+1, v)` (block-number). After this change it must use
the slot derived from `header.Time`:

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

`Prepare()` calls `calcDifficultySlot` with:
- `headerTime`  = the freshly set `header.Time`
- `genesisTime` = `chain.GetHeaderByNumber(0).Time`
- `periodMs`    = `d.config.TargetBlockPeriodMs()`

`CalcDifficulty()` (used by the miner to estimate TD of potential blocks) does
the same: fetch genesis time, compute slot from `parent.Time + periodMs`, call
`inturnSlot`.

---

## 5. Seal() — Re-stamp and Re-sign After Wiggle (C1 fix)

**Root cause of C1**: `Prepare()` sets `header.Time = now_at_prepare_time`.
`Seal()` then delays the *broadcast* by `rand(0, wiggle)` without updating
`header.Time`. An out-of-turn block is therefore stamped with the slot of the
*prepare* moment, not the *send* moment. No slot advancement occurs.

**Fix**: after the wiggle delay fires, out-of-turn blocks update `header.Time`
to the actual send time and **re-sign**:

```go
// Seal() — after delay fires:
case <-time.After(delay):
    if header.Difficulty.Cmp(diffNoTurn) == 0 {
        // Re-stamp: out-of-turn slot must reflect actual send time.
        now := uint64(time.Now().UnixMilli())
        if now > header.Time {
            header.Time = now
        }
        // Re-sign with updated header.Time.
        sighash, err := signFn(accounts.Account{Address: v},
            accounts.MimetypeDPoS, d.SealHash(header).Bytes())
        if err != nil {
            log.Error("DPoS re-seal failed", "err", err)
            return
        }
        seal, err := d.normalizeSealPayload(sighash)
        if err != nil {
            return
        }
        copy(header.Extra[len(header.Extra)-d.sealLength:], seal)
    }
    results <- block.WithSeal(header)
```

Effect:
- In-turn block: `header.Time` set at prepare time, no re-stamp. Slot = slot at prepare.
- Out-of-turn block: `header.Time` updated after wiggle fires. Slot = slot at actual send.

This ensures an out-of-turn block that fires 500 ms late legitimately claims
slot `parentSlot + 1` (or `+2` if the wiggle crossed a slot boundary), matching
the V1 design intent.

---

## 6. verifyCascadingFields() — Three New Rules

```go
func (d *DPoS) verifyCascadingFields(...) error {
    // ... (existing parent lookup and minimum-interval check unchanged)
    if header.Time < parent.Time+d.config.TargetBlockPeriodMs() {
        return errInvalidTimestamp
    }

    genesisTime := chain.GetHeaderByNumber(0).Time
    periodMs    := d.config.TargetBlockPeriodMs()

    // M2: guard against underflow before computing slots.
    if header.Time < genesisTime || parent.Time < genesisTime {
        return errInvalidTimestamp
    }

    parentSlot := (parent.Time - genesisTime) / periodMs
    headerSlot := (header.Time - genesisTime) / periodMs

    // Rule 1 — strict slot increase (parent/child).
    if headerSlot <= parentSlot {
        return errInvalidSlot // slot must advance
    }

    // Rule 2 — slot admissibility: reject claims too far in the future (C2 fix).
    // A proposer may only claim a slot within the current wall-clock window.
    // Bound: slot(now + allowedFutureBlockTime).
    nowMs       := uint64(time.Now().UnixMilli())
    maxFuture   := nowMs + 3*periodMs           // same grace as allowedFutureBlockTime
    maxSlot, _  := headerSlot(maxFuture, genesisTime, periodMs)
    if headerSlot > maxSlot {
        return consensus.ErrFutureBlock
    }

    // ... (snapshot and verifySeal as before)
}
```

**Why Rule 2 fixes C2**: with block-number `inturn()`, any timestamp was fine
because in-turn was block-number-determined. With slot-based `inturn()`, choosing
a far-future timestamp lets a proposer pick whichever slot makes them in-turn.
Rule 2 limits the claimable slot to `slot(now + 3×period)`, which covers at most
the next 3 slots — not enough to wait for a favourable rotation slot while
avoiding the current one.

**M1 acknowledged**: Rule 1 prevents same-slot parent-child pairs only. Two
validators can still produce same-slot blocks on *competing fork branches*. Fork
resolution uses TD (total difficulty) as before; the `diffInTurn` / `diffNoTurn`
weighting already provides convergence pressure. This is acceptable for ≤ 21
validators.

---

## 7. verifySeal() — Slot-Based inturn()

```go
func (d *DPoS) verifySeal(snap *Snapshot, header *types.Header, genesisTime, periodMs uint64) error {
    // ... (signer recovery, coinbase check, validator membership — unchanged)

    // Recents check — now slot-keyed (M3 fix, see §8).
    slot, ok := headerSlot(header.Time, genesisTime, periodMs)
    if !ok {
        return errInvalidTimestamp
    }
    limit := snap.config.RecentSignerWindowSize(len(snap.Validators))
    for seenSlot, recent := range snap.Recents {
        if recent == signer {
            if slot < limit || seenSlot > slot-limit {
                return errRecentlySigned
            }
        }
    }

    // Difficulty check — slot-based inturn().
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

## 8. Recents Window — Slot-Keyed (M3 fix)

**Root cause of M3**: `Recents` is `map[blockNumber]address`; eviction is
`delete(Recents, blockNumber - windowSize)`. With slot-based rotation, a
validator can be scheduled again after one skipped slot (~720 ms) while fewer
than `windowSize` *blocks* have been produced. The eviction hasn't fired, so the
validator is falsely blocked.

**Fix**: change the Recents key from block number to slot number.

In `Snapshot`:
```go
Recents map[uint64]common.Address `json:"recents"` // slot → signer (was: blockNum → signer)
```

In `apply()`:
```go
slot, _ := headerSlot(header.Time, snap.genesisTime, snap.periodMs)

// Evict slots outside the window.
limit := snap.config.RecentSignerWindowSize(len(snap.Validators))
if slot >= limit {
    delete(snap.Recents, slot-limit)
}

// Record signer at this slot.
snap.Recents[slot] = signer
```

`Snapshot` needs two new fields (`GenesisTime uint64`, `PeriodMs uint64`) that
are set at snapshot creation and propagated through `copy()` and JSON
serialisation. These are derived from `params.DPoSConfig` and the genesis header,
both already available at `snapshot()` call sites.

**Effect**: the recency window is now `N/3 + 1` *slots* (~6 × 360 ms = ~2.16 s)
regardless of how many blocks were produced in that window. A validator that
legitimately comes back into rotation after a slot skip is no longer blocked.

---

## 9. Complete List of Changes

| File | Change | Reason |
|---|---|---|
| `consensus/dpos/snapshot.go` | Add `inturnSlot(slot, addr)` | H1, new rotation |
| `consensus/dpos/snapshot.go` | Change `Recents` key to slot; add `GenesisTime`, `PeriodMs` fields | M3 |
| `consensus/dpos/snapshot.go` | Update `apply()` eviction to slot-based | M3 |
| `consensus/dpos/dpos.go` | Add `headerSlot()` helper with underflow guard | M2 |
| `consensus/dpos/dpos.go` | `calcDifficulty` → `calcDifficultySlot` | H1 |
| `consensus/dpos/dpos.go` | `Prepare()`: call `calcDifficultySlot` | H1 |
| `consensus/dpos/dpos.go` | `CalcDifficulty()`: use slot-based inturn | H1 |
| `consensus/dpos/dpos.go` | `Seal()`: re-stamp + re-sign out-of-turn after wiggle | C1 |
| `consensus/dpos/dpos.go` | `verifyCascadingFields()`: slot increase + admissibility rules | C2, M2 |
| `consensus/dpos/dpos.go` | `verifySeal()`: use `inturnSlot`, slot-keyed Recents | H1, M3 |
| Tests | New cases: same-slot siblings, +2 slot jump, clock skew, recents with gaps | — |

---

## 10. Invariants Achieved

| Invariant | Mechanism |
|---|---|
| `slot(header) > slot(parent)` | Rule 1 in `verifyCascadingFields` |
| `slot(header) ≤ slot(now + 3×period)` | Rule 2 (admissibility) in `verifyCascadingFields` |
| `header.Time ≥ genesis.Time` | M2 guard before any slot computation |
| Out-of-turn slot = actual send slot | Seal() re-stamp after wiggle |
| Difficulty consistent with slot-based inturn across all paths | `calcDifficultySlot` used everywhere |
| Recents window measured in slots not blocks | M3 fix in `apply()` and `verifySeal()` |

---

## 11. Open Questions (unchanged from V1)

1. **Genesis time helper**: `chain.GetHeaderByNumber(0)` may incur a DB read on
   every `verifyCascadingFields` call. Cache it in the `DPoS` struct at startup.

2. **Stake-weighted schedule**: once validators hold meaningfully different stake,
   replace round-robin with stake-proportional slot allocation (as in Agave).

3. **On-chain slot sysvar**: deferred until TOS has contract execution.
