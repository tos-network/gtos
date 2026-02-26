# GTOS DPoS Slot Design V2

Status: `PROPOSED`
Supersedes: `docs/SLOT.md` (V1)
Reviews: Codex (`gpt-5.3-codex`) + Agave (`~/agave`) — findings incorporated below.

---

## 1. Changes from V1

V1 had six issues identified by Codex review. V2 fixes all of them:

| V1 issue | Fix in V2 |
|---|---|
| C1: wiggle delays broadcast, not `header.Time` — slot doesn't advance | Agave review shows re-stamp is unnecessary; `Prepare()` already uses `max(parent+period, now)` so wall-clock latency naturally advances the slot. Wiggle stays broadcast-only. |
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

## 5. Seal() — No Change Required (C1 Revised)

**Agave review finding** (§11.1): Agave never re-stamps block timestamps and has
no out-of-turn concept. The re-stamp + re-sign approach proposed in V2-draft is
unnecessary complexity.

**Revised approach**: `Seal()` is **unchanged**. Wiggle remains a broadcast-only
delay, as in the current code. The slot is determined at `Prepare()` time:

```go
// Prepare() — unchanged from current code:
header.Time = parent.Time + d.config.TargetBlockPeriodMs()
if now := uint64(time.Now().UnixMilli()); header.Time < now {
    header.Time = now   // wall-clock already past expected slot → advances slot naturally
}
```

**Slot behaviour under this model:**

| Scenario | `header.Time` at Prepare | Slot |
|---|---|---|
| In-turn on time | `parent.Time + 360ms` | `parentSlot + 1` |
| Out-of-turn (wiggle = 500ms, system on time) | `parent.Time + 360ms` | `parentSlot + 1` (same slot, diffNoTurn) |
| Both slow (system lagging 800ms) | `now = parent.Time + 800ms` | `parentSlot + 2` (genuine skip) |

In the common case, in-turn and out-of-turn claim **the same slot** (parentSlot + 1).
Fork resolution via TD (`diffInTurn` > `diffNoTurn`) handles convergence.
Genuine slot skipping occurs when the whole network is behind wall clock by more
than one `periodMs` — no re-signing required.

**`Seal()` requires no code change.**

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
| `consensus/dpos/dpos.go` | `Seal()`: **no change** — wiggle stays broadcast-only | C1 revised |
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
| Out-of-turn and in-turn may share same slot (parentSlot+1); TD resolves fork | `diffInTurn` > `diffNoTurn` weighting; Seal() unchanged |
| Difficulty consistent with slot-based inturn across all paths | `calcDifficultySlot` used everywhere |
| Recents window measured in slots not blocks | M3 fix in `apply()` and `verifySeal()` |

---

## 11. Agave Comparative Review

Reviewed against Agave source (`~/agave`). Key file references:
`ledger/src/blockstore.rs`, `runtime/src/bank.rs`,
`runtime/src/leader_schedule_utils.rs`, `ledger/src/sigverify_shreds.rs`,
`runtime/src/stake_weighted_timestamp.rs`.

### 11.1 C1 Revision — Re-stamp is unnecessary; drop it

**Agave finding**: Agave does **not** re-stamp block timestamps after initial
production (`bank.rs:2926`). The timestamp is frozen at production time and
updated in the Clock sysvar exactly once during finalization.

**Why Agave avoids the problem entirely**: Agave has **no out-of-turn concept**.
Each slot has exactly one designated leader; if that leader is absent, the slot
is simply skipped and the next slot's leader takes over. There is no secondary
validator racing with a random delay.

**Consequence for SLOT_V2**: The re-stamp + re-sign approach in §5 is correct
in principle but adds unnecessary complexity (re-signing in a hot path, header
in intermediate state after wiggle fires). A simpler alternative works:

**Revised C1 fix (no re-signing):**

Keep `Prepare()` as-is: `header.Time = max(parent.Time + periodMs, now)`.
Keep `Seal()` wiggle as-is: delays broadcast only, does **not** change `header.Time`.
The slot is therefore determined at `Prepare()` time from the wall clock:

- If the machine is on time: `header.Time ≈ parent.Time + periodMs` → slot = parentSlot + 1.
- If the machine is already 720 ms behind (both in-turn and out-of-turn slow):
  `now > parent.Time + 2×periodMs` → `header.Time = now` → slot = parentSlot + 2 or more
  (genuine skip, no re-signing needed).
- Wiggle delay (broadcast-only): the block is sent later but still claims the slot
  computed at prepare time. In-turn and out-of-turn may claim the same slot number
  (parentSlot + 1). Fork resolution via TD (diffInTurn vs diffNoTurn) handles this.

**Effect**: In the common case (system not lagging), wiggle does not cause slot
skipping — both in-turn and out-of-turn claim slot parentSlot + 1. Genuine slot
skips happen only when `now > parent.Time + 2×periodMs` at prepare time, which
occurs when the whole network is lagging. This is acceptable for ≤ 21 validators.

**Change to §9 table**: remove the `Seal()` re-stamp + re-sign row.
**Change to §10 invariants**: remove "Out-of-turn slot = actual send slot" row.

### 11.2 C2 Admissibility Rule — Valid but weaker than Agave's approach

**Agave finding**: Agave has **no explicit future-slot time bound**. Future slots
are rejected implicitly because `sigverify_shreds.rs:36` requires a known leader
pubkey for the slot, and the leader schedule only covers the current and next epoch.
Slots beyond that have no entry → rejected.

**GTOS situation**: GTOS does not pre-compute a leader schedule. The `slot(now +
3×period)` bound in `verifyCascadingFields` is therefore the correct GTOS-specific
equivalent — it bounds the slot claim by wall-clock proximity rather than by
schedule existence. This is **valid** for a small known validator set.

**No change needed.** The rule is weaker than Agave's but sufficient for GTOS.

### 11.3 Recents Window — GTOS-specific, no Agave equivalent

**Agave finding**: Agave has **no recency window**. The same validator can be
assigned 4 consecutive slots (`NUM_CONSECUTIVE_LEADER_SLOTS = 4`,
`leader_schedule_utils.rs:3`). Fairness and punishment for equivocation are
enforced at the consensus/slashing layer, not the slot-assignment layer.

**GTOS situation**: The Recents window (`N/3 + 1` slots) is a Clique-heritage
mechanism that prevents a single validator from sealing consecutive blocks. It is
a GTOS-specific fairness guarantee that has no direct Agave counterpart. The M3
fix (slot-keyed eviction) remains **correct and necessary** for GTOS.

**No change needed.**

### 11.4 Slot Strictly Increasing — Confirmed correct

**Agave finding**: `blockstore.rs:5126` enforces `parent < slot` at shred
insertion — exactly the same invariant as SLOT_V2 Rule 1 (`headerSlot > parentSlot`).

Agave additionally detects same-slot shreds with different content as
equivocation evidence (`store_duplicate_slot()`). GTOS does not implement
equivocation evidence yet; fork resolution via TD is sufficient for now.

**Confirmed correct. No change needed.**

### 11.5 Timestamp Basis

**Agave finding**: The Clock sysvar `unix_timestamp` is a **stake-weighted median
of recent vote timestamps**, clamped to ±drift% of the slot-boundary estimate
(`genesis + slot × slot_duration`). It is neither pure wall-clock nor pure slot
boundary (`stake_weighted_timestamp.rs:26`).

**GTOS situation**: GTOS uses plain wall-clock time (`time.Now().UnixMilli()`)
at `Prepare()`. This is correct and simpler; stake-weighted median timestamps
require a voting mechanism that GTOS does not have. No change needed.

### 11.6 Summary of Agave Review Impact

| Aspect | Agave finding | Impact on SLOT_V2 |
|---|---|---|
| Re-stamp after delay | Agave never re-stamps; no out-of-turn concept | **Simplify C1 fix**: drop re-stamp; wiggle stays broadcast-only |
| Future slot admissibility | Agave uses leader schedule; no time-bound rule | **Valid difference**: time-bound rule is correct GTOS substitute |
| Consecutive leader slots | Agave allows 4 consecutive slots per leader | **No change**: GTOS Recents window is intentional stricter policy |
| Out-of-turn concept | Does not exist in Agave | GTOS-specific Clique heritage; acceptable |
| Slot strictly increasing | `parent < slot` at insertion — same as V2 | **Confirmed correct** |
| Timestamp basis | Stake-weighted median (complex) | GTOS wall-clock is simpler and valid |

---

## 12. Open Questions (updated)

1. **Genesis time helper**: `chain.GetHeaderByNumber(0)` may incur a DB read on
   every `verifyCascadingFields` call. Cache it in the `DPoS` struct at startup.

2. **Stake-weighted schedule**: once validators hold meaningfully different stake,
   replace round-robin with stake-proportional slot allocation (as in Agave).
   Agave uses `NUM_CONSECUTIVE_LEADER_SLOTS = 4` within a weighted epoch schedule;
   GTOS can adopt a similar epoch-scoped pre-computed schedule.

3. **Equivocation evidence**: Agave records same-slot blocks with different content
   as provable equivocation (`store_duplicate_slot`). GTOS currently relies on fork
   resolution via TD. Equivocation slashing is a future governance feature.

4. **On-chain slot sysvar**: deferred until TOS has contract execution.
