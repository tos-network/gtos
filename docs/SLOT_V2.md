# GTOS DPoS Slot Design V2

Status: `PROPOSED`
Supersedes: `docs/SLOT.md` (V1)
Reviews: Codex (`gpt-5.3-codex`) + Agave (`~/agave`) — findings incorporated below.

---

## 1. Changes from V1

V1 had six issues identified by Codex review. V2 addresses them as follows:

| V1 issue | Fix in V2 |
|---|---|
| C1: wiggle delays broadcast, not `header.Time` — slot doesn't advance | Agave review shows re-stamp is unnecessary; `Prepare()` already uses `max(parent+period, now)` so wall-clock latency naturally advances the slot. Wiggle stays broadcast-only. |
| C2: proposer can pick any slot via `header.Time` → multi-diffInTurn forks | Keep the existing `ErrFutureBlock` upper bound (`now + 3×period`) as the admissibility guard; document residual slot-gaming without a pre-committed leader schedule |
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

`genesisTime` is derived from the genesis header and retrieved via
`getGenesisTime(chain)` (cached helper; see §12.2).
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
- `genesisTime` = `getGenesisTime(chain)`
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

## 6. verifyCascadingFields() — Two Consensus Rules

```go
func (d *DPoS) verifyCascadingFields(...) error {
    // ... (existing parent lookup and minimum-interval check unchanged)
    if header.Time < parent.Time+d.config.TargetBlockPeriodMs() {
        return errInvalidTimestamp
    }

    genesisTime, err := d.getGenesisTime(chain) // cached helper; see §12.2
    if err != nil {
        return err
    }
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

    // ... (snapshot and verifySeal as before)
}
```

**C2 status in this version**: admissibility is enforced by the existing
`verifyHeader` check:

```go
if header.Time > uint64(time.Now().UnixMilli()) + 3*d.config.TargetBlockPeriodMs() {
    return consensus.ErrFutureBlock
}
```

This bounds future claims but does **not** fully eliminate slot-gaming. Without
a pre-committed schedule, a proposer can still choose `header.Time` inside the
admitted window and may land on a favorable in-turn slot.

**Why complete elimination is impossible without a schedule**: eliminating slot
gaming entirely requires a pre-committed leader schedule (as in Agave, where
`sigverify_shreds.rs:36` rejects shreds whose leader pubkey does not match the
scheduled leader for that slot). GTOS computes `inturn` on demand with no
pre-committed schedule; a malicious proposer who happens to be in-turn for a
slot inside the admitted window can legitimately earn `diffInTurn`. This is accepted
behaviour for ≤ 21 validators where fork convergence via TD is reliable.

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

// Evict all stale slots (bulk evict to prevent unbounded map growth on slot jumps).
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
| `consensus/dpos/dpos.go` | `verifyCascadingFields()`: M2 guard + strict slot increase | C2, M2 |
| `consensus/dpos/dpos.go` | `verifyHeader()`: keep single admissibility gate via `ErrFutureBlock` (`now+3×period`) | C2 |
| `consensus/dpos/dpos.go` | `verifySeal()`: use `inturnSlot`, slot-keyed Recents | H1, M3 |
| Tests | New cases: same-slot siblings, +2 slot jump, clock skew, recents with gaps | — |

---

## 10. Invariants Achieved

| Invariant | Mechanism |
|---|---|
| `slot(header) > slot(parent)` | Rule 1 in `verifyCascadingFields` |
| `header.Time ≤ now + 3×period` | Existing `ErrFutureBlock` in `verifyHeader` |
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
production. The timestamp is frozen at production time; the Clock sysvar receives
exactly one update during slot finalization via a dedicated code path.

_(Note: an earlier draft cited `bank.rs:2926` as evidence, but that line is part
of the Alpenglow-specific clock sysvar update function, not the general timestamp
generation path. The finding itself — no re-stamp — remains correct; it follows
from the fundamental design that Agave has no out-of-turn concept, so there is
no secondary validator that would need to re-stamp.)_

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

### 11.2 C2 Admissibility Rule — Bounded, but not fully eliminated

**Agave finding**: Agave rejects far-future slots through **two complementary
mechanisms**:

1. **Fetch-stage distance filter** (`core/src/shred_fetch_stage.rs:145-147`):
   incoming shreds with `slot > last_known_slot + max(500, 2×epoch_slots)` are
   discarded at ingress — a hard wall-clock-independent distance limit (~16 slots
   at mainnet settings, ~6.5 s). This is the coarse outer guard.

2. **Leader lookup / sigverify** (`ledger/src/sigverify_shreds.rs:36`):
   shreds that pass the distance filter are then verified against the
   pre-committed leader schedule — if the slot has no known leader pubkey the
   shred is rejected. This is the fine-grained inner guard that structurally
   eliminates slot-gaming.

The key point: in Agave the **schedule decides the leader**; the leader does not
choose which slot to claim.

**GTOS situation**: GTOS does not pre-compute a leader schedule. A GTOS proposer
freely chooses `header.Time` and therefore which slot they claim. This is the
root of C2: within `[parent.Time + periodMs, now + 3×period]` a proposer can
scan for a slot where they are `inturn`.

**Current V2 stance**: keep a single admissibility bound via existing
`ErrFutureBlock` (`header.Time <= now + 3×period`) and avoid introducing a
stricter second local-clock check in `verifyCascadingFields`.

This avoids over-tight clock coupling across validators. Residual gaming inside
the admitted window remains and is explicitly accepted until a pre-committed
leader schedule is added.

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
| Future slot admissibility | Agave uses pre-committed schedule; leader cannot pick slot | GTOS keeps `ErrFutureBlock` (`now+3×period`) bound; full C2 elimination deferred to schedule |
| Consecutive leader slots | Agave allows 4 consecutive slots per leader | **No change**: GTOS Recents window is intentional stricter policy |
| Out-of-turn concept | Does not exist in Agave | GTOS-specific Clique heritage; acceptable |
| Slot strictly increasing | `parent < slot` at insertion — same as V2 | **Confirmed correct** |
| Timestamp basis | Stake-weighted median (complex) | GTOS wall-clock is simpler and valid |

---

## 12. Agave Second-Round Review

Eight specific questions answered against Agave source (`ledger/src/blockstore.rs`,
`runtime/src/bank.rs`, `runtime/src/leader_schedule_utils.rs`,
`core/src/shred_fetch_stage.rs`, `runtime/src/stake_weighted_timestamp.rs`,
`leader-schedule/src/lib.rs`).

### 12.1 C2 Admissibility Rule — Keep single bound, avoid stricter duplicate check

**Final finding**: `ErrFutureBlock` already provides the network time admissibility
bound (`header.Time > now + 3×period` -> reject). Re-expressing the same limit as
an extra slot rule in `verifyCascadingFields` is redundant.

Using a stricter secondary bound (for example `slot(now)+1`) introduces
clock-coupling risk between validators and can reject otherwise admissible blocks
under skew/jitter.

**Correct action**: keep the single `ErrFutureBlock` bound and keep
`verifyCascadingFields` focused on deterministic parent-relative checks:

```go
// verifyCascadingFields — M2 guard + Rule 1 only
genesisTime, err := d.getGenesisTime(chain) // cached helper
if err != nil {
    return err
}
periodMs    := d.config.TargetBlockPeriodMs()

// M2 guard
if header.Time < genesisTime || parent.Time < genesisTime {
    return errInvalidTimestamp
}

parentSlot := (parent.Time - genesisTime) / periodMs
headerSlot := (header.Time - genesisTime) / periodMs

// Rule 1: slot must advance
if headerSlot <= parentSlot {
    return errInvalidSlot
}

```

**Agave comparison**: Agave's `verify_shred_slots()` checks `parent < slot` only
because Agave's slot gaming is structurally impossible — `sigverify_shreds.rs:36`
validates the shred signature against the **pre-scheduled** leader for that slot,
so a proposer cannot benefit from picking a different slot. GTOS lacks a
pre-committed schedule, so C2 is only bounded (not eliminated) in V2.

**Residual risk**: a validator can still search within the admitted future window
(`now + 3×period`) for favorable in-turn slots. Complete elimination requires a
pre-committed schedule (future work, see §15.2).

### 12.2 Genesis Time — Promote to Required Change (was Open Question)

**Finding** (`bank.rs:466`, `bank.rs:1339`): Agave caches `genesis_creation_time`
as a field in every `Bank` object, set once from genesis config and inherited by
all child banks. This avoids any per-slot DB read.

**Required change for GTOS**: cache genesis time in the `DPoS` struct via a
lazy helper (because `DPoS.New()` currently has no chain reader argument):

```go
type DPoS struct {
    // ...
    genesisTime     uint64
    genesisTimeOnce sync.Once
    genesisTimeErr  error
}
```

Set on first chain-aware call:
```go
func (d *DPoS) getGenesisTime(chain consensus.ChainHeaderReader) (uint64, error) {
    d.genesisTimeOnce.Do(func() {
        g := chain.GetHeaderByNumber(0)
        if g == nil {
            d.genesisTimeErr = errors.New("dpos: missing genesis block")
            return
        }
        d.genesisTime = g.Time
    })
    return d.genesisTime, d.genesisTimeErr
}
```

All call sites that previously called `chain.GetHeaderByNumber(0).Time` inline
now reference `getGenesisTime(chain)`. This removes repeated header lookups from
hot paths and keeps a single canonical source.

**Update §9 table**: add this as a new required change row.

### 12.3 inturn Formula — Round-Robin vs Stake-Weighted

**Finding** (`leader-schedule/src/lib.rs:40–65`): Agave uses **stake-weighted
random sampling** seeded by epoch number, NOT `slot % count` round-robin. For
equal-stake validators, the result is a pseudo-random interleaving (uniform
distribution), still deterministic per epoch, but **not in address order**.

**GTOS stance**: `validators[slot % count]` is intentionally simpler and correct
for GTOS's current phase where all validators meet the same minimum stake
threshold and hold equal or near-equal stake. Round-robin ensures strictly
fair rotation; Agave's stake-weighted approach is needed only when allocating
slots proportionally to stake. This difference is **intentional** and documented.

**No change needed.** When stake-weighted schedule is adopted in future (Open
Question §15.2), the algorithm will converge toward Agave's model.

### 12.4 Clock Skew Tolerance — SLOT_V2 is appropriately stricter

**Finding** (`stake_weighted_timestamp.rs:17-18`):
```rust
MAX_ALLOWABLE_DRIFT_PERCENTAGE_FAST: u32 = 25;   // timestamps faster than PoH
MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW_V2: u32 = 150; // timestamps slower than PoH
```
At slot 10 with 400ms slots, SLOW drift = ±150% × 4s = ±6s = **±15 slots**.
Agave is extremely lenient because it runs a global, permissionless validator set
where clock skew can be significant.

**GTOS**: `ErrFutureBlock` at `now + 3×period = 1080ms` (≈3 slots) is much
stricter, appropriate for a controlled validator set where validators MUST run
NTP (see `docs/VALIDATOR_NODES.md §5`, requirement: clock skew < 50ms). No change.

### 12.5 Epoch Boundary — Same Validator Across Boundary is Expected

**Finding** (`leader_schedule_cache.rs:71-82`): At epoch boundary, Agave computes
a completely new leader schedule for the new epoch. However, because of modulo
arithmetic, the same validator **can** be in-turn for the last slot of epoch N
and the first slot of epoch N+1. Agave has no code preventing this; it is
considered normal behavior.

**GTOS**: The same property holds with `slot % count`. If the validator set is
unchanged across the boundary, the rotation continues seamlessly. If the set
changes (epoch update in `apply()`), the new count changes the modulo result,
so boundary coincidences are rare. No special handling needed.

**Confirmed: no change needed.**

### 12.6 Recents Window Safety — N/3+1 Formula Confirmed

**Finding** (Agave has no Recents window — `NUM_CONSECUTIVE_LEADER_SLOTS=4`
allows consecutive same-leader slots): GTOS's `validators/3 + 1` is a stronger
fairness guarantee. Safety rationale:

- Window size = `N/3 + 1` slots: at most `N/3` validators can have signed recently.
- At least `2N/3` validators remain available → **liveness guaranteed**.
- Prevents a single validator from sealing consecutive blocks even if in-turn
  repeatedly (e.g., during validator set shrinkage).

For 15 validators: window = 6 slots × 360ms = **2.16 seconds**. Correct and safe.
The slot-keyed change (M3) preserves this safety property after slot skips.

**Confirmed: M3 fix (slot-keyed Recents) is correct.**

### 12.7 verifyCascadingFields Completeness

**Finding**: Agave separates validation into three layers:
1. Fetch stage: `slot > last_known_slot + max(500, 2×epoch_slots)` → drop
2. Blockstore: `parent < slot && parent >= root` → reject
3. Replay stage: timestamps, votes, stake-weighted clock

GTOS splits the responsibility across **`verifyHeader` + `verifyCascadingFields`**
rather than having a single consolidated function. Together they cover all three
layers:
- `verifyHeader`: `ErrFutureBlock` (`header.Time > now + 3×period`) replaces
  Agave's fetch-stage distance filter (layer 1)
- `verifyCascadingFields`: M2 guard (underflow) + Rule 1 (`headerSlot > parentSlot`)
  replace Agave's blockstore `parent < slot` check (layer 2); M2 guard replaces
  Rust's `saturating_*` arithmetic safety
- No replay-stage equivalent yet (layer 3 is deferred to future BFT work)

**No missing checks identified.**

### 12.8 Summary — Second Round

| Question | Finding | Action |
|---|---|---|
| C2 admissibility rule | Single `ErrFutureBlock` bound is necessary; stricter duplicate bound increases clock-coupling risk | Keep only `ErrFutureBlock` as admissibility gate; document residual C2 risk |
| Genesis time caching | Must cache in `DPoS` struct (Agave caches in every Bank) | **Promote to required change** |
| inturn formula | Agave uses stake-weighted random; GTOS uses round-robin intentionally | Confirmed intentional difference; document |
| Clock skew tolerance | Agave ±150%; GTOS 3×period is correctly stricter for controlled network | No change |
| Epoch boundary crossing | Same validator at boundary is normal in both | No change |
| Recents N/3+1 safety | Well-founded; M3 slot-keyed fix is correct | Confirmed |
| verifyCascadingFields | All necessary checks present; no missing checks | Confirmed |

---

## 13. Third-Round Review Findings

Four issues identified in a targeted review; all resolved above.

### 13.1 Avoid over-tight local-clock admissibility (High)

**Issue**: tightening admissibility to `slot(now)+1` can cause cross-node
accept/reject divergence under normal clock skew and network jitter.

**Fix**: remove the stricter duplicate bound from `verifyCascadingFields`; keep
the single existing `ErrFutureBlock` bound (`now + 3×period`) in `verifyHeader`.

### 13.2 Genesis time source dual-spec (Medium)

**Issue**: one section used inline `chain.GetHeaderByNumber(0).Time`, another
required cached `d.genesisTime`.

**Fix**: unify on a lazy cached helper `getGenesisTime(chain)` and reference it
consistently in code snippets.

### 13.3 Interface mismatch in implementation notes (Medium)

**Issue**: previous text required setting genesis time in `DPoS.New()` and
stated `VerifyHeaders` verifies each header in separate goroutines, both
inconsistent with current GTOS code.

**Fix**: update notes to a lazy cache design compatible with current `New(config, db)`
signature and remove the incorrect per-header goroutine claim.

### 13.4 Recents eviction and Agave citation (Low-Medium)

**Issue**: stale Recents growth on slot jumps and inaccurate `bank.rs:2926`
citation usage.

**Fix**: keep bulk eviction in §8 and replace the citation with architecture-level
reasoning in §11.1.

---

## 14. Agave Fourth-Round Review

Eight specific questions answered against Agave source (`ledger/src/sigverify_shreds.rs`,
`core/src/shred_fetch_stage.rs`, `runtime/src/bank.rs`, `consensus/tower_storage.rs`,
`leader-schedule/src/lib.rs`).

### 14.1 Rule 2 / Fetch-stage — Confirmed: single ErrFutureBlock is correct

**Q1 finding** (`core/src/shred_fetch_stage.rs:147`):
```rust
let max_slot = last_slot + MAX_SHRED_DISTANCE_MINIMUM.max(2 * slots_per_epoch);
```
Agave's fetch-stage distance filter is `last_slot + max(500, 2×slots_per_epoch)`.
With 8192 slots/epoch and 400ms slots this is **~16 slots (~6.5 s)** ahead. GTOS's
`ErrFutureBlock` at `now + 3×period = 1080ms ≈ 3 slots` is already **5× stricter**
than Agave's equivalent filter. No further tightening is needed or beneficial.

`sigverify_shreds.rs:36` verifies leader pubkey against a pre-committed schedule —
structurally impossible to replicate in GTOS without a leader schedule.

**Confirmed**: `ErrFutureBlock` alone is the correct single admissibility bound.
Adding a stricter wall-clock slot check would risk divergent accept/reject under
NTP jitter (50ms skew ÷ 360ms period = 14% disagreement probability at boundaries).

### 14.2 Recents — Confirmed efficient and correct (Q2, Q7)

**Q2 finding**: Agave has no recency window at all (`NUM_CONSECUTIVE_LEADER_SLOTS = 4`
in `leader_schedule_utils.rs`). GTOS's N/3+1 window is Clique-heritage, intentionally
stricter. The bulk-evict loop in §8 is O(window-size) ≤ O(7) for N=21, negligible
per block.

**Q7 finding**: Recents formula `if slot < limit || seenSlot > slot-limit` is correct
for all N ≥ 3 (matches Clique heritage). Liveness guaranteed: at most N/3 validators
blocked at any time, ≥ 2N/3 always available.

### 14.3 Snapshot backward-compatibility — New actionable finding (Q5)

**Finding**: When `GenesisTime` and `PeriodMs` are added to `Snapshot` struct and
serialised to JSON, snapshots loaded from an **existing DB** (written before this
change) will deserialise with `GenesisTime = 0` and `PeriodMs = 0` (Go zero-value
defaults). Any subsequent call to `apply()` that reads `snap.genesisTime` will
compute `slot = header.Time / 0` (division by zero) or `slot = header.Time` (wrong).

**Required fix**: on `loadSnapshot()`, patch zero-valued genesis fields before returning:

```go
func loadSnapshot(config *params.DPoSConfig, sigcache *lru.ARCCache,
    db ethdb.KeyValueStore, hash common.Hash,
    genesisTime uint64) (*Snapshot, error) {
    // ... (existing DB read + JSON unmarshal) ...

    // Patch fields missing from pre-migration snapshots.
    if snap.GenesisTime == 0 {
        snap.GenesisTime = genesisTime
    }
    if snap.PeriodMs == 0 {
        snap.PeriodMs = config.TargetBlockPeriodMs()
    }
    return snap, nil
}
```

The `genesisTime` argument is supplied by the caller (which already has the chain
reader and can call `d.getGenesisTime(chain)`). This is a **required migration
step** — without it, the first `apply()` on a loaded snapshot will panic or
compute wrong slots.

### 14.4 calcDifficultySlot call sites — All confirmed (Q4)

**Q4 finding** (grepping `consensus/dpos/dpos.go`):

| Line | Current call | Must change to |
|---|---|---|
| `dpos.go:449` | `snap.inturn(number, signer)` in `verifySeal` | `snap.inturnSlot(slot, signer)` |
| `dpos.go:589` | `calcDifficulty(snap, v)` in `Prepare()` | `calcDifficultySlot(snap, header.Time, genesisTime, periodMs, v)` |
| `dpos.go:764` | `calcDifficulty(snap, v)` in `CalcDifficulty()` | `calcDifficultySlot(snap, parent.Time+periodMs, genesisTime, periodMs, v)` |
| `dpos.go:768` | `snap.inturn(snap.Number+1, v)` inside `calcDifficulty()` helper | Remove helper; inline `snap.inturnSlot()` in each caller |

No circular dependency: `Prepare()` sets `header.Time` first (from wall clock), then
calls `calcDifficultySlot(header.Time, ...)`. The difficulty is derived from the
already-frozen timestamp, not the reverse.

### 14.5 timestamp→slot inversion — Confirmed intentional (Q8)

**Q8 finding**: Agave's canonical direction is **slot → timestamp** (slot is primary,
derived from PoH; timestamp is stake-weighted median validated against slot estimate).
GTOS's direction is **timestamp → slot** (`header.Time` is primary; slot computed
from it).

This inversion is structurally necessary: GTOS has no PoH and no pre-committed
schedule. The proposer sets `header.Time` at `Prepare()` time (wall clock), and slot
is derived from that. The admission bounds (`ErrFutureBlock` + parent-interval check)
prevent the timestamp from being arbitrary. This is **intentional and safe** for
GTOS's architecture.

### 14.6 Summary — Fourth Round

| Question | Finding | Action |
|---|---|---|
| Q1 Rule 2 bound | Agave fetch-stage = 16 slots; GTOS 3 slots already 5× stricter | Confirmed: `ErrFutureBlock` only; no slot(now)+1 |
| Q2 Recents bulk evict | O(window) ≤ O(7) per block; Agave has no equivalent | Confirmed correct and efficient |
| Q3 nowMs < genesisTime | Moot — no wall-clock slot check in verifyCascadingFields | N/A |
| Q4 calcDifficultySlot sites | 4 call sites identified; no circular dependency | Add to §9 change table |
| Q5 Snapshot compat | Old DB snapshots have GenesisTime=0, PeriodMs=0 → panic on apply | **Required**: patch on loadSnapshot |
| Q6 Epoch boundary | Round-robin recomputes per snapshot state; past slots unaffected | Confirmed safe |
| Q7 Recents N=3 | Formula matches Clique; liveness guaranteed | Confirmed |
| Q8 timestamp inversion | GTOS timestamp→slot vs Agave slot→timestamp; intentional given no PoH | Confirmed acceptable |

---

## 15. Open Questions (updated)

1. **Genesis time implementation**: land the required §12.2 helper
   `getGenesisTime(chain)` and switch all call sites to it.

2. **Stake-weighted schedule**: once validators hold meaningfully different stake,
   replace round-robin with stake-proportional slot allocation (as in Agave:
   `WeightedU64Index` seeded by epoch, `NUM_CONSECUTIVE_LEADER_SLOTS = 4`).

3. **Equivocation evidence**: Agave records same-slot conflicting blocks as
   provable equivocation (`store_duplicate_slot`, `blockstore.rs` ~lines 1537/1901). GTOS
   relies on TD fork resolution. Slashing on equivocation is a future feature.

4. **On-chain slot sysvar**: deferred until TOS has contract execution.

5. **Snapshot DB migration**: patch `loadSnapshot()` to supply `GenesisTime` and
   `PeriodMs` from engine config when deserialising pre-migration snapshots (§14.3).
   Required before shipping the slot implementation to any node that has an
   existing chain DB.
