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

    // Rule 2 — slot admissibility (C2 partial fix): restrict claimable slot to
    // current wall-clock slot + 1. This narrows the gaming window from ~3 slots
    // to at most 1 slot. Complete elimination requires a pre-committed leader
    // schedule (Agave approach; out of scope for GTOS).
    nowMs := uint64(time.Now().UnixMilli())
    if nowMs >= genesisTime {
        nowSlot := (nowMs - genesisTime) / periodMs
        if headerSlot > nowSlot+1 {
            return errInvalidSlot
        }
    }

    // ... (snapshot and verifySeal as before)
}
```

**Why Rule 2 partially fixes C2**: with slot-based `inturn()`, a proposer can
pick `header.Time` anywhere in `[parent.Time + periodMs, now + 3×period]` to
land in whichever slot makes them `inturn`. Rule 2 tightens the upper bound to
`slot(now) + 1`, limiting the scan to at most 1 future slot. In a 15-validator
round-robin, the probability of any given validator being in-turn for the single
claimable future slot is 1/15 ≈ 6.7%, vs 3/15 = 20% with a 3-slot window.

**Why complete elimination is impossible without a schedule**: eliminating slot
gaming entirely requires a pre-committed leader schedule (as in Agave, where
`sigverify_shreds.rs:36` rejects shreds whose leader pubkey does not match the
scheduled leader for that slot). GTOS computes `inturn` on demand with no
pre-committed schedule; a malicious proposer who happens to be in-turn for
`slot(now)` or `slot(now)+1` legitimately earns `diffInTurn`. This is accepted
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
| `consensus/dpos/dpos.go` | `verifyCascadingFields()`: slot increase + admissibility rules | C2, M2 |
| `consensus/dpos/dpos.go` | `verifySeal()`: use `inturnSlot`, slot-keyed Recents | H1, M3 |
| Tests | New cases: same-slot siblings, +2 slot jump, clock skew, recents with gaps | — |

---

## 10. Invariants Achieved

| Invariant | Mechanism |
|---|---|
| `slot(header) > slot(parent)` | Rule 1 in `verifyCascadingFields` |
| `slot(header) ≤ slot(now) + 1` | Rule 2 (tightened admissibility) in `verifyCascadingFields` |
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

### 11.2 C2 Admissibility Rule — Valid but must be tightened to slot(now)+1

**Agave finding**: Agave has **no explicit future-slot time bound**. Future slots
are rejected implicitly because `sigverify_shreds.rs:36` requires a known leader
pubkey for the slot, and the leader schedule only covers the current and next epoch.
Slots beyond that have no entry → rejected. The key point: in Agave the **schedule
decides the leader**; the leader does not choose which slot to claim.

**GTOS situation**: GTOS does not pre-compute a leader schedule. A GTOS proposer
freely chooses `header.Time` and therefore which slot they claim. This is the
root of C2: within `[parent.Time + periodMs, now + 3×period]` a proposer can
scan for a slot where they are `inturn`.

**Fix**: tighten Rule 2 from `slot(now + 3×period)` to `slot(now) + 1`, reducing
the gaming window from ~3 claimable slots to 1. See §6 for revised code.
Complete elimination of gaming is impossible without a pre-committed schedule.

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
| Future slot admissibility | Agave uses pre-committed schedule; leader cannot pick slot | **Tighten Rule 2**: bound to `slot(now)+1`; reduces gaming from ~3 slots to 1 |
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

### 12.1 C2 Admissibility Rule — Tighten to slot(now)+1, do NOT remove

**Earlier finding (revised)**: A previous draft of this section concluded that
Rule 2 is "redundant with `ErrFutureBlock`" and should be removed. This was
**incorrect**. Removing Rule 2 reopens C2 to a 3-slot gaming window:

- `ErrFutureBlock` in `verifyHeader` rejects `header.Time > now + 3×period`.
- This still permits a proposer to scan slots `[parentSlot+1, slot(now+3×period)]`
  — up to 3 future slots — to find one where they are `inturn` and claim `diffInTurn`.
- Simply enforcing `slot(header) ≤ slot(now + 3×period)` is the same constraint
  as `ErrFutureBlock` expressed in slot units: indeed redundant, but REMOVING it
  does not fix C2.

**Correct action**: Keep Rule 2 but **tighten** the bound from `slot(now + 3×period)`
to `slot(now) + 1`. This limits the scan to at most 1 future slot:

```go
// verifyCascadingFields — all three checks (M2 guard + Rule 1 + Rule 2 tightened)
genesisTime := d.genesisTime   // cached in DPoS struct at startup (see §12.2)
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

// Rule 2 (tightened): claimable slot ≤ slot(now) + 1
nowMs := uint64(time.Now().UnixMilli())
if nowMs >= genesisTime {
    nowSlot := (nowMs - genesisTime) / periodMs
    if headerSlot > nowSlot+1 {
        return errInvalidSlot
    }
}
```

**Agave comparison**: Agave's `verify_shred_slots()` checks `parent < slot` only
because Agave's slot gaming is structurally impossible — `sigverify_shreds.rs:36`
validates the shred signature against the **pre-scheduled** leader for that slot,
so a proposer cannot benefit from picking a different slot. GTOS lacks a
pre-committed schedule, making Rule 2 necessary.

**Residual risk**: with Rule 2 tightened, a validator is in-turn for `slot(now)+1`
in 1/N of cases (e.g. 1/15 ≈ 6.7%). This is accepted; complete elimination
requires a pre-committed schedule (future work, see §14.2).

### 12.2 Genesis Time — Promote to Required Change (was Open Question)

**Finding** (`bank.rs:466`, `bank.rs:1339`): Agave caches `genesis_creation_time`
as a field in every `Bank` object, set once from genesis config and inherited by
all child banks. This avoids any per-slot DB read.

**Required change for GTOS**: cache genesis time in the `DPoS` struct at `New()`:

```go
type DPoS struct {
    // ...
    genesisTime uint64  // cached from genesis block header; set in New()
}
```

Set at engine creation:
```go
genesis := chain.GetHeaderByNumber(0)
d.genesisTime = genesis.Time
```

All call sites that previously called `chain.GetHeaderByNumber(0).Time` inline
now reference `d.genesisTime`. This is required for correctness under concurrent
header verification (`VerifyHeaders` spawns a goroutine per header).

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
Question §14.2), the algorithm will converge toward Agave's model.

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

SLOT_V2 consolidates layers 1+2 into `verifyCascadingFields`. This is correct
for GTOS's architecture (no separate fetch/blockstore/replay split). The checks
are sufficient:
- M2 guard replaces Rust's `saturating_*` arithmetic safety
- Rule 1 (`headerSlot > parentSlot`) replaces Agave's `parent < slot`
- `ErrFutureBlock` in `verifyHeader` replaces Agave's fetch-stage distance filter

**No missing checks identified.**

### 12.8 Summary — Second Round

| Question | Finding | Action |
|---|---|---|
| C2 admissibility rule | Removing Rule 2 reopens 3-slot gaming window; tighten to `slot(now)+1` | **Keep Rule 2**, tighten bound from `now+3×period` to `now+1 slot` |
| Genesis time caching | Must cache in `DPoS` struct (Agave caches in every Bank) | **Promote to required change** |
| inturn formula | Agave uses stake-weighted random; GTOS uses round-robin intentionally | Confirmed intentional difference; document |
| Clock skew tolerance | Agave ±150%; GTOS 3×period is correctly stricter for controlled network | No change |
| Epoch boundary crossing | Same validator at boundary is normal in both | No change |
| Recents N/3+1 safety | Well-founded; M3 slot-keyed fix is correct | Confirmed |
| verifyCascadingFields | All necessary checks present; no missing checks | Confirmed |

---

## 13. Third-Round Review Findings

Four issues identified in a targeted review; all resolved above.

### 13.1 C2 slot-gaming window still open (High)

**Issue**: Even with Rule 2 as originally written (`slot(now + 3×period)`), a
proposer could scan up to 3 future slots to find one where they are `inturn` and
claim `diffInTurn`. Neither the `ErrFutureBlock` bound nor Rule 2-as-was closed
this. §12.1's earlier conclusion to "remove Rule 2" was wrong and would have made
it worse.

**Fix**: Tighten Rule 2 to `slot(now) + 1`. Gaming window: 3 slots → 1 slot.
Complete elimination deferred to pre-committed leader schedule (§14.2).
See §6 (updated code) and §12.1 (updated analysis).

### 13.2 Internal conflict: Rule 2 in §6 vs §12.1 (Medium)

**Issue**: §6 added Rule 2 with a 3-slot bound. §12.1 (second-round) said
"remove Rule 2 (redundant)". Both instructions coexisted in the document,
producing an unimplementable dual-spec.

**Fix**: §6 updated to tightened Rule 2 (`slot(now)+1`). §12.1 revised to
"tighten, do NOT remove". Document now has a single consistent stance.

### 13.3 Recents eviction leaves stale entries on slot jumps (Medium)

**Issue**: `apply()` evicted only `delete(snap.Recents, slot-limit)` — a single
map entry. If slot advanced by a large jump (e.g., network partition followed by
resync), entries for slots `[0, slot-limit-1]` all remained. Over time, the
Recents map grew without bound and `verifySeal`'s linear scan became costly.

**Fix**: Bulk evict all entries where `seenSlot ≤ slot - limit`.
See §8 (updated `apply()` code).

### 13.4 Agave citation bank.rs:2926 incorrect (Low-Medium)

**Issue**: §11.1 cited `bank.rs:2926` as evidence that "Agave doesn't re-stamp
timestamps after production." That line is an Alpenglow-specific Clock sysvar
update function, not the general block timestamp generation path. Using it as a
general-principle citation is inaccurate.

**Fix**: Removed the specific line citation from §11.1. The finding itself
(no re-stamp) is correct and now stated as a general architectural property:
Agave has no out-of-turn concept, so no re-stamp is ever needed.

---

## 14. Open Questions (updated)

1. **Genesis time**: now a **required change** (§12.2) — cache `d.genesisTime`
   in `DPoS.New()`.

2. **Stake-weighted schedule**: once validators hold meaningfully different stake,
   replace round-robin with stake-proportional slot allocation (as in Agave:
   `WeightedU64Index` seeded by epoch, `NUM_CONSECUTIVE_LEADER_SLOTS = 4`).

3. **Equivocation evidence**: Agave records same-slot conflicting blocks as
   provable equivocation (`store_duplicate_slot`, `blockstore.rs:1989`). GTOS
   relies on TD fork resolution. Slashing on equivocation is a future feature.

4. **On-chain slot sysvar**: deferred until TOS has contract execution.
