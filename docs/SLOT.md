# GTOS DPoS Slot Design

Status: `PROPOSED`
Reference: Agave (Solana validator client) `~/agave`

---

## 1. Background: Current Mechanism

GTOS DPoS is derived from go-ethereum's **Clique** PoA engine. In-turn validator
selection uses block number as the rotation index:

```go
// snapshot.go — inturn()
return number % uint64(len(s.Validators)) == uint64(i)
```

There is no explicit "slot" concept. Consequences:

- When the in-turn validator is slow, an out-of-turn validator produces **the same
  block number** after a random wiggle delay (`rand(0, 720ms)`).
- Block height and "turn" are always identical: block N is always assigned to
  `validators[N % count]`, even if produced by someone else.
- It is impossible to know in advance which validator should produce block N+1000
  without knowing all future block numbers.
- Monitoring can only track block production frequency, not missed turns.

---

## 2. Agave Reference Analysis

Agave (Solana's validator client) implements slots as a first-class protocol
concept. Key findings from the source:

### 2.1 Slot definition (`solana_clock`)

```rust
type Slot = u64;  // strictly monotone, starts at 0 (genesis)
```

- A slot is a fixed-duration time window (`DEFAULT_MS_PER_SLOT = 400`ms).
- Slot number is **independent of block production**: whether or not a block is
  produced, the slot number advances.
- `block_height ≤ slot_number` always. On mainnet they diverge immediately due
  to skipped slots.

### 2.2 Current slot computation

Every validator independently computes:

```
current_slot = floor((wall_time − genesis_time) / slot_duration)
```

No consensus round is needed to agree on the current slot — it follows from the
shared genesis timestamp and system clock.

### 2.3 Leader schedule (`leader-schedule/src/lib.rs`)

```
leader_for_slot(N) = LeaderSchedule[N % epoch_length]
```

The schedule is computed once per epoch (≈ 432 000 slots on mainnet) and is
**fully deterministic** given the epoch number and stake distribution. All
validators compute the same schedule independently.

### 2.4 Skipped slot handling

When a leader fails to produce within their slot:

- No block is stored for that slot in the ledger.
- Validators issue **skip certificates** (BFT `Vote::Skip`) for the missing slot.
- The next leader references the last confirmed parent (gap is explicit in the
  chain).
- Slot numbers are never reused or renumbered: if slot 100 is skipped, the next
  block occupies slot 101 (or later).

### 2.5 Slot stored in every shred

Agave stores the slot number in the `ShredCommonHeader` of every network packet:

```rust
struct ShredCommonHeader {
    signature: Signature,   // 64 bytes
    shred_variant: u8,
    slot: Slot,             // u64 — explicit in every wire message
    index: u32,
    version: u16,
    fec_set_index: u32,
}
```

The slot is not derived from block content at runtime; it is part of the
canonical identity of each piece of data.

### 2.6 Clock sysvar (`solana_sysvar::clock::Clock`)

On-chain programs can read:

```rust
Clock {
    slot: Slot,                 // current slot
    epoch: u64,                 // current epoch
    epoch_start_timestamp: i64, // unix seconds when epoch began
    unix_timestamp: i64,        // stake-weighted median of validator clocks
}
```

### 2.7 Key invariants (from Agave)

1. `slot(block) > slot(parent)` — strictly increasing, enforced in verification.
2. A slot can have at most one block (duplicate slots are rejected).
3. Skipped slots are explicit gaps; the ledger tracks them via a bitvector
   (`SlotHistory` sysvar).

---

## 3. GTOS Slot Design Proposal

### 3.1 Slot number formula

GTOS stores block timestamps as Unix milliseconds in `header.Time`. The slot
number is therefore **derivable without a new header field**:

```
slotNumber(header) = (header.Time − genesis.Time) / periodMs
```

With `periodMs = 360`, each slot is a 360 ms time window.

This matches Agave's principle exactly (`current_slot = (now − genesis) / slot_ms`)
while reusing the existing timestamp field.

### 3.2 In-turn validator (updated `inturn()`)

Replace block-number-based rotation with slot-number-based rotation:

```go
// Before (block-based, Clique heritage)
return number % uint64(len(s.Validators)) == uint64(i)

// After (slot-based)
slot := (header.Time - genesis.Time) / uint64(periodMs)
return slot % uint64(len(s.Validators)) == uint64(i)
```

The genesis timestamp is available from `chain.Config()` or passed in from
`ChainHeaderReader`.

### 3.3 Skipped slot semantics

When the in-turn validator is slow, out-of-turn validators fire after
`rand(0, wiggle)` and produce a block. That block's timestamp falls in a
**later slot window**, which may belong to a different validator. Effects:

- Slot 100 belongs to validator A. A is slow.
- Out-of-turn validator B fires at `T + 360ms + 490ms = T + 850ms`.
- `floor(850 / 360) = 2` → block lands in slot 102.
- Slot 100 and 101 are implicitly skipped.
- In-turn for slot 102 is `validators[102 % 3]` — which may or may not be B.
  B produces with `diffNoTurn` if it is not the in-turn validator for slot 102.

This is the correct behaviour: **missed slots advance the slot clock forward**,
naturally rotating the responsibility to the next eligible validator. No explicit
skip certificates are needed (unlike Agave's BFT-voting model) because the
wiggle mechanism already resolves the race deterministically.

### 3.4 Block height vs slot number

After introducing slots, block height and slot number diverge whenever a slot is
skipped. Both values are meaningful:

| Value | Meaning | How obtained |
|---|---|---|
| `header.Number` | block height (chain length) | existing field |
| `slotNumber` | time-based rotation index | `(header.Time − genesis.Time) / periodMs` |

RPC consumers that need the slot number can compute it from the timestamp.
No header schema change is required.

### 3.5 Recents window

The existing `Recents` map (`blockNumber → signer`) prevents a validator from
signing twice within a window of `N/3 + 1` consecutive **blocks**. After the
slot change, the semantic stays correct: the recency check still uses block
numbers (the map key is block number), and the window size is already
`len(validators)/3 + 1` blocks. No change needed here.

### 3.6 Strict slot increase — new verification rule

Agave enforces `slot(block) > slot(parent)`. GTOS must add the equivalent to
`verifyCascadingFields`:

```go
parentSlot := (parent.Time - genesisTime) / uint64(periodMs)
headerSlot := (header.Time - genesisTime) / uint64(periodMs)
if headerSlot <= parentSlot {
    return errInvalidSlot // slot must strictly increase
}
```

This also prevents two blocks from claiming the same slot (Agave invariant §2.7.2).

---

## 4. Correctness Review Against Agave

| Invariant (Agave) | GTOS Slot Proposal | Status |
|---|---|---|
| Slot is time-based: `(now − genesis) / period` | Same formula, uses `header.Time` | ✅ Correct |
| `slot(block) > slot(parent)` strictly | Enforced in `verifyCascadingFields` | ✅ Add rule |
| At most one block per slot | Follows from strict-increase rule | ✅ Correct |
| Slot number stored in every message | Derivable from `header.Time`; no extra field | ✅ Equivalent |
| Block height ≤ slot number | True once any slot is skipped | ✅ Correct |
| Leader for slot N is deterministic | `validators[slot % count]` per epoch | ✅ Correct |
| Skipped slots have no block | Implicit via timestamp gap | ✅ Correct |
| Skip mechanism | Agave: BFT skip certificates | GTOS: wiggle race — simpler, sufficient for ≤ 21 validators |
| Stake-weighted leader schedule | Agave: proportional slots per stake | GTOS: round-robin among validators above stake threshold — intentional simplification |
| Clock sysvar (on-chain slot) | `Clock.slot` sysvar account | GTOS: slot derivable by any contract from `BLOCKTIMESTAMP` opcode equivalent |

**Intentional differences justified:**

1. **No skip certificates**: Agave requires BFT votes for every skipped slot because
   it supports thousands of validators and needs provable finality. GTOS with ≤ 21
   validators uses the wiggle race instead — the out-of-turn validator that wins is
   chosen by timing, which is sufficient for a small, known validator set.

2. **Round-robin vs stake-weighted schedule**: Agave allocates slots proportionally
   to stake (more stake = more leader slots per epoch). GTOS uses equal rotation
   among validators who have met the minimum stake requirement. This is correct for
   the current phase where all validators hold equal or similar stake.

---

## 5. Required Changes

### 5.1 `consensus/dpos/snapshot.go` — `inturn()`

```go
// Pass genesis.Time and periodMs into inturn().
func (s *Snapshot) inturn(number uint64, header *types.Header,
    genesisTime uint64, periodMs uint64, validator common.Address) bool {
    if len(s.Validators) == 0 || periodMs == 0 {
        return false
    }
    slot := (header.Time - genesisTime) / periodMs
    for i, v := range s.Validators {
        if v == validator {
            return slot%uint64(len(s.Validators)) == uint64(i)
        }
    }
    return false
}
```

### 5.2 `consensus/dpos/dpos.go` — `verifyCascadingFields()`

Add after the existing timestamp minimum-interval check:

```go
genesisTime := chain.Config().GenesisTimestamp // or from genesis header
periodMs    := uint64(d.config.TargetBlockPeriodMs())
parentSlot  := (parent.Time - genesisTime) / periodMs
headerSlot  := (header.Time - genesisTime) / periodMs
if headerSlot <= parentSlot {
    return fmt.Errorf("dpos: slot did not advance: parent slot %d, header slot %d",
        parentSlot, headerSlot)
}
```

### 5.3 RPC / monitoring

Add a `dpos_slotNumber` RPC method or include `slot` in `dpos_getValidatorInfo`
response, computed as:

```
slot = (block.timestamp - genesis.timestamp) / periodMs
```

---

## 6. Slot-Based Monitoring Capabilities (new)

Once slot number is a first-class concept, the following metrics become available
without additional on-chain state:

| Metric | Formula |
|---|---|
| Expected leader for slot N | `validators[N % count]` |
| Slot fill rate (validator V) | `blocks_produced_by_V / slots_assigned_to_V` |
| Consecutive skipped slots | longest gap in `(header.Time − parent.Time) / periodMs − 1` |
| Current slot | `(now − genesis.Time) / periodMs` (wall-clock) |
| Slots per epoch | `epoch / periodMs` (with `epoch = 1667 × 360ms ≈ 600s`) |

---

## 7. Codex Review Findings

Reviewed by `gpt-5.3-codex` against current source (`consensus/dpos/dpos.go`,
`consensus/dpos/snapshot.go`). Findings ordered by severity.

### 7.1 Critical

**C1 — Skipped-slot narrative does not match current sealing behavior**
(`dpos.go:562`, `dpos.go:715–721`)

The proposal states that a wiggle delay makes a block "land in a later slot".
This is wrong. `Prepare()` sets `header.Time = parent.Time + periodMs` before
sealing; `Seal()` only delays the *broadcast*, not the timestamp. An out-of-turn
block therefore carries the *same* `header.Time` (same slot) as the in-turn
window, not a later one. Slot advancement is a proposer timestamp *choice*, not
an automatic consequence of wiggle.

Fix: if slots are to advance on skipped windows, `Prepare()` must compute
`header.Time` as `max(now, parent.Time + periodMs)` rounded up to the next slot
boundary, not simply `parent.Time + periodMs`.

**C2 — Timestamp gaming enables multi-`diffInTurn` siblings**
(`dpos.go:329`, `dpos.go:449`)

With slot-based `inturn()`, a proposer controls which slot it claims by choosing
`header.Time`. Since the only upper bound is `allowedFutureBlockTime` (~1 080 ms
ahead of wall clock), two validators can each craft a `diffInTurn` block at the
same block height but at different slots, both valid under current verification.
This creates competing equal-weight chain tips and weakens fork convergence.

Fix: add a *slot admissibility rule* — a proposer may only claim the slot that
corresponds to `floor(now / periodMs)` (current wall-clock slot) or the
immediately following one. Slots further ahead must be rejected by
`verifyCascadingFields`.

### 7.2 High

**H1 — Difficulty path not updated (`Prepare` / `calcDifficulty`)**
(`dpos.go:589`, `dpos.go:767`)

The proposal updates `inturn()` and `verifySeal`, but `Prepare()` and
`calcDifficulty()` still derive in-turn status from `snap.Number+1` (block
number). After the change, a miner will compute `diffInTurn` with block-number
logic while `verifySeal` checks it with slot logic — these can disagree and cause
`errWrongDifficulty` on valid blocks.

Fix: `Prepare()` and `calcDifficulty()` must call the new slot-based `inturn()`
via the same formula and genesis time source used in verification.

### 7.3 Medium

**M1 — Strict slot increase does not prevent same-slot siblings on forks**
(`docs/SLOT.md §3.6`)

`headerSlot > parentSlot` only forbids a block from claiming the same slot as its
*own parent*. Two miners can still each produce a block at the same slot number
on competing fork branches. The invariant is weaker than stated; it does not
achieve Agave's "at most one block per slot" property network-wide.

**M2 — uint64 underflow if `header.Time < genesis.Time`**
(`docs/SLOT.md §3.1`)

`(header.Time - genesis.Time) / periodMs` wraps to a huge value on uint64 when
`header.Time < genesis.Time`. This can occur on test networks or if a genesis
time is set in the future.

Fix: add an explicit guard:
```go
if header.Time < genesisTime {
    return 0, errInvalidTimestamp
}
```

**M3 — Recents window does not decay with skipped slots**
(`snapshot.go:133`, `snapshot.go:149`, `dpos.go:440`)

The `Recents` map is block-count based (evicted after `N/3+1` *blocks*). With
slot-based rotation, a validator may be scheduled again after only one skipped
slot (~720 ms) while its recents entry has not yet aged out of the block window.
`Seal()` will return "signed recently, must wait", blocking the legitimately
scheduled validator.

Fix: either convert the recents window to slot-count (evict after `N/3+1`
*slots*), or widen the recents window to account for potential slot skips.

### 7.4 Summary: must-fix before implementation

| # | Issue | Severity |
|---|---|---|
| C1 | `Prepare()` must set `header.Time` to the actual current slot boundary, not just `parent + periodMs` | Critical |
| C2 | Add slot admissibility rule to prevent timestamp gaming / multi-diffInTurn forks | Critical |
| H1 | Update `Prepare()` and `calcDifficulty()` to use slot-based `inturn()` | High |
| M1 | Document that same-slot siblings on competing forks are not prevented | Medium |
| M2 | Guard `header.Time >= genesis.Time` before slot formula | Medium |
| M3 | Convert `Recents` eviction window from block-count to slot-count | Medium |

---

## 8. Open Questions

1. **Genesis timestamp source**: `chain.Config()` does not currently expose
   `GenesisTimestamp`. The genesis block's `header.Time` is the natural source.
   Needs a helper: `chain.GetHeaderByNumber(0).Time`.

2. **Slot admissibility bound**: the exact rule for how far ahead a proposer may
   set `header.Time` (C2 above) needs to be specified — likely `parent.Time +
   periodMs ≤ header.Time ≤ now + allowedFutureBlockTime`, and additionally
   `slot(header) ≤ slot(now) + 1`.

3. **Stake-weighted schedule (future)**: once validators hold meaningfully
   different stake amounts, round-robin should be replaced with stake-proportional
   slot allocation (as in Agave).

4. **On-chain slot sysvar**: deferred until TOS has contract execution.
