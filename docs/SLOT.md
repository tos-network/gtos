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

## 7. Open Questions

1. **Genesis timestamp source**: `chain.Config()` does not currently expose
   `GenesisTimestamp`. The genesis block's `header.Time` is the natural source.
   Needs a helper: `chain.GetHeaderByNumber(0).Time`.

2. **Stake-weighted schedule (future)**: Once validators hold meaningfully different
   stake amounts, the round-robin rotation should be replaced with stake-proportional
   slot allocation (as in Agave). This is a protocol-level change requiring an epoch
   schedule recomputation mechanism.

3. **On-chain slot sysvar**: For contracts to read the current slot, a `SLOT` opcode
   or sysvar equivalent should be defined. Currently TOS has no VM, so this is
   deferred until contract execution is introduced.
