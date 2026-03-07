# Turn Length for GTOS DPoS

**Status**: 100% implemented
**Target**: `params/config.go`, `consensus/dpos/snapshot.go`, `consensus/dpos/dpos.go`, local ops/docs
**Scope**: introduce grouped proposer turns with initial `turnLength = 16`

---

## 1. Decision

GTOS is still under active development and there is no production chain that must
remain backward compatible.

Therefore this design takes the simple path:

- `turnLength` is introduced as a **genesis-fixed consensus parameter**
- initial value is **`16`**
- there is **no compatibility bridge** for old `turnLength = 1` networks
- there is **no hard-fork transition logic**
- there is **no dynamic turn length** driven by contracts, headers, or epochs

This is a new baseline protocol rule for GTOS DPoS.

---

## 2. Motivation

Current GTOS DPoS is effectively:

```text
turnLength = 1
```

meaning proposer rotation changes every block.

That keeps the scheduling simple, but it also means:

- proposer changes are very frequent
- short network jitter can cause more missed turns
- the active proposer has only one slot to recover from small timing variance
- the protocol cannot intentionally give one validator a wider continuous sealing window

Introducing `turnLength = 16` means:

- one validator is the in-turn proposer for **16 consecutive slots**
- proposer switching happens less frequently
- sealing behavior becomes more stable under short-lived network jitter
- GTOS DPoS becomes operationally closer to modern Parlia-style grouped turns

The tradeoff is explicit:

- fairness is still round-robin over time
- but proposer cadence becomes burstier inside each epoch

---

## 3. Terminology

- `slot`: the logical slot derived from `(header.Time - genesisTime) / periodMs`
- `turnLength`: the number of consecutive slots owned by the same in-turn proposer
- `turn group`: the contiguous slot interval owned by one proposer
- `recent signer window`: the slot-distance window used to prevent the same validator
  from re-entering rotation too early after finishing its turn group

---

## 4. Consensus Rule

Let:

- `N = number of active validators in the snapshot used for the slot`
- `T = turnLength`
- `slot = headerSlot(header.Time, genesisTime, periodMs)`

GTOS must anchor grouped turns to the **slot of the block being produced**, not to the
parent snapshot number.

The first produced block after genesis normally has `slot = 1`, because:

- `headerSlot()` returns `0` when `headerTime == genesisTime`
- block production begins at `genesisTime + periodMs`

Therefore the grouped-turn rule for GTOS must be:

```text
proposerIndex(slot) = ((slot - 1) / T) % N    for slot >= 1
```

`slot == 0` must never be fed into this formula. Implementations must guard it
explicitly, because `slot` is `uint64` and `slot - 1` would underflow.

Practical rule:

- genesis is never sealed
- grouped-turn proposer selection applies only to produced blocks, which start at
  `slot >= 1`
- helper functions should return "not in turn" or an explicit error when `slot == 0`

The validator at `Validators[proposerIndex(slot)]` is the only in-turn proposer for
all slots in the interval:

```text
[(k*T)+1, (k*T)+T]
```

for some integer `k >= 0`.

With `T = 16`, validator `V_i` is in turn for 16 consecutive slots, then the next
validator becomes in turn for the next 16 slots.

### Example

For validators `[A, B, C]` and `turnLength = 16`:

- slots `1..16`   -> `A`
- slots `17..32`  -> `B`
- slots `33..48`  -> `C`
- slots `49..64`  -> `A`

This is the rule implementers must use in GTOS. Do not switch to raw `slot / T`
without the `slot-1` anchor, otherwise the first proposer group becomes one slot short
for produced blocks.

---

## 5. Recent-Signer Rule

This is the most important protocol change after proposer scheduling.

GTOS currently tracks recent signers in a `Recents` map keyed by slot. That structure
can remain, but the semantics must change.

If only proposer selection changes while recent-signer checks remain `turnLength = 1`
style, the same validator would be rejected after signing the first slot of its own
16-slot turn group. That would be a consensus bug.

### Rule

For `N` validators and `turnLength = T`, the default recent-signer window is:

```text
recentWindow = (floor(N/2) + 1) * T - 1
```

For the current GTOS default of 3 validators and `T = 16`:

```text
recentWindow = (1 + 1) * 16 - 1 = 31
```

This matches the intended grouped-turn safety rule:

- a validator may sign all slots in its own turn group
- but it may not re-enter rotation too early before enough other proposer groups have
  had a chance to sign

### Consequence

`recentlySigned` can no longer mean:

```text
"is this validator present anywhere in Recents?"
```

It must **not** mean a pure slot-distance predicate such as:

```text
"did this validator sign within the active recent window relative to the slot being verified?"
```

That rule is insufficient because it would reject slot 2 of the same validator's own
16-slot turn group immediately after slot 1.

### Required semantics

GTOS should follow the same high-level model BSC uses for grouped turns:

1. keep `Recents` keyed by slot
2. count only entries within the active recent window
3. let one validator appear up to `TurnLength` times inside that window
4. reject only when the validator has already consumed its allowed `TurnLength`
   signatures in the active window

Equivalent pseudocode:

```go
func (s *Snapshot) recentlySignedAt(slot uint64, validator common.Address) bool {
    if len(s.Validators) == 1 {
        return false
    }
    if s.config == nil || s.config.TurnLength == 0 {
        return false // misconfigured; config validation must reject this earlier
    }

    left := uint64(0)
    window := s.recentSignerWindowSize()
    if slot > window {
        left = slot - window
    }

    seen := uint64(0)
    for seenSlot, signer := range s.Recents {
        if seenSlot <= left {
            continue
        }
        if signer == validator {
            seen++
        }
    }
    return seen >= s.config.TurnLength
}
```

This is the intended rule:

- the validator may sign all `TurnLength` slots in its own current turn group
- the validator is blocked only when it tries to exceed that allowance inside the
  active grouped-turn history window
- a single-validator network never self-blocks on recency
- the active recent window uses an **exclusive** left bound
  - entries with `seenSlot <= left` are outside the window
  - entries with `seenSlot > left` are inside the window

### Override

`RecentSignerWindow` may remain as an optional explicit override in `DPoSConfig`.
If set, it is interpreted in **slots**, not in proposer groups.

If `RecentSignerWindow == 0`, GTOS uses the derived grouped-turn default above.

### Existing helper must change

Current GTOS caps the recent-signer window at `validators`, which is valid only for the
old single-slot model. That cap must be removed when grouped turns are introduced.

For example, with `N=3` and `TurnLength=16`, the correct default window is `31`, which
is already greater than `validators=3`.

Therefore `RecentSignerWindowSize()` must be redefined around grouped-turn semantics and
must no longer clamp the value to the validator count.

Equivalent helper pseudocode:

```go
func (c *DPoSConfig) RecentSignerWindowSize(validators int) uint64 {
    if validators <= 0 {
        return 1
    }
    if c != nil && c.RecentSignerWindow > 0 {
        return c.RecentSignerWindow
    }
    turnLength := uint64(1)
    if c != nil && c.TurnLength > 0 {
        turnLength = c.TurnLength
    }
    return (uint64(validators/2) + 1) * turnLength - 1
}
```

---

## 6. Configuration

Add a new field to `params.DPoSConfig` in [config.go](../params/config.go):

```go
type DPoSConfig struct {
    PeriodMs                uint64   `json:"periodMs"`
    Epoch                   uint64   `json:"epoch"`
    MaxValidators           uint64   `json:"maxValidators"`
    RecentSignerWindow      uint64   `json:"recentSignerWindow,omitempty"`
    TurnLength              uint64   `json:"turnLength,omitempty"`
    SealSignerType          string   `json:"sealSignerType,omitempty"`
    CheckpointInterval      uint64   `json:"checkpointInterval,omitempty"`
    CheckpointFinalityBlock *big.Int `json:"checkpointFinalityBlock,omitempty"`
}
```

### v1 Rule

For this version of GTOS:

- `TurnLength` is mandatory
- `TurnLength = 16` is the recommended genesis default
- `TurnLength` is immutable consensus config

### Validation

GTOS should reject configs where:

- `TurnLength == 0`
- `Epoch == 0`
- `TurnLength > Epoch`
- `Epoch % TurnLength != 0`

The `Epoch % TurnLength == 0` rule is a correctness invariant for this v1 design, not
just a convenience rule.

Reason:

- proposer groups are anchored to absolute slots from genesis
- validator-set changes occur at epoch boundaries
- if an epoch boundary lands in the middle of a turn group, the remaining slots of that
  partially-consumed group become ambiguous after the validator set changes

Therefore v1 requires epoch boundaries to align exactly with proposer-group boundaries.

### Compatibility

Because GTOS does not need backward compatibility here:

- `checkCompatible` should still compare `TurnLength`
- `TurnLength` mismatch is a hard safety failure, not a soft warning
- nodes with different `TurnLength` values will derive different proposer schedules and
  will fork as soon as scheduling diverges
- there is no need to support empty or legacy fallback semantics

---

## 7. Snapshot Semantics

Target file: [snapshot.go](../consensus/dpos/snapshot.go)

The `Snapshot` structure does not need a new persisted `TurnLength` field if it can
always read `snap.config.TurnLength`. The parameter is chain-wide and immutable in v1.

### Persistence baseline

This design assumes a fresh GTOS network baseline with `TurnLength` present from the
start in genesis.

Because GTOS does not need backward compatibility here:

- reusing databases that contain snapshots and recents created under the old implicit
  `turnLength = 1` semantics is out of scope
- nodes should initialize from genesis, or from chain data produced by the same
  `TurnLength` rules

This intentionally avoids defining mixed old/new snapshot semantics.

### Required helpers

Add helpers equivalent to:

```go
func (s *Snapshot) proposerIndexForSlot(slot uint64) int
func (s *Snapshot) inturnSlot(slot uint64, validator common.Address) bool
func (s *Snapshot) recentSignerWindowSize() uint64
func (s *Snapshot) recentlySignedAt(slot uint64, validator common.Address) bool
```

`proposerIndexForSlot`, `inturnSlot`, and `recentlySignedAt` must always receive the
slot of the **candidate header being validated or sealed**, not the parent slot and not
the snapshot block number.

`recentSignerWindowSize()` on `Snapshot` is a convenience wrapper around config:

```go
func (s *Snapshot) recentSignerWindowSize() uint64 {
    return s.config.RecentSignerWindowSize(len(s.Validators))
}
```

The old helper:

```go
func (s *Snapshot) recentlySigned(validator common.Address) bool
```

must be deleted, not kept as a legacy alias. `recentlySignedAt(slot, validator)` is a
breaking signature change, and call sites must pass the slot explicitly.

### Proposer selection

`inturnSlot` must use:

```text
((slot - 1) / TurnLength) % len(Validators)    for slot >= 1
```

not:

```text
slot % len(Validators)
```

### Recent-signer check

`recentlySignedAt(slot, validator)` must:

1. derive the active window length
2. scan `Recents`
3. treat entries older than the window as irrelevant
4. count how many times the validator appears inside the active window
5. report true only if the validator has already signed `TurnLength` times in that
   active window

In `apply()`, the `slot` value is already computed before signer validation. The old:

```go
if snap.recentlySigned(signer) { ... }
```

must become:

```go
if snap.recentlySignedAt(slot, signer) { ... }
```

### Re-trimming

When applying headers or switching validator set at an epoch boundary, stale recents
must be trimmed using the grouped-turn window length, not the old single-slot rule.

---

## 8. Consensus Engine Changes

Target file: [dpos.go](../consensus/dpos/dpos.go)

The following paths must be kept strictly consistent:

1. proposer eligibility in `Seal`
2. proposer verification in `verifySeal`
3. difficulty calculation in `CalcDifficulty`
4. any helper that infers in-turn / out-of-turn semantics

If any of these keeps the old `turnLength = 1` interpretation while the others move to
grouped turns, GTOS will fork.

### Required rule

All in-turn checks must use the same grouped-turn formula:

```text
proposerIndex(slot) = ((slot - 1) / TurnLength) % N    for slot >= 1
```

### Required recent-signer rule

All recent-signer checks must use the same count-based grouped-turn rule relative to the
slot being validated or sealed.

### Recommended refactor

Move proposer and recency logic into `Snapshot` helpers and let both `Seal` and
`verifySeal` call the same helpers, instead of duplicating the logic in two places.

This is not just a style cleanup. Current GTOS has two inline recency loops in
`dpos.go` that bypass `Snapshot`:

- `verifySeal` currently contains an inline distance-based loop around
  [dpos.go:1241](../consensus/dpos/dpos.go:1241)
- `Seal` currently contains an inline distance-based loop around
  [dpos.go:1602](../consensus/dpos/dpos.go:1602)

Both loops must be replaced wholesale with:

```go
if snap.recentlySignedAt(slot, signer) { ... }
```

or, in `Seal`:

```go
if snap.recentlySignedAt(sealSlot, v) { ... }
```

Updating `RecentSignerWindowSize()` alone is not sufficient. If those inline loops are
left in place while the grouped-turn window grows from the old tiny value to the new
derived value, GTOS can halt early because the old `slot < limit || seenSlot > slot-limit`
distance check is incompatible with grouped-turn recency semantics.

---

## 9. Difficulty Semantics

GTOS currently uses difficulty as part of the in-turn / out-of-turn signaling.

That signaling must now align with grouped turns.

For all slots inside the same proposer group:

- the designated validator is in turn
- all other validators are out of turn

There must be no hidden assumption that only one block per round may be in turn.

This means `CalcDifficulty` must be checked carefully and rewritten, if needed, to use
the grouped-turn proposer rule instead of block-by-block modulo rotation.

---

## 9A. Out-of-Turn Delay and Backoff

GTOS currently allows out-of-turn sealing with a bounded wiggle window in `Seal`.

For v1 grouped turns, GTOS should keep that model and change only the definition of
"in turn":

- the designated grouped-turn proposer is in turn for all `TurnLength` slots in its
  current group
- all other validators remain out of turn
- the existing out-of-turn wiggle mechanism remains in place unless GTOS explicitly
  redesigns it in a later document

This is an intentional simplification relative to BSC. BSC couples grouped turns with
additional delay/backoff logic, but GTOS does not need to import that complexity in v1.

What **must** be consistent is:

- `Seal`
- `verifySeal`
- `CalcDifficulty`
- any in-turn/out-of-turn metric or logging path

All of them must agree on the same grouped-turn proposer for a given slot.

---

## 10. Epoch Semantics

GTOS validator-set updates remain **epoch-based**.

This design does **not** change:

- validator registry semantics
- epoch checkpoint blocks
- epoch extra validator encoding
- the rule that active proposer set changes at epoch boundaries

It changes only:

- who is the in-turn proposer for each slot inside an epoch
- how recent signer recency is interpreted

### Operational consequence

Maintenance mode behavior does not become immediate.

A validator that enters maintenance is still removed from the proposer set at the next
epoch snapshot, just like today.

What changes is that proposer ownership inside one epoch becomes burstier:

- each validator gets 16 consecutive slots instead of 1

With current GTOS defaults:

- `PeriodMs = 360`
- `TurnLength = 16`

one proposer turn group lasts:

```text
16 * 360ms = 5760ms ~= 5.76s
```

That is acceptable and still short enough for local and production-like testnets.

---

## 11. Checkpoint Finality Integration

This design is intended to remain fully compatible with
[Checkpoint.md](../docs/Checkpoint.md).

### What does not change

- checkpoint block definition
- checkpoint QC structure
- checkpoint signer-set derivation
- finalized fork-choice enforcement
- retention requirements

### What must be re-tested

`turnLength = 16` changes sealing cadence, so the following paths need regression tests:

1. local vote generation near eligible checkpoints
2. vote journaling
3. vote gossip under consecutive slots by the same proposer
4. QC assembly in descendant blocks

The protocol model itself does not need to change. This is an implementation and test
integration concern, not a design rewrite.

---

## 12. Validator Maintenance Integration

This design is intended to remain fully compatible with
[Validator-Ops.md](../docs/Validator-Ops.md).

### No protocol change is required for maintenance

The existing maintenance model remains:

- `VALIDATOR_ENTER_MAINTENANCE`
- `VALIDATOR_EXIT_MAINTENANCE`
- maintenance becomes active at the next epoch validator-set refresh

### Operational impact

Runbooks and scripts must stop assuming that proposer rotation changes every block.

With `turnLength = 16`:

- seeing the same validator seal 16 consecutive blocks is expected
- that is not liveness failure
- monitoring must understand grouped-turn rotation

The `drain` / `resume` shell flows do not need protocol changes, but their logging and
waiting messages should mention grouped turns.

---

## 13. Local Testnet and Deployment Script Changes

Target file: [validator_cluster.sh](../scripts/validator_cluster.sh)

Required changes:

1. add `TURN_LENGTH` with default `16`
2. write `turnLength` into genesis DPoS config
3. print effective proposer-group duration:

```text
turnGroupDurationMs = TurnLength * PeriodMs
```

4. validation rules:
   - `TURN_LENGTH > 0`
   - `TURN_LENGTH <= EPOCH`
   - `EPOCH % TURN_LENGTH == 0`
5. status output should display:
   - epoch length
   - turn length
   - next epoch boundary
   - expected proposer-group duration

### Recommended CLI note

The script help text should explain:

- `turnLength = 16` means one validator may seal 16 consecutive blocks
- this is expected behavior

---

## 14. RPC and Operator Visibility

Target file: [api.go](../consensus/dpos/api.go)

`GetEpochInfo` should be extended to expose:

- `TurnLength`
- `TurnGroupDurationMs`
- optionally `RecentSignerWindow`

This matters operationally because once grouped turns are enabled, the old mental model
of "rotation changes every block" is no longer valid.

Suggested extension:

```go
type EpochInfo struct {
    Number               hexutil.Uint64 `json:"number"`
    EpochLength          hexutil.Uint64 `json:"epochLength"`
    EpochIndex           hexutil.Uint64 `json:"epochIndex"`
    EpochStart           hexutil.Uint64 `json:"epochStart"`
    NextEpochStart       hexutil.Uint64 `json:"nextEpochStart"`
    BlocksUntilEpoch     hexutil.Uint64 `json:"blocksUntilEpoch"`
    TargetBlockPeriodMs  hexutil.Uint64 `json:"targetBlockPeriodMs"`
    TurnLength           hexutil.Uint64 `json:"turnLength"`
    TurnGroupDurationMs  hexutil.Uint64 `json:"turnGroupDurationMs"`
    RecentSignerWindow   hexutil.Uint64 `json:"recentSignerWindow"`
}
```

---

## 15. Testing Plan

### Config tests

Target file: [config_test.go](../params/config_test.go)

Add tests for:

- `TurnLength = 0` rejected
- `TurnLength > Epoch` rejected
- `Epoch % TurnLength != 0` rejected
- `TurnLength` mismatch rejected by config compatibility checks

### Snapshot tests

Target file: [dpos_test.go](../consensus/dpos/dpos_test.go)

Add tests for:

1. grouped proposer selection
   - same validator is in turn for slots `1..16`
   - next validator is in turn for slots `17..32`

2. recent-signer window semantics
   - a validator can sign all slots in its own turn group
   - it is blocked from re-entering too early
   - it becomes eligible again exactly at the window boundary
   - `N=1` never self-blocks
   - an out-of-turn validator is blocked only after consuming `TurnLength`
     appearances inside the active window, not after a single early seal

3. recents trimming
   - stale slot entries are dropped correctly under the new window length

### Integration tests

Target file: [integration_test.go](../consensus/dpos/integration_test.go)

Add tests for:

1. multi-validator chain seals in 16-slot groups
2. epoch boundary validator-set updates still work
3. maintenance remains next-epoch effective
4. checkpoint finality still progresses under grouped turns

### Local deployment smoke test

Use the three-node local testnet with:

- `turnLength = 16`
- checkpoint finality on and off
- maintenance enter/exit

Expected behavior:

- blocks continue growing
- rotation occurs by groups, not by single blocks
- no node stalls because of old recent-signer assumptions

---

## 16. Rollout Plan

Because GTOS does not need backward compatibility here, rollout is simple:

1. implement the protocol changes
2. make `turnLength = 16` the default in genesis generation for new local/test networks
3. run integration and local soak tests
4. update operator docs and runbooks
5. treat grouped turns as the new GTOS baseline

No migration plan for legacy GTOS DPoS networks is required in this version.

### Atomicity requirement

All turn-length-related proposer/recency changes must ship in the same binary version.
There is no safe partial deployment.

At minimum, the following must land together:

1. `RecentSignerWindowSize()` grouped-turn formula
2. `inturnSlot()` grouped-turn proposer formula
3. new `recentlySignedAt(slot, validator)` helper
4. `apply()` switched from `recentlySigned()` to `recentlySignedAt(...)`
5. inline recency loops in `verifySeal` and `Seal` replaced with
   `recentlySignedAt(...)`

If the window formula is updated without replacing the old inline distance-based recency
loops, GTOS can halt instead of merely degrading.

---

## 17. File-by-File Implementation Checklist

### ✅ [config.go](../params/config.go)

- ✅ add `TurnLength`
- ✅ add validation rules (`ValidateTurnLengthConfig`: zero, >Epoch, Epoch%TurnLength!=0)
- ✅ add compatibility comparison for `TurnLength` as a mandatory safety check (`checkCompatible`)
- ✅ update string/debug rendering
- ✅ emit a clear validation error that distinguishes `turnLength` missing/zero from other
  invalid values

### ✅ [snapshot.go](../consensus/dpos/snapshot.go)

- ✅ add grouped proposer helpers (`proposerIndexForSlot`)
- ✅ rewrite `inturnSlot` (uses `((slot-1)/T)%N` with slot=0 guard)
- ✅ delete `recentlySigned(validator)`
- ✅ add `recentlySignedAt(slot, validator)` (count-based, N=1 short-circuit, TurnLength guard)
- ✅ update `apply()` to pass `slot` into `recentlySignedAt(...)`
- ✅ rewrite recents trimming

### ✅ [dpos.go](../consensus/dpos/dpos.go)

- ✅ update `Seal` (inline distance loop replaced with `snap.recentlySignedAt(sealSlot, v)`)
- ✅ update `verifySeal` (inline distance loop replaced with `snap.recentlySignedAt(slot, signer)`)
- ✅ update `CalcDifficulty` (uses `snap.inturnSlot(slot, v)` via `calcDifficultySlot`)
- ✅ ensure all grouped-turn decisions use the same helper logic
- ✅ replace the inline recency loop in [dpos.go:1241](../consensus/dpos/dpos.go:1241) with `snap.recentlySignedAt(slot, signer)`
- ✅ replace the inline recency loop in [dpos.go:1602](../consensus/dpos/dpos.go:1602) with `snap.recentlySignedAt(sealSlot, v)`

### ✅ [api.go](../consensus/dpos/api.go)

- ✅ expose `TurnLength`
- ✅ expose `TurnGroupDurationMs`
- ✅ expose effective recent-signer window (`RecentSignerWindow`)

### ✅ [validator_cluster.sh](../scripts/validator_cluster.sh)

- ✅ add `TURN_LENGTH` (default 16, `--turn-length` flag)
- ✅ validate `TURN_LENGTH > 0`
- ✅ validate `TURN_LENGTH <= EPOCH`
- ✅ validate `EPOCH % TURN_LENGTH == 0`
- ✅ emit `turnLength` into genesis JSON
- ✅ show grouped-turn operator hints (duration, status output)

### ✅ [Validator-Ops.md](../docs/Validator-Ops.md)

- ✅ document grouped-turn interpretation for operators (§ "Grouped-Turn Operations", lines 272-293)
- ✅ update maintenance expectations (lines 366-372, 422-428)

### ✅ [Checkpoint.md](../docs/Checkpoint.md)

- ✅ no protocol rewrite required
- ✅ add a brief note that grouped turns do not change checkpoint QC semantics (lines 36-43)

### ✅ Tests ([config_test.go](../params/config_test.go), [dpos_test.go](../consensus/dpos/dpos_test.go), [integration_test.go](../consensus/dpos/integration_test.go))

- ✅ `ValidateTurnLengthConfig` rejection cases (zero, >Epoch, not-divisible)
- ✅ `RecentSignerWindowSize` formula tests
- ✅ `checkCompatible` TurnLength mismatch test
- ✅ grouped proposer selection (same validator in turn for slots 1..T)
- ✅ recent-signer window semantics (count-based; allowed T seals before block)
- ✅ N=1 never self-blocks
- ✅ multi-validator integration chain with TurnLength=16
- ✅ epoch boundary validator-set updates under grouped turns

---

## 18. Integrity Check

This design is internally consistent with the current GTOS direction:

- `ed25519-only` DPoS sealing remains unchanged
- checkpoint finality remains valid
- maintenance mode remains valid
- local testnet scripts can express the config cleanly

There are only two non-negotiable implementation rules:

1. proposer selection and recent-signer logic must change together
2. `Seal`, `verifySeal`, and `CalcDifficulty` must share the same grouped-turn rule

If those two rules are followed, `turnLength = 16` is a coherent next-step evolution of
GTOS DPoS.
