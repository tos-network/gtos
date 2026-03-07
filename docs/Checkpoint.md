# Checkpoint Finality for GTOS DPoS

**Status**: Draft design (pre-implementation)
**Target**: `consensus/dpos/` + `params/config.go` + `core/types/` + `tos/protocols/tos/`
**Scope**: deterministic checkpoint finality without BLS

---

## 1. Overview

GTOS DPoS currently provides probabilistic safety only. A block becomes safer as more
children are appended, but there is no protocol-level irreversible checkpoint.

This design adds a minimal **checkpoint finality gadget** on top of the existing GTOS
DPoS chain:

- Every `K` blocks, a block is designated as a **checkpoint block**.
- Validators sign the checkpoint block hash using their existing consensus key.
- Once signatures from at least `ceil(2N/3)` active validators are collected, they form a
  **CheckpointQC** (quorum certificate).
- When a valid `CheckpointQC` is included in a descendant block, the checkpoint block and
  all of its ancestors become **finalized**.
- Finalized checkpoints are **consensus-hard**: the node must never reorganize to a
  branch that does not contain the finalized checkpoint as an ancestor.

This design deliberately avoids:

- BLS keys and aggregate signatures
- Casper FFG vote source/target logic
- HotStuff-style per-block locking
- new transaction types in the first version

The goal is to provide a simple, auditable, deterministic finality point for bridges,
withdrawals, and external settlement systems.

---

## 2. Goals and Non-Goals

### Goals

1. Add deterministic finality with minimal consensus changes.
2. Support chain-wide `ed25519` from day one.
3. Reuse GTOS's existing validator signer model.
4. Expose a clear RPC finality signal for relayers and custodial systems.
5. QC verification is split into two phases so that each phase only requires data that
   is guaranteed to be available at that stage of block processing:
   - **Phase 1 (`VerifyHeader`)**: structural checks only — no pre-state, no ancestor walk.
   - **Phase 2 (`VerifyBlock` / full import)**: cryptographic checks against pre-state signer set.

### Non-Goals

1. Per-block instant finality.
2. Signature aggregation.
3. Weighted voting by stake in v1.
4. Mixed validator signer types in one network version.
5. Slashing implementation in this phase.

---

## 3. High-Level Model

Let `K = CheckpointInterval`.

A block at height `h` is a checkpoint block iff:

```text
h > 0 && h % K == 0
```

Checkpoint finality activates at `CheckpointFinalityBlock`.

Define:

```text
FirstEligibleCheckpoint = the smallest h such that
    h >= CheckpointFinalityBlock && h % K == 0
```

Only checkpoint heights `>= FirstEligibleCheckpoint` are eligible for checkpoint votes
and quorum certificates. A QC for an earlier checkpoint is always invalid.

For each eligible checkpoint block `C`:

1. Validators observe `C` on the canonical branch.
2. Each validator signs `CheckpointVote{ChainID, Number, Hash, ValidatorSetHash}`.
3. Votes are gossiped to peers and cached in memory.
4. Any later proposer may collect at least `2/3` of the votes and embed a
   `CheckpointQC` into a descendant block `D`, where `D.Number > C.Number`.
5. On successful verification of the `CheckpointQC`, block `C` becomes finalized.

A checkpoint certificate does not need to appear in the immediate next block. Requiring
that would create unnecessary liveness coupling to a single proposer.

---

## 4. Configuration

Add the following fields to `params.DPoSConfig` in [config.go](/home/tomi/gtos/params/config.go):

```go
type DPoSConfig struct {
    PeriodMs                uint64   `json:"periodMs"`
    Epoch                   uint64   `json:"epoch"`
    MaxValidators           uint64   `json:"maxValidators"`
    RecentSignerWindow      uint64   `json:"recentSignerWindow,omitempty"`
    SealSignerType          string   `json:"sealSignerType,omitempty"`
    CheckpointInterval      uint64   `json:"checkpointInterval,omitempty"`
    CheckpointFinalityBlock *big.Int `json:"checkpointFinalityBlock,omitempty"`
}

func (c *DPoSConfig) IsCheckpointFinality(num *big.Int) bool {
    return c != nil && c.CheckpointFinalityBlock != nil &&
        num != nil && num.Cmp(c.CheckpointFinalityBlock) >= 0
}
```

### Recommended defaults

- `CheckpointFinalityBlock = nil` on existing networks until activation is planned
- `CheckpointInterval = 50` for bridge-oriented deployments
- `CheckpointInterval = 200` only if matching the existing epoch cadence is more
  important than latency

Finality latency is approximately:

```text
CheckpointInterval * PeriodMs
```

### Signer type rule

Checkpoint finality v1 assumes a single chain-wide `SealSignerType = ed25519`.

That matches current GTOS DPoS semantics: `SealSignerType` is a chain config parameter,
and changing it is already treated as a fatal config incompatibility.

Implication:

- checkpoint finality v1 is defined only for networks whose chain-wide signer type is
  `ed25519`
- mixed signer types inside one network version are out of scope for v1
- `secp256k1` checkpoint voting is out of scope for v1
- if GTOS wants a future signer-type hard fork, it should be a checkpoint-finality v2
  protocol revision, not hidden behind snapshot-dependent vote verification logic

---

## 5. Validator Signer Set Rule

This rule is consensus-critical.

For checkpoint block `C` at height `h`, the validator quorum is verified against the
**checkpoint pre-state signer set** at height `h-1`.

The signer set is the ordered list of validator signer records:

```go
type ValidatorSigner struct {
    Address     common.Address
    SignerType  string // canonical signer type
    SignerValue string // canonical signer value from account signer state
}
```

The record must be derived from the state associated with the snapshot at `h-1`.

Equivalently:

- block `h` may change the validator set for future blocks
- but the finality votes for checkpoint `h` are always verified against the validator
  signer set already active when `h` was proposed

This avoids circular dependencies where a block would both define and certify the same
validator set.

### Signer metadata invariant

Checkpoint finality v1 requires that **every active validator** in the checkpoint
pre-state has valid canonical signer metadata of the chain-wide `SealSignerType`.

Concretely, for every active validator address in snapshot `h-1`:

1. `accountsigner.Get(state, addr)` must return `ok=true`
2. `NormalizeSigner(signerType, signerValue)` must succeed
3. the normalized signer type must equal `ed25519`
4. `AddressFromSigner(normalizedType, normalizedPub)` must map back to `addr`

If any active validator fails these checks, the checkpoint signer set is invalid and any
checkpoint vote or QC for height `h` is invalid.

This rule keeps the quorum denominator unambiguous:

- `N` is always the number of active validators in snapshot `h-1`
- v1 does **not** silently drop malformed validators from the signer set
- therefore activation requires operator readiness before `FirstEligibleCheckpoint`

### ValidatorSetHash

`ValidatorSetHash` is defined as:

```text
keccak256(RLP([
  {address, signerType, signerValue},
  ...
]))
```

where the list is sorted by validator address ascending.

Binding `signerType` and `signerValue` into `ValidatorSetHash` ensures the vote is tied
not only to the validator addresses, but also to the exact consensus public keys active
for that checkpoint.

---

## 6. New Types

Create a new file such as `core/types/checkpoint.go`.

```go
package types

import (
    "math/big"

    "github.com/tos-network/gtos/common"
)

type CheckpointVote struct {
    ChainID          *big.Int    // replay protection; mirrors GTOS chain config semantics
    Number           uint64      // checkpoint block number
    Hash             common.Hash // checkpoint block hash
    ValidatorSetHash common.Hash // hash of ordered {address, signerType, signerValue} at Number-1
}

type CheckpointVoteEnvelope struct {
    Vote      CheckpointVote
    Signer    common.Address // explicit signer; used to locate the validator's ed25519 pubkey
    Signature [64]byte       // ed25519 signature, always exactly 64 bytes
}

type CheckpointQC struct {
    Vote       CheckpointVote
    Bitmap     uint64     // bit i corresponds to validator i in the ordered signer set
    Signatures [][64]byte // ed25519 signatures aligned with set bits in Bitmap, ascending index
}
```

### Why `Signer` is explicit in `CheckpointVoteEnvelope`

`ed25519` signatures do not recover the signer address. The explicit `Signer` field lets
the verifier locate the validator's canonical ed25519 public key in the checkpoint
pre-state signer set.

### Hashing rule

Validators sign:

```text
keccak256(rlp([
  "GTOS_CHECKPOINT_V1",
  ChainID,
  Number,
  Hash,
  ValidatorSetHash,
]))
```

Do not sign raw byte concatenation. Use a typed, versioned domain string so the message
format is unambiguous and extensible.

---

## 7. Validator Ordering and Bitmap

`Bitmap` uses the same deterministic validator order across all nodes.

The order is:

1. take the checkpoint pre-state signer set from snapshot `Number-1`
2. sort validator addresses ascending in raw byte order
3. bit `i` corresponds to validator signer record at ordered index `i`

v1 requires `MaxValidators <= 64` as a **hard protocol invariant**, not merely an
assumption. A `uint64` bitmap can encode at most 64 validator positions; a network with
more validators cannot form a valid QC under this wire format.

This invariant must be enforced as a config validation rule: if
`CheckpointFinalityBlock != nil`, then `MaxValidators` must be `<= 64`. Violating this
is a fatal misconfiguration, not a runtime degradation.

Add to `DPoSConfig` validation in `params/config.go`:

```go
if c.CheckpointFinalityBlock != nil && c.MaxValidators > 64 {
    return fmt.Errorf("checkpoint finality v1 requires MaxValidators <= 64, got %d",
        c.MaxValidators)
}
```

If GTOS ever needs more than 64 validators with checkpoint finality, `Bitmap` must
become a variable-length bitset and the protocol version bumped to v2.

---

## 8. Vote Dissemination

Although the `CheckpointQC` is embedded into block `Extra`, validators still need a way
to send individual votes to future proposers.

The first version should add one lightweight p2p message to the GTOS protocol stack:

```text
NewCheckpointVoteMsg
```

Target code path:

- `tos/protocols/tos/protocol.go`
- `tos/protocols/tos/handler.go`
- `tos/protocols/tos/peer.go`

Payload:

```text
RLP(CheckpointVoteEnvelope)
```

Rationale:

- smaller and cleaner than turning votes into transactions
- avoids txpool, nonce, fee, and state-execution semantics
- still keeps the first version simpler than BLS vote pooling

---

## 9. In-Memory Vote Cache

Add a minimal in-memory cache under `consensus/dpos/`, for example:

```go
type checkpointVotePool struct {
    // key: checkpoint number + checkpoint hash
    votes map[checkpointKey]map[common.Address]*types.CheckpointVoteEnvelope
}
```

Notes:

- this is not a general-purpose vote pool like BSC fast-finality vote handling
- it only stores votes for eligible checkpoint blocks
- one validator may contribute at most one vote per checkpoint number
- conflicting votes for the same checkpoint number (different hashes) should be retained
  as evidence for future slashing, even if slashing is not yet implemented

### Cache cleanup

The cache must be pruned to avoid unbounded memory growth:

- when `FinalizedNumber` advances to checkpoint `C`, all votes for checkpoint numbers
  `<= C.Number` may be evicted from the cache
- additionally, evict any vote for a checkpoint number older than
  `currentHead - 2 * CheckpointInterval`, regardless of finality state, to bound memory
  during prolonged finality stalls

This sliding-window rule is a local memory policy only. It is **not** part of consensus
validity for on-chain QCs.

### Vote admission rules

Before inserting a `CheckpointVoteEnvelope` into the in-memory cache, the node should
perform bounded admission checks:

1. `Vote.Number` must be an eligible checkpoint height
2. `Vote.Number` must be within a bounded local window around the current head
3. `Vote.ChainID` must equal the local chain config `ChainID`
4. `Signer` must be present in the checkpoint pre-state signer set
5. `ValidatorSetHash` must match the checkpoint pre-state signer set
6. the envelope signature must verify for the declared `Signer` using the canonical
   ed25519 public key from the checkpoint pre-state signer set
7. if another vote from the same signer already exists for the same checkpoint number:
   - same hash: treat as duplicate and ignore
   - different hash: retain as equivocation evidence but do not replace the first cached
     vote used for QC assembly

These checks are not a substitute for on-chain QC verification, but they keep proposer
state bounded and avoid wasting resources on obviously invalid votes.

If the checkpoint pre-state snapshot (`Vote.Number - 1`) is not yet available locally
(e.g. the node is mid-sync), skip checks 4–6 and place the envelope in a **pending
queue** keyed by `Vote.Number`. When the snapshot becomes available, re-run checks 4–6
on all pending envelopes for that checkpoint number and promote passing ones into the
main cache. This ensures validator votes are not silently dropped during initial sync.

---

## 10. Header Extra Layout

GTOS already uses `Extra` for vanity, epoch validator payloads, and the seal.
Checkpoint finality adds an optional `CheckpointQC` payload before the seal.

### Before activation

```text
Genesis block: [32B vanity][N x AddressLength validators]
Normal block:  [32B vanity][seal]
Epoch block:   [32B vanity][N x AddressLength validators][seal]
```

### After activation

```text
Normal block without QC:
  [32B vanity][seal]

Normal block with QC:
  [32B vanity][CheckpointQC RLP][seal]

Epoch block without QC:
  [32B vanity][1B count=N][N x AddressLength validators][seal]

Epoch block with QC:
  [32B vanity][1B count=N][N x AddressLength validators][CheckpointQC RLP][seal]
```

The `count` byte is introduced for epoch blocks at activation so that the parser can
determine exactly where the validator list ends and the QC begins.

Without it, the middle slice `[N x AddressLength validators][CheckpointQC RLP]` is not a
multiple of `AddressLength`, and the existing epoch validator parser would either
miscalculate `N` or reject the block.

### Parsing rule

For v1 (`SealSignerType = ed25519`), `sealLength = 96` (32B pubkey + 64B sig).

```text
sealLength = 96   // ed25519 only in v1
middle := header.Extra[extraVanity : len(header.Extra)-sealLength]

if isEpoch && IsCheckpointFinality(header.Number):
    N       := int(middle[0])
    valEnd  := 1 + N*common.AddressLength
    validators := middle[1:valEnd]
    qcBytes    := middle[valEnd:]
else if isEpoch:
    validators := middle
    qcBytes    := nil
else:
    qcBytes    := middle

if len(qcBytes) > 0:
    decode RLP(qcBytes) -> CheckpointQC
```

- absence of QC is represented by zero remaining bytes after the validator slice
- do not use a special empty RLP marker
- a non-empty `qcBytes` that fails RLP decode is a hard error
- `parseEpochValidators` must branch on `IsCheckpointFinality(number)`

---

## 11. Vote Production

Validators only sign checkpoint blocks `C` such that:

```text
C.Number >= FirstEligibleCheckpoint
```

They must never sign a checkpoint below that height.

For an eligible checkpoint block `C` accepted on the local canonical chain:

1. the validator loads the checkpoint pre-state signer set from snapshot `C-1`
2. it checks whether its own validator address is present in that signer set
3. it looks up its persistent signed-checkpoint record for `C.Number`
4. if a record exists for `C.Number` with a different hash, it must not sign
5. if no record exists, or the record matches `C.Hash`, it builds `CheckpointVote`
6. it signs the vote digest with its configured consensus key
7. it durably writes `(C.Number, C.Hash)` to its signed-checkpoint store before gossiping
8. it gossips `CheckpointVoteEnvelope` to peers through `NewCheckpointVoteMsg`
9. it stores the vote locally in the checkpoint vote cache

### Persistent signed-checkpoint record

Each validator node must persist which `(Number, Hash)` pairs it has signed to durable
storage (for example, a small key-value table in the node DB). This record survives
restarts and prevents accidental double-sign after crash and reorg.

On reorg to a different hash at the same checkpoint number, the validator silently skips
signing the new fork's checkpoint.

**Core safety rule**: a validator must never sign two different checkpoint hashes for the
same checkpoint number.

### Restart re-gossip

After a crash and restart, the validator may have durable signed-checkpoint records for
checkpoints that are not yet finalized. On startup, the validator must:

1. read all signed-checkpoint records where `Number > FinalizedNumber`
2. for each such record, re-construct and re-gossip the `CheckpointVoteEnvelope` to
   peers via `NewCheckpointVoteMsg`

Without this step, signed votes are lost on restart and the corresponding checkpoint may
never accumulate a quorum, stalling finality indefinitely.

---

## 12. QC Assembly

When producing block `D`, the proposer may embed at most one `CheckpointQC`.

Suggested policy for v1:

1. find the latest checkpoint block not yet finalized
2. ensure the checkpoint is eligible (`>= FirstEligibleCheckpoint`)
3. collect votes for that checkpoint from the local cache
4. verify they all match the same `CheckpointVote`
5. verify each vote envelope individually against the checkpoint pre-state signer set
6. if votes from at least `ceil(2N/3)` validators exist, build `CheckpointQC`
7. RLP-encode the QC and insert it into `Extra`

The proposer does not need to wait for a QC to produce a block. A block without QC
remains valid.

This preserves liveness when signatures arrive late or the current proposer is missing.

---

## 13. QC Verification

QC verification is split into two phases matching the two stages of block processing
in GTOS. Each phase only uses data that is guaranteed to be available at that stage.

### Phase 1 — Structural checks (`VerifyHeader`)

Called during header-only verification, before state or ancestors are available.
No pre-state snapshot, no ancestor walk.

Add `verifyCheckpointQCStructure(header)` called from `VerifyHeader` after `Extra`
is parsed:

1. If `IsCheckpointFinality(header.Number)` is false, return success.
2. Parse `CheckpointQC` from `header.Extra` using the rule in §10. If absent, return
   success. If present but RLP-malformed, return error.
3. Compute `firstEligible := firstCheckpointAtOrAfter(CheckpointFinalityBlock, CheckpointInterval)`.
4. Require `qc.Vote.Number >= firstEligible`.
5. Require `qc.Vote.Number % CheckpointInterval == 0`.
6. Require `header.Number > qc.Vote.Number`.
7. **Staleness limit**: require `header.Number - qc.Vote.Number <= 2 * CheckpointInterval`.
   This bounds the ancestor walk in Phase 2 and prevents DoS via artificially old QCs.
8. Require `qc.Vote.ChainID != nil` and `qc.Vote.ChainID.Cmp(chain.Config().ChainID) == 0`.
9. Count set bits in `qc.Bitmap`; require `popcount(qc.Bitmap) > 0` and
   `popcount(qc.Bitmap) <= MaxValidators`.
10. Require `len(qc.Signatures) == popcount(qc.Bitmap)`.

### Phase 2 — Cryptographic checks (`FinalizedStateVerifier.VerifyFinalizedState`)

Called by `StateProcessor.Process` in `core/state_processor.go:113` after
`engine.Finalize()`, via the `consensus.FinalizedStateVerifier` optional interface:

```go
if fsv, ok := p.engine.(consensus.FinalizedStateVerifier); ok {
    if err := fsv.VerifyFinalizedState(header, statedb); err != nil { ... }
}
```

`DPoS` already implements `FinalizedStateVerifier`. Extend `VerifyFinalizedState` to
call `verifyCheckpointQCFull(chain, header, statedb)` when `IsCheckpointFinality` is
active. At this point the full post-transaction state and all ancestor headers are
available, making the cryptographic checks sound.

Add `verifyCheckpointQCFull(chain, header, statedb)` as a private method on `DPoS`:

1. Walk ancestors of `header` back to height `qc.Vote.Number`. Because of the staleness
   limit from Phase 1, the walk is at most `2 * CheckpointInterval` blocks.
   Require the block hash at that height equals `qc.Vote.Hash`.
2. Load snapshot at `qc.Vote.Number - 1`.

   **Protocol rule**: nodes participating in checkpoint finality consensus MUST retain
   snapshots for at least `2 * CheckpointInterval` blocks behind the current head.
   This is a protocol invariant, not an operational suggestion. A node that prunes
   snapshots more aggressively than this window cannot safely verify QCs and must not
   participate as a validator or block proposer until it has re-synced the required
   state.

   Practically, this rule should be enforced at node startup: if checkpoint finality
   is active and the configured state-pruning horizon is shorter than
   `2 * CheckpointInterval`, the node must refuse to start or log a fatal error.

   If the snapshot is unavailable despite this rule (e.g. during initial sync before
   the node has reached `qc.Vote.Number`), return a missing-prestate error and defer
   block acceptance until the required state is available.
3. Require that every active validator in the checkpoint pre-state satisfies the signer
   metadata invariant from §5.
4. Recompute `ValidatorSetHash` from the ordered signer set and require it equals
   `qc.Vote.ValidatorSetHash`.
5. Iterate set bits of `qc.Bitmap` in ascending bit-position order. Maintain a dense
   signature index `sigIdx` starting at 0, incrementing by 1 for each set bit:
   - let `i` = the current set bit position (validator index in ordered signer set)
   - resolve the signer record at validator index `i`
   - require `SignerType == ed25519`
   - verify `qc.Signatures[sigIdx]` (64B) against the signer's canonical ed25519 public key
   - increment `sigIdx`

   Using `sigIdx` (dense) rather than `i` (sparse bit position) is mandatory. For a
   bitmap like `0b10000010` (bits 1 and 7 set), `len(Signatures) == 2`; accessing
   `Signatures[7]` would read out of bounds.
6. Reject on any individual signature failure.
7. Require at least `ceil(2N/3)` valid signatures, where `N = len(signerSet)`.

The QC must always be verified against the checkpoint's pre-state signer set, never
against current head state.

---

## 14. Finality State Update

Extend [snapshot.go](/home/tomi/gtos/consensus/dpos/snapshot.go) with:

```go
type Snapshot struct {
    // existing fields...

    FinalizedNumber uint64      `json:"finalizedNumber,omitempty"`
    FinalizedHash   common.Hash `json:"finalizedHash,omitempty"`
}
```

Update rules:

- if a block contains no valid `CheckpointQC`, finalized state is unchanged
- if a block contains a valid `CheckpointQC` for checkpoint `C`, then:
  - `FinalizedNumber = C.Number`
  - `FinalizedHash = C.Hash`
- finalized height must be monotonic; ignore any QC whose `Number` is not greater than
  the current `FinalizedNumber`
- a node must reject any QC that would move finalized state backward or bind the same
  finalized number to a different hash

Once checkpoint `C` is finalized, every ancestor of `C` is also finalized by definition.

### copy() update

`Snapshot.copy()` must copy both new fields explicitly:

```go
cpy.FinalizedNumber = s.FinalizedNumber
cpy.FinalizedHash   = s.FinalizedHash
```

Omitting this causes LRU-cached snapshots to appear un-finalized after a copy,
silently breaking finality monotonicity and RPC correctness.

### Authoritative finality state

There are two layers of finality state in the implementation:

1. **Consensus-layer snapshot state**
   - `Snapshot.FinalizedNumber`
   - `Snapshot.FinalizedHash`
2. **Runtime chain state**
   - `BlockChain.currentFinalizedBlock`
   - `rawdb.WriteFinalizedBlockHash(...)`

The authoritative runtime finality state is `BlockChain.currentFinalizedBlock`, persisted
through the existing finalized-head storage path.

`Snapshot.FinalizedNumber/Hash` are derived consensus metadata used during header/block
verification and snapshot transitions. When canonical head advances and a new checkpoint
becomes finalized, both layers must be updated in lockstep:

1. update snapshot finality fields for consensus correctness
2. call `BlockChain.SetFinalized(block)` for the finalized checkpoint block —
   this method already exists in `core/blockchain.go:509` and persists the
   finalized hash via `rawdb.WriteFinalizedBlockHash`; no new code needed
3. persist the finalized hash through the existing rawdb finalized-head path

After restart, the blockchain finalized head restored from rawdb is the source of truth
for fork-choice enforcement; snapshot fields reconstructed on top of canonical history
must agree with it.

---

## 15. Finality Enforcement in Fork Choice

Checkpoint finality is consensus-hard.

Therefore, when a node already has finalized checkpoint `(F.Number, F.Hash)`, it must not
switch the canonical chain head to any block whose ancestry does not include
`(F.Number, F.Hash)`.

This rule must be enforced in canonical chain selection and reorg handling.

Operationally:

1. on block import, before adopting a new canonical head, verify that the branch contains
   the current finalized checkpoint
2. if it does not, reject the reorg even if total difficulty or other fork-choice inputs
   would normally prefer that branch
3. persist the finalized block hash using the existing finalized-head storage path so the
   rule survives restart

This turns checkpoint finality from an RPC hint into a true consensus invariant.

### Zero-state handling

Before any checkpoint has been finalized (`FinalizedNumber == 0`, `FinalizedHash == common.Hash{}`),
the fork choice constraint is a **no-op**. No branch is rejected on finality grounds.

The constraint activates only after the first `CheckpointQC` is successfully verified
in Phase 2 and `FinalizedNumber` is set to a non-zero value. From that point forward,
all reorgs must preserve the finalized checkpoint as an ancestor.

---

## 16. RPC Exposure

Expose a GTOS-specific finality RPC:

```text
tos_getFinalizedBlock
```

Suggested response fields:

- `number`
- `hash`
- `timestamp`
- `validatorSetHash`

This RPC should return the latest finalized checkpoint, not merely the latest justified
or locally safe block.

Bridges and withdrawal systems should trust `tos_getFinalizedBlock`, not raw head depth.

---

## 17. Safety and Liveness

### Safety

Safety relies on the standard quorum intersection property:

- any two `2/3` quorums intersect in at least one-third of validators
- honest validators never sign two different checkpoint hashes for the same checkpoint
  number
- finalized checkpoints are enforced in fork choice
- therefore two conflicting finalized checkpoints at the same checkpoint number cannot
  both be accepted unless at least one-third of validators equivocate

### Liveness

Liveness is preserved because:

- blocks do not require a QC to be produced
- a QC may be embedded by any later proposer
- finality may lag temporarily during network disruption, but normal block production can
  continue

This is weaker than full BFT liveness under asynchrony, but much simpler to deploy on top
of the current GTOS DPoS chain.

---

## 18. Security Considerations

1. **Double-sign rule**: a validator must never sign two different hashes for the same
   checkpoint number.
2. **Replay protection**: signed payload must include both `ChainID` and a protocol
   domain string, and QC verification must compare `Vote.ChainID` against local chain
   config.
3. **Signer-set binding**: signed payload must include `ValidatorSetHash`, computed from
   `{address, signerType, signerValue}` records.
4. **Ancestor-only rule**: a QC may only finalize a real ancestor of the current block,
   not an arbitrary known block.
5. **Fork-choice enforcement**: finalized checkpoints must constrain reorgs.
6. **No map-order dependence**: signatures must be matched to bitmap positions
   deterministically.
7. **Deterministic validity**: header acceptance must not depend on whether the local
   node is currently missing old ancestors or pre-state.
8. **Future slashing**: conflicting `CheckpointVoteEnvelope` objects should be retainable
   as slash evidence even if slashing is postponed.

---

## 19. File Map

| File | Change |
|---|---|
| `params/config.go` | Add `CheckpointInterval`, `CheckpointFinalityBlock`, `IsCheckpointFinality` |
| `core/types/checkpoint.go` | New `CheckpointVote`, `CheckpointVoteEnvelope`, `CheckpointQC` |
| `consensus/dpos/dpos.go` | Add QC parsing, assembly, `firstCheckpointAtOrAfter`, `verifyCheckpointQCStructure` (Phase 1 — called from `VerifyHeader`), `verifyCheckpointQCFull` (Phase 2 — called from `VerifyFinalizedState`) |
| `consensus/dpos/dpos.go` (`VerifyFinalizedState`) | Extend existing `FinalizedStateVerifier` implementation to call `verifyCheckpointQCFull` when `IsCheckpointFinality` is active |
| `params/config.go` | Add config validation: `CheckpointFinalityBlock != nil` requires `MaxValidators <= 64` |
| `consensus/dpos/snapshot.go` | Add `FinalizedNumber`, `FinalizedHash`; update `copy()` to include both fields |
| `consensus/dpos/finality_pool.go` | New lightweight checkpoint vote cache with cleanup logic |
| `consensus/dpos/signed_checkpoints.go` | New persistent signed-checkpoint record; prevents double-sign after restart |
| `consensus/dpos/signer_set.go` | New helper to load ordered checkpoint pre-state signer records and compute `ValidatorSetHash` |
| `tos/protocols/tos/protocol.go` | Add `NewCheckpointVoteMsg` |
| `tos/protocols/tos/handler.go` | Decode and forward `CheckpointVoteEnvelope` into the vote cache |
| `tos/protocols/tos/peer.go` | Add send helper for checkpoint votes |
| `core/blockchain.go` / fork-choice path | Reject reorgs that cross the current finalized checkpoint |
| RPC layer | Add `tos_getFinalizedBlock` |

---

## 20. Recommended Activation Plan

### Phase 1: passive rollout

- release binaries with parsing, vote gossip, QC assembly, QC verification, and finalized
  fork-choice checks
- keep `CheckpointFinalityBlock = nil`
- test on devnet and staging networks

### Phase 2: activation

- set `CheckpointFinalityBlock = N`
- compute `FirstEligibleCheckpoint` as the first multiple of `CheckpointInterval` at or
  above `N`
- validators begin signing checkpoint votes starting at `FirstEligibleCheckpoint`
- descendants may begin carrying valid `CheckpointQC`
- `tos_getFinalizedBlock` becomes meaningful from the first finalized checkpoint onward

### Phase 3: enforcement hardening

Optional later upgrades:

- slash equivocation
- widen bitmap beyond 64 validators if needed
- compress QC signatures
- add richer relayer APIs for finalized ranges

---

## 21. Verification Checklist

After implementation, verify:

- [ ] `CheckpointInterval > 0`
- [ ] `CheckpointFinalityBlock == nil` leaves existing networks unchanged
- [ ] `FirstEligibleCheckpoint` is computed identically on all nodes
- [ ] QC parser correctly distinguishes absent payload from malformed payload
- [ ] validator ordering is deterministic and identical across all nodes
- [ ] `ValidatorSetHash` matches ordered `{address, signerType, signerValue}` at
      checkpoint pre-state
- [ ] every active validator has valid canonical signer metadata of the chain-wide
      `ed25519` signer type before `FirstEligibleCheckpoint`
- [ ] signature count equals bitmap popcount
- [ ] `>= ceil(2N/3)` valid signatures are required
- [ ] `ed25519` vote verification works from the explicit `Signer` field plus pre-state
      signer metadata
- [ ] checkpoint finality v1 rejects non-`ed25519` signer metadata in the checkpoint
      pre-state signer set
- [ ] a validator cannot contribute twice to the same QC
- [ ] finalized height never decreases
- [ ] reorgs across the finalized checkpoint are rejected
- [ ] `Vote.ChainID` is checked during QC verification
- [ ] `VerifyHeader` (Phase 1) passes with only structural data — no pre-state required
- [ ] Phase 2 is wired into `FinalizedStateVerifier.VerifyFinalizedState`, called by `StateProcessor.Process` after `engine.Finalize()`
- [ ] Phase 2 performs full ed25519 verification against pre-state signer set
- [ ] staleness limit `header.Number - qc.Vote.Number <= 2 * CheckpointInterval` enforced in Phase 1 (structural)
- [ ] config validation rejects `CheckpointFinalityBlock != nil && MaxValidators > 64`
- [ ] node refuses to start if state-pruning horizon is shorter than `2 * CheckpointInterval`
- [ ] Signatures are indexed densely (`sigIdx++`) not by set-bit position; out-of-bounds access is impossible
- [ ] ancestor walk in Phase 2 is bounded by the staleness limit
- [ ] `FinalizedNumber == 0` means no fork-choice constraint (zero-state no-op)
- [ ] validator re-gossips signed-checkpoint records for unfinalized checkpoints on restart
- [ ] `[64]byte` signature fields are used throughout; no `[]byte` for ed25519 signatures
- [ ] vote cache pending queue handles snapshot-unavailable case during sync
- [ ] `BlockChain.SetFinalized` (`core/blockchain.go:509`), `currentFinalizedBlock`, and `rawdb.WriteFinalizedBlockHash` are confirmed present and reused as-is
- [ ] `BlockChain.currentFinalizedBlock` and snapshot finality fields remain consistent
      across restart and reorg handling
- [ ] `tos_getFinalizedBlock` returns the latest finalized checkpoint
- [ ] a checkpoint QC in a later descendant remains valid
- [ ] blocks without QC remain valid and do not stall liveness

---

## 22. Practical Recommendation

For GTOS in its current form, this checkpoint finality design is the most pragmatic first
step if the primary requirement is bridge safety, withdrawal finality, or exchange-style
confirmation guarantees.

It is materially simpler than importing BLS fast finality, while still providing a clear
and deterministic finalization point to external systems.
