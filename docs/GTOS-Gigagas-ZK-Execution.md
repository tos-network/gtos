# GTOS Gigagas ZK Execution Architecture

**Status**: Design Document
**Version**: 0.1.0
**Target**: `consensus/dpos/`, `core/types/`, `core/state_processor.go`, `core/blockchain.go`, `core/rawdb/`, new `zkexec/` packages, and `tos/protocols/tos/`
**Scope**: migrate GTOS from replicated execution to proof-verified execution while preserving GTOS DPoS ordering and checkpoint finality

> This document adapts the public Ethereum "Scale L1 / realtime proving / gigagas"
> direction to GTOS. The GTOS goal is not to copy Ethereum's exact roadmap, but to
> apply the same core idea to GTOS: validators should verify succinct execution
> proofs instead of all validators re-executing every transaction.

---

## 1. Problem Statement

Current GTOS follows the classic full-node model:

- proposers assemble blocks
- every validating node executes every transaction
- every validating node recomputes receipts and post-state roots
- consensus safety depends on all validators repeating the same execution

This model is simple and robust, but it does not scale to "gigagas L1" throughput.
At approximately `10,000 TPS`, the bottleneck is no longer only proposer rotation or
signature verification. The dominant cost becomes:

1. repeated execution of the same transactions by all validators
2. repeated witness generation and trie access by all validators
3. wall-clock time to execute and commit each block before the next block arrives

The core architectural change is:

```text
execute once (or a small number of times) -> produce a proof -> let all validators verify the proof
```

This does **not** remove consensus. GTOS still needs:

- a block ordering protocol
- data availability
- fork choice
- finality

The change is specifically about **execution validity**.

In the target architecture:

- GTOS `DPoS` remains the ordering layer
- GTOS checkpoint finality remains the deterministic finality layer
- zk proofs become the execution-validity layer

The target result is:

```text
DPoS orders blocks
Proofs justify state transitions
Checkpoint QCs finalize proved checkpoints
```

---

## 2. Goals and Non-Goals

### Goals

1. Preserve GTOS `DPoS + grouped turns + checkpoint finality` as the consensus skeleton.
2. Replace "every validator re-executes every transaction" with "validators verify proofs".
3. Keep a fast optimistic head for low latency, even if proof generation lags by a short window.
4. Bind zk validity to checkpoint finality so that only **proved** checkpoints can become finalized.
5. Support a phased rollout from today's GTOS without a one-shot rewrite.
6. Keep transaction data available enough for independent proving and auditing.
7. Allow proposer, executor-builder, prover, and validator roles to be physically separate.

### Non-Goals

1. Replacing GTOS DPoS with Tendermint, HotStuff, or Ethereum Beacon consensus.
2. Requiring a per-block proof from day one.
3. Eliminating data availability requirements. Proofs reduce re-execution, not data bandwidth.
4. Proving every possible future runtime in phase 1. In particular, the ATOS multi-runtime model in [ATOS-Execution-Layer.md](./ATOS-Execution-Layer.md) is not automatically in scope for zk execution v1.
5. Removing checkpoint QC voting in v1. The first design keeps the current GTOS finality gadget and makes it proof-gated.

---

## 3. Current GTOS Baseline

GTOS already has the following consensus structure:

- stake-based validator selection
- active validator set truncated to `MaxValidators`
- deterministic grouped-turn proposer scheduling via `TurnLength`
- `ed25519` block seals
- checkpoint finality with `ceil(2N/3)` validator signatures

The current execution validity rule is still traditional:

```text
block is valid iff each validating node can execute it locally and obtain the same post-state root
```

This means GTOS today is:

```text
DPoS ordering + replicated execution + checkpoint QC finality
```

The proposed target is:

```text
DPoS ordering + proof-verified execution + checkpoint QC finality
```

This is a large change, but it is modular:

- ordering stays in `consensus/dpos/`
- state transition semantics remain GTOS-specific
- finality remains checkpoint-based
- only the "how do validators know the execution is valid?" layer changes

---

## 4. Design Principles

### 4.1 Keep consensus and execution separate

DPoS decides **which block sequence the network follows**.
The zk system decides **whether the state transition for that sequence is valid**.

### 4.2 Proof-gate finality, not block production

Block production should remain low-latency and continuous.
Proof generation is more expensive and can lag behind by a bounded interval.

Therefore GTOS should expose three different safety levels:

- `unsafe head`: latest DPoS canonical head
- `proved head`: latest canonical block covered by a valid execution proof
- `finalized head`: latest proved checkpoint that also has a valid checkpoint QC

### 4.3 Do not overload `Header.Extra` with proof bytes

GTOS already uses `Extra` for:

- vanity bytes
- epoch validator lists
- checkpoint QC payloads
- the DPoS seal

Execution proofs can be much larger and should be carried as a separate body object
committed by a dedicated header hash field.

### 4.4 Align proofs to checkpoint intervals in v1

GTOS already has checkpoint intervals.
The simplest first version is:

- one execution proof range per checkpoint interval
- validators may vote only on checkpoints whose interval is already proved

This minimizes changes to the existing finality logic.

### 4.5 Proofs do not remove the need for execution somewhere

Even if validators stop re-executing every transaction, some actor still must:

- execute transactions to construct candidate blocks
- compute receipts and post-state roots
- build witnesses for the proving system

That work moves from "all validators" to "builder/executor + prover".

---

## 5. Architecture Overview

GTOS Gigagas mode has three planes.

### 5.1 Ordering Plane

- current GTOS `DPoS`
- grouped-turn proposer ownership
- difficulty-based in-turn / out-of-turn behavior
- canonical fork choice

### 5.2 Data Plane

- transaction bodies in phase 1
- chunked or blob-like data in later phases
- enough data must remain available for independent proof generation

### 5.3 Validity Plane

- optimistic execution by an executor-builder
- asynchronous zk proof generation by provers
- validator proof verification
- proof-gated checkpoint voting and finality

High-level flow:

```text
Users
  |
  v
Proposer / Sequencer
  |
  | orders txs
  v
Executor-Builder
  |
  | computes optimistic block outputs
  v
GTOS Block (unsafe head)
  |
  | canonical chain continues growing
  v
Prover Network
  |
  | generates proof for checkpoint-aligned range
  v
Execution Certificate carried by later block
  |
  | validators verify proof
  v
Proved Checkpoint
  |
  | validators sign checkpoint vote
  v
Checkpoint QC in descendant block
  |
  v
Finalized Checkpoint
```

---

## 6. Roles and Responsibilities

### 6.1 Proposer / Sequencer

The proposer remains a GTOS validator chosen by DPoS.

Responsibilities:

- select transactions
- order them into a block
- obtain optimistic execution outputs from a local or remote executor-builder
- publish the block immediately without waiting for a zk proof
- continue using the existing DPoS seal and proposer rotation rules

The proposer may also operate:

- an executor-builder
- a prover

but these are not consensus requirements.

### 6.2 Executor-Builder

The executor-builder is the service that actually computes:

- post-state root
- receipt root
- gas used
- logs
- intermediate witness material needed later by provers

This role exists because someone must know the block result before the block is
broadcast.

In the target design, only a small number of actors do this for block production.
Normal validators do not need to repeat this work.

### 6.3 Prover

The prover generates succinct validity proofs for a checkpoint-aligned block range.

Responsibilities:

- consume canonical block data
- reconstruct or receive the witness for the covered interval
- generate an `ExecutionCertificate`
- gossip or submit that certificate so it can be carried by a later GTOS block

The prover is **not** required to be a validator in the long run.
For operational simplicity, early phases may begin with validator-run provers.

### 6.4 Validator

The validator remains the GTOS consensus actor.

Responsibilities in Gigagas mode:

- verify normal DPoS header rules
- verify data commitments and body availability rules
- verify zk execution certificates when they appear
- maintain local `unsafe`, `proved`, and `finalized` heads
- sign checkpoint votes only for **proved** checkpoints
- reject finality for unproved checkpoints

### 6.5 Optional Full Executor / Auditor

Full execution becomes an operational role, not a consensus requirement.

Auditors may:

- re-execute blocks for independent assurance
- compare local execution against proved outputs
- help detect prover bugs or circuit bugs

This is strongly recommended operationally, but it is not the target consensus path.

---

## 7. Safety Levels and Chain State

GTOS should explicitly track three levels of chain acceptance.

### 7.1 Unsafe Head

The latest block accepted by normal GTOS DPoS fork choice.

Properties:

- low latency
- can extend quickly
- not yet backed by zk validity for all recent blocks
- may still be reorganized, subject to existing checkpoint rules

### 7.2 Proved Head

The latest canonical block covered by a verified execution certificate.

Properties:

- execution validity has been justified by zk proof
- does not require all validators to have re-executed the range
- stronger than unsafe head
- still not fully irreversible without checkpoint QC finality

### 7.3 Finalized Head

The latest checkpoint that is both:

1. proved by a valid execution certificate
2. finalized by the existing GTOS checkpoint QC mechanism

This is the deterministic finality point for bridges, withdrawals, and external systems.

---

## 8. Proposed Block Format

The design keeps GTOS block semantics familiar while adding explicit commitments for
data and proof payloads.

### 8.1 Header Changes

Add two new header fields:

```go
type Header struct {
    // existing GTOS fields...

    DataRoot            common.Hash // zero => legacy tx-body mode
    ExecutionBundleHash common.Hash // zero => no proof bundle carried by this block
}
```

Rules:

- `DataRoot == 0` means the block uses the current GTOS transaction body as the
  authoritative data source.
- `DataRoot != 0` means the block's raw execution data is committed by chunked or
  blob-like data objects instead of only `TxHash`.
- `ExecutionBundleHash == 0` means the block carries no execution certificates.
- `ExecutionBundleHash != 0` commits to an `ExecutionBundle` in the block body.

`Header.Extra` remains dedicated to GTOS DPoS concerns:

- vanity
- epoch validator list
- checkpoint QC
- seal

Proof payloads are **not** stored in `Extra`.

### 8.2 Body Changes

Add two optional body-level objects:

```go
type Block struct {
    Header                *Header
    Transactions          []*Transaction        // phase 1 / compatibility mode
    DataChunks            []*ExecutionDataChunk // phase 3+, optional
    ExecutionBundle       *ExecutionBundle      // optional
}
```

With:

```go
type ExecutionDataChunk struct {
    Index uint32
    Data  []byte
}

type ExecutionBundle struct {
    Certificates []*ExecutionCertificate
}
```

Bundle rules:

- certificates must be sorted by `(RangeStart, RangeEnd)`
- certificates in one bundle must not overlap
- a block may carry zero, one, or multiple certificates
- multiple certificates allow catch-up if proof generation lags

### 8.3 Compatibility Modes

Phase 1 compatibility mode:

- transactions stay in the normal block body
- `TxHash` remains authoritative for transaction ordering
- `DataRoot = 0`

Gigagas mode:

- `TxHash` commits the logical transaction list
- `DataRoot` commits the actual byte layout used for proving and data availability
- `DataChunks` or blob-like objects become the data plane

---

## 9. Execution Proof Object

The proof object should be **range-based**, not strictly per-block.

### 9.1 Core Type

```go
type ExecutionCertificate struct {
    Version             uint8
    ProofSystem         string      // e.g. "gtos-zkevm-v1"
    VerifierID          common.Hash // hash of verifying key / verifier config
    ChainID             *big.Int

    RangeStart          uint64
    RangeEnd            uint64
    StartParentHash     common.Hash // hash of block RangeStart-1
    EndBlockHash        common.Hash // hash of block RangeEnd

    PrevStateRoot       common.Hash // state root before RangeStart
    EndStateRoot        common.Hash // state root after RangeEnd
    BlockCommitmentRoot common.Hash // commitment to all block leaves in the range
    PublicInputsHash    common.Hash

    Proof               []byte
}
```

### 9.2 Block Leaf Commitment

Each block in the covered range contributes a deterministic leaf:

```go
type BlockExecutionLeaf struct {
    Number      uint64
    Hash        common.Hash
    ParentHash  common.Hash
    TxHash      common.Hash
    DataRoot    common.Hash
    ReceiptHash common.Hash
    GasUsed     uint64
    StateRoot   common.Hash
}
```

`BlockCommitmentRoot` is the Merkle root or equivalent ordered commitment over these leaves.

This binds the proof to:

- the exact ordered block range
- the exact transactions or data layout
- the exact receipts
- the exact post-state roots

### 9.3 Public Inputs

The zk verifier should treat at least the following as public inputs:

- `ChainID`
- circuit or verifier identifier
- `RangeStart`
- `RangeEnd`
- `StartParentHash`
- `EndBlockHash`
- `PrevStateRoot`
- `EndStateRoot`
- `BlockCommitmentRoot`
- a GTOS execution configuration hash

### 9.4 What the Circuit Must Prove

For the covered block range, the circuit must prove that:

1. the blocks form a contiguous chain segment
2. the transaction data committed by `TxHash` and `DataRoot` is well formed
3. GTOS state transition rules are applied correctly for every transaction
4. receipts and logs commitments are correct
5. fee accounting and gas accounting are correct
6. the resulting end-state root equals `EndStateRoot`

Importantly, the circuit is proving **GTOS execution semantics**, not "an abstract EVM"
in the abstract.

### 9.5 GTOS Execution Kernel Boundary

The proving target in v1 should cover the GTOS state transition kernel:

- plain transfers
- nonce rules
- gas accounting
- system action execution
- validator registry and checkpoint-related native paths
- deterministic LVM execution, if LVM remains the canonical VM in the covered range

Out of scope for zk execution v1 unless explicitly modeled:

- arbitrary external runtimes from ATOS
- non-deterministic host behavior
- any execution path not frozen into a deterministic proving specification

If GTOS later adopts ATOS as canonical execution, the proving boundary must be
redefined so that ATOS execution becomes a deterministic proof target rather than an
unconstrained external oracle.

---

## 10. Proof Interval and Alignment Rules

To minimize consensus complexity, v1 should enforce:

```text
ProofInterval == CheckpointInterval
```

Meaning:

- every proof range ends at an eligible checkpoint
- validators vote only on checkpoints whose range has already been proved

For a proved checkpoint `C`, the certificate range is:

```text
[P+1, C]
```

where `P` is the previous proved checkpoint, or `0` for the first proved range.

V1 rules:

1. `RangeEnd` must be an eligible checkpoint height.
2. `RangeStart` must be exactly one block after the previous proved checkpoint.
3. certificates must therefore form a contiguous proved chain with no gaps.
4. the end block hash in the certificate must equal the canonical hash at `RangeEnd`.

This keeps proof accounting simple and makes checkpoint finality a natural consumer of
proof completion.

---

## 11. Validator Verification Flow

### 11.1 Block Import Without Proof

When a new block arrives, validators still perform normal lightweight checks:

- DPoS header verification
- seal verification
- timestamp and gas sanity checks
- transaction encoding checks
- data-availability checks for body or chunked data

If the block carries no `ExecutionBundle`, the block may still become part of the
`unsafe head`.

### 11.2 Block Import With Proof Bundle

If a block carries an `ExecutionBundle`, validators must:

1. verify `ExecutionBundleHash`
2. parse all certificates
3. verify certificate ordering and non-overlap
4. verify each certificate's range alignment
5. reconstruct the public inputs from canonical blocks
6. run the zk verifier
7. mark the covered checkpoint as proved if verification succeeds

An invalid execution certificate is consensus-invalid and the carrier block must be rejected.

### 11.3 Local State Updates

GTOS should track:

- latest canonical unsafe head
- latest canonical proved checkpoint
- latest canonical finalized checkpoint

This likely requires new rawdb markers and runtime pointers analogous to the existing
finalized head tracking.

### 11.4 Pending Vote Promotion

GTOS already has the concept of pending checkpoint votes that cannot yet be admitted.
That pattern should be reused:

- if a vote for checkpoint `C` arrives before `C` is proved, keep it pending
- once `C` becomes proved, re-validate and promote pending votes

This minimizes protocol churn because the vote gossip path can stay largely familiar.

---

## 12. Checkpoint Integration

This is the most important rule in the design.

### 12.1 Keep Checkpoint Votes and QCs Minimal in V1

The first version should keep the current vote structure unchanged:

```text
CheckpointVote{ChainID, Number, Hash, ValidatorSetHash}
```

The zk proof does **not** need to be embedded into the vote itself.

Instead, GTOS changes the **eligibility rule**:

```text
a validator may sign or admit a checkpoint vote only if that checkpoint is already proved
```

### 12.2 New Finality Rule

A checkpoint `C` becomes finalized only if all of the following are true:

1. `C` is an eligible checkpoint
2. a valid `ExecutionCertificate` covers the range ending at `C`
3. validators produce `CheckpointVote`s for `C`
4. a valid `CheckpointQC` for `C` is included in a canonical descendant block

Therefore:

```text
proof gives validity
QC gives deterministic finality
```

### 12.3 Carrier Pattern

The proof and the QC do not need to appear in the same block.

Typical flow:

1. checkpoint block `C` is produced
2. later block `P` carries the proof for the range ending at `C`
3. validators verify the proof and begin signing votes for `C`
4. later block `D` carries the `CheckpointQC` for `C`
5. `C` becomes finalized when `D` is canonical

This is important because vote collection can only begin after proof verification.

### 12.4 Finalization Semantics

GTOS should interpret the three heads as:

- `unsafe`: canonical but not yet proved
- `proved`: execution-valid, but not yet checkpoint-final
- `finalized`: execution-valid and checkpoint-final

External bridges and settlement systems should use the **finalized** head.
Internal low-latency UX may choose to use the **proved** head when acceptable.

---

## 13. Fork Choice and Reorg Policy

The existing GTOS finality guard remains intact:

- branches that do not contain the finalized checkpoint are rejected

Additional policy for proved checkpoints:

- v1 should keep "proved" as a strong local safety signal, but not yet a new
  consensus-hard fork-choice barrier
- finality remains the hard barrier

This keeps the first deployment simpler:

- `proved` improves execution assurance
- `finalized` remains the irreversible protocol point

In later phases, GTOS may add a stronger safe-head preference:

- prefer branches extending the highest proved checkpoint
- cap the unproved backlog beyond a configured window

---

## 14. Liveness and Failure Handling

### 14.1 Proof Lag

If proofs lag, GTOS can continue producing unsafe blocks.

However, if proofs never catch up:

- `proved head` stalls
- checkpoint voting for later checkpoints stalls
- deterministic finality stalls

This is acceptable if the backlog is bounded.

### 14.2 Proof Grace Window

Add a chain config parameter:

```text
ProofGraceBlocks
```

Meaning:

- the chain may advance optimistically beyond the latest proved checkpoint
- but only by a bounded number of blocks

If the backlog exceeds this window, nodes may:

- refuse to extend the chain further
- or refuse to vote on later checkpoints

This prevents infinite optimistic drift.

### 14.3 Invalid Proofs

If an execution certificate is invalid:

- its carrier block is invalid
- the block must not be imported
- the invalid proof must not affect canonical state

### 14.4 Multiple Provers

Multiple provers may submit proofs for the same range.

Consensus rule:

- any valid proof for the correct public inputs is acceptable
- prover identity is not consensus-critical

Operationally:

- the first valid proof included on canonical chain wins

### 14.5 Data Unavailability

If block data is unavailable, the range cannot be independently proved.
Therefore proof verification architecture does **not** weaken the need for DA.

At Gigagas throughput, DA is a first-class bottleneck.
Proofs remove repeated execution, not repeated network transport.

---

## 15. Chain Configuration Proposal

Introduce a dedicated config section:

```go
type ZKExecutionConfig struct {
    ActivationBlock   *big.Int    `json:"activationBlock,omitempty"`
    ProofInterval     uint64      `json:"proofInterval,omitempty"`
    ProofGraceBlocks  uint64      `json:"proofGraceBlocks,omitempty"`
    ProofSystem       string      `json:"proofSystem,omitempty"`
    VerifierID        common.Hash `json:"verifierId,omitempty"`
    DataMode          string      `json:"dataMode,omitempty"` // "body", "chunks", "blobs"
    MaxUnprovedBlocks uint64      `json:"maxUnprovedBlocks,omitempty"`
}
```

V1 invariants:

1. `ActivationBlock != nil`
2. checkpoint finality must already be enabled
3. `ProofInterval == CheckpointInterval`
4. `ProofSystem` is chain-wide and fixed for a given network version
5. `VerifierID` is chain-wide and fixed for a given network version
6. `DataMode = "body"` in the first compatibility rollout

---

## 16. Phased Rollout Plan

The migration should be incremental.

### Phase 0: Current GTOS

State:

- every validator executes every block
- checkpoint finality works as implemented today
- no zk execution certificates

Purpose:

- baseline performance and correctness reference

### Phase 1: Shadow Proving

State:

- validators still fully execute blocks
- provers generate certificates for checkpoint ranges off to the side
- proof bundles may be carried and verified, but are not yet required for finality

Changes:

- add `ExecutionBundleHash`
- add `ExecutionBundle`
- add verifier pipeline
- add `proved head` tracking

Purpose:

- validate circuits and verifier integration
- measure proof latency and proof size
- debug witness generation without risking consensus

Exit criteria:

- stable proving latency within the intended checkpoint interval
- no persistent proof divergence from local execution

### Phase 2: Proof-Gated Checkpoint Voting

State:

- validators still execute recent blocks locally for operational assurance
- checkpoint votes become proof-gated
- only proved checkpoints may gather valid checkpoint votes

Consensus change:

- checkpoint finality now depends on proof availability

Purpose:

- make zk execution matter for consensus finality
- preserve a conservative local execution safety net during transition

Exit criteria:

- proof pipeline is reliable in production
- pending vote promotion works correctly
- finality no longer depends on all validators repeating execution

### Phase 3: Validity-Primary GTOS

State:

- normal validators verify proofs instead of fully re-executing all historical blocks
- local full execution becomes optional auditor mode
- `DataRoot` and chunked data mode are introduced
- recursive aggregation may compress multiple sub-proofs into checkpoint-range proofs

Purpose:

- materially reduce validator execution cost
- shift the network into "verify proofs, do not repeat execution" mode

Expected result:

- validator resource usage becomes dominated by proof verification, networking,
  storage, and DA rather than full execution

### Phase 4: Gigagas GTOS

State:

- chunked or blob-like execution data plane
- pipelined proposer / builder / prover workflow
- permissionless or semi-permissionless prover market
- bounded optimistic window
- proof generation fast enough to keep up with checkpoint cadence

Target:

- move GTOS toward the `~10,000 TPS` class

Important caveat:

- hitting this target requires both proof-based execution validity **and**
  significantly higher data-plane throughput
- proof verification alone does not deliver Gigagas throughput

---

## 17. Why This Fits GTOS Better Than a Direct Ethereum Copy

GTOS should not try to mirror Ethereum line by line.

GTOS already has:

- DPoS ordering
- grouped turns
- checkpoint QC finality
- a smaller validator set
- a different execution and native-action surface

This means the GTOS adaptation should be:

- checkpoint-oriented rather than slot-attestation-oriented
- range-proof-oriented rather than forcing instant per-block proofs
- compatible with the current DPoS QC path rather than replacing it

Ethereum's public direction suggests the strategic principle:

```text
validators verify proofs instead of repeating execution
```

GTOS should keep that principle but implement it in GTOS-native form:

```text
DPoS orders
builders execute optimistically
provers prove checkpoint ranges
validators verify proofs
checkpoint QCs finalize only proved checkpoints
```

---

## 18. Open Questions

The following items need separate design work before implementation:

1. What exact GTOS execution surface is included in the proving kernel for v1?
2. Should `proved head` become a consensus-hard safe-head barrier in a later phase?
3. What is the best `ProofGraceBlocks` value relative to `CheckpointInterval`?
4. Should GTOS allow multiple certificates per block in v1, or start with exactly one?
5. How should prover incentives be priced and distributed?
6. How should privacy and any future ATOS-backed execution integrate with the zk proving boundary?

---

## 19. References

- [Checkpoint Finality for GTOS DPoS](./Checkpoint.md)
- [Turn Length for GTOS DPoS](./turnLength.md)
- [ATOS Execution Layer Integration](./ATOS-Execution-Layer.md)
- Ethereum Foundation, "Realtime proving" (2025-07-10): <https://blog.ethereum.org/2025/07/10/realtime-proving>
- Ethereum Foundation, "Protocol update 001: Scale L1" (2025-08-05): <https://blog.ethereum.org/2025/08/05/protocol-update-001>
- Ethereum Foundation, "Lean Ethereum" (2025-07-31): <https://blog.ethereum.org/2025/07/31/lean-ethereum>
