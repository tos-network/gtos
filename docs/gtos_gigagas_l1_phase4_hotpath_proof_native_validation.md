# gtos Phase 4 Design
## Toward Gigagas L1
### Majority Hot-Path Execution Enters Proof-Native Validation

## Status

**Document status:** design-ready  
**Target audience:** core protocol engineers working on `gtos`  
**Language:** English  
**Scope:** detailed enough to implement directly

---

# 1. Purpose

This document defines the next phase after:

- Phase 1 — shadow proving
- Phase 2 — proof-backed transfer validation
- Phase 3 — restricted contract proving

Phase 4 is the first phase that is intentionally aimed at becoming:

> **substantially closer to a real Gigagas L1 architecture, where most hot-path execution no longer requires validator replay and instead enters proof-native validation.**

The key shift is no longer just “some tx classes can be proven.”

The key shift becomes:

- most high-frequency transaction paths are routed into proof-native batches
- validators verify proofs and materialize post-state
- validator replay becomes the exception, not the default
- block production, proof generation, state materialization, and validation become a coordinated proof-native pipeline

Phase 4 is still not the final destination, but it is the first phase where the system can begin to resemble the architecture implied by a Gigagas-style L1.

---

# 2. Core Objective

Phase 4 expands proof-native validation from narrow subsets into the **majority hot path**:

- transfer-class transactions
- restricted proof-eligible contract calls
- selected high-frequency built-in / package / protocol call patterns
- selected pre-approved contract profiles
- selected system-assisted execution profiles

The validator should increasingly do the following:

- load a proof sidecar for the block
- verify the proof and public inputs
- verify tx, trace, witness, receipt, and state-diff commitments
- materialize proven post-state into a real `StateDB`
- accept the block without replaying the majority proof-covered execution paths

The proof-native path becomes the **default fast path** for high-frequency traffic.

---

# 3. Non-Goals

Phase 4 does **not** attempt to:

- prove every possible Lua / LVM execution shape
- prove unrestricted deployment and unrestricted recursive call graphs
- move proof metadata into canonical header hashing
- remove the legacy fallback path completely
- eliminate all non-proof tx classes
- solve every rare edge case before shipping the dominant hot path

Phase 4 is about **dominant-path proofification**, not universal completeness.

---

# 4. Current Situation and Why Phase 4 Exists

Today, `gtos` still has the classical execution backbone:

- `InsertChain(...)`
- `StateProcessor.Process(...)`
- `BlockValidator.ValidateState(...)`
- state commit via `writeBlockWithState(...)`

Contract execution still flows through the LVM entry and `vm.Execute(...)`, with a large runtime surface exposed via `tos.*` and related helpers in `core/vm/lvm.go` fileciteturn18file0

Phases 2 and 3 added proof-backed validation for:
- transfers
- restricted contracts

But the architecture is still fundamentally hybrid:
- proof path for selected classes
- replay path for everything else

Phase 4 exists to change the **traffic distribution**:

> **Most high-frequency paths must be deliberately redesigned to fit proof-native validation.**

This is how validator replay stops dominating throughput.

---

# 5. Architectural Decision

## Phase 4 still uses out-of-band sidecars

Phase 4 keeps the same structural decision as Phase 1–3:

- no `Header` changes
- no proof metadata inside canonical block hash
- proof sidecars keyed by canonical block hash
- rawdb-persisted sidecars and artifacts

This remains the correct choice for this phase.

---

# 6. Definition of “Majority Hot Path”

Phase 4 needs an explicit operational definition.

A transaction class belongs to the **majority hot path** if it satisfies all of the following:

1. occurs frequently enough to dominate validator execution cost
2. has bounded execution shape
3. has proof-friendly semantics
4. can be modeled with committed trace + committed state diff
5. can be batch-proved economically

## 6.1 Phase 4 target classes

The following should be treated as target hot-path classes:

### A. Transfer-class
- native transfer
- shield
- private transfer
- unshield

### B. Restricted-contract class
- Phase 3 restricted proof-eligible contracts

### C. Profiled contract classes
- frequently used contracts whose behavior can be classified into a small number of approved proof profiles

### D. Package-call profiles
- selected package-dispatched contract calls where package identity and code hash are known and allowlisted

### E. Selected protocol-assisted flows
- high-frequency standard call patterns that can be expressed as constrained state transitions, even if implemented inside contracts

---

# 7. Phase 4 High-Level Outcome

Phase 4 is complete when:

1. most blocks are dominated by proof-covered transactions
2. the majority of validator time is spent on:
   - proof verification
   - sidecar loading
   - state-diff materialization
   - commitment checks
3. replay execution is reserved primarily for:
   - rare fallback txs
   - unsupported tx classes
   - deployment and unusual execution shapes
4. the system can continue to function safely in mixed proof / legacy mode

---

# 8. New Phase 4 Proof Model

Phase 4 introduces a generalized proof-native execution family for hot-path blocks.

## Recommended proof type family

- `hotpath-batch-v1`

This is a supertype that may cover:
- transfer-class txs
- restricted contract txs
- profiled contract txs
- package-call profiles
- approved system-assisted flows

Instead of having one proof type per tiny use case, Phase 4 should unify the majority path under one batch model.

---

# 9. Phase 4 Sidecar Design

## New file
- `core/types/proof_hotpath_sidecar.go`

## Required struct

```go
type HotPathBatchSidecar struct {
    BlockHash              common.Hash
    ProofType              string
    ProofVersion           uint32
    CircuitVersion         string

    PreStateRoot           common.Hash
    PostStateRoot          common.Hash

    BatchTxCommitment      common.Hash
    WitnessCommitment      common.Hash
    TraceCommitment        common.Hash
    StateDiffCommitment    common.Hash
    ReceiptCommitment      common.Hash
    PublicInputsHash       common.Hash

    ProofArtifactHash      common.Hash
    ProofBytes             []byte
    PublicInputs           []byte

    CoveredTxs             []HotPathCoveredTxRef
    UsedGas                uint64

    Receipts               []*types.Receipt
    StateDiff              *HotPathStateDiff
    TraceSummary           *HotPathTraceSummary

    BatchProfile           *HotPathBatchProfile
    ProverID               string
    ProvingTimeMs          uint64
}
```

## Required auxiliary structs

```go
type HotPathCoveredTxRef struct {
    TxHash      common.Hash
    Index       uint32
    TxType      uint8
    Class       uint8
    ProfileID   common.Hash
}
```

```go
type HotPathBatchProfile struct {
    AllowedClasses            []uint8
    MaxRestrictedCallDepth    uint8
    MaxStorageReadsPerTx      uint32
    MaxStorageWritesPerTx     uint32
    MaxLogsPerTx              uint32
    MaxProofCoveredTxs        uint32
    AllowLegacyTail           bool
}
```

## Required rules
- `ProofType` must be `hotpath-batch-v1`
- `PostStateRoot` must equal canonical block root
- `CoveredTxs` must match exact covered transaction ordering
- `ProfileID` must bind each covered tx to a deterministic hot-path profile

---

# 10. Hot-Path Classification Model

## New file
- `core/types/hotpath_class.go`

## Required enum

```go
type HotPathClass uint8

const (
    HotPathUnknown HotPathClass = iota
    HotPathTransfer
    HotPathRestrictedContract
    HotPathProfiledContract
    HotPathPackageCall
    HotPathSystemAssisted
    HotPathLegacyFallback
)
```

## Required helpers
```go
func (tx *Transaction) HotPathClass(statedb *state.StateDB) HotPathClass
func (tx *Transaction) IsHotPathCandidate(statedb *state.StateDB) bool
func (tx *Transaction) HotPathProfileID(statedb *state.StateDB) common.Hash
```

## Required behavior
The classification must be:
- deterministic
- state-dependent only through consensus-visible state
- stable across validator / builder / prover

---

# 11. Hot-Path Profiles

Phase 4 must stop thinking only in terms of transaction “types” and start thinking in terms of **execution profiles**.

A profile describes a reusable proofable execution shape.

## New file
- `core/vm/hotpath_profiles.go`

## Required struct

```go
type HotPathExecutionProfile struct {
    ID                      common.Hash
    Class                   HotPathClass
    CodeHash                common.Hash
    PackageHash             common.Hash
    Selector                [4]byte

    MaxCallDepth            uint8
    MaxInstructions         uint64
    MaxStorageReads         uint32
    MaxStorageWrites        uint32
    MaxLogs                 uint32

    AllowRevert             bool
    AllowExternalCalls      bool
    AllowDelegateLikeCall   bool
    AllowPackageCall        bool
    AllowUnoPaths           bool
}
```

## Required profile sources
Profiles may come from:
- allowlisted code hashes
- allowlisted package hashes
- allowlisted `(codeHash, selector)` combinations
- protocol-assisted templates

## Recommended Phase 4 implementation
Profile identity should be based on:
- code hash
- selector
- execution class

This makes profiling concrete enough to prove.

---

# 12. Expanding Beyond “Restricted Contract”

Phase 3 only allowed a tightly restricted contract subset.

Phase 4 should expand by **profile**, not by unrestricted permission.

That means:
- not “all contracts can now be proven”
- but “more contract shapes are now proven because they fit approved profiles”

## 12.1 Allowed expansion dimensions
Phase 4 may add:
- more allowlisted code hashes
- more selectors
- bounded package calls
- bounded nested calls under explicit profile control
- bounded event/log patterns
- bounded host-call subsets

## 12.2 Forbidden expansion
Phase 4 should still forbid:
- unrestricted recursion
- unrestricted dynamic host interaction
- arbitrary deployment proving
- arbitrary dynamic logs
- arbitrary package execution without profile binding

---

# 13. Hot-Path Trace Model

## New files
- `core/types/proof_hotpath_trace.go`
- `core/vm/hotpath_trace.go`

## Required struct family

```go
type HotPathTraceSummary struct {
    TxTraces []HotPathTxTraceSummary
}
```

```go
type HotPathTxTraceSummary struct {
    TxHash               common.Hash
    TxIndex              uint32
    Class                HotPathClass
    ProfileID            common.Hash

    CodeHash             common.Hash
    PackageHash          common.Hash
    Selector             [4]byte

    CallDepth            uint8
    InstructionCount     uint64
    StorageReadCount     uint32
    StorageWriteCount    uint32
    LogCount             uint32

    Reverted             bool
    ReturnDataCommitment common.Hash
}
```

## Required trace rules
- exact tx order preserved
- exact class/profile binding preserved
- bounded counts preserved
- no debug-only nondeterministic fields
- canonical encoding for commitment

## Required helper
```go
func DeriveHotPathTraceCommitment(trace *HotPathTraceSummary) (common.Hash, error)
```

---

# 14. Hot-Path State Diff Model

## New file
- `core/types/proof_hotpath_state_diff.go`

## Required struct family

```go
type HotPathStateDiff struct {
    Accounts []HotPathAccountDiff
}
```

```go
type HotPathAccountDiff struct {
    Address           common.Address
    PreNonce          uint64
    PostNonce         uint64
    PreBalance        *big.Int
    PostBalance       *big.Int
    StorageDiffs      []HotPathStorageDiff
    PrivStateDiffs    []HotPathPrivStateDiff
}
```

```go
type HotPathStorageDiff struct {
    Key   common.Hash
    Pre   common.Hash
    Post  common.Hash
}
```

```go
type HotPathPrivStateDiff struct {
    Key   []byte
    Pre   []byte
    Post  []byte
}
```

## Required rules
- canonical ordering
- duplicate rejection
- pre-value verification before apply
- profile-appropriate state diff shape

---

# 15. Hot-Path Receipt Model

Phase 4 continues the Phase 2/3 approach:
- sidecar-supplied receipts
- canonical commitment validation
- no local replay-based receipt derivation for covered txs

## New helper
- `DeriveHotPathReceiptCommitment(...)`

## Required receipt rules
For covered txs:
- tx hash
- status
- cumulative gas used
- gas used
- optional proof metadata
- bounded / profile-consistent logs only

---

# 16. Processor Design

## New file
- `core/state_processor_hotpath.go`

## Required function

```go
func (p *StateProcessor) ProcessHotPathProofBlock(
    block *types.Block,
    parent *types.Header,
    sidecar *types.HotPathBatchSidecar,
) (types.Receipts, uint64, *state.StateDB, error)
```

## Required behavior
- do not locally execute covered txs
- validate tx-set against sidecar
- validate class/profile binding
- materialize receipts from sidecar
- allocate fresh `StateDB` from parent root
- apply hot-path state diff
- return `(receipts, usedGas, statedb, nil)`

## Optional mixed mode behavior
If `AllowLegacyTail == true`, the processor may:
- process covered txs through sidecar materialization
- process uncovered tail txs through legacy execution

### Recommendation
Do **not** enable mixed-mode inside the same batch in the first Phase 4 rollout.

Prefer:
- a block is either majority proof-covered with a small explicitly unsupported tail
- or fully legacy

---

# 17. State Application Design

## New file
- `core/state/proof_apply_hotpath.go`

## Required functions

```go
func ApplyHotPathStateDiff(
    statedb *state.StateDB,
    diff *types.HotPathStateDiff,
) error
```

```go
func applyHotPathAccountDiff(
    statedb *state.StateDB,
    diff *types.HotPathAccountDiff,
) error
```

## Required behavior
- canonical sort before apply
- verify pre-values before apply
- reject duplicates
- apply account, storage, private-state changes
- yield deterministic post-root

---

# 18. Validator Design

## New file
- `core/block_validator_hotpath.go`

## Required interface

```go
type HotPathBatchProofVerifier interface {
    VerifyHotPathBatchProof(inputs *HotPathProofValidationInputs) error
}
```

## Required structs

```go
type HotPathProofValidationInputs struct {
    Block                *types.Block
    Sidecar              *types.HotPathBatchSidecar
    ParentRoot           common.Hash
    TxCommitment         common.Hash
    TraceCommitment      common.Hash
    WitnessCommitment    common.Hash
    StateDiffCommitment  common.Hash
    ReceiptCommitment    common.Hash
}
```

## Required function

```go
func (v *BlockValidator) ValidateStateHotPathProof(
    block *types.Block,
    parentRoot common.Hash,
    sidecar *types.HotPathBatchSidecar,
    receipts types.Receipts,
    usedGas uint64,
) error
```

## Required checks
- sidecar exists
- proof type/version supported
- block hash binding correct
- post-state root matches block root
- covered tx list matches exact block tx list or exact covered subset
- hot-path class/profile binding valid
- tx commitment matches
- trace commitment matches
- witness commitment matches
- state diff commitment matches
- receipt commitment matches
- proof verifies
- gas checks pass
- materialized post-state root matches block root

---

# 19. Blockchain Import Design

## Existing file
- `core/blockchain.go`

Phase 4 adds another proof-aware import branch.

## New helper functions

```go
func (bc *BlockChain) loadHotPathProofSidecar(
    blockHash common.Hash,
) (*types.HotPathBatchSidecar, error)
```

```go
func (bc *BlockChain) shouldUseHotPathProofValidation(
    block *types.Block,
    sidecar *types.HotPathBatchSidecar,
) bool
```

## Required branch order

For each block in `insertChain(...)`:

1. no sidecar => legacy path
2. transfer proof sidecar => Phase 2 path
3. restricted contract sidecar => Phase 3 path
4. hot-path sidecar => Phase 4 path

## Phase 4 path
- load hot-path sidecar
- call `ProcessHotPathProofBlock(...)`
- call `ValidateStateHotPathProof(...)`
- continue into normal `writeBlockWithState(...)`

---

# 20. VM Surface Reduction Strategy

The LVM surface today is large and includes many runtime primitives under `tos.*` in `core/vm/lvm.go` fileciteturn18file0

Phase 4 cannot make “most hot path” proof-native unless the hot path avoids the unbounded runtime surface.

Therefore Phase 4 must introduce a **proof-native VM surface reduction policy**.

## New file
- `core/vm/hotpath_runtime_policy.go`

## Required responsibilities
For a tx/profile to be hot-path proof-eligible:
- only allowed runtime primitives may be touched
- all touched primitives must map to proof-mode semantics
- disallowed primitives force fallback to legacy path

## Examples of likely disallowed primitives in first Phase 4 rollout
- unrestricted scheduling flows
- unrestricted registry mutation
- unrestricted package deployment
- unrestricted delegation mutation
- unrestricted event/log emission
- unrestricted nested package/proxy execution

---

# 21. Package and Profile Support

Phase 4 should begin to support more real-world package-based traffic.

## New file
- `core/vm/hotpath_package_profiles.go`

## Required behavior
- allowlist `(packageHash, contractName, selector)` combinations
- bind these combinations to deterministic `HotPathExecutionProfile`
- validate profile at builder, prover, and validator

This allows high-frequency package calls to become proof-native without allowing arbitrary package behavior.

---

# 22. Allowlist / Registry Design

## New files
- `core/vm/hotpath_registry.go`
- optionally `core/rawdb/accessors_hotpath_registry.go`

## Required functions
```go
func IsHotPathProfileAllowed(statedb vm.StateDB, profileID common.Hash) bool
func ReadHotPathProfile(statedb vm.StateDB, profileID common.Hash) (*HotPathExecutionProfile, bool)
func ResolveHotPathProfileID(statedb vm.StateDB, tx *types.Transaction) (common.Hash, bool)
```

## Required rule
Profile lookup must be:
- deterministic
- consensus-visible
- not local-node-only

---

# 23. Batch Builder Design

Phase 4 needs a more intelligent proof-native batch builder.

## New file
- `miner/hotpath_batch_builder.go`

## Required struct

```go
type HotPathBatchBuilder struct {
    // configuration, profile registry, limits, etc.
}
```

## Required behavior
- group proof-eligible txs into hot-path batches
- maximize covered tx percentage
- avoid mixing incompatible profiles in one batch if prover cannot support it
- optionally leave rare txs in legacy tail or legacy block path
- expose:
  - covered txs
  - uncovered txs
  - batch class/profile summary

---

# 24. Prover Design

## New file
- `proofworker/hotpath_batch_prover.go`

## Required function

```go
func ProveHotPathBatch(req *HotPathProofWorkerRequest) (*HotPathProofWorkerResponse, error)
```

## Required response content
- sidecar-ready proof artifact
- public inputs
- tx commitment
- trace commitment
- witness commitment
- state diff commitment
- receipt commitment
- state diff
- receipt set
- trace summary

Phase 4 still keeps proving out of the node hot path.

---

# 25. RPC Design

## New file
- `internal/tosapi/proof_hotpath_api.go`

## Required APIs
- `tos_getHotPathProofSidecar(blockHash)`
- `tos_getTransactionHotPathStatus(txHash)`
- `tos_getHotPathBatchProfile(blockHash)`
- optional debug-only trace summary endpoint

## Standard APIs should expose
- proof type
- proof version
- proof-covered
- hot-path class
- profile ID

---

# 26. Metrics and Telemetry

## New metrics
- `chain/hotpath/covered_txs`
- `chain/hotpath/covered_ratio`
- `chain/hotpath/proof_verify_time`
- `chain/hotpath/state_apply_time`
- `chain/hotpath/legacy_fallback_txs`
- `chain/hotpath/profile_hits`
- `chain/hotpath/profile_misses`

## Required logs
On hot-path proof-backed block validation:
- block number/hash
- covered tx count
- covered ratio
- profile distribution
- verify time
- state apply time
- fallback tail count if any

---

# 27. Security Rules

## 27.1 No silent downgrade
If a block carries a hot-path proof sidecar:
- validator must validate it under hot-path proof rules
- or reject it

## 27.2 Exact tx binding
The proof must bind to:
- exact covered tx list
- exact order
- exact tx hashes
- exact classes
- exact profile IDs

## 27.3 Profile discipline
A tx must not claim a hot-path profile unless:
- that profile is allowlisted
- that tx actually fits the profile

## 27.4 State diff pre-value checks
Every applied state diff must validate pre-values before mutation.

## 27.5 Bounded trace discipline
Every hot-path profile must remain bounded:
- no unbounded recursion
- no unbounded logs
- no unbounded host-call surface

---

# 28. Testing Plan

# 28.1 Unit tests

## Types
- hot-path sidecar encode/decode
- hot-path trace summary validation
- hot-path state diff validation
- commitment determinism

## VM
- hot-path classification
- profile resolution
- runtime policy rejection
- package-profile resolution

## State
- hot-path state diff apply
- wrong pre-value rejection
- deterministic post-root

## Core
- processor hot-path path
- validator hot-path path
- blockchain insert hot-path path

---

# 28.2 Integration tests

## Happy path
- hot-path transfer-heavy block
- hot-path restricted-contract-heavy block
- hot-path mixed-profile block if supported
- hot-path majority-covered block with small fallback tail if supported

## Negative path
- missing sidecar
- wrong block hash
- wrong profile ID
- unsupported profile
- trace commitment mismatch
- state diff commitment mismatch
- receipt commitment mismatch
- post-state mismatch
- invalid covered-tx set
- forbidden runtime primitive under claimed hot-path profile

---

# 28.3 Regression tests
- legacy path unchanged
- Phase 2 path unchanged
- Phase 3 path unchanged
- state commit path unchanged
- reorg logic unchanged for non-proof blocks

---

# 29. Implementation Order

## Step 1
Define:
- hot-path sidecar types
- hot-path trace summary types
- hot-path state diff types
- hot-path class/profile types

## Step 2
Implement:
- hot-path profile registry
- tx/profile resolution
- runtime policy gating

## Step 3
Implement:
- hot-path commitment functions
- hot-path sidecar persistence
- hot-path trace summary generation

## Step 4
Implement:
- hot-path state diff materialization
- hot-path processor path

## Step 5
Implement:
- hot-path validator path

## Step 6
Integrate:
- blockchain import branching
- miner hot-path batch builder
- proof worker hot-path batch prover

## Step 7
Expose:
- RPC and telemetry

## Step 8
Complete:
- integration tests
- negative tests
- dominant-path traffic simulations

---

# 30. Migration Strategy

## Recommended rollout
1. keep Phase 2 and Phase 3 paths working
2. add Phase 4 hot-path proof path behind a feature flag
3. start with a very small allowlisted hot-path profile set
4. test on devnet
5. test on internal testnet
6. measure covered-ratio and validator replay savings
7. expand profiles gradually
8. only then make hot-path proof coverage the default for dominant traffic

---

# 31. Final Summary

Phase 4 is the first phase that aims to make `gtos` operationally resemble a Gigagas L1.

The key principle is:

> **Do not wait for universal proving. Move the majority hot path into proof-native validation first.**

To make that work, Phase 4 must add:

- a generalized hot-path proof sidecar
- hot-path transaction classes
- hot-path execution profiles
- hot-path trace commitments
- hot-path state-diff commitments
- a proof-native processor and validator for majority traffic
- a batch builder that maximizes proof-covered volume
- a runtime policy that narrows the VM surface of proof-covered traffic

That is the narrowest realistic Phase 4 path that:
- builds on Phases 1–3
- remains implementable with the current `gtos` architecture
- pushes validator replay off the dominant path
- gets meaningfully closer to a true Gigagas-style L1

---

## Related Documents

- [Gigagas L1 Roadmap](./gtos_gigagas_l1_roadmap.md)
- [Phase 3 Design: Restricted Contract Proving](./gtos_gigagas_l1_phase3_restricted_contract_proving.md)
- [Phase 4 File-by-File Coding Checklist](./gtos_gigagas_l1_phase4_coding_checklist.md)
- [Phase 5 Design: Throughput Scaling](./gtos_gigagas_l1_phase5_throughput_scaling.md)
