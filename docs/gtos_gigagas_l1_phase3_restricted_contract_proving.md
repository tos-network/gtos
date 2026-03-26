# gtos Phase 3 Design
## Restricted Contract Proving
### Detailed Implementation Design for `restricted-contract-batch-v1`

## Status

**Document status:** design-ready  
**Target audience:** core protocol engineers working on `gtos`  
**Language:** English  
**Scope:** detailed enough to implement directly

---

# 1. Purpose

This document defines **Phase 3** of the Gigagas L1 roadmap for `gtos`.

Phase 2 introduced **proof-backed transfer validation** for a narrow proof-covered transaction set:

- native transfer
- shield
- private transfer
- unshield

Phase 3 extends the proof-backed model from transfer-only execution to a **restricted contract subset**.

The goal is:

> **Validators stop fully re-executing a restricted, proof-eligible contract subset and instead validate a sidecar proof, committed receipts, and a committed materializable post-state diff.**

This is still **not** full arbitrary contract proving.  
It is a carefully constrained proving mode for a limited LVM/TOS contract subset.

---

# 2. Core Objective

Phase 3 adds proof-backed validation for:

- proof-eligible restricted contract calls
- optionally mixed with proof-backed transfer-class transactions in the same proof batch

The validator should:

- load the proof sidecar
- verify the proof and public inputs
- validate receipt, trace, and state-diff commitments
- materialize the committed post-state into a real `StateDB`
- accept the block without locally replaying the proof-covered restricted contract calls

This extends the Phase 2 architecture without changing the canonical header.

---

# 3. Non-Goals

Phase 3 does **not** attempt to:

- prove arbitrary LVM / Lua programs
- prove the entire contract ecosystem without restrictions
- support unrestricted host calls
- support unrestricted dynamic logs/events
- support unrestricted cross-contract recursion
- move proof data into canonical block hashing
- replace all validator execution with proof verification

Phase 3 is intentionally a **restricted proving phase**, not the final proving phase.

---

# 4. Current Execution Anchors in gtos

The current execution path in `gtos` still runs through the classical processor and VM stack:

- block execution runs through `StateProcessor.Process(...)` in `core/state_processor.go` fileciteturn16file0
- ordinary tx execution ultimately reaches the VM execution path
- scheduled/native tasks also reach `vm.Execute(...)` through `RunScheduledTasks(...)` in `core/state_processor.go` fileciteturn16file0
- the contract VM execution entry is in `core/vm/lvm.go` fileciteturn17file0

This means Phase 3 must not invent a disconnected proving architecture.  
It must plug into the same three seams:

1. **tx classification**
2. **state processor branching**
3. **VM execution / restricted trace extraction**

---

# 5. Architectural Decision

## Phase 3 continues to use out-of-band sidecars

Phase 3 keeps the same sidecar model introduced in Phase 1 and used in Phase 2:

- no `Header` changes
- no proof metadata in canonical block hash
- proof sidecar keyed by canonical block hash
- rawdb persistence for proof sidecars

This is still the correct design for this phase.

---

# 6. What “Restricted Contract Proving” Means

Phase 3 must define a proofable contract subset that is:

- deterministic
- statically classifiable
- bounded in execution shape
- bounded in host interaction
- bounded in storage mutation structure
- bounded in logging behavior

This subset is called:

> **restricted-contract-batch-v1**

Only transactions in this subset may use the Phase 3 proof-backed contract validation path.

---

# 7. Required Functional Outcome

Phase 3 is complete when a validator can do the following for a restricted-contract-batch block:

1. receive the block
2. resolve its proof sidecar by block hash
3. verify that all proof-covered txs belong to the restricted subset
4. verify:
   - sidecar type/version
   - tx commitment
   - receipt commitment
   - trace commitment
   - state-diff commitment
   - public inputs
   - proof artifact
5. materialize the proven post-state into a real `StateDB`
6. accept the block without replaying the proof-covered restricted contract calls

---

# 8. Scope of Proof-Covered Contract Calls

Phase 3 must start with a narrow contract subset.

## 8.1 Allowed transaction classes

Phase 3 proof-covered transactions may include:

- Phase 2 transfer-class txs:
  - native transfer
  - shield
  - private transfer
  - unshield
- restricted contract calls that satisfy all restricted-proof rules

## 8.2 Recommended initial restricted subset

A contract call is proof-eligible in Phase 3 only if all of the following are true:

- target code is marked proof-eligible
- no deployment / create path
- no contract creation
- no dynamic code loading
- no unrestricted recursion
- no unrestricted cross-contract call graph
- no unsupported host call
- no unsupported precompile or native bridge
- no unsupported log/event pattern
- bounded storage touch count
- bounded gas / step count
- deterministic revert semantics

---

# 9. Phase 3 Proof Modes

## 9.1 New proof sidecar types

Phase 3 introduces a new proof type family:

- `restricted-contract-batch-v1`

Optionally later:
- `restricted-contract-batch-v1-with-transfers`

## 9.2 Recommendation

Use a single proof type for Phase 3:

- `restricted-contract-batch-v1`

and allow that batch to cover:
- restricted contract calls
- transfer-class transactions

This keeps the validator branching model simpler.

---

# 10. Restricted Contract Eligibility Model

## New file
- `core/vm/proof_eligibility.go`

## Required enum

```go
type ContractProofEligibility uint8

const (
    ContractProofIneligible ContractProofEligibility = iota
    ContractProofRestrictedV1
)
```

## Required structs

```go
type RestrictedContractProofProfile struct {
    CodeHash              common.Hash
    MaxInstructions       uint64
    MaxStorageReads       uint32
    MaxStorageWrites      uint32
    MaxLogs               uint32
    MaxCallDepth          uint8
    AllowExternalCalls    bool
    AllowDelegateLikeCall bool
    AllowValueTransfer    bool
    AllowRevert           bool
}
```

## Required helpers

```go
func IsRestrictedProofEligibleCode(code []byte) bool
func RestrictedProofProfileForCode(code []byte) (*RestrictedContractProofProfile, error)
func IsRestrictedProofEligibleTx(tx *types.Transaction, statedb *state.StateDB) bool
```

## Rule

Eligibility must be decided **before execution** and must be deterministic across all nodes.

---

# 11. Restricted Contract Rules

Phase 3 should ship with explicit hard rules.

## 11.1 Contract creation
Forbidden.

- no CREATE-like semantics
- no package deploy
- no constructor proving in Phase 3

## 11.2 Cross-contract calls
Strongly restricted.

### Recommended Phase 3 rule
Only one of these should be allowed:

- **Option A:** no contract-to-contract calls at all
- **Option B:** only calls into contracts already marked restricted-proof-eligible, with max depth = 1

### Recommended implementation choice
Use **Option A** for the first Phase 3 rollout.

That means:
- one tx
- one contract
- no nested contract execution

This is much easier to prove and validate.

## 11.3 Host calls / syscalls
Only a whitelisted subset is allowed.

Examples of disallowed categories:
- environment queries with non-trivial semantics not modeled in proof
- external system mutation calls
- lease / governance / validator maintenance system actions
- unrestricted cryptographic host calls not yet modeled
- arbitrary event/log emission with variable structure

## 11.4 Storage
Storage access is allowed only within explicit bounded limits:

- max storage read count
- max storage write count
- no unbounded iteration over dynamic structures

## 11.5 Events / logs
Strictly restricted.

### Recommended Phase 3 rule
- either no logs
- or only fixed-shape logs with bounded count and statically known topics layout

### Recommended first rollout
Use **no contract-generated logs** in the proof-covered restricted subset.

## 11.6 Revert semantics
Allowed only if:
- revert result is fully captured in sidecar receipts and trace
- no partial side effects leak outside tx-local execution
- state diff for reverted tx is empty or explicitly represented as no-op

---

# 12. New Sidecar Model for Restricted Contract Batches

## Existing base
Phase 3 extends the Phase 2 sidecar.

## New file
- `core/types/proof_contract_sidecar.go`

## Required structs

### `RestrictedContractBatchSidecar`
```go
type RestrictedContractBatchSidecar struct {
    BlockHash             common.Hash
    ProofType             string
    ProofVersion          uint32
    CircuitVersion        string

    PreStateRoot          common.Hash
    PostStateRoot         common.Hash
    BatchTxCommitment     common.Hash
    WitnessCommitment     common.Hash
    TraceCommitment       common.Hash
    StateDiffCommitment   common.Hash
    ReceiptCommitment     common.Hash
    PublicInputsHash      common.Hash

    ProofArtifactHash     common.Hash
    ProofBytes            []byte
    PublicInputs          []byte

    ProofCoveredTxs       []ProofCoveredTxRef
    UsedGas               uint64
    Receipts              []*types.Receipt
    StateDiff             *RestrictedContractStateDiff
    TraceSummary          *RestrictedContractTraceSummary

    ProverID              string
    ProvingTimeMs         uint64
}
```

### `RestrictedContractTraceSummary`
```go
type RestrictedContractTraceSummary struct {
    TxTraces []RestrictedContractTxTraceSummary
}
```

### `RestrictedContractTxTraceSummary`
```go
type RestrictedContractTxTraceSummary struct {
    TxHash               common.Hash
    TxIndex              uint32
    Callee               common.Address
    CodeHash             common.Hash
    CallDepth            uint8
    InstructionCount     uint64
    StorageReadCount     uint32
    StorageWriteCount    uint32
    Reverted             bool
    ReturnDataCommitment common.Hash
}
```

---

# 13. Trace Model for Restricted Contracts

## New files
- `core/vm/proof_trace.go`
- `core/vm/proof_trace_contract.go`

## Purpose
Phase 3 proof-backed contract validation needs a committed summary of execution shape.

Unlike Phase 2 transfer proving, contract proving requires an execution trace summary.

## Required structs
- `RestrictedContractExecutionTrace`
- `RestrictedContractTraceEntry`
- `RestrictedContractStorageTouch`
- `RestrictedContractReturnDataSummary`

## Required helper functions
```go
func DeriveRestrictedContractTraceCommitment(trace *RestrictedContractExecutionTrace) (common.Hash, error)
func SummarizeRestrictedContractTrace(trace *RestrictedContractExecutionTrace) (*RestrictedContractTraceSummary, error)
```

## Required rules
- canonical ordering
- exact call depth tracking
- exact storage read/write counts
- exact revert/no-revert outcome
- exact return-data commitment
- no unbounded dynamic trace fields

---

# 14. State Diff Model for Restricted Contracts

## New file
- `core/types/proof_contract_state_diff.go`

## Required structs

```go
type RestrictedContractStateDiff struct {
    Accounts []RestrictedContractAccountDiff
}
```

```go
type RestrictedContractAccountDiff struct {
    Address           common.Address
    PreNonce          uint64
    PostNonce         uint64
    PreBalance        *big.Int
    PostBalance       *big.Int
    StorageDiffs      []RestrictedContractStorageDiff
    PrivStateDiffs    []RestrictedContractPrivStateDiff
}
```

```go
type RestrictedContractStorageDiff struct {
    Key   common.Hash
    Pre   common.Hash
    Post  common.Hash
}
```

```go
type RestrictedContractPrivStateDiff struct {
    Key   []byte
    Pre   []byte
    Post  []byte
}
```

## Rules
- same canonical sorting rules as Phase 2
- no duplicate account entries
- no duplicate storage entries
- no duplicate private-state entries
- all pre-values must be verified before apply

---

# 15. Receipt Model for Restricted Contracts

## Required approach
Use sidecar-supplied receipts, exactly like Phase 2, but with restricted contract status encoded.

## Rules
Receipts in Phase 3 must include:
- tx hash
- tx type
- status
- gas used
- cumulative gas used
- contract address fields if applicable
- proof metadata fields if used by RPC

## Additional recommendation
For Phase 3, do not support arbitrary dynamic logs inside proof-covered restricted contracts.  
Either:
- no logs
- or a fixed-shape log subset in a later sub-phase

---

# 16. Processor Changes

## Existing file
- `core/state_processor.go`

## New file
- `core/state_processor_restricted_proof.go`

## Required new functions

```go
func (p *StateProcessor) ProcessRestrictedContractProofBlock(
    block *types.Block,
    parent *types.Header,
    sidecar *types.RestrictedContractBatchSidecar,
) (types.Receipts, uint64, *state.StateDB, error)
```

```go
func (p *StateProcessor) materializeRestrictedContractReceipts(
    sidecar *types.RestrictedContractBatchSidecar,
) (types.Receipts, error)
```

```go
func (p *StateProcessor) validateRestrictedProofCoveredTxSet(
    block *types.Block,
    sidecar *types.RestrictedContractBatchSidecar,
) error
```

## Required behavior
- do not execute proof-covered restricted contract txs locally
- validate tx-set against sidecar
- materialize receipts from sidecar
- allocate fresh `StateDB` from parent root
- apply restricted contract state diff
- return `(receipts, usedGas, statedb, nil)`

---

# 17. State Application Changes

## Existing Phase 2 file
- `core/state/proof_apply.go`

## New file
- `core/state/proof_apply_contract.go`

## Required functions
```go
func ApplyRestrictedContractStateDiff(
    statedb *state.StateDB,
    diff *types.RestrictedContractStateDiff,
) error
```

```go
func applyRestrictedContractAccountDiff(
    statedb *state.StateDB,
    diff *types.RestrictedContractAccountDiff,
) error
```

## Required behavior
- verify pre-values before apply
- canonical sort before apply
- reject duplicates
- apply account balance/nonce updates
- apply storage updates
- apply private-state updates if allowed in restricted subset

---

# 18. Validator Changes

## Existing file
- `core/block_validator.go`

## New file
- `core/block_validator_restricted_proof.go`

## Required new functions

```go
func (v *BlockValidator) ValidateStateRestrictedContractProof(
    block *types.Block,
    parentRoot common.Hash,
    sidecar *types.RestrictedContractBatchSidecar,
    receipts types.Receipts,
    usedGas uint64,
) error
```

```go
func (v *BlockValidator) validateRestrictedContractProofSidecarBinding(
    block *types.Block,
    sidecar *types.RestrictedContractBatchSidecar,
) error
```

```go
func (v *BlockValidator) validateRestrictedContractTrace(
    sidecar *types.RestrictedContractBatchSidecar,
) error
```

```go
func (v *BlockValidator) validateRestrictedContractEligibility(
    block *types.Block,
    sidecar *types.RestrictedContractBatchSidecar,
) error
```

## Required checks
- sidecar exists
- proof type matches `restricted-contract-batch-v1`
- sidecar block hash matches block hash
- post-state root matches block root
- tx set exactly matches proof-covered set
- all proof-covered txs are restricted-proof-eligible
- batch tx commitment matches
- trace commitment matches
- state diff commitment matches
- receipt commitment matches
- proof verifies
- gas checks pass
- materialized post-state root matches block root

---

# 19. Blockchain Import Path Changes

## Existing file
- `core/blockchain.go`

## Required changes
Extend the Phase 2 import branching logic with a third branch.

## New helper functions

```go
func (bc *BlockChain) shouldUseRestrictedContractProofValidation(
    block *types.Block,
    sidecar *types.RestrictedContractBatchSidecar,
) bool
```

```go
func (bc *BlockChain) loadRestrictedContractProofSidecar(
    blockHash common.Hash,
) (*types.RestrictedContractBatchSidecar, error)
```

## New branching logic
For each block in `insertChain(...)`:

### Case A — no sidecar
- legacy flow

### Case B — Phase 2 transfer sidecar
- Phase 2 proof-backed transfer path

### Case C — Phase 3 restricted contract sidecar
- call `ProcessRestrictedContractProofBlock(...)`
- call `ValidateStateRestrictedContractProof(...)`
- continue into normal `writeBlockWithState(...)`

---

# 20. VM and Trace Extraction Changes

## Existing VM anchor
- `core/vm/lvm.go` fileciteturn17file0

## New files
- `core/vm/proof_eligibility.go`
- `core/vm/proof_trace.go`
- `core/vm/proof_trace_contract.go`

## Required responsibilities
- classify whether code is restricted-proof-eligible
- build deterministic restricted trace summaries
- enforce restricted call rules
- reject forbidden execution shapes early

## Recommended implementation rule
Do not try to prove raw unrestricted VM steps in Phase 3.  
Instead, define a **restricted semantic trace** that is proof-friendly.

That means the trace should encode:
- instruction count
- storage read/write count
- revert outcome
- return-data commitment
- call graph shape (preferably depth 0 or 1 only)

---

# 21. Code Annotation / Eligibility Metadata

## Recommendation
Phase 3 needs a deterministic way to know whether a contract is proof-eligible.

Use one of these approaches:

### Option A — code-hash allowlist
- simplest for first implementation
- recommended for Phase 3 initial rollout

### Option B — compiler-emitted proof profile metadata
- better long-term
- more work now

## Required Phase 3 choice
Use **Option A** first:

- maintain a proof-eligible code-hash registry
- optionally generated at deploy time or governance-approved
- validator checks target code hash against this registry

## New storage or registry helpers
- `core/vm/proof_registry.go`
- `core/rawdb/accessors_proof_registry.go` or equivalent state-based registry

---

# 22. Contract Deployment Policy

## Phase 3 rule
Contracts are **not** deployed directly into restricted-proof mode automatically.

Deployment remains legacy-path.

A deployed contract becomes restricted-proof-eligible only if:
- its code hash is registered as restricted-proof-eligible
- its proof profile is known and valid

This keeps deployment complexity out of Phase 3.

---

# 23. Cross-Contract Call Policy

## Recommended Phase 3 first rollout
No contract-to-contract calls in proof-backed restricted mode.

This means:
- one proof-covered tx
- one target contract
- one code hash
- no nested contract graph

## Why
This sharply reduces:
- trace complexity
- state-diff complexity
- eligibility checking complexity
- proving complexity

## Later extension
A future sub-phase may permit:
- restricted-proof-eligible callee only
- max call depth = 1

But that should not be in the first Phase 3 rollout.

---

# 24. Revert and Return Data Policy

## Allowed
- revert
- success return

## Required commitments
Sidecar trace summary must commit to:
- reverted / not reverted
- return data hash / commitment
- gas used
- zero state diff on revert if semantics require it

## Validation rule
A reverted restricted-proof tx must:
- still have committed receipt outcome
- still match gas accounting
- not leak unexpected state writes into state diff

---

# 25. RawDB Persistence

## New files
- `core/rawdb/schema_proof_contract.go`
- `core/rawdb/accessors_proof_contract.go`

## Required functions
```go
func ReadRestrictedContractProofSidecar(db tosdb.KeyValueReader, blockHash common.Hash) *types.RestrictedContractBatchSidecar
func WriteRestrictedContractProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash, sidecar *types.RestrictedContractBatchSidecar)
func DeleteRestrictedContractProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash)
func HasRestrictedContractProofSidecar(db tosdb.Reader, blockHash common.Hash) bool
```

## Recommendation
Keep transfer proof sidecars and restricted contract sidecars in the same proof-sidecar namespace if schema versioning is clean enough.  
Otherwise split them by proof type prefix.

---

# 26. RPC Changes

## New file
- `internal/tosapi/proof_contract_api.go`

## Modified file
- `internal/tosapi/api.go`

## Required APIs
- `tos_getRestrictedContractProofSidecar(blockHash)`
- `tos_getTransactionRestrictedProofStatus(txHash)`
- optional debug-only `tos_getRestrictedProofTraceSummary(blockHash)`

## Standard APIs should expose when present
- proof type
- proof version
- proof-covered
- proof batch index
- restricted proof profile identifier or code hash if useful

---

# 27. New Error Set

## New file
- `core/types/proof_contract_errors.go`

## Required errors
- `ErrRestrictedProofMissingSidecar`
- `ErrRestrictedProofUnsupportedType`
- `ErrRestrictedProofTxSetMismatch`
- `ErrRestrictedProofEligibilityMismatch`
- `ErrRestrictedProofTraceCommitmentMismatch`
- `ErrRestrictedProofStateDiffCommitmentMismatch`
- `ErrRestrictedProofReceiptCommitmentMismatch`
- `ErrRestrictedProofVerificationFailed`
- `ErrRestrictedProofForbiddenCallShape`
- `ErrRestrictedProofUnsupportedHostCall`
- `ErrRestrictedProofUnsupportedLogs`
- `ErrRestrictedProofPostStateMismatch`

---

# 28. Testing Plan

# 28.1 Unit tests

## `core/types`
- sidecar encode/decode
- restricted state diff validation
- restricted trace summary validation
- commitments deterministic

## `core/state`
- restricted state diff apply
- wrong pre-value rejection
- deterministic post-root

## `core/vm`
- proof eligibility classification
- forbidden call shape rejection
- unsupported host call rejection

## `core`
- restricted proof processor path
- restricted proof validator path
- blockchain insert branch dispatch

---

# 28.2 Integration tests

## Happy path
- one restricted contract call block
- multiple restricted contract call block
- mixed transfer + restricted contract block if enabled
- reverting restricted contract call block

## Negative path
- sidecar missing
- wrong block hash
- unsupported contract code hash
- forbidden nested call
- forbidden host call
- trace commitment mismatch
- state diff commitment mismatch
- receipt commitment mismatch
- post-state mismatch

---

# 28.3 Regression tests
- legacy blocks unchanged
- Phase 2 transfer proof blocks unchanged
- non-proof contract execution unchanged
- reorg logic unchanged for legacy path

---

# 29. Implementation Order

## Step 1
Define:
- restricted sidecar types
- restricted state diff types
- restricted trace summary types
- restricted proof errors

## Step 2
Implement:
- rawdb sidecar persistence
- code-hash proof eligibility registry
- tx eligibility checks

## Step 3
Implement:
- restricted trace commitment functions
- restricted state diff commitment functions
- receipt commitment reuse/adaptation

## Step 4
Implement:
- state diff materialization
- restricted proof processor path

## Step 5
Implement:
- restricted proof validator path

## Step 6
Integrate:
- blockchain import branching

## Step 7
Expose:
- RPC and debugging surfaces

## Step 8
Complete:
- integration tests
- negative tests
- telemetry

---

# 30. Migration Strategy

## Recommended rollout
1. keep Phase 2 transfer proof path working
2. add Phase 3 restricted contract proof path behind a feature flag
3. enable only for allowlisted code hashes
4. test on devnet
5. test on internal testnet
6. enable for a tiny contract subset first
7. only later expand proof-eligible contract profiles

---

# 31. Final Summary

Phase 3 is the first point where `gtos` moves beyond transfer-only proof validation and begins proving a limited contract subset.

The key design principle is:

> **Do not prove arbitrary contracts yet. Prove only a tightly restricted, explicitly classified, bounded contract subset.**

To make that work inside the current `gtos` architecture, Phase 3 must add:

- restricted contract proof sidecars
- restricted contract eligibility rules
- restricted execution trace summaries
- restricted committed state diffs
- proof-backed restricted processor path
- proof-backed restricted validator path
- blockchain import branching for restricted proof blocks
- code-hash-based allowlisting for proof-eligible contracts

That is the narrowest realistic Phase 3 path that:
- builds directly on Phase 2
- avoids a premature full zkVM commitment
- is specific enough to implement now
- keeps `gtos` moving toward a real Gigagas L1 architecture

---

## Related Documents

- [Gigagas L1 Roadmap](./gtos_gigagas_l1_roadmap.md)
- [Phase 2 Design: Proof-Backed Transfer Validation](./gtos_gigagas_l1_phase2_proof_backed_transfer_validation.md)
- [Phase 3 File-by-File Coding Checklist](./gtos_gigagas_l1_phase3_coding_checklist.md)
- [Phase 4 Design: Hot-Path Proof-Native Validation](./gtos_gigagas_l1_phase4_hotpath_proof_native_validation.md)
