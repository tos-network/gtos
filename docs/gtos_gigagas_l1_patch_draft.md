# gtos Gigagas L1 Patch Draft
## File-Level Patch Plan for the 12 Native-Transfer Batch-Proof Modules

## Scope

This document is a **file-level patch draft** for the first Gigagas-oriented milestone in `gtos`:

- native transfer
- shield
- private transfer
- unshield

It is intentionally scoped to a **zk-native-transfer batch proof pipeline** and does **not** include full arbitrary LVM/Lua smart-contract proving yet.

The goal is to move `gtos` from a classical execution-and-root-validation flow toward a model where:

- the executor emits a canonical batch witness
- a proof worker generates a batch state-transition proof
- the block header carries proof metadata
- validators verify the proof and public inputs instead of replaying the full batch

This draft is grounded against the current code layout, including:

- `core/block_validator.go`
- `miner/worker.go`
- `core/types/block.go`
- `core/types/receipt.go`
- `internal/tosapi/api.go`

---

# 1. core/state

## Module 1 — Batch Witness Export Layer

### Purpose
Extend state execution so the proving pipeline receives a deterministic witness directly from execution, instead of reconstructing touched state after the fact.

### New files
- `core/state/batch_witness.go`
- `core/state/witness_encoder.go`

### Modified files
- `core/state/statedb.go`
- `core/state/journal.go`
- `core/state/state_object.go`

### New structs
- `BatchWitness`
- `BatchWitnessAccountEntry`
- `BatchWitnessStorageEntry`
- `BatchWitnessPrivEntry`
- `WitnessWriteKind`
- `WitnessExportOptions`

### New interfaces
- `type WitnessCollector interface {`
  - `OnAccountTouched(addr common.Address)`
  - `OnBalanceChange(addr common.Address, pre, post *big.Int)`
  - `OnNonceChange(addr common.Address, pre, post uint64)`
  - `OnCodeHashChange(addr common.Address, pre, post common.Hash)`
  - `OnStorageChange(addr common.Address, key common.Hash, pre, post common.Hash)`
  - `OnPrivStateChange(addr common.Address, key common.Hash, pre, post []byte)`
  - `Finalize() *BatchWitness`
  - `}`

### Patch sketch
#### `core/state/batch_witness.go`
Add the canonical witness model used by the proof worker:
- batch-level metadata
- touched accounts
- pre/post state fragments
- priv-specific deltas
- deterministic ordering guarantees

#### `core/state/witness_encoder.go`
Add:
- canonical serialization
- hash / digest helpers
- deterministic sorting rules
- optional compact encoding for IPC to proof workers

#### `core/state/statedb.go`
Add fields to `StateDB`:
- `witnessCollector WitnessCollector`
- `witnessEnabled bool`

Add methods:
- `EnableBatchWitness(collector WitnessCollector)`
- `DisableBatchWitness()`
- `ExportBatchWitness() *BatchWitness`

Instrument:
- `SetBalance`
- `SetNonce`
- `SetCode`
- `SetState`
- relevant private-state setters / mutators

#### `core/state/journal.go`
Extend journal entries so reverted writes can also revert witness state if needed.

#### `core/state/state_object.go`
Hook account-level state changes into witness collection with pre/post capture.

---

## Module 2 — Proof-Friendly State Commitment Layer

### Purpose
Introduce a proof-oriented commitment model parallel to the classical canonical root.

### New files
- `core/state/proof_root.go`
- `core/state/proof_commitment.go`

### Modified files
- `core/state/statedb.go`
- `core/block_validator.go`
- `miner/worker.go`

### New structs
- `ProofStateCommitment`
- `BatchCommitmentInputs`
- `ProofCommitmentSet`

### New interfaces
- `type ProofCommitmentBuilder interface {`
  - `BuildPreStateCommitment(st *StateDB) (common.Hash, error)`
  - `BuildPostStateCommitment(st *StateDB) (common.Hash, error)`
  - `BuildBatchTxCommitment(txs types.Transactions) (common.Hash, error)`
  - `BuildWitnessCommitment(w *BatchWitness) (common.Hash, error)`
  - `}`

### Patch sketch
#### `core/state/proof_root.go`
Add logic to compute:
- `PreStateRoot`
- `PostStateRoot`
- `BatchTxCommitment`
- `BatchWitnessCommitment`

#### `core/state/proof_commitment.go`
Add canonical commitment rules and proof-mode versioning.

#### `core/state/statedb.go`
Add helpers to derive proof commitments from the active execution state.

#### `core/block_validator.go`
Add proof commitment validation path without removing existing root validation yet.

#### `miner/worker.go`
Compute and carry proof commitments during proof-eligible block assembly.

---

# 2. core/vm

## Module 3 — Native / Privacy Transfer Trace Emitter

### Purpose
Produce a deterministic execution trace for transfer-only proving without pulling in full arbitrary contract semantics.

### New files
- `core/vm/trace_transfer.go`
- `core/vm/trace_types.go`

### Modified files
- `core/state_transition.go`
- `core/tx_processor.go` or the current transaction execution entry file
- `core/vm/evm.go` or equivalent VM/block-context bridge where transfer semantics are wired
- privacy execution entry points under `core/priv/`

### New structs
- `TransferTrace`
- `TransferTraceEntry`
- `FeeTraceEntry`
- `PrivTraceEntry`
- `TransferTraceBatch`

### New interfaces
- `type TransferTraceEmitter interface {`
  - `BeginTx(txHash common.Hash, txType uint8)`
  - `OnNativeTransfer(from, to common.Address, amount *big.Int)`
  - `OnShield(from common.Address, recipient [32]byte, amount uint64)`
  - `OnPrivTransfer(from, to common.Address, sourceCommitment [32]byte, commitment [32]byte)`
  - `OnUnshield(from common.Address, recipient common.Address, amount uint64)`
  - `OnFee(from common.Address, amount *big.Int)`
  - `EndTx(status uint64, gasUsed uint64)`
  - `Finalize() *TransferTraceBatch`
  - `}`

### Patch sketch
#### `core/vm/trace_types.go`
Define transfer-only trace events and canonical ordering.

#### `core/vm/trace_transfer.go`
Implement trace capture for:
- native balance movements
- fee debits / credits
- privacy transfer lifecycle events

#### `core/state_transition.go`
Emit trace events during message / transfer application.

#### privacy execution path
Bridge `ShieldTx`, `PrivTransferTx`, and `UnshieldTx` processing into the trace emitter.

---

## Module 4 — Unified Batch Event Model for Privacy Operations

### Purpose
Lift privacy operations from single-tx proof helpers into first-class batch semantics.

### New files
- `core/priv/batch_events.go`
- `core/priv/batch_normalizer.go`

### Modified files
- `core/priv/prover.go`
- `core/priv/verify.go`
- `core/priv/state.go`
- tx execution path that applies privacy transactions

### New structs
- `PrivBatchEvent`
- `ShieldAppliedEvent`
- `PrivTransferAppliedEvent`
- `UnshieldAppliedEvent`
- `PrivFeeAppliedEvent`
- `PrivNonceAdvancedEvent`

### New interfaces
- `type PrivBatchNormalizer interface {`
  - `NormalizeShield(tx *types.Transaction) (*ShieldAppliedEvent, error)`
  - `NormalizePrivTransfer(tx *types.Transaction) (*PrivTransferAppliedEvent, error)`
  - `NormalizeUnshield(tx *types.Transaction) (*UnshieldAppliedEvent, error)`
  - `}`

### Patch sketch
#### `core/priv/batch_events.go`
Define batch-visible privacy event types.

#### `core/priv/batch_normalizer.go`
Turn existing tx-local privacy execution facts into batch event objects.

#### `core/priv/prover.go`
Keep single-tx proving helpers, but expose batch-oriented event extraction APIs alongside them.

#### `core/priv/verify.go`
Add batch validation helpers for normalized privacy events.

---

# 3. core/types

## Module 5 — Extend Block Header with Batch-Proof Metadata

### Purpose
Make proof metadata part of the block object model.

### New files
- `core/types/proof_header.go`

### Modified files
- `core/types/block.go`
- `core/types/gen_header_json.go` (regenerated)
- `core/types/gen_header_rlp.go` (regenerated)
- any header hashing / marshalling tests

### New structs
- `BatchProofHeaderFields`
- `ProofMode`
- `ProofVersion`

### New interfaces
None required at this layer.

### Patch sketch
#### `core/types/proof_header.go`
Define proof metadata fields and helpers:
- `ProofType`
- `ProofVersion`
- `BatchProofHash`
- `BatchPublicInputsHash`
- `BatchTxCommitment`
- `BatchWitnessCommitment`

#### `core/types/block.go`
Option A:
- add proof fields directly to `Header`

Option B:
- add a proof sidecar header object referenced from `Header.Extra`

Recommended first patch:
- use explicit fields if you are comfortable regenerating RLP/JSON types now
- otherwise stage through sidecar support first

Also add methods:
- `func (h *Header) HasBatchProof() bool`
- `func (h *Header) BatchProofType() string`

---

## Module 6 — Extend Transaction / Receipt Types for Proof Coverage

### Purpose
Expose proof coverage at the transaction and receipt layers so RPC, tooling, and validators can reason about proof-native execution.

### New files
- `core/types/proof_receipt.go`

### Modified files
- `core/types/receipt.go`
- `core/types/transaction.go`
- any tx type switch helpers
- receipt derivation helpers

### New structs
- `ProofReceiptMeta`
- `ProofCoverageClass`
- `BatchReceiptRef`

### New interfaces
None required.

### Patch sketch
#### `core/types/proof_receipt.go`
Define:
- proof coverage class
- proof-covered flag
- batch index
- trace digest
- proof reference hash

#### `core/types/receipt.go`
Add optional fields to `Receipt`:
- `ProofCovered bool`
- `ProofBatchIndex uint32`
- `ProofTraceDigest common.Hash`
- `ProofType string`

These can be implementation-layer fields, not consensus fields in phase one.

#### `core/types/transaction.go`
Add helpers:
- `func (tx *Transaction) IsProofFastPath() bool`
- `func (tx *Transaction) ProofClass() ProofCoverageClass`

Classify:
- native transfer
- shield
- private transfer
- unshield
as proof-eligible in phase one.

---

# 4. miner / block

## Module 7 — Two-Phase Block Assembly in the Miner

### Purpose
Refactor block production so proof-eligible batches are executed, witnessed, proved, and then assembled into a block.

### New files
- `miner/proof_batch.go`
- `miner/proof_orchestrator.go`

### Modified files
- `miner/worker.go`

### New structs
- `ProofEligibleBatch`
- `ProofAssemblyResult`
- `ProofBuildContext`

### New interfaces
- `type BatchProofOrchestrator interface {`
  - `BuildEligibleBatch(env *environment) (*ProofEligibleBatch, error)`
  - `ExecuteBatch(env *environment, batch *ProofEligibleBatch) error`
  - `ExportWitness(env *environment) (*state.BatchWitness, error)`
  - `RequestProof(batch *ProofEligibleBatch) (*ProofAssemblyResult, error)`
  - `}`

### Patch sketch
#### `miner/proof_batch.go`
Introduce:
- proof-eligible tx selection
- batch boundary rules
- proof fast-path exclusion logic

#### `miner/proof_orchestrator.go`
Add orchestration logic for:
- execute batch
- collect witness
- compute commitments
- call proof worker
- attach proof artifact back to block assembly

#### `miner/worker.go`
Refactor:
- `fillTransactions`
- `generateWork`
- `commitWork`
- `commit`

Add a new path:
- build proof-eligible batch
- execute batch
- export witness
- request proof
- attach proof metadata to header / block
- continue seal flow

Do not remove classical path yet.

---

## Module 8 — Proof-Based Block Validation Path

### Purpose
Add validator logic for proof-backed transfer batches.

### New files
- `core/block_validator_proof.go`

### Modified files
- `core/block_validator.go`

### New structs
- `ProofValidationResult`
- `ProofValidationInputs`

### New interfaces
- `type BatchProofVerifier interface {`
  - `VerifyTransferBatchProof(inputs *ProofValidationInputs) error`
  - `}`

### Patch sketch
#### `core/block_validator_proof.go`
Implement:
- proof-path validation
- commitment checks
- public input checks
- proof mode dispatch

#### `core/block_validator.go`
Split validation:
- legacy `ValidateState`
- proof-aware `ValidateStateWithProof`

Suggested branching:
- if header has no batch proof -> existing path
- if header proof type is `native-transfer-batch-v1` -> proof validation path

---

# 5. rpc

## Module 9 — Proof-Aware RPC Query Surface

### Purpose
Expose proof-native block metadata and transaction proof status to external systems.

### New files
- `internal/tosapi/proof_api.go`

### Modified files
- `internal/tosapi/api.go`
- RPC service registration file if APIs are registered elsewhere
- block / receipt marshalling helpers

### New structs
- `RPCBatchProof`
- `RPCBatchProofMeta`
- `RPCTransactionProofStatus`
- `RPCBatchPublicInputs`

### New interfaces
- `type ProofQueryBackend interface {`
  - `GetBatchProof(ctx context.Context, batchHash common.Hash) ([]byte, error)`
  - `GetBatchProofMeta(ctx context.Context, batchHash common.Hash) (*types.BatchProofHeaderFields, error)`
  - `GetTransactionProofStatus(ctx context.Context, txHash common.Hash) (*types.ProofReceiptMeta, error)`
  - `}`

### Patch sketch
#### `internal/tosapi/proof_api.go`
Add RPCs such as:
- `tos_getBatchProof`
- `tos_getBatchProofMetadata`
- `tos_getBatchPublicInputs`
- `tos_getTransactionProofStatus`

#### `internal/tosapi/api.go`
Update block / receipt marshalling to include proof metadata when present.

Also update:
- `GetTransactionReceipt`
- `RPCMarshalHeader`
- `RPCMarshalBlock`

so proof-backed blocks and txs are visible over RPC.

---

## Module 10 — Proof Eligibility and Batch Admission in Send Path / TxPool

### Purpose
Classify proof-fast-path transactions at admission time.

### New files
- `core/types/proof_class.go`
- `core/txpool/proof_admission.go` or equivalent txpool path file

### Modified files
- `internal/tosapi/api.go`
- txpool admission / validation files
- miner tx selection code in `miner/worker.go`

### New structs
- `ProofAdmissionClass`
- `ProofEligibilityResult`

### New interfaces
- `type ProofEligibilityDecider interface {`
  - `Classify(tx *types.Transaction) ProofAdmissionClass`
  - `}`

### Patch sketch
#### `core/types/proof_class.go`
Define the tx classification enum:
- `ProofFastPath`
- `LegacyPath`
- `ProofDeferred`

#### txpool proof admission file
Classify incoming txs and attach metadata used later by the miner.

#### `internal/tosapi/api.go`
Optionally expose proof eligibility in transaction result objects for debugging / tooling.

#### `miner/worker.go`
Use proof class during selection:
- build proof-eligible transfer batches first
- leave unsupported txs in the classical path

---

# 6. proof worker

## Module 11 — Dedicated Batch Prover Worker

### Purpose
Move proving out of the node hot path into a dedicated process.

### New files
- `cmd/tosproofd/main.go`
- `proofworker/service.go`
- `proofworker/server.go`
- `proofworker/client.go`
- `proofworker/config.go`

### Modified files
- `miner/worker.go`
- privacy prover integration points if reused
- node config / CLI wiring files

### New structs
- `ProofWorkerRequest`
- `ProofWorkerResponse`
- `ProofWorkerConfig`
- `TransferBatchProverService`

### New interfaces
- `type TransferBatchProver interface {`
  - `Prove(req *ProofWorkerRequest) (*ProofWorkerResponse, error)`
  - `}`
- `type ProofWorkerClient interface {`
  - `RequestTransferBatchProof(req *ProofWorkerRequest) (*ProofWorkerResponse, error)`
  - `}`

### Patch sketch
#### `cmd/tosproofd/main.go`
Add standalone daemon bootstrap.

#### `proofworker/service.go`
Implement proof request lifecycle.

#### `proofworker/server.go`
Expose IPC / gRPC / unix socket / HTTP endpoint for proving requests.

#### `proofworker/client.go`
Add node-side client used by the miner.

#### `proofworker/config.go`
Add configuration for:
- endpoint
- timeout
- max batch size
- proof mode / circuit version

#### `miner/worker.go`
Invoke proof worker after batch execution and witness export.

---

## Module 12 — Standardized Proof Artifact Format

### Purpose
Create a stable artifact shared by builder, prover, validator, and RPC.

### New files
- `core/types/proof.go`
- `proofworker/artifact.go`

### Modified files
- `miner/worker.go`
- `core/block_validator_proof.go`
- `internal/tosapi/proof_api.go`

### New structs
- `ProofArtifact`
- `ProofPublicInputs`
- `ProofArtifactDigest`
- `CircuitVersion`
- `ProofProvenance`

### New interfaces
- `type ProofArtifactCodec interface {`
  - `Encode(*ProofArtifact) ([]byte, error)`
  - `Decode([]byte) (*ProofArtifact, error)`
  - `Digest(*ProofArtifact) common.Hash`
  - `}`

### Patch sketch
#### `core/types/proof.go`
Define canonical proof artifact schema:
- proof type
- version
- pre-state root
- post-state root
- tx commitment
- witness commitment
- receipt commitment
- proof bytes
- public inputs
- circuit version
- prover id
- proving time

#### `proofworker/artifact.go`
Implement encoding / decoding / digest helpers.

#### validator / miner / RPC files
Use the same artifact type end-to-end.

---

# Suggested Minimal Patch Order

## Step 1 — Types and artifact skeleton
Implement first:
- `core/types/proof.go`
- `core/types/proof_header.go`
- `core/types/proof_receipt.go`

This gives the rest of the system stable object models.

## Step 2 — State witness export
Implement:
- `core/state/batch_witness.go`
- `core/state/witness_encoder.go`
- instrumentation in `StateDB`

This is the minimum viable proving input.

## Step 3 — Miner orchestration
Implement:
- `miner/proof_batch.go`
- `miner/proof_orchestrator.go`
- `proofworker/client.go`

This gives block builders a proof request path.

## Step 4 — Dedicated proof worker
Implement:
- `cmd/tosproofd/main.go`
- `proofworker/service.go`
- `proofworker/server.go`
- `proofworker/artifact.go`

## Step 5 — Validator proof path
Implement:
- `core/block_validator_proof.go`
- `BatchProofVerifier`

## Step 6 — RPC visibility
Implement:
- `internal/tosapi/proof_api.go`
- proof-aware receipt / block marshalling

---

# Notes on Compatibility Strategy

## Recommendation 1
Do not remove the classical path yet.

Keep:
- legacy block assembly
- legacy validation
- existing state root logic

Add:
- proof-native transfer-only path in parallel

## Recommendation 2
Do not attempt full LVM proving in this patch series.

The first proof-covered transaction classes should remain limited to:
- native transfer
- shield
- private transfer
- unshield

## Recommendation 3
Treat proof metadata as versioned from day one.

Every artifact and header extension should include:
- `proofType`
- `proofVersion`
- `circuitVersion`

This avoids hard-forking internal assumptions too early.

---

# Final Summary

This patch draft turns the earlier 12-module roadmap into a concrete file-level plan.

The most important architectural shift is not “adding more proofs” to existing privacy operations. It is changing the execution pipeline so that:

1. state mutation emits a canonical witness
2. the miner assembles proof-eligible transfer batches
3. a dedicated proof worker proves batch state transitions
4. block headers carry proof metadata
5. validators verify proofs instead of replaying the entire batch
6. RPC exposes proof-native observability

That is the narrowest realistic path from the current `gtos` architecture toward a Gigagas L1 candidate.
