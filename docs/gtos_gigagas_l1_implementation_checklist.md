# gtos Gigagas L1 — Phase 1 Implementation Checklist
## Native-Transfer Batch-Proof Pipeline

## Document Purpose

This document translates the earlier patch draft into a **Phase 1 implementation checklist**.

Phase 1 is intentionally narrow. Its purpose is to get `gtos` from:

- proof-capable modules
- classical block execution and validation

to:

- a working **native-transfer batch-proof pipeline**
- proof-aware block assembly
- proof-aware block validation
- proof-aware observability over RPC

Phase 1 explicitly covers only:

- native transfer
- shield
- private transfer
- unshield

Phase 1 explicitly does **not** cover:

- arbitrary LVM / Lua contract proving
- full contract storage proving
- cross-contract call graph proving
- proof-based replacement of all canonical state validation paths

---

# Phase 1 Goals

## Primary Goal
Ship a first end-to-end `native-transfer-batch-v1` path where:

1. a proof-eligible batch is selected
2. execution emits a canonical batch witness
3. a dedicated proof worker generates a batch proof
4. block metadata carries proof commitments
5. validators can verify the proof path
6. RPC can expose batch-proof information

## Success Criteria
Phase 1 is complete when all of the following are true:

- proof-eligible transfer batches can be built by the miner
- the node can export a deterministic witness for those batches
- the proof worker can accept the witness and return a proof artifact
- proof metadata is attached to a block object
- validators can verify `native-transfer-batch-v1` blocks without replaying the full proof-covered batch
- RPC clients can inspect proof metadata and per-transaction proof status
- classical non-proof blocks still work unchanged

---

# Phase 1 Boundaries

## Included
- proof-aware types
- proof artifact model
- batch witness model
- transfer-only trace model
- proof worker daemon
- miner orchestration for proof-eligible batches
- validator proof-path branch
- proof-aware RPC endpoints
- txpool / miner proof-fast-path classification

## Excluded
- general-purpose zkVM
- full LVM trace proving
- arbitrary contract receipts under proof mode
- forced consensus switch to proof-only validation
- replacement of existing canonical state root logic

---

# Recommended Delivery Order

The recommended delivery order is:

1. **Type skeleton**
2. **Witness export**
3. **Trace and batch normalization**
4. **Proof artifact format**
5. **Proof worker daemon**
6. **Miner orchestration**
7. **Validator proof path**
8. **RPC visibility**
9. **Integration, test vectors, and hardening**

---

# Checklist by Workstream

## Workstream A — Type and Data Model Foundation

### A1. Add proof artifact core types
**Files**
- `core/types/proof.go`

**Checklist**
- [ ] Define `ProofArtifact`
- [ ] Define `ProofPublicInputs`
- [ ] Define `ProofProvenance`
- [ ] Define `CircuitVersion`
- [ ] Define `ProofArtifactDigest`
- [ ] Add serialization helpers
- [ ] Add deterministic digest helper
- [ ] Add version fields from day one

**Exit criteria**
- [ ] Artifact objects can be serialized and deserialized deterministically
- [ ] Artifact hash is stable across repeated runs
- [ ] Unit tests cover round-trip encoding

---

### A2. Add block-header proof metadata model
**Files**
- `core/types/proof_header.go`
- `core/types/block.go`

**Checklist**
- [ ] Define `BatchProofHeaderFields`
- [ ] Define `ProofMode`
- [ ] Define `ProofVersion`
- [ ] Add header helpers such as `HasBatchProof()`
- [ ] Decide whether Phase 1 uses explicit header fields or sidecar carriage
- [ ] Update hash / encoding behavior consistently
- [ ] Regenerate JSON / RLP code if needed

**Exit criteria**
- [ ] A block can carry proof-mode metadata
- [ ] Header encoding and decoding remains stable
- [ ] Existing non-proof blocks still decode unchanged

---

### A3. Add receipt-level proof metadata
**Files**
- `core/types/proof_receipt.go`
- `core/types/receipt.go`
- `core/types/transaction.go`

**Checklist**
- [ ] Define `ProofReceiptMeta`
- [ ] Define `ProofCoverageClass`
- [ ] Define `BatchReceiptRef`
- [ ] Add `ProofCovered` or equivalent flag to receipt implementation fields
- [ ] Add batch index metadata
- [ ] Add trace digest field
- [ ] Add transaction helper `IsProofFastPath()`
- [ ] Add transaction helper `ProofClass()`

**Exit criteria**
- [ ] Receipts can express proof coverage for proof-backed transfers
- [ ] Transactions can be classified into proof-fast-path vs legacy-path
- [ ] Existing receipt persistence remains backward-compatible

---

## Workstream B — State Witness Export

### B1. Add witness model
**Files**
- `core/state/batch_witness.go`
- `core/state/witness_encoder.go`

**Checklist**
- [ ] Define `BatchWitness`
- [ ] Define account-level witness entry types
- [ ] Define storage-level witness entry types
- [ ] Define privacy-state witness entry types
- [ ] Define deterministic ordering rules
- [ ] Add canonical serialization format
- [ ] Add witness hash helper

**Exit criteria**
- [ ] Witnesses are deterministic for identical execution
- [ ] Witness encoding is stable across repeated runs
- [ ] Witness hash matches across nodes given identical state and tx batch

---

### B2. Instrument `StateDB` for witness collection
**Files**
- `core/state/statedb.go`
- `core/state/journal.go`
- `core/state/state_object.go`

**Checklist**
- [ ] Add `witnessCollector` field to `StateDB`
- [ ] Add `EnableBatchWitness()`
- [ ] Add `DisableBatchWitness()`
- [ ] Add `ExportBatchWitness()`
- [ ] Instrument balance mutation
- [ ] Instrument nonce mutation
- [ ] Instrument code hash mutation
- [ ] Instrument storage writes
- [ ] Instrument private-state writes
- [ ] Ensure revert / snapshot semantics keep witness state consistent

**Exit criteria**
- [ ] Every proof-covered tx produces witness deltas
- [ ] Reverted writes do not leak into final witness
- [ ] Batch witness exports successfully from a real execution path

---

### B3. Add proof-oriented state commitment helpers
**Files**
- `core/state/proof_root.go`
- `core/state/proof_commitment.go`

**Checklist**
- [ ] Define `ProofStateCommitment`
- [ ] Define `BatchCommitmentInputs`
- [ ] Define `ProofCommitmentSet`
- [ ] Implement pre-state commitment builder
- [ ] Implement post-state commitment builder
- [ ] Implement batch tx commitment builder
- [ ] Implement witness commitment builder

**Exit criteria**
- [ ] Pre/post commitments can be generated for a proof batch
- [ ] Commitments remain deterministic across repeated runs
- [ ] Commitments can be attached to proof artifacts and headers

---

## Workstream C — Execution Trace and Batch Semantics

### C1. Add transfer-only trace model
**Files**
- `core/vm/trace_types.go`
- `core/vm/trace_transfer.go`

**Checklist**
- [ ] Define `TransferTrace`
- [ ] Define `TransferTraceEntry`
- [ ] Define `FeeTraceEntry`
- [ ] Define `PrivTraceEntry`
- [ ] Define `TransferTraceBatch`
- [ ] Add deterministic ordering rules
- [ ] Add serialization / digest helper

**Exit criteria**
- [ ] Trace objects can represent all proof-covered Phase 1 transaction classes
- [ ] Trace output is deterministic across repeated runs

---

### C2. Emit trace from native and privacy execution
**Files**
- `core/state_transition.go`
- current tx execution entry file
- privacy execution entry points under `core/priv/`

**Checklist**
- [ ] Add trace emitter plumbing into execution context
- [ ] Emit native transfer events
- [ ] Emit fee debit / credit events
- [ ] Emit shield events
- [ ] Emit private transfer events
- [ ] Emit unshield events
- [ ] Emit tx begin / tx end markers
- [ ] Emit status / gas-used summary per tx

**Exit criteria**
- [ ] A proof-covered transfer batch yields a full deterministic execution trace
- [ ] Trace matches receipt and witness output for the same batch

---

### C3. Normalize privacy events into batch semantics
**Files**
- `core/priv/batch_events.go`
- `core/priv/batch_normalizer.go`
- `core/priv/prover.go`
- `core/priv/verify.go`

**Checklist**
- [ ] Define batch-visible privacy event types
- [ ] Add normalizer for `ShieldTx`
- [ ] Add normalizer for `PrivTransferTx`
- [ ] Add normalizer for `UnshieldTx`
- [ ] Keep single-tx prover APIs intact
- [ ] Add batch-oriented adapters alongside existing APIs

**Exit criteria**
- [ ] Privacy txs can be represented as uniform batch events
- [ ] Batch normalizer output is stable and compatible with witness + trace data

---

## Workstream D — Proof Worker and Artifact Flow

### D1. Add proof worker daemon shell
**Files**
- `cmd/tosproofd/main.go`
- `proofworker/config.go`
- `proofworker/service.go`
- `proofworker/server.go`
- `proofworker/client.go`

**Checklist**
- [ ] Create daemon bootstrap
- [ ] Define worker config
- [ ] Define request / response model
- [ ] Choose IPC transport for Phase 1
- [ ] Add client library for node-side calls
- [ ] Add timeout handling
- [ ] Add proof-mode / version negotiation fields
- [ ] Add health endpoint or ping method

**Exit criteria**
- [ ] The node can send a proof request to the worker
- [ ] The worker returns a structured response
- [ ] Transport failures are handled cleanly

---

### D2. Add canonical proof artifact handling
**Files**
- `proofworker/artifact.go`
- `core/types/proof.go`

**Checklist**
- [ ] Implement artifact encode / decode
- [ ] Implement artifact digest
- [ ] Include proof type
- [ ] Include proof version
- [ ] Include circuit version
- [ ] Include pre/post commitments
- [ ] Include tx commitment
- [ ] Include witness commitment
- [ ] Include public inputs
- [ ] Include proving metadata

**Exit criteria**
- [ ] Proof artifacts round-trip through encode / decode
- [ ] Miner, validator, and RPC can all use the same artifact structure

---

### D3. Implement a Phase 1 transfer-batch prover stub, then real prover integration
**Files**
- `proofworker/service.go`
- prover backend integration files as needed

**Checklist**
- [ ] Add stub prover mode for integration testing
- [ ] Add deterministic fake proof mode for CI
- [ ] Add real transfer-batch prover integration
- [ ] Verify response schema remains identical between stub and real mode

**Exit criteria**
- [ ] CI can exercise full pipeline with stub proofs
- [ ] Real prover can be plugged in without changing node-side protocol

---

## Workstream E — Miner / Block Integration

### E1. Add proof-batch selection and orchestration
**Files**
- `miner/proof_batch.go`
- `miner/proof_orchestrator.go`
- `miner/worker.go`

**Checklist**
- [ ] Define `ProofEligibleBatch`
- [ ] Define `ProofAssemblyResult`
- [ ] Define `ProofBuildContext`
- [ ] Add proof-eligible batch selection
- [ ] Exclude unsupported tx classes from proof path
- [ ] Execute proof-covered batch
- [ ] Export witness after execution
- [ ] Compute commitments
- [ ] Invoke proof worker
- [ ] Attach proof result to block assembly state

**Exit criteria**
- [ ] Miner can build a `native-transfer-batch-v1` candidate
- [ ] The batch produces witness + commitments + proof artifact before sealing

---

### E2. Integrate proof metadata into final block assembly
**Files**
- `miner/worker.go`
- `core/types/block.go`

**Checklist**
- [ ] Attach proof metadata to header or sidecar
- [ ] Persist batch commitments
- [ ] Persist proof hash / artifact reference
- [ ] Preserve compatibility for legacy non-proof blocks
- [ ] Update logging to indicate proof-backed block creation

**Exit criteria**
- [ ] Finalized block object contains proof metadata when applicable
- [ ] Non-proof blocks remain unaffected

---

### E3. Add proof-fast-path tx classification to miner flow
**Files**
- `core/types/proof_class.go`
- txpool admission file
- `miner/worker.go`

**Checklist**
- [ ] Define proof admission enum
- [ ] Classify native transfer
- [ ] Classify shield
- [ ] Classify private transfer
- [ ] Classify unshield
- [ ] Mark all other txs as legacy-path or deferred
- [ ] Ensure miner can prioritize proof-eligible transfer batches

**Exit criteria**
- [ ] Miner can separate proof-fast-path txs from legacy-path txs
- [ ] Unsupported txs do not break proof-batch assembly

---

## Workstream F — Validator Integration

### F1. Add proof verification branch
**Files**
- `core/block_validator_proof.go`
- `core/block_validator.go`

**Checklist**
- [ ] Define `ProofValidationInputs`
- [ ] Define `ProofValidationResult`
- [ ] Define `BatchProofVerifier` interface
- [ ] Implement `native-transfer-batch-v1` proof validation
- [ ] Verify public inputs
- [ ] Verify tx commitment
- [ ] Verify witness commitment
- [ ] Verify proof metadata consistency with header
- [ ] Keep legacy validation path unchanged

**Exit criteria**
- [ ] Validator accepts valid proof-backed transfer blocks
- [ ] Validator rejects malformed proof-backed transfer blocks
- [ ] Legacy blocks still validate unchanged

---

### F2. Add safe fallback and feature gating
**Files**
- `core/block_validator.go`
- chain config / feature gating files

**Checklist**
- [ ] Add feature flag or chain-config gate for proof validation
- [ ] Support networks with proof path disabled
- [ ] Support mixed legacy and proof-backed blocks in Phase 1
- [ ] Make validation failure logs explicit and debuggable

**Exit criteria**
- [ ] Proof mode can be enabled or disabled safely
- [ ] Networks can upgrade incrementally

---

## Workstream G — RPC and Observability

### G1. Add proof-aware RPC endpoints
**Files**
- `internal/tosapi/proof_api.go`
- `internal/tosapi/api.go`

**Checklist**
- [ ] Add `tos_getBatchProof`
- [ ] Add `tos_getBatchProofMetadata`
- [ ] Add `tos_getBatchPublicInputs`
- [ ] Add `tos_getTransactionProofStatus`
- [ ] Add backend interface methods needed by these APIs
- [ ] Add nil / not-found behavior consistent with existing RPC conventions

**Exit criteria**
- [ ] External clients can query proof metadata for a block or batch
- [ ] External clients can query proof status for an individual tx

---

### G2. Expose proof metadata in block and receipt responses
**Files**
- `internal/tosapi/api.go`

**Checklist**
- [ ] Extend `RPCMarshalHeader`
- [ ] Extend `RPCMarshalBlock`
- [ ] Extend `GetTransactionReceipt`
- [ ] Add proof fields only when present
- [ ] Preserve existing JSON shape for non-proof responses

**Exit criteria**
- [ ] Proof-backed blocks show proof metadata over standard RPC calls
- [ ] Proof-covered tx receipts expose proof status and batch index

---

## Workstream H — Testing and Hardening

### H1. Unit tests for data-model determinism
**Checklist**
- [ ] Test proof artifact round-trip encoding
- [ ] Test witness determinism
- [ ] Test transfer trace determinism
- [ ] Test commitment determinism
- [ ] Test receipt proof metadata persistence

**Exit criteria**
- [ ] Determinism tests pass consistently

---

### H2. Integration tests for end-to-end proof pipeline
**Checklist**
- [ ] Build integration test with native transfer batch
- [ ] Build integration test with shield batch
- [ ] Build integration test with private transfer batch
- [ ] Build integration test with unshield batch
- [ ] Build mixed transfer batch test
- [ ] Validate block assembly -> proof worker -> validation path
- [ ] Run same tests in stub-proof mode and real-proof mode

**Exit criteria**
- [ ] End-to-end proof-backed transfer blocks work in automated tests

---

### H3. Negative tests
**Checklist**
- [ ] Invalid proof bytes
- [ ] Wrong pre-state root
- [ ] Wrong post-state root
- [ ] Wrong witness commitment
- [ ] Wrong tx commitment
- [ ] Header/proof mismatch
- [ ] Receipt/proof mismatch
- [ ] Unsupported tx mistakenly included in proof batch

**Exit criteria**
- [ ] Validator rejects all malformed proof-backed cases

---

### H4. Operational hardening
**Checklist**
- [ ] Add metrics for proof request count
- [ ] Add metrics for proof generation latency
- [ ] Add metrics for proof verification latency
- [ ] Add metrics for proof-batch size
- [ ] Add logs for proof worker failures
- [ ] Add retry / timeout policy
- [ ] Add bounded queueing so miner does not deadlock

**Exit criteria**
- [ ] Proof path is observable and debuggable in staging

---

# Milestone-Based Execution Plan

## Milestone 1 — Type Skeleton
Complete:
- A1
- A2
- A3

**Milestone exit**
- proof-aware types compile
- tests for type encoding pass

---

## Milestone 2 — Witness and Trace
Complete:
- B1
- B2
- B3
- C1
- C2
- C3

**Milestone exit**
- proof-covered transfer execution emits stable witness + trace + commitments

---

## Milestone 3 — Proof Worker
Complete:
- D1
- D2
- D3

**Milestone exit**
- proof worker accepts a batch request and returns a valid artifact structure

---

## Milestone 4 — Miner Integration
Complete:
- E1
- E2
- E3

**Milestone exit**
- miner can produce a proof-backed transfer block candidate

---

## Milestone 5 — Validator Integration
Complete:
- F1
- F2

**Milestone exit**
- validator can accept or reject proof-backed transfer blocks correctly

---

## Milestone 6 — RPC and External Visibility
Complete:
- G1
- G2

**Milestone exit**
- wallets, explorers, and tooling can inspect proof-backed batches and txs

---

## Milestone 7 — Full Phase 1 Hardening
Complete:
- H1
- H2
- H3
- H4

**Milestone exit**
- Phase 1 is ready for controlled staging rollout

---

# Phase 1 Risks

## Risk 1 — Witness nondeterminism
If witness emission depends on map iteration or non-canonical state traversal, proofs will be unstable.

**Mitigation**
- sort all witness entries deterministically
- hash-test repeated executions

## Risk 2 — Revert mismatch between execution and witness
If reverted writes leak into the witness, proof verification will fail or prove the wrong transition.

**Mitigation**
- bind witness lifecycle to journal / snapshot semantics
- add revert-focused tests early

## Risk 3 — Proof worker latency stalls block production
If proof generation is synchronous and slow, miner performance collapses.

**Mitigation**
- start with bounded batches
- add timeout and fallback behavior
- keep classical path alive

## Risk 4 — Header / artifact version drift
If block metadata and proof artifact schemas evolve independently, the pipeline fragments.

**Mitigation**
- enforce version fields in all proof objects
- centralize artifact model in `core/types`

## Risk 5 — Scope creep into full contract proving
Trying to include arbitrary LVM execution in Phase 1 will delay delivery significantly.

**Mitigation**
- keep Phase 1 transfer-only
- defer full contract proving to Phase 2+

---

# Phase 1 Final Deliverables

Phase 1 should end with the following concrete deliverables:

- [ ] Proof-aware block and receipt type extensions
- [ ] Canonical batch witness model
- [ ] Canonical transfer-only trace model
- [ ] Proof-friendly batch commitments
- [ ] Dedicated `tosproofd` worker daemon
- [ ] Proof artifact schema shared across node and worker
- [ ] Miner support for proof-backed transfer batches
- [ ] Validator support for `native-transfer-batch-v1`
- [ ] RPC endpoints for proof inspection
- [ ] End-to-end tests and negative tests
- [ ] Metrics and logs for proof pipeline observability

---

# Final Summary

Phase 1 is successful if `gtos` can produce, transport, validate, and expose a **proof-backed native-transfer batch block** without trying to solve full smart-contract proving yet.

That is the correct first step toward a Gigagas L1 architecture:

- narrow enough to ship
- meaningful enough to change the node architecture
- compatible with future expansion toward restricted-contract and then full-contract proof coverage
