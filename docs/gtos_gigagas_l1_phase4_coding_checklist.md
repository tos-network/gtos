# gtos Phase 4
## File-by-File Coding Checklist
### Majority Hot-Path Execution Enters Proof-Native Validation

## Purpose

This document converts the Phase 4 design into a **file-by-file implementation checklist**.

The scope of Phase 4 is:

- most high-frequency transaction paths become proof-native
- validators verify proofs and materialize post-state instead of replaying most hot-path execution
- proof-native validation covers:
  - transfer-class transactions
  - restricted-contract transactions
  - profiled contract transactions
  - selected package/profile-based execution flows
- validator replay becomes the exception rather than the default

This document is written so the engineering team can implement directly, file by file.

---

# 1. Cross-Cutting Phase 4 Rules

Before touching any file, Phase 4 must respect the following rules:

- **No `Header` changes**
- **No proof metadata inside block hash**
- **Use out-of-band sidecar keyed by canonical block hash**
- **No silent downgrade from proof mode to legacy mode**
- **Proof-native coverage is driven by deterministic hot-path classes and profiles**
- **Most hot-path traffic should enter proof-native validation**
- **Rare or unsupported transactions may remain on legacy fallback path**
- **State diff must still be materialized into a real `StateDB`**
- **All deterministic data structures must use canonical ordering**
- **Proof-native batches must bind exact tx set, exact profile IDs, exact commitments**

---

# 2. New Files and Modified Files Overview

## New files
- `core/types/proof_hotpath_sidecar.go`
- `core/types/proof_hotpath_state_diff.go`
- `core/types/proof_hotpath_trace.go`
- `core/types/proof_hotpath_errors.go`
- `core/types/hotpath_class.go`
- `core/vm/hotpath_profiles.go`
- `core/vm/hotpath_registry.go`
- `core/vm/hotpath_runtime_policy.go`
- `core/vm/hotpath_trace.go`
- `core/state/proof_apply_hotpath.go`
- `core/state_processor_hotpath.go`
- `core/block_validator_hotpath.go`
- `core/rawdb/schema_proof_hotpath.go`
- `core/rawdb/accessors_proof_hotpath.go`
- `miner/hotpath_batch_builder.go`
- `proofworker/hotpath_batch_prover.go`
- `internal/tosapi/proof_hotpath_api.go`

## Modified files
- `core/blockchain.go`
- `core/block_validator.go`
- `core/state_processor.go`
- `core/types/transaction.go`
- `core/types/receipt.go`
- `core/vm/lvm.go`
- `internal/tosapi/api.go`

Optional supporting modifications:
- miner-side Phase 1–3 proof orchestration files
- proof worker artifact persistence files
- profile registry persistence/wiring files
- tests near each modified package

---

# 3. File-by-File Checklist

# 3.1 `core/types/proof_hotpath_sidecar.go`

## Purpose
Define the canonical Phase 4 hot-path proof sidecar.

## Add structs
- [ ] `HotPathBatchSidecar`
- [ ] `HotPathCoveredTxRef`
- [ ] `HotPathBatchProfile`
- [ ] `HotPathSidecarValidationSummary`

## `HotPathBatchSidecar` required fields
- [ ] `BlockHash common.Hash`
- [ ] `ProofType string`
- [ ] `ProofVersion uint32`
- [ ] `CircuitVersion string`
- [ ] `PreStateRoot common.Hash`
- [ ] `PostStateRoot common.Hash`
- [ ] `BatchTxCommitment common.Hash`
- [ ] `WitnessCommitment common.Hash`
- [ ] `TraceCommitment common.Hash`
- [ ] `StateDiffCommitment common.Hash`
- [ ] `ReceiptCommitment common.Hash`
- [ ] `PublicInputsHash common.Hash`
- [ ] `ProofArtifactHash common.Hash`
- [ ] `ProofBytes []byte`
- [ ] `PublicInputs []byte`
- [ ] `CoveredTxs []HotPathCoveredTxRef`
- [ ] `UsedGas uint64`
- [ ] `Receipts []*types.Receipt`
- [ ] `StateDiff *HotPathStateDiff`
- [ ] `TraceSummary *HotPathTraceSummary`
- [ ] `BatchProfile *HotPathBatchProfile`
- [ ] `ProverID string`
- [ ] `ProvingTimeMs uint64`

## `HotPathCoveredTxRef` required fields
- [ ] `TxHash common.Hash`
- [ ] `Index uint32`
- [ ] `TxType uint8`
- [ ] `Class uint8`
- [ ] `ProfileID common.Hash`

## `HotPathBatchProfile` required fields
- [ ] `AllowedClasses []uint8`
- [ ] `MaxRestrictedCallDepth uint8`
- [ ] `MaxStorageReadsPerTx uint32`
- [ ] `MaxStorageWritesPerTx uint32`
- [ ] `MaxLogsPerTx uint32`
- [ ] `MaxProofCoveredTxs uint32`
- [ ] `AllowLegacyTail bool`

## Add methods/helpers
- [ ] `func (s *HotPathBatchSidecar) ValidateBasic() error`
- [ ] `func (s *HotPathBatchSidecar) IsHotPathBatchV1() bool`
- [ ] `func (s *HotPathBatchSidecar) HasProofBytes() bool`

## Validation rules
- [ ] reject zero `BlockHash`
- [ ] reject empty `ProofType`
- [ ] reject nil `StateDiff`
- [ ] reject nil `TraceSummary`
- [ ] reject nil `BatchProfile`
- [ ] reject missing commitments

## Tests
- [ ] sidecar encode/decode round trip
- [ ] `ValidateBasic()` success case
- [ ] `ValidateBasic()` failure cases
- [ ] exact `ProofType == "hotpath-batch-v1"` check

---

# 3.2 `core/types/proof_hotpath_state_diff.go`

## Purpose
Define the materializable post-state diff for hot-path proof blocks.

## Add structs
- [ ] `HotPathStateDiff`
- [ ] `HotPathAccountDiff`
- [ ] `HotPathStorageDiff`
- [ ] `HotPathPrivStateDiff`

## Required fields
### `HotPathStateDiff`
- [ ] `Accounts []HotPathAccountDiff`

### `HotPathAccountDiff`
- [ ] `Address common.Address`
- [ ] `PreNonce uint64`
- [ ] `PostNonce uint64`
- [ ] `PreBalance *big.Int`
- [ ] `PostBalance *big.Int`
- [ ] `StorageDiffs []HotPathStorageDiff`
- [ ] `PrivStateDiffs []HotPathPrivStateDiff`

### `HotPathStorageDiff`
- [ ] `Key common.Hash`
- [ ] `Pre common.Hash`
- [ ] `Post common.Hash`

### `HotPathPrivStateDiff`
- [ ] `Key []byte`
- [ ] `Pre []byte`
- [ ] `Post []byte`

## Add methods/helpers
- [ ] `func (d *HotPathStateDiff) ValidateBasic() error`
- [ ] `func (d *HotPathStateDiff) SortCanonical()`
- [ ] `func (d *HotPathStateDiff) HasDuplicateEntries() error`

## Validation rules
- [ ] duplicate account entries forbidden
- [ ] duplicate storage keys in one account forbidden
- [ ] duplicate private keys in one account forbidden
- [ ] canonical sort enforced
- [ ] nil balances forbidden where declared

## Tests
- [ ] canonical sort determinism
- [ ] duplicate account rejection
- [ ] duplicate storage key rejection
- [ ] duplicate private key rejection
- [ ] valid diff acceptance

---

# 3.3 `core/types/proof_hotpath_trace.go`

## Purpose
Define the canonical hot-path trace summary model.

## Add structs
- [ ] `HotPathTraceSummary`
- [ ] `HotPathTxTraceSummary`

## `HotPathTraceSummary` required fields
- [ ] `TxTraces []HotPathTxTraceSummary`

## `HotPathTxTraceSummary` required fields
- [ ] `TxHash common.Hash`
- [ ] `TxIndex uint32`
- [ ] `Class HotPathClass`
- [ ] `ProfileID common.Hash`
- [ ] `CodeHash common.Hash`
- [ ] `PackageHash common.Hash`
- [ ] `Selector [4]byte`
- [ ] `CallDepth uint8`
- [ ] `InstructionCount uint64`
- [ ] `StorageReadCount uint32`
- [ ] `StorageWriteCount uint32`
- [ ] `LogCount uint32`
- [ ] `Reverted bool`
- [ ] `ReturnDataCommitment common.Hash`

## Add methods/helpers
- [ ] `func (t *HotPathTraceSummary) ValidateBasic() error`
- [ ] `func (t *HotPathTraceSummary) SortCanonical()`
- [ ] `func (t *HotPathTraceSummary) HasForbiddenShape() error`

## Validation rules
- [ ] exact tx trace count matches covered tx count
- [ ] exact class/profile IDs preserved
- [ ] bounded call depth
- [ ] bounded storage read/write count
- [ ] bounded logs
- [ ] no forbidden call shapes

## Tests
- [ ] trace summary encode/decode round trip
- [ ] forbidden call shape rejected
- [ ] deterministic ordering
- [ ] changed trace changes commitment

---

# 3.4 `core/types/proof_hotpath_errors.go`

## Purpose
Define stable Phase 4 error values.

## Add errors
- [ ] `ErrHotPathMissingSidecar`
- [ ] `ErrHotPathUnsupportedType`
- [ ] `ErrHotPathUnsupportedVersion`
- [ ] `ErrHotPathCoveredTxMismatch`
- [ ] `ErrHotPathProfileMismatch`
- [ ] `ErrHotPathTraceCommitmentMismatch`
- [ ] `ErrHotPathWitnessCommitmentMismatch`
- [ ] `ErrHotPathStateDiffCommitmentMismatch`
- [ ] `ErrHotPathReceiptCommitmentMismatch`
- [ ] `ErrHotPathVerificationFailed`
- [ ] `ErrHotPathForbiddenRuntimePrimitive`
- [ ] `ErrHotPathForbiddenCallShape`
- [ ] `ErrHotPathUnsupportedProfile`
- [ ] `ErrHotPathPostStateMismatch`
- [ ] `ErrHotPathStateDiffPreValueMismatch`

## Tests
- [ ] error identity tests
- [ ] processor and validator use consistent errors

---

# 3.5 `core/types/hotpath_class.go`

## Purpose
Define the classification model for Phase 4 hot-path coverage.

## Add enum
- [ ] `HotPathClass`
- [ ] `HotPathUnknown`
- [ ] `HotPathTransfer`
- [ ] `HotPathRestrictedContract`
- [ ] `HotPathProfiledContract`
- [ ] `HotPathPackageCall`
- [ ] `HotPathSystemAssisted`
- [ ] `HotPathLegacyFallback`

## Add helpers
- [ ] `func ParseHotPathClass(...)`
- [ ] `func (c HotPathClass) String() string`

## Tests
- [ ] enum string conversions
- [ ] parse/validation helpers if implemented

---

# 3.6 `core/types/transaction.go`

## Purpose
Extend transaction classification to support Phase 4 hot-path classes and profile IDs.

## Add / extend methods
- [ ] `func (tx *Transaction) HotPathClass(statedb *state.StateDB) HotPathClass`
- [ ] `func (tx *Transaction) IsHotPathCandidate(statedb *state.StateDB) bool`
- [ ] `func (tx *Transaction) HotPathProfileID(statedb *state.StateDB) common.Hash`

## Classification rules
- [ ] transfer-class txs classified as `HotPathTransfer`
- [ ] Phase 3 restricted-proof txs classified as `HotPathRestrictedContract`
- [ ] allowlisted profiled contract txs classified as `HotPathProfiledContract`
- [ ] allowlisted package-call txs classified as `HotPathPackageCall`
- [ ] selected protocol-assisted flows classified as `HotPathSystemAssisted`
- [ ] everything else classified as `HotPathLegacyFallback`

## Tests
- [ ] transfer classification unchanged
- [ ] restricted-contract classification correct
- [ ] profiled contract classification correct
- [ ] package-call classification correct
- [ ] fallback classification correct

---

# 3.7 `core/types/receipt.go`

## Purpose
Attach hot-path metadata to receipts for RPC and tooling.

## Add fields to `Receipt`
Implementation-layer only.

- [ ] `ProofCovered bool`
- [ ] `ProofBatchIndex uint32`
- [ ] `ProofType string`
- [ ] `HotPathClass uint8`
- [ ] `HotPathProfileID common.Hash`

## Add helper methods
- [ ] `func (r *Receipt) MarkHotPathCovered(batchIndex uint32, proofType string, class uint8, profileID common.Hash)`
- [ ] `func (r *Receipt) IsHotPathCovered() bool`

## Persistence decision
- [ ] decide whether to store or derive from sidecar
- [ ] recommended: derive from sidecar at query time where possible

## Tests
- [ ] metadata set correctly
- [ ] legacy receipt encoding unaffected
- [ ] receipt commitment remains canonical

---

# 3.8 `core/vm/hotpath_profiles.go`

## Purpose
Define deterministic hot-path execution profiles.

## Add struct
- [ ] `HotPathExecutionProfile`

## Required fields
- [ ] `ID common.Hash`
- [ ] `Class HotPathClass`
- [ ] `CodeHash common.Hash`
- [ ] `PackageHash common.Hash`
- [ ] `Selector [4]byte`
- [ ] `MaxCallDepth uint8`
- [ ] `MaxInstructions uint64`
- [ ] `MaxStorageReads uint32`
- [ ] `MaxStorageWrites uint32`
- [ ] `MaxLogs uint32`
- [ ] `AllowRevert bool`
- [ ] `AllowExternalCalls bool`
- [ ] `AllowDelegateLikeCall bool`
- [ ] `AllowPackageCall bool`
- [ ] `AllowUnoPaths bool`

## Add methods/helpers
- [ ] `func (p *HotPathExecutionProfile) ValidateBasic() error`
- [ ] `func (p *HotPathExecutionProfile) IsCompatibleWithClass(class HotPathClass) bool`

## Tests
- [ ] valid profile accepted
- [ ] invalid profile rejected
- [ ] profile/class compatibility checks work

---

# 3.9 `core/vm/hotpath_registry.go`

## Purpose
Provide deterministic lookup of allowlisted hot-path profiles.

## Add structs
- [ ] `HotPathRegistryEntry`

## Add functions
- [ ] `func IsHotPathProfileAllowed(statedb vm.StateDB, profileID common.Hash) bool`
- [ ] `func ReadHotPathProfile(statedb vm.StateDB, profileID common.Hash) (*HotPathExecutionProfile, bool)`
- [ ] `func ResolveHotPathProfileID(statedb vm.StateDB, tx *types.Transaction) (common.Hash, bool)`

## Required behavior
- [ ] deterministic profile resolution
- [ ] no local-node-only behavior
- [ ] support:
  - code-hash mapping
  - selector mapping
  - package/profile mapping
  - optional system-assisted profile mapping

## Tests
- [ ] allowed profile lookup works
- [ ] unknown profile rejected
- [ ] deterministic profile resolution for same state/tx

---

# 3.10 `core/vm/hotpath_runtime_policy.go`

## Purpose
Constrain the VM runtime surface for proof-native hot-path execution.

## Add structs
- [ ] `HotPathRuntimePolicy`

## Add functions
- [ ] `func IsHotPathRuntimePrimitiveAllowed(profile *HotPathExecutionProfile, primitive string) bool`
- [ ] `func ValidateHotPathRuntimeUsage(profile *HotPathExecutionProfile, usage *HotPathRuntimeUsage) error`

## Add auxiliary struct
- [ ] `HotPathRuntimeUsage`

## Required behavior
- [ ] reject forbidden runtime primitives
- [ ] reject unsupported host calls
- [ ] reject unsupported package/delegate/external call usage
- [ ] reject over-limit logs/storage/call depth

## Tests
- [ ] allowed primitive passes
- [ ] forbidden primitive rejected
- [ ] profile limits enforced

---

# 3.11 `core/vm/hotpath_trace.go`

## Purpose
Define trace generation and commitment helpers for hot-path execution.

## Add functions
- [ ] `func DeriveHotPathTraceCommitment(trace *types.HotPathTraceSummary) (common.Hash, error)`
- [ ] `func SummarizeHotPathTrace(...) (*types.HotPathTraceSummary, error)`

## Required behavior
- [ ] exact tx order preserved
- [ ] exact class/profile binding included
- [ ] deterministic encoding
- [ ] changed trace changes commitment

## Tests
- [ ] trace commitment determinism
- [ ] trace summary generation stable
- [ ] changes in profile/class/selector alter commitment

---

# 3.12 `core/vm/lvm.go`

## Purpose
Hook hot-path eligibility, tracing, and runtime policy into the actual VM execution surface.

## Modify execution seam
- [ ] add optional hot-path trace emitter plumbing
- [ ] add runtime policy enforcement when hot-path mode is active
- [ ] track:
  - instruction count
  - storage read/write count
  - log count
  - call depth
  - profile ID
  - selector/package identity if relevant
- [ ] preserve legacy execution path when hot-path tracing is disabled

## Required checks
- [ ] if hot-path mode active, reject forbidden runtime primitives
- [ ] if hot-path mode active, enforce profile bounds
- [ ] if hot-path mode active, emit hot-path trace summaries

## Tests
- [ ] legacy path unaffected
- [ ] hot-path mode tracks counts correctly
- [ ] forbidden runtime primitive fails fast
- [ ] profile limit failures are deterministic

---

# 3.13 `core/state/proof_apply_hotpath.go`

## Purpose
Apply proven hot-path state diffs to a fresh `StateDB`.

## Add functions
- [ ] `func ApplyHotPathStateDiff(statedb *state.StateDB, diff *types.HotPathStateDiff) error`
- [ ] `func applyHotPathAccountDiff(statedb *state.StateDB, diff *types.HotPathAccountDiff) error`
- [ ] `func verifyHotPathAccountPreValues(statedb *state.StateDB, diff *types.HotPathAccountDiff) error`
- [ ] `func applyHotPathStorageDiffs(...)`
- [ ] `func applyHotPathPrivStateDiffs(...)`

## Required behavior
- [ ] canonical sort before apply
- [ ] verify pre-values before post-values
- [ ] reject duplicates
- [ ] apply account, storage, private-state changes deterministically

## Tests
- [ ] happy-path state diff apply
- [ ] wrong pre-state rejected
- [ ] duplicate diff rejected
- [ ] deterministic post-root

---

# 3.14 `core/state_processor_hotpath.go`

## Purpose
Provide the processor path for proof-native hot-path blocks.

## Add functions
- [ ] `func (p *StateProcessor) ProcessHotPathProofBlock(block *types.Block, parent *types.Header, sidecar *types.HotPathBatchSidecar) (types.Receipts, uint64, *state.StateDB, error)`
- [ ] `func (p *StateProcessor) materializeHotPathReceipts(sidecar *types.HotPathBatchSidecar) (types.Receipts, error)`
- [ ] `func (p *StateProcessor) validateHotPathCoveredTxSet(block *types.Block, sidecar *types.HotPathBatchSidecar) error`
- [ ] `func (p *StateProcessor) validateHotPathTraceSummary(sidecar *types.HotPathBatchSidecar) error`
- [ ] `func (p *StateProcessor) validateHotPathProfileBinding(block *types.Block, sidecar *types.HotPathBatchSidecar) error`

## Required behavior
- [ ] do not locally execute covered txs
- [ ] validate tx set against sidecar
- [ ] validate class/profile binding
- [ ] validate trace summary
- [ ] materialize receipts from sidecar
- [ ] allocate fresh `StateDB` from parent root
- [ ] apply hot-path state diff
- [ ] return `(receipts, usedGas, statedb, nil)`

## Optional mixed mode
- [ ] if supporting legacy tail, define explicit processing order and boundaries
- [ ] recommended: disable mixed-mode in initial rollout unless absolutely necessary

## Tests
- [ ] happy path hot-path block
- [ ] tx-set mismatch rejected
- [ ] profile binding mismatch rejected
- [ ] invalid trace summary rejected
- [ ] resulting state root later matches validator expectation

---

# 3.15 `core/block_validator_hotpath.go`

## Purpose
Implement proof-native hot-path validation logic.

## Add structs
- [ ] `HotPathProofValidationInputs`
- [ ] `HotPathProofValidationResult`

## Add interface
- [ ] `HotPathBatchProofVerifier`

## Add functions
- [ ] `func (v *BlockValidator) ValidateStateHotPathProof(block *types.Block, parentRoot common.Hash, sidecar *types.HotPathBatchSidecar, receipts types.Receipts, usedGas uint64) error`
- [ ] `func (v *BlockValidator) validateHotPathProofSidecarBinding(block *types.Block, sidecar *types.HotPathBatchSidecar) error`
- [ ] `func (v *BlockValidator) validateHotPathCoveredTxs(block *types.Block, sidecar *types.HotPathBatchSidecar) error`
- [ ] `func (v *BlockValidator) validateHotPathProfileBinding(block *types.Block, sidecar *types.HotPathBatchSidecar) error`
- [ ] `func (v *BlockValidator) validateHotPathTrace(sidecar *types.HotPathBatchSidecar) error`
- [ ] `func (v *BlockValidator) validateHotPathReceiptCommitment(...) error`
- [ ] `func (v *BlockValidator) validateHotPathStateDiffCommitment(...) error`
- [ ] `func (v *BlockValidator) validateHotPathGas(...) error`

## Required checks
- [ ] sidecar exists
- [ ] proof type matches `hotpath-batch-v1`
- [ ] sidecar block hash matches block hash
- [ ] post-state root matches block root
- [ ] covered tx set matches exact block tx set or exact allowed covered subset
- [ ] class/profile binding valid
- [ ] tx commitment matches
- [ ] trace commitment matches
- [ ] witness commitment matches if used
- [ ] state diff commitment matches
- [ ] receipt commitment matches
- [ ] proof verifies
- [ ] gas checks pass
- [ ] materialized post-state root matches block root

## Tests
- [ ] happy path accept
- [ ] missing sidecar reject
- [ ] unsupported proof type reject
- [ ] unsupported profile reject
- [ ] tx commitment mismatch reject
- [ ] trace commitment mismatch reject
- [ ] state diff commitment mismatch reject
- [ ] receipt commitment mismatch reject
- [ ] post-state root mismatch reject
- [ ] proof verification failure reject

---

# 3.16 `core/block_validator.go`

## Purpose
Extend proof-aware dispatch to support Phase 4.

## Modify function
- [ ] extend `ValidateStateProofAware(...)` to dispatch across:
  - legacy path
  - Phase 2 transfer proof path
  - Phase 3 restricted contract proof path
  - Phase 4 hot-path proof path

## Behavior
- [ ] if no sidecar => legacy path
- [ ] if transfer proof sidecar => Phase 2 path
- [ ] if restricted contract sidecar => Phase 3 path
- [ ] if hot-path sidecar => Phase 4 path
- [ ] unsupported proof type => reject

## Tests
- [ ] correct branch dispatch
- [ ] unsupported proof type rejected
- [ ] no silent downgrade

---

# 3.17 `core/blockchain.go`

## Purpose
Change canonical block import flow so majority hot-path execution can bypass replay.

## Add helper functions
- [ ] `func (bc *BlockChain) loadHotPathProofSidecar(blockHash common.Hash) (*types.HotPathBatchSidecar, error)`
- [ ] `func (bc *BlockChain) shouldUseHotPathProofValidation(block *types.Block, sidecar *types.HotPathBatchSidecar) bool`

## Modify insert path in `insertChain(...)`
Current proof-aware evolution:
- legacy path
- Phase 2 transfer proof path
- Phase 3 restricted contract proof path

Phase 4 adds:
- hot-path proof path

## New hot-path branch
- [ ] resolve sidecar by block hash
- [ ] if no sidecar => existing path
- [ ] if hot-path sidecar => Phase 4 path
- [ ] call `ProcessHotPathProofBlock(...)`
- [ ] call `ValidateStateHotPathProof(...)`
- [ ] continue with existing `writeBlockWithState(...)`
- [ ] continue with existing `writeBlockAndSetHead(...)`

## New errors to propagate
- [ ] missing sidecar
- [ ] unsupported proof type
- [ ] profile mismatch
- [ ] hot-path proof validation failure
- [ ] hot-path state diff materialization failure

## Tests
- [ ] legacy block import unchanged
- [ ] Phase 2 block import unchanged
- [ ] Phase 3 block import unchanged
- [ ] hot-path proof block import works
- [ ] invalid hot-path block rejected
- [ ] state commit path still works after hot-path branch

---

# 3.18 `core/rawdb/schema_proof_hotpath.go`

## Purpose
Define rawdb key schema for Phase 4 hot-path proof sidecars.

## Add key builders
- [ ] `func hotPathProofSidecarKey(blockHash common.Hash) []byte`
- [ ] optional `func hotPathProofArtifactKey(artifactHash common.Hash) []byte`

## Rules
- [ ] sidecar key must be block-hash keyed
- [ ] schema distinct from Phase 2/3 if needed
- [ ] avoid ambiguous overlap with earlier proof sidecars

## Tests
- [ ] key uniqueness
- [ ] stable prefix if iteration support is needed

---

# 3.19 `core/rawdb/accessors_proof_hotpath.go`

## Purpose
Implement rawdb persistence for hot-path proof sidecars.

## Add functions
- [ ] `func ReadHotPathProofSidecar(db tosdb.KeyValueReader, blockHash common.Hash) *types.HotPathBatchSidecar`
- [ ] `func WriteHotPathProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash, sidecar *types.HotPathBatchSidecar)`
- [ ] `func DeleteHotPathProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash)`
- [ ] `func HasHotPathProofSidecar(db tosdb.Reader, blockHash common.Hash) bool`

Optional:
- [ ] artifact read/write/delete helpers if split storage is used

## Encoding decision
- [ ] use canonical encoding consistent with the proof-sidecar family
- [ ] recommended: RLP unless a stronger reason exists otherwise

## Tests
- [ ] write/read sidecar round trip
- [ ] delete works
- [ ] malformed sidecar decoding handled safely

---

# 3.20 `miner/hotpath_batch_builder.go`

## Purpose
Build proof-native batches that maximize hot-path coverage.

## Add structs
- [ ] `HotPathBatchBuilder`
- [ ] `HotPathBatchBuildResult`
- [ ] `HotPathCoverageSummary`

## Add functions
- [ ] `func NewHotPathBatchBuilder(...) *HotPathBatchBuilder`
- [ ] `func (b *HotPathBatchBuilder) Build(txs types.Transactions, statedb *state.StateDB) (*HotPathBatchBuildResult, error)`
- [ ] `func (b *HotPathBatchBuilder) classifyTxs(...)`
- [ ] `func (b *HotPathBatchBuilder) groupByProfile(...)`
- [ ] `func (b *HotPathBatchBuilder) computeCoverageSummary(...)`

## Required behavior
- [ ] classify txs into hot-path classes
- [ ] resolve profile IDs
- [ ] maximize covered tx ratio
- [ ] avoid mixing incompatible profiles if unsupported by prover
- [ ] optionally produce fallback tail metadata

## Tests
- [ ] high-coverage tx set grouped correctly
- [ ] incompatible profiles split correctly
- [ ] coverage summary correct
- [ ] deterministic batch building for same input/state

---

# 3.21 `proofworker/hotpath_batch_prover.go`

## Purpose
Provide proofworker-side proving support for Phase 4 hot-path batches.

## Add structs
- [ ] `HotPathProofWorkerRequest`
- [ ] `HotPathProofWorkerResponse`

## Add functions
- [ ] `func ProveHotPathBatch(req *HotPathProofWorkerRequest) (*HotPathProofWorkerResponse, error)`
- [ ] `func buildHotPathProofSidecar(...) (*types.HotPathBatchSidecar, error)`

## Required response content
- [ ] proof artifact
- [ ] public inputs
- [ ] tx commitment
- [ ] trace commitment
- [ ] witness commitment
- [ ] state diff commitment
- [ ] receipt commitment
- [ ] materializable state diff
- [ ] receipt set
- [ ] trace summary
- [ ] batch profile summary

## Tests
- [ ] request/response round trip
- [ ] sidecar construction correct
- [ ] malformed request rejected

---

# 3.22 `internal/tosapi/proof_hotpath_api.go`

## Purpose
Expose hot-path proof sidecars and metadata over RPC.

## Add methods
- [ ] `func (s *TOSAPI) GetHotPathProofSidecar(ctx context.Context, blockHash common.Hash) (*types.HotPathBatchSidecar, error)`
- [ ] `func (s *TOSAPI) GetTransactionHotPathStatus(ctx context.Context, txHash common.Hash) (map[string]interface{}, error)`
- [ ] `func (s *TOSAPI) GetHotPathBatchProfile(ctx context.Context, blockHash common.Hash) (map[string]interface{}, error)`
- [ ] optional debug-only trace summary endpoint

## Required behavior
- [ ] resolve sidecar by block hash
- [ ] locate tx in block and determine hot-path coverage status
- [ ] return proof type, class, profile ID, and batch summary

## Tests
- [ ] block sidecar query works
- [ ] tx hot-path status query works
- [ ] batch profile query works
- [ ] missing sidecar handled consistently

---

# 3.23 `internal/tosapi/api.go`

## Purpose
Expose hot-path metadata in normal block and receipt APIs when sidecar exists.

## Modify methods
- [ ] `RPCMarshalHeader`
- [ ] `RPCMarshalBlock`
- [ ] `GetTransactionReceipt`

## Add response fields when hot-path-backed
- [ ] `proofType`
- [ ] `proofVersion`
- [ ] `proofCovered`
- [ ] `hotPathClass`
- [ ] `hotPathProfileId`
- [ ] `proofBatchIndex`

## Rules
- [ ] legacy RPC responses remain unchanged unless fields are optional
- [ ] do not expose full witness publicly
- [ ] keep detailed trace/profile debug output in proof-specific APIs

## Tests
- [ ] legacy RPC responses unchanged
- [ ] hot-path block exposes metadata
- [ ] hot-path receipt exposes metadata

---

# 3.24 Tests to Add by Package

## `core/types`
- [ ] hot-path sidecar encode/decode
- [ ] hot-path state diff validation
- [ ] hot-path trace summary validation
- [ ] commitment determinism

## `core/rawdb`
- [ ] hot-path sidecar write/read/delete
- [ ] malformed hot-path sidecar handling
- [ ] block-hash keyed retrieval

## `core/state`
- [ ] apply hot-path state diff
- [ ] wrong pre-value rejection
- [ ] deterministic post-root

## `core/vm`
- [ ] hot-path profile validation
- [ ] hot-path registry lookup
- [ ] runtime policy enforcement
- [ ] hot-path trace extraction

## `core`
- [ ] hot-path processor path
- [ ] hot-path validator path
- [ ] blockchain insert hot-path path
- [ ] negative tests for invalid sidecar/profile/commitment cases

## `miner`
- [ ] hot-path batch building
- [ ] coverage summary correctness
- [ ] deterministic grouping

## `proofworker`
- [ ] hot-path prover request/response
- [ ] sidecar construction

## `internal/tosapi`
- [ ] hot-path proof RPC methods
- [ ] hot-path metadata in standard APIs

---

# 4. Required Error Flow

## Processor errors
- [ ] invalid sidecar
- [ ] tx mismatch
- [ ] profile mismatch
- [ ] invalid trace summary
- [ ] invalid batch profile
- [ ] state diff invalid
- [ ] state diff apply failure

## Validator errors
- [ ] sidecar missing
- [ ] unsupported proof type/version
- [ ] block-hash mismatch
- [ ] covered tx mismatch
- [ ] profile mismatch
- [ ] forbidden runtime primitive
- [ ] forbidden call shape
- [ ] trace commitment mismatch
- [ ] witness commitment mismatch
- [ ] state diff commitment mismatch
- [ ] receipt commitment mismatch
- [ ] post-state root mismatch
- [ ] proof verification failure

## RPC errors
- [ ] hot-path sidecar not found
- [ ] tx not hot-path-covered
- [ ] invalid hot-path metadata read

---

# 5. Suggested Commit Sequence

## Commit 1
- [ ] `core/types/proof_hotpath_sidecar.go`
- [ ] `core/types/proof_hotpath_state_diff.go`
- [ ] `core/types/proof_hotpath_trace.go`
- [ ] `core/types/proof_hotpath_errors.go`
- [ ] `core/types/hotpath_class.go`

## Commit 2
- [ ] `core/vm/hotpath_profiles.go`
- [ ] `core/vm/hotpath_registry.go`
- [ ] `core/vm/hotpath_runtime_policy.go`

## Commit 3
- [ ] `core/rawdb/schema_proof_hotpath.go`
- [ ] `core/rawdb/accessors_proof_hotpath.go`

## Commit 4
- [ ] `core/types/transaction.go`
- [ ] `core/types/receipt.go`

## Commit 5
- [ ] `core/vm/hotpath_trace.go`
- [ ] `core/vm/lvm.go`

## Commit 6
- [ ] `core/state/proof_apply_hotpath.go`

## Commit 7
- [ ] `core/state_processor_hotpath.go`

## Commit 8
- [ ] `core/block_validator_hotpath.go`
- [ ] `core/block_validator.go`

## Commit 9
- [ ] `core/blockchain.go`

## Commit 10
- [ ] `miner/hotpath_batch_builder.go`

## Commit 11
- [ ] `proofworker/hotpath_batch_prover.go`

## Commit 12
- [ ] `internal/tosapi/proof_hotpath_api.go`
- [ ] `internal/tosapi/api.go`

## Commit 13
- [ ] integration tests
- [ ] telemetry and metrics
- [ ] coverage-ratio reporting

---

# 6. Final Exit Criteria

Phase 4 file-by-file implementation is complete when:

- [ ] every new file listed above exists
- [ ] every required struct exists
- [ ] every required function exists
- [ ] rawdb can persist hot-path proof sidecars
- [ ] txs can be classified into deterministic hot-path classes
- [ ] profiles can be resolved deterministically
- [ ] miner can build majority hot-path proof batches
- [ ] proofworker can prove hot-path batches and produce sidecars
- [ ] blockchain import can branch into hot-path proof validation
- [ ] validator no longer replays most covered hot-path txs
- [ ] hot-path state diff is materialized into `StateDB`
- [ ] trace, witness, state diff, receipt, and tx commitments all validate
- [ ] legacy path remains unchanged
- [ ] Phase 2 and Phase 3 paths remain unchanged
- [ ] RPC exposes hot-path metadata
- [ ] unit tests and integration tests pass

---

# 7. Final Summary

This checklist is the implementation decomposition of Phase 4.

The most important engineering fact is:

> **Phase 4 is not merely “add one more proof type”. It is a coordinated patch across types, VM profiling, runtime policy, rawdb, state materialization, processor, validator, blockchain insertion, miner batch building, proofworker, and RPC.**

The majority-hot-path proof-native architecture becomes real only when all of these are true at once:

- tx classes are deterministic
- profiles are deterministic
- runtime surface is constrained
- hot-path batches can be built
- proofs can be generated
- proofs can be verified
- state diffs can be applied deterministically
- post-state roots match
- receipts and gas match
- validator replay is removed from most hot-path execution
