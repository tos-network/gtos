# gtos Phase 3
## File-by-File Coding Checklist
### Restricted Contract Proving for `restricted-contract-batch-v1`

## Purpose

This document converts the Phase 3 design into a **file-by-file implementation checklist**.

The scope of Phase 3 is:

- proof-backed validation for a **restricted contract subset**
- optional coexistence with Phase 2 proof-covered transfer-class transactions
- validator does **not** fully replay proof-covered restricted contract calls
- validator verifies:
  - proof sidecar
  - tx commitment
  - trace commitment
  - witness commitment
  - state-diff commitment
  - receipt commitment
- validator materializes the proven post-state into a real `StateDB`

This document is written so the engineering team can implement directly, file by file.

---

# 1. Cross-Cutting Phase 3 Rules

Before touching any file, Phase 3 must respect the following rules:

- **No `Header` changes**
- **No proof metadata inside block hash**
- **Use out-of-band sidecar keyed by canonical block hash**
- **No silent downgrade from proof mode to legacy mode**
- **Restricted contract subset only**
- **No unrestricted nested contract call graph in initial rollout**
- **No unrestricted logs/events in initial rollout**
- **State diff must be materialized into a real `StateDB`**
- **All deterministic data structures must use canonical ordering**
- **Proof-backed restricted contract blocks in initial rollout must contain only proof-eligible tx classes**

---

# 2. New Files and Modified Files Overview

## New files
- `core/types/proof_contract_sidecar.go`
- `core/types/proof_contract_state_diff.go`
- `core/types/proof_contract_trace.go`
- `core/types/proof_contract_errors.go`
- `core/vm/proof_eligibility.go`
- `core/vm/proof_registry.go`
- `core/vm/proof_trace.go`
- `core/vm/proof_trace_contract.go`
- `core/state/proof_apply_contract.go`
- `core/state_processor_restricted_proof.go`
- `core/block_validator_restricted_proof.go`
- `core/rawdb/schema_proof_contract.go`
- `core/rawdb/accessors_proof_contract.go`
- `internal/tosapi/proof_contract_api.go`

## Modified files
- `core/blockchain.go`
- `core/block_validator.go`
- `core/types/transaction.go`
- `core/types/receipt.go`
- `internal/tosapi/api.go`
- `core/state_processor.go` if Phase 3 branch hooks are placed here
- `core/vm/lvm.go` if trace extraction and eligibility gates are hooked here

Optional supporting modifications:
- miner-side sidecar writer / proof orchestration files from Phase 1 and Phase 2
- proof worker artifact files
- deployment / code-hash registry wiring files
- tests near each modified package

---

# 3. File-by-File Checklist

# 3.1 `core/types/proof_contract_sidecar.go`

## Purpose
Define the canonical Phase 3 proof sidecar object used by validators, RPC, and storage.

## Add structs
- [ ] `RestrictedContractBatchSidecar`
- [ ] `RestrictedContractProofCoveredTxRef`
- [ ] `RestrictedContractSidecarValidationSummary`

## `RestrictedContractBatchSidecar` required fields
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
- [ ] `ProofCoveredTxs []RestrictedContractProofCoveredTxRef`
- [ ] `CoverageMode string`
- [ ] `UsedGas uint64`
- [ ] `Receipts []*types.Receipt`
- [ ] `StateDiff *RestrictedContractStateDiff`
- [ ] `TraceSummary *RestrictedContractTraceSummary`
- [ ] `ProverID string`
- [ ] `ProvingTimeMs uint64`

## Add methods/helpers
- [ ] `func (s *RestrictedContractBatchSidecar) ValidateBasic() error`
- [ ] `func (s *RestrictedContractBatchSidecar) IsRestrictedContractBatchV1() bool`
- [ ] `func (s *RestrictedContractBatchSidecar) HasProofBytes() bool`

## Add validation rules
- [ ] reject zero `BlockHash`
- [ ] reject empty `ProofType`
- [ ] reject nil `StateDiff`
- [ ] reject nil `TraceSummary`
- [ ] reject nil receipts when proof-backed mode requires receipts
- [ ] reject missing commitments

## Tests
- [ ] sidecar encode/decode round trip
- [ ] `ValidateBasic()` success case
- [ ] `ValidateBasic()` failure cases
- [ ] exact `ProofType == "restricted-contract-batch-v1"` check

---

# 3.2 `core/types/proof_contract_state_diff.go`

## Purpose
Define the materializable post-state diff for restricted contract proof blocks.

## Add structs
- [ ] `RestrictedContractStateDiff`
- [ ] `RestrictedContractAccountDiff`
- [ ] `RestrictedContractStorageDiff`
- [ ] `RestrictedContractPrivStateDiff`

## Required fields
### `RestrictedContractStateDiff`
- [ ] `Accounts []RestrictedContractAccountDiff`

### `RestrictedContractAccountDiff`
- [ ] `Address common.Address`
- [ ] `PreNonce uint64`
- [ ] `PostNonce uint64`
- [ ] `PreBalance *big.Int`
- [ ] `PostBalance *big.Int`
- [ ] `StorageDiffs []RestrictedContractStorageDiff`
- [ ] `PrivStateDiffs []RestrictedContractPrivStateDiff`

### `RestrictedContractStorageDiff`
- [ ] `Key common.Hash`
- [ ] `Pre common.Hash`
- [ ] `Post common.Hash`

### `RestrictedContractPrivStateDiff`
- [ ] `Key []byte`
- [ ] `Pre []byte`
- [ ] `Post []byte`

## Add methods/helpers
- [ ] `func (d *RestrictedContractStateDiff) ValidateBasic() error`
- [ ] `func (d *RestrictedContractStateDiff) SortCanonical()`
- [ ] `func (d *RestrictedContractStateDiff) HasDuplicateEntries() error`

## Validation rules
- [ ] duplicate account entries forbidden
- [ ] duplicate storage keys in one account forbidden
- [ ] duplicate private keys in one account forbidden
- [ ] nil balances forbidden where balance change is declared
- [ ] canonical-sort enforcement

## Tests
- [ ] canonical sort determinism
- [ ] duplicate account rejection
- [ ] duplicate storage key rejection
- [ ] duplicate private key rejection
- [ ] valid diff acceptance

---

# 3.3 `core/types/proof_contract_trace.go`

## Purpose
Define the canonical restricted contract trace summary model.

## Add structs
- [ ] `RestrictedContractTraceSummary`
- [ ] `RestrictedContractTxTraceSummary`
- [ ] `RestrictedContractReturnDataSummary`
- [ ] optional `RestrictedContractStorageTouchSummary`

## Required fields

### `RestrictedContractTraceSummary`
- [ ] `TxTraces []RestrictedContractTxTraceSummary`

### `RestrictedContractTxTraceSummary`
- [ ] `TxHash common.Hash`
- [ ] `TxIndex uint32`
- [ ] `Callee common.Address`
- [ ] `CodeHash common.Hash`
- [ ] `CallDepth uint8`
- [ ] `InstructionCount uint64`
- [ ] `StorageReadCount uint32`
- [ ] `StorageWriteCount uint32`
- [ ] `Reverted bool`
- [ ] `ReturnDataCommitment common.Hash`

## Add methods/helpers
- [ ] `func (t *RestrictedContractTraceSummary) ValidateBasic() error`
- [ ] `func (t *RestrictedContractTraceSummary) SortCanonical()`
- [ ] `func (t *RestrictedContractTraceSummary) HasForbiddenShape() error`

## Validation rules
- [ ] exact tx trace count matches proof-covered contract tx count
- [ ] call depth obeys restricted policy
- [ ] no forbidden host-call marker if represented
- [ ] no forbidden nested-call shape in initial rollout
- [ ] no unsupported log markers if represented

## Tests
- [ ] trace summary encode/decode round trip
- [ ] forbidden nested call shape rejected
- [ ] forbidden call depth rejected
- [ ] deterministic ordering

---

# 3.4 `core/types/proof_contract_errors.go`

## Purpose
Define stable Phase 3 error values.

## Add errors
- [ ] `ErrRestrictedProofMissingSidecar`
- [ ] `ErrRestrictedProofUnsupportedType`
- [ ] `ErrRestrictedProofUnsupportedVersion`
- [ ] `ErrRestrictedProofTxSetMismatch`
- [ ] `ErrRestrictedProofEligibilityMismatch`
- [ ] `ErrRestrictedProofTraceCommitmentMismatch`
- [ ] `ErrRestrictedProofWitnessCommitmentMismatch`
- [ ] `ErrRestrictedProofStateDiffCommitmentMismatch`
- [ ] `ErrRestrictedProofReceiptCommitmentMismatch`
- [ ] `ErrRestrictedProofVerificationFailed`
- [ ] `ErrRestrictedProofForbiddenCallShape`
- [ ] `ErrRestrictedProofUnsupportedHostCall`
- [ ] `ErrRestrictedProofUnsupportedLogs`
- [ ] `ErrRestrictedProofPostStateMismatch`
- [ ] `ErrRestrictedProofStateDiffPreValueMismatch`

## Tests
- [ ] error identity tests
- [ ] validator and processor use these errors consistently

---

# 3.5 `core/types/transaction.go`

## Purpose
Extend proof classification to support restricted contract proving.

## Add enum handling
- [ ] extend or reuse proof classification enum from Phase 2
- [ ] add `ProofFastPathRestrictedContract` if not already present

## Add / extend methods
- [ ] `func (tx *Transaction) ProofClass() ProofAdmissionClass`
- [ ] `func (tx *Transaction) IsRestrictedContractProofCandidate() bool`

## Classification rules
- [ ] transfer-class txs keep Phase 2 classification
- [ ] contract-call txs may be marked restricted-contract-candidate only if target code/profile allows it
- [ ] all deployment txs remain legacy path
- [ ] unsupported tx types remain legacy path

## Tests
- [ ] transfer-class tx classification unchanged
- [ ] contract-call candidate classification correct
- [ ] deployment remains legacy path

---

# 3.6 `core/types/receipt.go`

## Purpose
Attach restricted-proof metadata to receipts used by RPC and tooling.

## Add fields to `Receipt`
These should remain implementation-layer fields.

- [ ] `ProofCovered bool`
- [ ] `ProofBatchIndex uint32`
- [ ] `ProofType string`
- [ ] `RestrictedProofCodeHash common.Hash` optional
- [ ] `RestrictedProofReverted bool` optional if useful for RPC

## Add helper methods
- [ ] `func (r *Receipt) MarkRestrictedProofCovered(batchIndex uint32, proofType string)`
- [ ] `func (r *Receipt) IsRestrictedProofCovered() bool`

## Persistence decision
- [ ] decide whether Phase 3 stores these in DB or derives from sidecar at query time
- [ ] recommended: derive from sidecar at query time where possible

## Tests
- [ ] proof metadata is set correctly
- [ ] legacy receipt encoding remains unaffected
- [ ] receipt commitment does not accidentally depend on non-canonical fields unless intended

---

# 3.7 `core/vm/proof_eligibility.go`

## Purpose
Decide whether a contract is eligible for restricted proving.

## Add enum
- [ ] `ContractProofEligibility`
- [ ] `ContractProofIneligible`
- [ ] `ContractProofRestrictedV1`

## Add structs
- [ ] `RestrictedContractProofProfile`

## Required fields for `RestrictedContractProofProfile`
- [ ] `CodeHash common.Hash`
- [ ] `MaxInstructions uint64`
- [ ] `MaxStorageReads uint32`
- [ ] `MaxStorageWrites uint32`
- [ ] `MaxLogs uint32`
- [ ] `MaxCallDepth uint8`
- [ ] `AllowExternalCalls bool`
- [ ] `AllowDelegateLikeCall bool`
- [ ] `AllowValueTransfer bool`
- [ ] `AllowRevert bool`

## Add functions
- [ ] `func IsRestrictedProofEligibleCode(code []byte) bool`
- [ ] `func RestrictedProofProfileForCode(code []byte) (*RestrictedContractProofProfile, error)`
- [ ] `func IsRestrictedProofEligibleTx(tx *types.Transaction, statedb *state.StateDB) bool`

## Required behavior
- [ ] deterministic eligibility
- [ ] no dependence on local non-consensus state
- [ ] initial rollout rejects nested calls if policy forbids them
- [ ] initial rollout rejects unsupported host-call usage

## Tests
- [ ] eligible code accepted
- [ ] ineligible code rejected
- [ ] forbidden profile rejected
- [ ] tx-level eligibility matches code/profile

---

# 3.8 `core/vm/proof_registry.go`

## Purpose
Provide a deterministic allowlist/registry for restricted-proof-eligible code hashes.

## Add structs
- [ ] `RestrictedProofRegistryEntry`

## Add functions
- [ ] `func IsRestrictedProofCodeHashAllowed(statedb vm.StateDB, codeHash common.Hash) bool`
- [ ] `func ReadRestrictedProofProfile(statedb vm.StateDB, codeHash common.Hash) (*RestrictedContractProofProfile, bool)`
- [ ] `func WriteRestrictedProofProfile(statedb vm.StateDB, profile *RestrictedContractProofProfile) error` if state-backed registry is used

## Required decision
- [ ] decide whether Phase 3 uses:
  - state-backed registry
  - rawdb-backed local registry
  - hardcoded allowlist for first rollout

## Recommended initial choice
- [ ] use deterministic state-backed or config-backed allowlist, not local-node-only rawdb

## Tests
- [ ] allowed code hash lookup works
- [ ] unknown code hash rejected
- [ ] profile lookup deterministic

---

# 3.9 `core/vm/proof_trace.go`

## Purpose
Define generic trace interfaces/helpers for proof-backed contract tracing.

## Add structs/interfaces
- [ ] `RestrictedContractExecutionTrace`
- [ ] `RestrictedContractTraceEntry`
- [ ] `RestrictedContractTraceEmitter`

## Add functions
- [ ] `func DeriveRestrictedContractTraceCommitment(trace *RestrictedContractExecutionTrace) (common.Hash, error)`
- [ ] `func SummarizeRestrictedContractTrace(trace *RestrictedContractExecutionTrace) (*types.RestrictedContractTraceSummary, error)`

## Required rules
- [ ] exact tx order preserved
- [ ] canonical ordering inside trace elements
- [ ] bounded trace structure
- [ ] no arbitrary debug-only fields in canonical commitment

## Tests
- [ ] trace commitment determinism
- [ ] trace summary generation stable
- [ ] modified trace changes commitment

---

# 3.10 `core/vm/proof_trace_contract.go`

## Purpose
Collect restricted-proof trace information from contract execution.

## Add functions
- [ ] `func BeginRestrictedContractTrace(...)`
- [ ] `func EndRestrictedContractTrace(...)`
- [ ] `func OnRestrictedContractStorageRead(...)`
- [ ] `func OnRestrictedContractStorageWrite(...)`
- [ ] `func OnRestrictedContractCallAttempt(...)`
- [ ] `func OnRestrictedContractReturn(...)`
- [ ] `func OnRestrictedContractRevert(...)`

## Required behavior
- [ ] count storage reads
- [ ] count storage writes
- [ ] record effective call depth
- [ ] record revert outcome
- [ ] record return data commitment
- [ ] reject forbidden nested call shape
- [ ] reject unsupported host call shape if detected at this layer

## Tests
- [ ] storage read/write counting
- [ ] revert recorded correctly
- [ ] return data commitment recorded correctly
- [ ] forbidden nested call rejected

---

# 3.11 `core/vm/lvm.go`

## Purpose
Hook restricted-proof trace/eligibility into the actual VM entry path.

## Modify execution seam
- [ ] add optional restricted trace emitter plumbing
- [ ] gate restricted-proof execution shape
- [ ] surface forbidden nested-call or host-call behavior as explicit errors
- [ ] preserve legacy execution path when proof tracing is disabled

## Required checks
- [ ] if restricted-proof mode active, reject unsupported operations immediately
- [ ] if restricted-proof mode active, track counts required by trace summary
- [ ] if restricted-proof mode active, enforce profile bounds

## Tests
- [ ] restricted mode does not affect legacy mode
- [ ] restricted trace integrates with VM execution
- [ ] forbidden patterns fail fast

---

# 3.12 `core/state/proof_apply_contract.go`

## Purpose
Apply proven restricted contract state diffs to a fresh `StateDB`.

## Add functions
- [ ] `func ApplyRestrictedContractStateDiff(statedb *state.StateDB, diff *types.RestrictedContractStateDiff) error`
- [ ] `func applyRestrictedContractAccountDiff(statedb *state.StateDB, diff *types.RestrictedContractAccountDiff) error`
- [ ] `func verifyRestrictedContractAccountPreValues(statedb *state.StateDB, diff *types.RestrictedContractAccountDiff) error`
- [ ] `func applyRestrictedContractStorageDiffs(statedb *state.StateDB, addr common.Address, diffs []types.RestrictedContractStorageDiff) error`
- [ ] `func applyRestrictedContractPrivStateDiffs(statedb *state.StateDB, addr common.Address, diffs []types.RestrictedContractPrivStateDiff) error`

## Required behavior
- [ ] sort accounts canonically before apply
- [ ] sort storage diffs canonically before apply
- [ ] sort private diffs canonically before apply
- [ ] verify pre-values before applying post-values
- [ ] reject mismatches
- [ ] reject duplicates

## Tests
- [ ] happy-path state diff apply
- [ ] wrong pre-state rejected
- [ ] duplicate diff rejected
- [ ] deterministic post-root generation

---

# 3.13 `core/state_processor_restricted_proof.go`

## Purpose
Provide the processor path for proof-backed restricted contract blocks.

## Add functions
- [ ] `func (p *StateProcessor) ProcessRestrictedContractProofBlock(block *types.Block, parent *types.Header, sidecar *types.RestrictedContractBatchSidecar) (types.Receipts, uint64, *state.StateDB, error)`
- [ ] `func (p *StateProcessor) materializeRestrictedContractReceipts(sidecar *types.RestrictedContractBatchSidecar) (types.Receipts, error)`
- [ ] `func (p *StateProcessor) validateRestrictedProofCoveredTxSet(block *types.Block, sidecar *types.RestrictedContractBatchSidecar) error`
- [ ] `func (p *StateProcessor) validateRestrictedTraceSummary(sidecar *types.RestrictedContractBatchSidecar) error`

## Required behavior
- [ ] do not locally execute proof-covered restricted contract txs
- [ ] validate tx set against sidecar
- [ ] validate trace summary basic shape
- [ ] materialize receipts from sidecar
- [ ] allocate fresh `StateDB` from parent root
- [ ] apply restricted contract state diff
- [ ] return `(receipts, usedGas, statedb, nil)`

## Must not do
- [ ] do not call ordinary contract execution for proof-covered restricted contract blocks
- [ ] do not mutate canonical state before all checks pass

## Tests
- [ ] happy path restricted contract block
- [ ] mismatched tx set rejected
- [ ] invalid trace summary rejected
- [ ] invalid sidecar rejected
- [ ] resulting state root later matches validator expectation

---

# 3.14 `core/block_validator_restricted_proof.go`

## Purpose
Implement proof-backed restricted contract validation logic.

## Add structs
- [ ] `RestrictedContractProofValidationInputs`
- [ ] `RestrictedContractProofValidationResult`

## Add interface
- [ ] `RestrictedContractBatchProofVerifier`

## Add functions
- [ ] `func (v *BlockValidator) ValidateStateRestrictedContractProof(block *types.Block, parentRoot common.Hash, sidecar *types.RestrictedContractBatchSidecar, receipts types.Receipts, usedGas uint64) error`
- [ ] `func (v *BlockValidator) validateRestrictedContractProofSidecarBinding(block *types.Block, sidecar *types.RestrictedContractBatchSidecar) error`
- [ ] `func (v *BlockValidator) validateRestrictedContractEligibility(block *types.Block, sidecar *types.RestrictedContractBatchSidecar) error`
- [ ] `func (v *BlockValidator) validateRestrictedContractTrace(sidecar *types.RestrictedContractBatchSidecar) error`
- [ ] `func (v *BlockValidator) validateRestrictedContractReceiptCommitment(block *types.Block, sidecar *types.RestrictedContractBatchSidecar, receipts types.Receipts) error`
- [ ] `func (v *BlockValidator) validateRestrictedContractStateDiffCommitment(sidecar *types.RestrictedContractBatchSidecar) error`
- [ ] `func (v *BlockValidator) validateRestrictedContractGas(block *types.Block, sidecar *types.RestrictedContractBatchSidecar, receipts types.Receipts, usedGas uint64) error`

## Required checks
- [ ] sidecar exists
- [ ] proof type matches `restricted-contract-batch-v1`
- [ ] sidecar block hash matches block hash
- [ ] post-state root matches block root
- [ ] tx set exactly matches proof-covered set
- [ ] all proof-covered txs are restricted-proof-eligible
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
- [ ] unsupported contract reject
- [ ] forbidden nested call reject
- [ ] trace commitment mismatch reject
- [ ] state diff commitment mismatch reject
- [ ] receipt commitment mismatch reject
- [ ] post-state root mismatch reject
- [ ] proof verification failure reject

---

# 3.15 `core/block_validator.go`

## Purpose
Extend the proof-aware entry point to support Phase 3.

## Modify function
- [ ] extend `ValidateStateProofAware(...)` to dispatch across:
  - legacy path
  - Phase 2 transfer proof path
  - Phase 3 restricted contract proof path

## Behavior
- [ ] if no sidecar => legacy path
- [ ] if transfer proof sidecar => Phase 2 path
- [ ] if restricted contract proof sidecar => Phase 3 path
- [ ] if unsupported proof type => reject

## Tests
- [ ] proof-aware dispatch picks correct branch
- [ ] unsupported proof type rejected
- [ ] no silent downgrade

---

# 3.16 `core/blockchain.go`

## Purpose
Change canonical block import flow to branch before local execution for restricted proof blocks.

## Add helper functions
- [ ] `func (bc *BlockChain) loadRestrictedContractProofSidecar(blockHash common.Hash) (*types.RestrictedContractBatchSidecar, error)`
- [ ] `func (bc *BlockChain) shouldUseRestrictedContractProofValidation(block *types.Block, sidecar *types.RestrictedContractBatchSidecar) bool`

## Modify insert path in `insertChain(...)`
Current proof-aware evolution:
- legacy path
- Phase 2 transfer proof path

Phase 3 adds:
- restricted contract proof path

## New proof-backed branch
- [ ] resolve sidecar by block hash
- [ ] if no sidecar => existing path
- [ ] if restricted-contract sidecar => Phase 3 path
- [ ] call `ProcessRestrictedContractProofBlock(...)`
- [ ] call `ValidateStateRestrictedContractProof(...)`
- [ ] continue with existing `writeBlockWithState(...)`
- [ ] continue with existing `writeBlockAndSetHead(...)`

## New errors to propagate
- [ ] missing sidecar
- [ ] unsupported proof type
- [ ] eligibility mismatch
- [ ] restricted proof validation failure
- [ ] restricted state diff materialization failure

## Tests
- [ ] legacy block import unchanged
- [ ] Phase 2 proof block import unchanged
- [ ] restricted proof block import works
- [ ] restricted invalid block rejected
- [ ] state commit path still works after restricted proof branch

---

# 3.17 `core/rawdb/schema_proof_contract.go`

## Purpose
Define rawdb key schema for restricted contract proof sidecars.

## Add key builders
- [ ] `func restrictedContractProofSidecarKey(blockHash common.Hash) []byte`
- [ ] optional `func restrictedContractProofArtifactKey(artifactHash common.Hash) []byte`

## Rules
- [ ] sidecar key must be block-hash keyed
- [ ] keep schema distinct from normal proof sidecars if needed
- [ ] avoid ambiguous key overlap with Phase 2

## Tests
- [ ] key uniqueness
- [ ] stable prefix if iterator support is needed

---

# 3.18 `core/rawdb/accessors_proof_contract.go`

## Purpose
Implement rawdb persistence for restricted contract proof sidecars.

## Add functions
- [ ] `func ReadRestrictedContractProofSidecar(db tosdb.KeyValueReader, blockHash common.Hash) *types.RestrictedContractBatchSidecar`
- [ ] `func WriteRestrictedContractProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash, sidecar *types.RestrictedContractBatchSidecar)`
- [ ] `func DeleteRestrictedContractProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash)`
- [ ] `func HasRestrictedContractProofSidecar(db tosdb.Reader, blockHash common.Hash) bool`

Optional:
- [ ] artifact read/write/delete functions if split storage is needed

## Encoding decision
- [ ] use canonical encoding consistent with proof sidecar family
- [ ] recommended: RLP unless a stronger reason exists otherwise

## Tests
- [ ] write/read sidecar round trip
- [ ] delete works
- [ ] malformed sidecar decoding handled safely

---

# 3.19 `internal/tosapi/proof_contract_api.go`

## Purpose
Expose restricted contract proof sidecars and restricted-proof metadata over RPC.

## Add methods
- [ ] `func (s *TOSAPI) GetRestrictedContractProofSidecar(ctx context.Context, blockHash common.Hash) (*types.RestrictedContractBatchSidecar, error)`
- [ ] `func (s *TOSAPI) GetTransactionRestrictedProofStatus(ctx context.Context, txHash common.Hash) (map[string]interface{}, error)`
- [ ] optional `func (s *TOSAPI) GetRestrictedProofTraceSummary(ctx context.Context, blockHash common.Hash) (*types.RestrictedContractTraceSummary, error)`

## Required behavior
- [ ] resolve sidecar by block hash
- [ ] locate tx in block and determine restricted proof-covered status
- [ ] return proof type, version, batch index, code hash, and restricted trace summary if appropriate

## Tests
- [ ] block sidecar query works
- [ ] tx restricted proof status query works
- [ ] missing sidecar handled consistently

---

# 3.20 `internal/tosapi/api.go`

## Purpose
Expose restricted-proof metadata in normal block and receipt APIs when sidecar exists.

## Modify methods
- [ ] `RPCMarshalHeader`
- [ ] `RPCMarshalBlock`
- [ ] `GetTransactionReceipt`

## Add response fields when restricted-proof-backed
- [ ] `proofType`
- [ ] `proofVersion`
- [ ] `proofCovered`
- [ ] `proofBatchIndex`
- [ ] optional `restrictedProofCodeHash`

## Rules
- [ ] do not change response shape for legacy blocks unless fields are optional
- [ ] do not expose full witness publicly
- [ ] keep trace summary exposure in proof-specific RPC methods

## Tests
- [ ] legacy RPC responses unchanged
- [ ] restricted-proof block exposes proof metadata
- [ ] restricted-proof receipt exposes proof fields

---

# 3.21 Tests to Add by Package

## `core/types`
- [ ] restricted sidecar encode/decode
- [ ] restricted state diff validation
- [ ] restricted trace summary validation
- [ ] commitment determinism

## `core/rawdb`
- [ ] restricted sidecar write/read/delete
- [ ] malformed restricted sidecar handling
- [ ] block-hash keyed retrieval

## `core/state`
- [ ] apply restricted state diff
- [ ] wrong pre-value rejection
- [ ] deterministic post-root

## `core/vm`
- [ ] proof eligibility classification
- [ ] proof registry lookup
- [ ] forbidden nested call rejection
- [ ] unsupported host call rejection
- [ ] restricted trace extraction

## `core`
- [ ] restricted proof processor path
- [ ] restricted proof validator path
- [ ] blockchain insert restricted proof path
- [ ] negative tests for invalid sidecar cases

## `internal/tosapi`
- [ ] restricted proof RPC methods
- [ ] restricted proof metadata in standard APIs

---

# 4. Required Error Flow

## Processor errors
- [ ] invalid sidecar
- [ ] tx mismatch
- [ ] restricted eligibility mismatch
- [ ] invalid trace summary
- [ ] state diff invalid
- [ ] state diff apply failure

## Validator errors
- [ ] sidecar missing
- [ ] sidecar block hash mismatch
- [ ] unsupported proof type
- [ ] restricted eligibility mismatch
- [ ] forbidden call shape
- [ ] unsupported host call
- [ ] unsupported logs
- [ ] trace commitment mismatch
- [ ] state diff commitment mismatch
- [ ] receipt commitment mismatch
- [ ] post-state root mismatch
- [ ] proof verification failure

## RPC errors
- [ ] restricted proof sidecar not found
- [ ] tx not restricted-proof-covered
- [ ] invalid restricted proof metadata read

---

# 5. Suggested Commit Sequence

## Commit 1
- [ ] `core/types/proof_contract_sidecar.go`
- [ ] `core/types/proof_contract_state_diff.go`
- [ ] `core/types/proof_contract_trace.go`
- [ ] `core/types/proof_contract_errors.go`

## Commit 2
- [ ] `core/vm/proof_eligibility.go`
- [ ] `core/vm/proof_registry.go`

## Commit 3
- [ ] `core/rawdb/schema_proof_contract.go`
- [ ] `core/rawdb/accessors_proof_contract.go`

## Commit 4
- [ ] `core/types/transaction.go`
- [ ] `core/types/receipt.go`

## Commit 5
- [ ] `core/vm/proof_trace.go`
- [ ] `core/vm/proof_trace_contract.go`
- [ ] `core/vm/lvm.go`

## Commit 6
- [ ] `core/state/proof_apply_contract.go`

## Commit 7
- [ ] `core/state_processor_restricted_proof.go`

## Commit 8
- [ ] `core/block_validator_restricted_proof.go`
- [ ] `core/block_validator.go`

## Commit 9
- [ ] `core/blockchain.go`

## Commit 10
- [ ] `internal/tosapi/proof_contract_api.go`
- [ ] `internal/tosapi/api.go`

## Commit 11
- [ ] integration tests
- [ ] metrics/logging polish

---

# 6. Final Exit Criteria

Phase 3 file-by-file implementation is complete when:

- [ ] every new file listed above exists
- [ ] every required struct exists
- [ ] every required function exists
- [ ] rawdb can persist restricted contract proof sidecars
- [ ] blockchain import can branch into restricted proof validation
- [ ] validator no longer replays proof-covered restricted contract txs
- [ ] restricted proven state diff is materialized into `StateDB`
- [ ] restricted trace summary is validated against commitments
- [ ] receipts and gas are validated from sidecar-provided data
- [ ] legacy path remains unchanged
- [ ] Phase 2 transfer proof path remains unchanged
- [ ] RPC exposes restricted-proof metadata
- [ ] unit tests and integration tests pass

---

# 7. Final Summary

This checklist is the implementation decomposition of Phase 3.

The most important engineering fact is:

> **Phase 3 is not only “add restricted proof verification”. It is a coordinated patch across types, VM eligibility, VM trace extraction, rawdb, state materialization, processor, validator, blockchain insertion, and RPC.**

The restricted contract proof path becomes real only when all of these are true at once:

- sidecar exists
- restricted contract eligibility is deterministic
- restricted trace is committed and validated
- proof verifies
- state diff applies deterministically
- post-state root matches
- receipts and gas match
- block imports without contract replay
