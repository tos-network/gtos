# gtos Phase 2
## File-by-File Coding Checklist
### Proof-Backed Transfer Validation for `native-transfer-batch-v1`

## Purpose

This document converts the Phase 2 design into a **file-by-file implementation checklist**.

The scope of Phase 2 is:

- proof-backed validation for:
  - native transfer
  - shield
  - private transfer
  - unshield
- validator does **not** fully replay proof-covered transfer transactions
- validator verifies:
  - proof sidecar
  - tx commitment
  - witness commitment
  - state-diff commitment
  - receipt commitment
- validator materializes proven post-state into a real `StateDB`

This document is written so the engineering team can implement directly, file by file.

---

# 1. Cross-Cutting Phase 2 Rules

Before touching any file, Phase 2 must respect the following rules:

- **No `Header` changes**
- **No proof metadata inside block hash**
- **Use out-of-band sidecar keyed by canonical block hash**
- **No silent downgrade from proof mode to legacy mode**
- **State diff must be materialized into a real `StateDB`**
- **All deterministic data structures must use canonical ordering**
- **Proof-backed blocks in Phase 2 must contain only proof-fast-path tx classes**

---

# 2. New Files and Modified Files Overview

## New files
- `core/types/proof_sidecar.go`
- `core/types/proof_state_diff.go`
- `core/types/proof_commitment.go`
- `core/types/proof_errors.go`
- `core/state/proof_apply.go`
- `core/state_processor_proof.go`
- `core/block_validator_proof.go`
- `core/rawdb/schema_proof.go`
- `core/rawdb/accessors_proof.go`
- `internal/tosapi/proof_api.go`

## Modified files
- `core/blockchain.go`
- `core/block_validator.go`
- `core/types/transaction.go`
- `core/types/receipt.go`
- `internal/tosapi/api.go`

Optional supporting modifications:
- miner-side Phase 1 sidecar writer files
- proof worker artifact persistence files
- test files near each modified package

---

# 3. File-by-File Checklist

# 3.1 `core/types/proof_sidecar.go`

## Purpose
Define the canonical Phase 2 proof sidecar object used by validators, RPC, and storage.

## Add structs
- [ ] `BatchProofSidecar`
- [ ] `ProofCoveredTxRef`
- [ ] `ProofSidecarValidationSummary`

## `BatchProofSidecar` required fields
- [ ] `BlockHash common.Hash`
- [ ] `ProofType string`
- [ ] `ProofVersion uint32`
- [ ] `CircuitVersion string`
- [ ] `PreStateRoot common.Hash`
- [ ] `PostStateRoot common.Hash`
- [ ] `BatchTxCommitment common.Hash`
- [ ] `WitnessCommitment common.Hash`
- [ ] `StateDiffCommitment common.Hash`
- [ ] `ReceiptCommitment common.Hash`
- [ ] `PublicInputsHash common.Hash`
- [ ] `ProofArtifactHash common.Hash`
- [ ] `ProofBytes []byte`
- [ ] `PublicInputs []byte`
- [ ] `ProofCoveredTxs []ProofCoveredTxRef`
- [ ] `CoverageMode string`
- [ ] `UsedGas uint64`
- [ ] `Receipts []*types.Receipt`
- [ ] `StateDiff *ProofBackedTransferStateDiff`
- [ ] `ProverID string`
- [ ] `ProvingTimeMs uint64`

## Add methods/helpers
- [ ] `func (s *BatchProofSidecar) ValidateBasic() error`
- [ ] `func (s *BatchProofSidecar) IsTransferBatchV1() bool`
- [ ] `func (s *BatchProofSidecar) HasProofBytes() bool`

## Add validation rules
- [ ] reject zero `BlockHash`
- [ ] reject empty `ProofType`
- [ ] reject nil `StateDiff`
- [ ] reject nil receipts when proof-backed mode requires receipts
- [ ] reject missing commitments

## Tests
- [ ] sidecar encode/decode round trip
- [ ] `ValidateBasic()` success case
- [ ] `ValidateBasic()` failure cases
- [ ] exact `ProofType == "native-transfer-batch-v1"` check

---

# 3.2 `core/types/proof_state_diff.go`

## Purpose
Define the materializable post-state diff used by the proof-backed validation path.

## Add structs
- [ ] `ProofBackedTransferStateDiff`
- [ ] `ProofBackedAccountDiff`
- [ ] `ProofBackedStorageDiff`
- [ ] `ProofBackedPrivStateDiff`

## Required fields
### `ProofBackedTransferStateDiff`
- [ ] `Accounts []ProofBackedAccountDiff`

### `ProofBackedAccountDiff`
- [ ] `Address common.Address`
- [ ] `PreNonce uint64`
- [ ] `PostNonce uint64`
- [ ] `PreBalance *big.Int`
- [ ] `PostBalance *big.Int`
- [ ] `PrivPreNonce uint64`
- [ ] `PrivPostNonce uint64`
- [ ] `StorageDiffs []ProofBackedStorageDiff`
- [ ] `PrivStateDiffs []ProofBackedPrivStateDiff`

### `ProofBackedStorageDiff`
- [ ] `Key common.Hash`
- [ ] `Pre common.Hash`
- [ ] `Post common.Hash`

### `ProofBackedPrivStateDiff`
- [ ] `Key []byte`
- [ ] `Pre []byte`
- [ ] `Post []byte`

## Add methods/helpers
- [ ] `func (d *ProofBackedTransferStateDiff) ValidateBasic() error`
- [ ] `func (d *ProofBackedTransferStateDiff) SortCanonical()`
- [ ] `func (d *ProofBackedTransferStateDiff) HasDuplicateEntries() error`

## Validation rules
- [ ] duplicate account entries forbidden
- [ ] duplicate storage keys in one account forbidden
- [ ] duplicate private keys in one account forbidden
- [ ] nil balances forbidden where balance change is declared
- [ ] all arrays canonical-sortable

## Tests
- [ ] canonical sort determinism
- [ ] duplicate account rejection
- [ ] duplicate storage key rejection
- [ ] duplicate private key rejection
- [ ] basic valid diff acceptance

---

# 3.3 `core/types/proof_commitment.go`

## Purpose
Derive all deterministic commitments required by Phase 2.

## Add functions
- [ ] `func DeriveBatchTxCommitment(txs Transactions) (common.Hash, error)`
- [ ] `func DeriveProofReceiptCommitment(receipts Receipts) (common.Hash, error)`
- [ ] `func DeriveStateDiffCommitment(diff *ProofBackedTransferStateDiff) (common.Hash, error)`
- [ ] `func DeriveProofCoveredTxCommitment(refs []ProofCoveredTxRef) (common.Hash, error)`

## Commitment rules
### `DeriveBatchTxCommitment`
- [ ] include tx index
- [ ] include tx type
- [ ] include tx hash
- [ ] preserve exact block order

### `DeriveProofReceiptCommitment`
- [ ] include tx hash
- [ ] include status
- [ ] include gas used
- [ ] include cumulative gas used
- [ ] include tx index
- [ ] keep encoding canonical

### `DeriveStateDiffCommitment`
- [ ] canonical sort before encode
- [ ] include address
- [ ] include pre/post nonce
- [ ] include pre/post balance
- [ ] include storage diffs
- [ ] include private diffs

## Tests
- [ ] tx commitment determinism
- [ ] tx commitment changes when tx order changes
- [ ] receipt commitment determinism
- [ ] state diff commitment determinism
- [ ] state diff commitment changes when any diff field changes

---

# 3.4 `core/types/proof_errors.go`

## Purpose
Define stable error values for proof-backed validation.

## Add errors
- [ ] `ErrMissingProofSidecar`
- [ ] `ErrUnsupportedProofType`
- [ ] `ErrUnsupportedProofVersion`
- [ ] `ErrProofCoveredTxMismatch`
- [ ] `ErrProofTxCommitmentMismatch`
- [ ] `ErrProofWitnessCommitmentMismatch`
- [ ] `ErrProofStateDiffCommitmentMismatch`
- [ ] `ErrProofReceiptCommitmentMismatch`
- [ ] `ErrProofPostStateRootMismatch`
- [ ] `ErrProofVerificationFailed`
- [ ] `ErrProofUnsupportedTxType`
- [ ] `ErrProofStateDiffPreValueMismatch`

## Tests
- [ ] error identity tests where useful
- [ ] errors are used by validator and processor paths consistently

---

# 3.5 `core/types/transaction.go`

## Purpose
Mark proof-fast-path eligible transactions for Phase 2.

## Add enum or import
- [ ] use `ProofAdmissionClass` from `proof_class.go`

## Add methods
- [ ] `func (tx *Transaction) ProofClass() ProofAdmissionClass`
- [ ] `func (tx *Transaction) IsProofFastPath() bool`

## Classification rules
- [ ] native transfer => `ProofFastPathTransfer`
- [ ] `ShieldTx` => `ProofFastPathTransfer`
- [ ] `PrivTransferTx` => `ProofFastPathTransfer`
- [ ] `UnshieldTx` => `ProofFastPathTransfer`
- [ ] all others => `ProofLegacyPath`

## Tests
- [ ] each supported tx type classified correctly
- [ ] unsupported tx types classified as legacy
- [ ] nil/zero tx handling if needed

---

# 3.6 `core/types/receipt.go`

## Purpose
Attach proof metadata to receipts used by RPC and storage-layer consumers.

## Add fields to `Receipt`
These should be implementation-layer fields, not consensus fields.

- [ ] `ProofCovered bool`
- [ ] `ProofBatchIndex uint32`
- [ ] `ProofType string`
- [ ] `ProofTraceDigest common.Hash` or equivalent optional field

## Add helper methods
- [ ] `func (r *Receipt) MarkProofCovered(batchIndex uint32, proofType string)`
- [ ] `func (r *Receipt) IsProofCovered() bool`

## Persistence decision
- [ ] decide whether Phase 2 stores proof receipt fields in DB or derives them from sidecar at query time
- [ ] recommended: derive from sidecar at query time to avoid breaking legacy receipt encoding

## Tests
- [ ] proof metadata is set correctly
- [ ] receipt commitment does not accidentally depend on non-canonical fields unless intended
- [ ] legacy receipt encoding remains unaffected

---

# 3.7 `core/rawdb/schema_proof.go`

## Purpose
Define rawdb key schema for proof sidecars and optional proof artifacts.

## Add key builders
- [ ] `func proofSidecarKey(blockHash common.Hash) []byte`
- [ ] `func proofArtifactKey(artifactHash common.Hash) []byte` (optional)

## Rules
- [ ] sidecar key must be block-hash keyed
- [ ] do not key by block number only
- [ ] keep schema distinct from header/body/receipt namespace

## Tests
- [ ] key uniqueness
- [ ] stable prefix expectations if required by iterators

---

# 3.8 `core/rawdb/accessors_proof.go`

## Purpose
Implement rawdb persistence for proof sidecars.

## Add functions
- [ ] `func ReadBlockProofSidecar(db tosdb.KeyValueReader, blockHash common.Hash) *types.BatchProofSidecar`
- [ ] `func WriteBlockProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash, sidecar *types.BatchProofSidecar)`
- [ ] `func DeleteBlockProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash)`
- [ ] `func HasBlockProofSidecar(db tosdb.Reader, blockHash common.Hash) bool`

Optional:
- [ ] `func ReadProofArtifact(db tosdb.KeyValueReader, artifactHash common.Hash) []byte`
- [ ] `func WriteProofArtifact(db tosdb.KeyValueWriter, artifactHash common.Hash, blob []byte)`
- [ ] `func DeleteProofArtifact(db tosdb.KeyValueWriter, artifactHash common.Hash)`

## Encoding decision
- [ ] use RLP or another canonical encoding consistently
- [ ] recommended: RLP for consistency with chain storage

## Tests
- [ ] write/read sidecar round trip
- [ ] has sidecar works
- [ ] delete sidecar works
- [ ] malformed sidecar decoding handled safely

---

# 3.9 `core/state/proof_apply.go`

## Purpose
Apply proven state diffs to a fresh `StateDB` without replaying transactions.

## Add functions
- [ ] `func ApplyProofBackedTransferStateDiff(statedb *StateDB, diff *types.ProofBackedTransferStateDiff) error`
- [ ] `func applyProofBackedAccountDiff(statedb *StateDB, diff *types.ProofBackedAccountDiff) error`
- [ ] `func verifyAccountPreValues(statedb *StateDB, diff *types.ProofBackedAccountDiff) error`
- [ ] `func applyProofBackedStorageDiffs(statedb *StateDB, addr common.Address, diffs []types.ProofBackedStorageDiff) error`
- [ ] `func applyProofBackedPrivStateDiffs(statedb *StateDB, addr common.Address, diffs []types.ProofBackedPrivStateDiff) error`

## Required behavior
- [ ] sort accounts canonically before apply
- [ ] sort storage diffs canonically before apply
- [ ] sort private diffs canonically before apply
- [ ] verify pre-values before applying post-values
- [ ] reject mismatches
- [ ] reject duplicate entries
- [ ] apply nonce changes
- [ ] apply balance changes
- [ ] apply storage changes
- [ ] apply private-state changes

## Open implementation detail
- [ ] decide exact private-state setter/getter usage based on current `gtos` private state layout

## Tests
- [ ] successful state diff apply
- [ ] wrong pre-balance rejection
- [ ] wrong pre-nonce rejection
- [ ] wrong pre-storage rejection
- [ ] duplicate entry rejection
- [ ] resulting `IntermediateRoot(true)` matches expected root in test vector

---

# 3.10 `core/state_processor_proof.go`

## Purpose
Provide the processor path for proof-backed transfer blocks.

## Add functions
- [ ] `func (p *StateProcessor) ProcessProofBackedTransferBlock(block *types.Block, parent *types.Header, sidecar *types.BatchProofSidecar) (types.Receipts, uint64, *state.StateDB, error)`
- [ ] `func (p *StateProcessor) materializeProofBackedTransferReceipts(sidecar *types.BatchProofSidecar) (types.Receipts, error)`
- [ ] `func (p *StateProcessor) validateProofBackedTxSet(block *types.Block, sidecar *types.BatchProofSidecar) error`

## Required behavior
- [ ] allocate fresh `StateDB` from `parent.Root`
- [ ] validate sidecar structure
- [ ] validate block tx set matches `ProofCoveredTxs`
- [ ] materialize receipts from sidecar
- [ ] apply state diff
- [ ] return `(receipts, usedGas, statedb, nil)` without replaying transactions

## Must not do
- [ ] do not call ordinary tx execution for proof-covered transfer blocks
- [ ] do not mutate canonical state before all checks pass

## Tests
- [ ] happy path: proof-backed native transfer block
- [ ] mismatched tx set rejected
- [ ] invalid sidecar rejected
- [ ] post-state root later matches validator expectation

---

# 3.11 `core/block_validator_proof.go`

## Purpose
Implement proof-backed transfer validation logic.

## Add structs
- [ ] `ProofValidationInputs`
- [ ] `ProofValidationResult`

## Add interface
- [ ] `BatchProofVerifier`

## Add functions
- [ ] `func (v *BlockValidator) ValidateStateProofBackedTransfer(block *types.Block, parentRoot common.Hash, sidecar *types.BatchProofSidecar, receipts types.Receipts, usedGas uint64) error`
- [ ] `func (v *BlockValidator) validateProofSidecarBinding(block *types.Block, sidecar *types.BatchProofSidecar) error`
- [ ] `func (v *BlockValidator) validateProofCoveredTxs(block *types.Block, sidecar *types.BatchProofSidecar) error`
- [ ] `func (v *BlockValidator) validateProofReceiptCommitment(block *types.Block, sidecar *types.BatchProofSidecar, receipts types.Receipts) error`
- [ ] `func (v *BlockValidator) validateProofStateDiffCommitment(sidecar *types.BatchProofSidecar) error`
- [ ] `func (v *BlockValidator) validateProofGas(block *types.Block, sidecar *types.BatchProofSidecar, receipts types.Receipts, usedGas uint64) error`

## Required validation steps
- [ ] sidecar exists
- [ ] sidecar basic validation passes
- [ ] `ProofType == native-transfer-batch-v1`
- [ ] block hash matches sidecar
- [ ] post-state root matches block root
- [ ] all txs are proof-fast-path eligible
- [ ] `ProofCoveredTxs` matches exact tx list
- [ ] tx commitment matches
- [ ] receipt commitment matches
- [ ] state diff commitment matches
- [ ] proof verification passes
- [ ] gas checks pass
- [ ] bloom and receipt root checks pass

## Tests
- [ ] happy path accept
- [ ] missing sidecar reject
- [ ] unsupported proof type reject
- [ ] unsupported tx type reject
- [ ] tx commitment mismatch reject
- [ ] receipt commitment mismatch reject
- [ ] state diff commitment mismatch reject
- [ ] post-state root mismatch reject
- [ ] proof verification failure reject

---

# 3.12 `core/block_validator.go`

## Purpose
Introduce a proof-aware entry point while preserving legacy validation.

## Add function
- [ ] `func (v *BlockValidator) ValidateStateProofAware(block *types.Block, parentRoot common.Hash, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error`

## Behavior
- [ ] if no sidecar exists => call existing `ValidateState(...)`
- [ ] if sidecar exists => call `ValidateStateProofBackedTransfer(...)`

## Optional refactor
- [ ] keep existing `ValidateState(...)` unchanged
- [ ] use proof-aware wrapper from `core/blockchain.go`

## Tests
- [ ] legacy path unchanged
- [ ] proof path dispatch works
- [ ] no accidental silent downgrade

---

# 3.13 `core/blockchain.go`

## Purpose
Change canonical block import flow to branch before local execution for proof-backed transfer blocks.

## Add helper functions
- [ ] `func (bc *BlockChain) loadProofSidecar(blockHash common.Hash) (*types.BatchProofSidecar, error)`
- [ ] `func (bc *BlockChain) shouldUseProofBackedTransferValidation(block *types.Block, sidecar *types.BatchProofSidecar) bool`

## Modify insert path in `insertChain(...)`
Current path:
- load parent state
- call `bc.processor.Process(...)`
- call `bc.validator.ValidateState(...)`

Phase 2 path:
- [ ] resolve sidecar by block hash
- [ ] if no sidecar => legacy flow
- [ ] if sidecar and supported proof mode => proof-backed flow

## New proof-backed branch
- [ ] call `ProcessProofBackedTransferBlock(...)`
- [ ] call `ValidateStateProofBackedTransfer(...)`
- [ ] continue with existing `writeBlockWithState(...)`
- [ ] continue with existing `writeBlockAndSetHead(...)`

## New errors to propagate
- [ ] missing sidecar
- [ ] unsupported proof type
- [ ] proof validation failure
- [ ] state diff materialization failure

## Tests
- [ ] legacy block import unchanged
- [ ] proof-backed transfer block import works
- [ ] proof-backed invalid block rejected
- [ ] state commit path still works after proof branch
- [ ] reorg path unaffected for non-proof blocks

---

# 3.14 `internal/tosapi/proof_api.go`

## Purpose
Expose proof sidecar and proof-backed metadata over RPC.

## Add methods
- [ ] `func (s *TOSAPI) GetBlockProofSidecar(ctx context.Context, blockHash common.Hash) (*types.BatchProofSidecar, error)`
- [ ] `func (s *TOSAPI) GetTransactionProofStatus(ctx context.Context, txHash common.Hash) (map[string]interface{}, error)`
- [ ] optional `func (s *TOSAPI) GetProofStateDiff(ctx context.Context, blockHash common.Hash) (*types.ProofBackedTransferStateDiff, error)`

## Required behavior
- [ ] resolve sidecar by block hash
- [ ] locate tx in block and determine proof-covered status
- [ ] return proof type, version, batch index, and sidecar summary

## Tests
- [ ] block sidecar query works
- [ ] tx proof status query works
- [ ] missing sidecar returns nil/not found consistently

---

# 3.15 `internal/tosapi/api.go`

## Purpose
Expose proof metadata in normal block and receipt APIs when sidecar exists.

## Modify methods
- [ ] `RPCMarshalHeader`
- [ ] `RPCMarshalBlock`
- [ ] `GetTransactionReceipt`

## Add response fields when proof-backed
- [ ] `proofType`
- [ ] `proofVersion`
- [ ] `proofCovered`
- [ ] `proofBatchIndex`

## Rules
- [ ] do not change response shape for legacy blocks unless fields are optional
- [ ] do not expose full witness publicly
- [ ] optionally gate `StateDiff` exposure behind proof-specific RPC only

## Tests
- [ ] legacy RPC responses unchanged
- [ ] proof-backed block exposes proof metadata
- [ ] proof-backed receipt exposes proof fields

---

# 3.16 Tests to Add by Package

## `core/types`
- [ ] sidecar encode/decode
- [ ] state diff validation
- [ ] tx commitment determinism
- [ ] receipt commitment determinism
- [ ] state diff commitment determinism

## `core/rawdb`
- [ ] sidecar write/read/delete
- [ ] malformed sidecar handling
- [ ] block-hash keyed retrieval

## `core/state`
- [ ] apply proof-backed state diff
- [ ] pre-value mismatch rejection
- [ ] deterministic root after apply

## `core`
- [ ] processor proof path
- [ ] validator proof path
- [ ] blockchain insert proof path
- [ ] negative tests for invalid sidecar cases

## `internal/tosapi`
- [ ] proof RPC methods
- [ ] proof metadata in standard APIs

---

# 4. Required Error Flow

## Processor errors
- [ ] invalid sidecar
- [ ] tx mismatch
- [ ] state diff invalid
- [ ] state diff apply failure

## Validator errors
- [ ] sidecar missing
- [ ] sidecar block hash mismatch
- [ ] tx commitment mismatch
- [ ] receipt commitment mismatch
- [ ] state diff commitment mismatch
- [ ] post-state root mismatch
- [ ] proof verification failure
- [ ] unsupported tx type in proof block

## RPC errors
- [ ] proof sidecar not found
- [ ] tx not proof-covered
- [ ] invalid proof metadata read

---

# 5. Suggested Commit Sequence

## Commit 1
- [ ] `core/types/proof_sidecar.go`
- [ ] `core/types/proof_state_diff.go`
- [ ] `core/types/proof_commitment.go`
- [ ] `core/types/proof_errors.go`

## Commit 2
- [ ] `core/rawdb/schema_proof.go`
- [ ] `core/rawdb/accessors_proof.go`

## Commit 3
- [ ] `core/types/transaction.go`
- [ ] `core/types/receipt.go`

## Commit 4
- [ ] `core/state/proof_apply.go`

## Commit 5
- [ ] `core/state_processor_proof.go`

## Commit 6
- [ ] `core/block_validator_proof.go`
- [ ] `core/block_validator.go`

## Commit 7
- [ ] `core/blockchain.go`

## Commit 8
- [ ] `internal/tosapi/proof_api.go`
- [ ] `internal/tosapi/api.go`

## Commit 9
- [ ] integration tests
- [ ] metrics/logging polish

---

# 6. Final Exit Criteria

Phase 2 file-by-file implementation is complete when:

- [ ] every new file listed above exists
- [ ] every required struct exists
- [ ] every required function exists
- [ ] rawdb can persist proof sidecars
- [ ] blockchain import can branch into proof-backed transfer validation
- [ ] validator no longer replays proof-covered transfer txs
- [ ] proven state diff is materialized into `StateDB`
- [ ] receipts and gas are validated from sidecar-provided data
- [ ] legacy path remains unchanged
- [ ] RPC exposes proof-backed metadata
- [ ] unit tests and integration tests pass

---

# 7. Final Summary

This checklist is the implementation decomposition of Phase 2.

The most important engineering fact is:

> **Phase 2 is not only “add a verifier”. It is a coordinated patch across types, rawdb, state materialization, processor, validator, blockchain insertion, and RPC.**

The proof-backed transfer path becomes real only when all of these are true at once:

- sidecar exists
- commitments are derivable
- proof verifies
- state diff applies deterministically
- post-state root matches
- receipts and gas match
- block imports without tx replay
