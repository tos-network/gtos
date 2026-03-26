# gtos Phase 2 Design
## Proof-Backed Transfer Validation
### Detailed Implementation Design for `native-transfer-batch-v1`

## Status

**Document status:** design-ready  
**Target audience:** core protocol engineers working on `gtos`  
**Language:** English  
**Scope:** detailed enough to implement directly

---

# 1. Purpose

This document defines **Phase 2** of the Gigagas L1 roadmap for `gtos`.

Phase 1 established the proving pipeline in **shadow mode**:

- proof-eligible transfer batches
- deterministic witness export
- proof sidecar generation
- proof artifact persistence
- proof-aware observability

However, in Phase 1, validators still follow the classical `gtos` execution model:

- execute transactions locally
- derive receipts locally
- derive post-state root locally
- compare local results against block header fields

That is still the current architecture in `gtos` today:

- `InsertChain(...)` executes blocks through `bc.processor.Process(...)`
- then validates them through `bc.validator.ValidateState(...)`
- then writes the block and committed state via `writeBlockWithState(...)` and `writeBlockAndSetHead(...)`

This document defines the next step:

> **Phase 2 introduces a proof-backed transfer validation path for proof-covered transfer batches, allowing validators to stop fully re-executing those proof-covered transfer transactions.**

This is the first real step toward a Gigagas-style L1 validation model.

---

# 2. Core Objective

Phase 2 changes validator behavior for a narrow transaction class:

- native transfer
- shield
- private transfer
- unshield

For blocks that carry a valid **proof sidecar** of type `native-transfer-batch-v1`, validators should:

- **not re-execute the proof-covered transfer batch**
- **verify the batch proof and public inputs**
- **verify the commitments and metadata**
- **materialize and commit the proven post-state transition**
- **still preserve compatibility with the existing chain model**

This is **not** full zkVM / full-contract validation.  
It is a **transfer-only proof-backed validation mode**.

---

# 3. Non-Goals

Phase 2 does **not** attempt to:

- prove arbitrary LVM / Lua contract execution
- replace all validator execution with proof verification
- move proof data into canonical header hashing
- require a hard fork that changes `Header` encoding
- prove dynamic contract storage semantics
- prove logs from arbitrary contract calls

Phase 2 is intentionally narrow and should remain narrow.

---

# 4. Current Architecture and Why It Must Change

## 4.1 Current validator behavior

Today, the canonical block import path is:

1. `BlockChain.InsertChain(...)`
2. `bc.processor.Process(block, statedb)`
3. `bc.validator.ValidateState(block, statedb, receipts, usedGas)`
4. `bc.writeBlockWithState(block, receipts, statedb)`
5. `bc.writeBlockAndSetHead(...)`

This means validators still need:

- full transaction execution
- full receipt generation
- full post-state derivation

The key files involved are:

- `core/blockchain.go`
- `core/block_validator.go`

## 4.2 Why Phase 1 was not enough

Phase 1 generated:

- witnesses
- proof artifacts
- sidecars
- RPC visibility

But validators still used:

- `processor.Process(...)`
- `ValidateState(...)`

Therefore, Phase 1 did **not** reduce validator execution cost.

## 4.3 What Phase 2 must introduce

Phase 2 must add a genuine alternate validation branch:

- **legacy branch**
- **proof-backed transfer branch**

In the proof-backed transfer branch:

- validators do not replay the proof-covered transfer batch
- validators verify proof sidecar data
- validators validate the post-state commitment transition

This is the first point where validator execution cost can meaningfully drop.

---

# 5. Architectural Decision

## Phase 2 continues to use out-of-band sidecars

Phase 2 does **not** modify the canonical `Header` struct.

Proof metadata remains in an **out-of-band proof sidecar**, keyed by canonical block hash.

This is intentional because:

- changing `Header` changes `Header.Hash()`
- changing `Header` changes canonical block hashing
- changing `Header` requires regenerated RLP/JSON code
- changing `Header` is a consensus object change and should not happen in this phase

Therefore, Phase 2 continues this rule:

> **The canonical block remains unchanged. Proof validation data is carried in a block-hash-keyed proof sidecar.**

---

# 6. High-Level Validator Model in Phase 2

## 6.1 Legacy block

If a block has no proof sidecar:

- validator uses existing execution flow
- no behavior change

## 6.2 Proof-backed transfer block

If a block has a sidecar of type `native-transfer-batch-v1`:

- validator loads the sidecar
- validator verifies the proof artifact
- validator checks public inputs and commitments
- validator **does not** locally replay the proof-covered transfer batch
- validator reconstructs the proven execution outputs needed for persistence

## 6.3 Mixed block model

Phase 2 should support only one of the following two policies.

### Recommended Phase 2 policy

A `native-transfer-batch-v1` proof-backed block may contain only:

- proof-covered transfer-class transactions
- optional system tasks explicitly declared as out-of-scope or excluded from proof coverage

It should **not** mix:

- proof-covered transfers
- arbitrary contracts

inside the same proof-backed block.

This keeps validation logic much simpler.

---

# 7. Required Functional Outcome

Phase 2 is complete when a validator can do the following:

1. Receive a block `B`
2. Resolve block hash `H = B.Hash()`
3. Load `sidecar(H)`
4. Verify:
   - sidecar type
   - sidecar version
   - proof artifact
   - public inputs
   - pre-state root
   - post-state root
   - tx commitment
   - witness commitment
   - state-diff commitment
   - receipt commitment
5. Confirm that all transactions in the block are proof-eligible for `native-transfer-batch-v1`
6. Materialize the proven post-state into a real `StateDB`
7. Accept the block without replaying the proof-covered transfer transactions

---

# 8. Detailed Design

# 8.1 Proof Sidecar Data Model

## New file

- `core/types/proof_sidecar.go`

## Required structs

### `BatchProofSidecar`

```go
type BatchProofSidecar struct {
    BlockHash            common.Hash
    ProofType            string
    ProofVersion         uint32
    CircuitVersion       string

    PreStateRoot         common.Hash
    PostStateRoot        common.Hash
    BatchTxCommitment    common.Hash
    WitnessCommitment    common.Hash
    StateDiffCommitment  common.Hash
    ReceiptCommitment    common.Hash
    PublicInputsHash     common.Hash

    ProofArtifactHash    common.Hash
    ProofBytes           []byte
    PublicInputs         []byte

    ProofCoveredTxs      []ProofCoveredTxRef
    CoverageMode         string

    UsedGas              uint64
    Receipts             []*types.Receipt
    StateDiff            *ProofBackedTransferStateDiff

    ProverID             string
    ProvingTimeMs        uint64
}
```

### `ProofCoveredTxRef`

```go
type ProofCoveredTxRef struct {
    TxHash      common.Hash
    Index       uint32
    TxType      uint8
}
```

### `ProofSidecarValidationSummary`

```go
type ProofSidecarValidationSummary struct {
    ProofType            string
    ProofVersion         uint32
    BlockHash            common.Hash
    PreStateRoot         common.Hash
    PostStateRoot        common.Hash
    BatchTxCommitment    common.Hash
    WitnessCommitment    common.Hash
    StateDiffCommitment  common.Hash
    ReceiptCommitment    common.Hash
}
```

## Rules

- `BlockHash` must equal canonical block hash
- `PostStateRoot` must equal `block.Root()`
- `ProofCoveredTxs` must match the exact proof-covered tx set in the block
- `ProofType` for this phase must be exactly `native-transfer-batch-v1`

---

# 8.2 RawDB Persistence for Proof Sidecars

## New files

- `core/rawdb/schema_proof.go`
- `core/rawdb/accessors_proof.go`

## New keys

Recommended:

- `proofSidecarKey(blockHash common.Hash) []byte`
- `proofArtifactKey(artifactHash common.Hash) []byte`

## Required functions

```go
func ReadBlockProofSidecar(db tosdb.KeyValueReader, blockHash common.Hash) *types.BatchProofSidecar
func WriteBlockProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash, sidecar *types.BatchProofSidecar)
func DeleteBlockProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash)
func HasBlockProofSidecar(db tosdb.Reader, blockHash common.Hash) bool
```

Optional if artifact split is desired:

```go
func ReadProofArtifact(db tosdb.KeyValueReader, artifactHash common.Hash) []byte
func WriteProofArtifact(db tosdb.KeyValueWriter, artifactHash common.Hash, blob []byte)
func DeleteProofArtifact(db tosdb.KeyValueWriter, artifactHash common.Hash)
```

## Phase 2 recommendation

Store the entire `BatchProofSidecar` as the primary lookup object:

- keyed by `blockHash`
- single read for validator
- single read for RPC

Avoid over-normalizing storage in Phase 2.

---

# 8.3 Proof Eligibility Rules

## New file

- `core/types/proof_class.go`

## Required enum

```go
type ProofAdmissionClass uint8

const (
    ProofAdmissionUnknown ProofAdmissionClass = iota
    ProofFastPathTransfer
    ProofLegacyPath
)
```

## Required transaction helper

```go
func (tx *Transaction) ProofClass() ProofAdmissionClass
func (tx *Transaction) IsProofFastPath() bool
```

## Phase 2 rule

The proof-backed validation path is allowed only if **all block transactions** are in the supported proof class set for `native-transfer-batch-v1`.

Supported tx classes:

- native transfer transaction
- `ShieldTx`
- `PrivTransferTx`
- `UnshieldTx`

Unsupported:

- arbitrary contract call
- deployment
- tx types not explicitly whitelisted

If any tx in the block is unsupported:

- validator must reject the proof-backed path for that block
- do not silently downgrade to legacy mode

---

# 8.4 Batch Tx Commitment

## Purpose

Validators must confirm that the proof was generated for the exact tx sequence in the block.

## Required helper

New file:

- `core/types/proof_commitment.go` or `core/state/proof_commitment.go`

### Function

```go
func DeriveBatchTxCommitment(txs types.Transactions) (common.Hash, error)
```

## Rules

- use deterministic transaction ordering exactly as block body order
- do not reorder txs
- include tx hash, tx type, and index in commitment input
- privacy tx order must remain serial and canonical

### Suggested encoding

For each tx:

- `index`
- `tx.Type()`
- `tx.Hash()`

Hash over concatenation or RLP list.

---

# 8.5 Witness Commitment

## Purpose

Validators do not need the full witness in Phase 2, but they must bind proof verification to a committed witness.

## Function

```go
func DeriveWitnessCommitment(w *state.BatchWitness) (common.Hash, error)
```

## Rule

The witness commitment must be:

- deterministic
- canonical
- versioned

---

# 8.6 Receipt Commitment

## Purpose

Even if validators do not re-execute the transfer batch, they still need a committed receipt view.

## Required helper

```go
func DeriveProofReceiptCommitment(receipts types.Receipts) (common.Hash, error)
```

## Recommendation

Phase 2 receipt commitment should include:

- receipt status
- tx hash
- tx index
- cumulative gas used
- gas used
- proof metadata fields if present

Logs for Phase 2 transfer-only batches should be:

- either forbidden
- or reduced to a minimal deterministic model

### Recommended Phase 2 simplification

For `native-transfer-batch-v1`, do **not** allow arbitrary dynamic logs beyond those already guaranteed by the proof model.

---

# 8.7 Validator Proof Verification Interface

## New file

- `core/block_validator_proof.go`

## Existing infrastructure reference

gtos already has a pluggable proof verifier registry in `sysaction/oracle_hooks.go` (`RegisterProofVerifier()`, `RegisterProofVerifierAddress()`). The `BatchProofVerifier` implementation should be registered through this mechanism so that proof verification dispatch is consistent with the existing oracle/proof hook pattern.

The `BatchVerifier` pattern in `core/priv/batch_verify.go` (accumulate proof terms → single `Verify()` call) should inform the `VerifyTransferBatchProof` implementation: accumulate public inputs and commitment checks, then perform a single cryptographic verification.

## New interface

```go
type BatchProofVerifier interface {
    VerifyTransferBatchProof(inputs *ProofValidationInputs) error
}
```

## New structs

```go
type ProofValidationInputs struct {
    Block               *types.Block
    Sidecar             *types.BatchProofSidecar
    ParentRoot          common.Hash
    TxCommitment        common.Hash
    WitnessCommitment   common.Hash
    StateDiffCommitment common.Hash
    ReceiptCommitment   common.Hash
}
```

```go
type ProofValidationResult struct {
    BlockHash           common.Hash
    PostStateRoot       common.Hash
    ReceiptCommitment   common.Hash
    StateDiffCommitment common.Hash
}
```

---

# 8.8 Validator Branching Logic

## Existing file

- `core/block_validator.go`

## New functions

```go
func (v *BlockValidator) ValidateStateProofAware(
    block *types.Block,
    parentRoot common.Hash,
    statedb *state.StateDB,
    receipts types.Receipts,
    usedGas uint64,
) error
```

```go
func (v *BlockValidator) ValidateStateProofBackedTransfer(
    block *types.Block,
    parentRoot common.Hash,
    sidecar *types.BatchProofSidecar,
    receipts types.Receipts,
    usedGas uint64,
) error
```

## Behavior

### Case A — no sidecar

Use existing path:

```go
return v.ValidateState(block, statedb, receipts, usedGas)
```

### Case B — sidecar exists

Use proof path:

1. load sidecar by block hash
2. validate sidecar structure
3. validate tx eligibility
4. validate commitments
5. verify proof
6. verify `PostStateRoot == block.Root()`
7. verify `BatchTxCommitment`
8. verify `WitnessCommitment`
9. verify `StateDiffCommitment`
10. verify `ReceiptCommitment`
11. accept block without replaying proof-covered transfer txs

---

# 8.9 New Import Path in `BlockChain.InsertChain`

## Existing file

- `core/blockchain.go`

Today the path is:

- allocate state from parent root
- `processor.Process(block, statedb)`
- `validator.ValidateState(...)`

Phase 2 must introduce a branch **before local execution of proof-covered transfer blocks**.

## New top-level flow

### Proposed import decision function

```go
func (bc *BlockChain) shouldUseProofBackedTransferValidation(block *types.Block) bool
```

### Proposed behavior

For each block in `insertChain(...)`:

#### If no sidecar:

- keep existing flow

#### If sidecar present and type is `native-transfer-batch-v1`:

- do **not** call `bc.processor.Process(...)` for the proof-covered transfer batch
- instead call:

```go
receipts, usedGas, statedb, err := bc.processor.ProcessProofBackedTransferBlock(block, parent, sidecar)
```

- then call:

```go
err = bc.validator.ValidateStateProofBackedTransfer(block, parent.Root, sidecar, receipts, usedGas)
```

This requires a new processor path.

---

# 8.10 New Processor Path for Proof-Backed Transfer Blocks

## New file

- `core/state_processor_proof.go`

## New function

```go
func (p *StateProcessor) ProcessProofBackedTransferBlock(
    block *types.Block,
    parent *types.Header,
    sidecar *types.BatchProofSidecar,
) (types.Receipts, uint64, *state.StateDB, error)
```

## Required choice

**Phase 2 must verify the proof and then re-materialize post-state by applying a proven state diff.**

Because `gtos` still writes actual state to DB through:

- `writeBlockWithState(...)`
- `state.Commit(true)`

validators still need a real `StateDB` instance representing the post-state of the block.

Therefore, the proof sidecar must include a materializable state diff for the proof-covered batch.

---

# 8.11 State Diff Materialization

## New sidecar field

Add to `BatchProofSidecar`:

```go
StateDiff *ProofBackedTransferStateDiff
```

## New file

- `core/types/proof_state_diff.go`

## New structs

```go
type ProofBackedTransferStateDiff struct {
    Accounts []ProofBackedAccountDiff
}
```

```go
type ProofBackedAccountDiff struct {
    Address          common.Address
    PreNonce         uint64
    PostNonce        uint64
    PreBalance       *big.Int
    PostBalance      *big.Int

    PrivPreNonce     uint64
    PrivPostNonce    uint64

    StorageDiffs     []ProofBackedStorageDiff
    PrivStateDiffs   []ProofBackedPrivStateDiff
}
```

```go
type ProofBackedStorageDiff struct {
    Key   common.Hash
    Pre   common.Hash
    Post  common.Hash
}
```

```go
type ProofBackedPrivStateDiff struct {
    Key   []byte
    Pre   []byte
    Post  []byte
}
```

## Rule

The proof must bind to this exact state diff by commitment.

### New sidecar field

```go
StateDiffCommitment common.Hash
```

## Validator responsibilities

- verify proof
- verify `StateDiffCommitment`
- apply the state diff to a fresh `StateDB` rooted at parent root
- derive resulting `PostStateRoot`
- confirm it equals `block.Root()`

This is the critical bridge between:

- no full tx replay
- still having a real state trie to commit

---

# 8.12 Processor Materialization Logic

## Required function

```go
func ApplyProofBackedTransferStateDiff(
    statedb *state.StateDB,
    diff *types.ProofBackedTransferStateDiff,
) error
```

## New file

- `core/state/proof_apply.go`

## Required checks

Before applying each diff entry:

- confirm pre-values match current state
- apply post-values
- ensure no duplicate account entries
- ensure no duplicate storage keys inside one account
- ensure deterministic application order

## Deterministic order

Always sort:

- accounts by address
- storage diffs by key
- private diffs by key

## Why

Even though the sidecar is out-of-band, state application must remain deterministic.

---

# 8.13 Receipt Materialization for Proof-Backed Transfer Blocks

Because validators will not replay the txs, receipts must be explicit.

### Required choice for Phase 2

**Use sidecar-supplied receipts with commitment binding.**

Add:

```go
Receipts []*types.Receipt
```

to the sidecar, plus:

```go
ReceiptCommitment common.Hash
```

## Validator logic

- load sidecar receipts
- derive commitment
- compare to `sidecar.ReceiptCommitment`
- derive receipt root
- compare to `block.ReceiptHash`
- derive bloom
- compare to block header bloom
- compare gas usage against block header gas used

This keeps receipt behavior explicit and avoids trying to infer receipts from diff semantics.

---

# 8.14 UsedGas Handling

## Rule

For proof-backed transfer blocks:

- `usedGas` is taken from sidecar receipts / sidecar summary
- validator verifies:
  - `block.GasUsed() == sidecar.UsedGas`
  - receipt commitment matches
  - cumulative gas matches receipts
- validator does **not** recompute gas by replaying tx execution

Add field:

```go
UsedGas uint64
```

to `BatchProofSidecar`.

---

# 8.15 Detailed Validator Algorithm

## New function

```go
func (v *BlockValidator) ValidateStateProofBackedTransfer(
    block *types.Block,
    parentRoot common.Hash,
    sidecar *types.BatchProofSidecar,
    receipts types.Receipts,
    usedGas uint64,
) error
```

## Algorithm

### Step 1 — sidecar existence

- load sidecar by `block.Hash()`
- reject if missing

### Step 2 — type/version checks

- `ProofType == "native-transfer-batch-v1"`
- supported proof version
- supported circuit version

### Step 3 — block/sidecar binding

- `sidecar.BlockHash == block.Hash()`
- `sidecar.PostStateRoot == block.Root()`

### Step 4 — tx eligibility

- every tx in `block.Transactions()` must be proof-fast-path eligible
- `sidecar.ProofCoveredTxs` must match exact block tx list and ordering

### Step 5 — tx commitment

- derive tx commitment from block txs
- compare to sidecar `BatchTxCommitment`

### Step 6 — receipt checks

- load sidecar receipts
- derive receipt commitment
- compare to `sidecar.ReceiptCommitment`
- derive receipt root
- compare to `block.ReceiptHash`
- derive bloom
- compare to `block.Header().Bloom`

### Step 7 — witness/state-diff commitment checks

- derive `StateDiffCommitment`
- compare to sidecar
- optionally derive witness commitment if witness is persisted and available

### Step 8 — proof verification

- construct `ProofValidationInputs`
- call `BatchProofVerifier.VerifyTransferBatchProof(...)`

### Step 9 — post-state materialization

- create `statedb := state.New(parentRoot, ...)`
- apply sidecar state diff
- derive `postRoot := statedb.IntermediateRoot(true)`
- compare to `block.Root()`

### Step 10 — gas checks

- compare `usedGas`
- compare cumulative gas values

### Step 11 — accept

- block is valid under proof-backed transfer path

---

# 8.16 Block Import Path Changes

## Existing area

- `core/blockchain.go`

## New helper functions

```go
func (bc *BlockChain) loadProofSidecar(blockHash common.Hash) (*types.BatchProofSidecar, error)
func (bc *BlockChain) shouldUseProofBackedTransferValidation(block *types.Block, sidecar *types.BatchProofSidecar) bool
```

## Modified main insert loop

In `insertChain(...)`, replace:

```go
receipts, logs, usedGas, err := bc.processor.Process(block, statedb)
err = bc.validator.ValidateState(block, statedb, receipts, usedGas)
```

with a branch:

### Legacy

unchanged

### Proof-backed transfer

```go
sidecar, err := bc.loadProofSidecar(block.Hash())
if err != nil {
    return it.index, err
}
receipts, usedGas, statedb, err := bc.processor.ProcessProofBackedTransferBlock(block, parent, sidecar)
if err != nil {
    return it.index, err
}
err = bc.validator.ValidateStateProofBackedTransfer(block, parent.Root, sidecar, receipts, usedGas)
if err != nil {
    return it.index, err
}
```

This is the central implementation change of Phase 2.

---

# 8.17 State Commit and Persistence

## Existing behavior

`writeBlockWithState(...)` expects a materialized `StateDB` and then:

- writes block
- writes receipts
- commits state

That should remain unchanged in Phase 2.

### Why

This minimizes the size of the architectural change.

### Therefore

The proof-backed transfer path must still produce:

- a valid `StateDB`
- a valid receipts set
- a valid usedGas

The difference is:

- these are produced from verified sidecar data
- not from local full transfer replay

---

# 8.18 Sidecar Availability Policy

Phase 2 must define a clear policy.

## Recommended policy

If a block is intended for proof-backed transfer validation:

- the sidecar must be available at validation time
- missing sidecar => block import failure

This avoids undefined partial acceptance behavior.

### New error values

- `ErrMissingProofSidecar`
- `ErrUnsupportedProofType`
- `ErrProofCoveredTxMismatch`
- `ErrProofReceiptCommitmentMismatch`
- `ErrProofStateDiffMismatch`
- `ErrProofVerificationFailed`

---

# 8.19 RPC Changes in Phase 2

## Existing file

- `internal/tosapi/api.go`

## New file

- `internal/tosapi/proof_api.go`

## Required additions

### Standard block/receipt APIs

Expose proof metadata when sidecar exists:

- proof type
- proof version
- proof-covered
- proof batch index

### Proof APIs

- `tos_getBlockProofSidecar(blockHash)`
- `tos_getTransactionProofStatus(txHash)`
- `tos_getProofStateDiff(blockHash)` optionally gated for debug use only

### Recommendation

Do **not** expose full witness over public RPC in Phase 2.

---

# 8.20 Metrics and Telemetry

## Required metrics

- `chain/proof/sidecar_reads`
- `chain/proof/sidecar_missing`
- `chain/proof/verify_time`
- `chain/proof/verify_failures`
- `chain/proof/state_diff_apply_time`
- `chain/proof/receipt_materialize_time`

## Required logs

On proof-backed transfer validation:

- block hash
- block number
- proof type
- proof version
- sidecar read status
- verification elapsed time
- state diff application elapsed time

---

# 9. File-Level Patch Plan

## New files

- `core/types/proof_sidecar.go`
- `core/types/proof_state_diff.go`
- `core/types/proof_commitment.go`
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
- miner-side sidecar writer / proof orchestration files from Phase 1

---

# 10. Concrete Interfaces

## 10.1 Processor

```go
type ProofBackedTransferProcessor interface {
    ProcessProofBackedTransferBlock(
        block *types.Block,
        parent *types.Header,
        sidecar *types.BatchProofSidecar,
    ) (types.Receipts, uint64, *state.StateDB, error)
}
```

## 10.2 Validator

```go
type ProofBackedTransferValidator interface {
    ValidateStateProofBackedTransfer(
        block *types.Block,
        parentRoot common.Hash,
        sidecar *types.BatchProofSidecar,
        receipts types.Receipts,
        usedGas uint64,
    ) error
}
```

## 10.3 Sidecar storage

```go
type ProofSidecarStore interface {
    ReadBlockProofSidecar(blockHash common.Hash) (*types.BatchProofSidecar, error)
    WriteBlockProofSidecar(blockHash common.Hash, sidecar *types.BatchProofSidecar) error
    HasBlockProofSidecar(blockHash common.Hash) bool
}
```

## 10.4 Proof verifier

```go
type BatchProofVerifier interface {
    VerifyTransferBatchProof(inputs *ProofValidationInputs) error
}
```

---

# 11. Determinism and Revert Safety

## 11.1 Determinism

Phase 2 still depends on Phase 1 witness determinism rules:

- sorted accounts
- sorted storage keys
- sorted private-state keys
- stable receipt encoding
- stable tx commitment ordering

## 11.2 Revert behavior

Because proof-backed transfer blocks no longer replay txs at validation time, all revert semantics must already be resolved inside:

- sidecar receipts
- sidecar state diff
- proof artifact

For `native-transfer-batch-v1`, recommendation:

- no partially reverting complex semantics
- transfer-only proof path should remain simple and explicit

---

# 12. Security Rules

## 12.1 No silent downgrade

If a block carries a sidecar claiming proof-backed transfer mode:

- validator must either validate under proof mode
- or reject the block

Do not silently downgrade to classical execution.

## 12.2 Exact tx set binding

The proof must bind to:

- exact block hash
- exact tx ordering
- exact tx count
- exact tx hashes

## 12.3 State diff pre-value checks

When applying sidecar diff:

- verify all pre-values against current parent-derived state
- reject on mismatch

This prevents sidecar substitution attacks.

## 12.4 Sidecar block-hash binding

Sidecar must be keyed to canonical block hash, not number only.

---

# 13. Testing Plan

# 13.1 Unit tests

## Sidecar encoding

- encode/decode round trip
- commitment stability

## State diff apply

- pre/post balance
- pre/post nonce
- privacy nonce mutation
- duplicate entry rejection
- wrong pre-value rejection

## Commitment tests

- tx commitment stable
- receipt commitment stable
- state diff commitment stable

---

# 13.2 Integration tests

## Happy path

- native transfer only block
- shield-only block
- private transfer-only block
- unshield-only block
- mixed transfer-class block

## Negative path

- missing sidecar
- wrong block hash in sidecar
- wrong tx commitment
- wrong receipt commitment
- wrong state diff commitment
- wrong post-state root
- unsupported tx type inside proof-backed block
- sidecar receipt root mismatch

---

# 13.3 Regression tests

- legacy block import unchanged
- sidechain / reorg logic still works
- state commit path still works
- receipt persistence still works

---

# 14. Implementation Order

## Step 1

Implement:

- sidecar type
- rawdb sidecar accessors
- tx proof class helpers

## Step 2

Implement:

- tx commitment
- receipt commitment
- state diff commitment
- sidecar validation primitives

## Step 3

Implement:

- proof-backed state diff apply path
- proof-backed processor path

## Step 4

Implement:

- proof-backed validator path

## Step 5

Integrate into:

- `core/blockchain.go` insert loop

## Step 6

Expose:

- proof-backed receipt / block fields
- proof sidecar RPC

## Step 7

Complete:

- integration tests
- metrics
- failure-path logging

---

# 15. Migration Strategy

## Recommended rollout

1. keep Phase 1 shadow proving enabled
2. add Phase 2 proof-backed transfer validation behind a feature flag
3. test on devnet
4. test on internal testnet
5. enable on public testnet only for transfer-only proof-backed blocks
6. defer contract proving to Phase 3+

---

# 16. Final Summary

Phase 2 is the first stage where `gtos` can actually begin to behave like a Gigagas-style proof-validated chain.

The key change is not “more proofs”.  
The key change is this:

> **For proof-covered transfer batches, validators stop re-executing transactions and instead validate a proof sidecar, receipts commitment, and a materializable post-state diff.**

To make that work inside the current `gtos` architecture, Phase 2 must add:

- out-of-band proof sidecars keyed by block hash
- rawdb persistence for sidecars
- exact tx-set commitments
- exact receipt commitments
- exact state-diff commitments
- a proof-backed state processor path
- a proof-backed block validator path
- a state-diff materialization path that still yields a real `StateDB`
- a clean import-branch in `InsertChain(...)`

That is the narrowest realistic implementation path that:

- avoids changing canonical header hashing
- avoids requiring full contract proving
- allows direct coding now
- moves `gtos` closer to real proof-backed L1 validation

---

## Related Documents

- [Gigagas L1 Roadmap](./gtos_gigagas_l1_roadmap.md)
- [Phase 1 Implementation Checklist](./gtos_gigagas_l1_phase1_implementation_checklist.md)
- [Phase 2 File-by-File Coding Checklist](./gtos_gigagas_l1_phase2_coding_checklist.md)
- [Phase 3 Design: Restricted Contract Proving](./gtos_gigagas_l1_phase3_restricted_contract_proving.md)
