# gtos Roadmap: From Current Architecture to a Gigagas L1 Native-Transfer Batch-Proof Pipeline

## Scope

This document defines a **12-module engineering roadmap** for evolving `gtos` from its current execution architecture toward a **Gigagas L1** model, starting with a **zk-native-transfer batch proof** path and **explicitly excluding full smart-contract proving in the first phase**.

The immediate objective is **not** to prove arbitrary LVM/Lua contract execution. The first milestone is narrower and more practical:

- native plaintext transfers
- shield
- private transfer
- unshield

The long-term target is to move the chain from:

- **all validators re-execute all transactions**

to:

- **block builders / executors execute batches and generate a state-transition proof**
- **validators verify the proof and public inputs instead of fully re-executing the batch**

---

## Current Situation

At present, `gtos` already has meaningful zero-knowledge foundations, but they are still **module-local**, not **chain-global**:

- privacy transaction proving exists
- privacy proof verification exists
- UNO-related cryptographic operations already use proof-aware logic
- transaction execution and block validation still fundamentally follow the classical **execute-then-verify-root** model

That means `gtos` is currently a **proof-capable L1**, but not yet a **proof-first L1**.

To reach a Gigagas-style architecture, the system must be restructured so that:

1. execution emits a deterministic witness
2. a batch prover constructs a proof over the batch state transition
3. the block header carries proof-related commitments
4. validators verify the batch proof instead of replaying all transactions

---

# Six Areas and Twelve Concrete Modules

## 1. core/state

### Module 1: Batch Witness Export Layer
**Suggested location:** `core/state/batch_witness.go`

The current state layer is still optimized for trie mutation, journaling, snapshots, and revert handling. To support batch proving, `StateDB` must be extended so that execution produces a canonical witness stream.

This module should:

- record all touched accounts in a batch
- record pre/post values for:
  - nonce
  - balance
  - code hash
  - storage slots
  - private slots / encrypted balance fields
- record transfer-related deltas
- record receipt/log-relevant effects
- export a stable witness structure consumable by a proof worker

**Why it matters:**  
The prover should not reconstruct state access by reverse-engineering node execution. The execution path itself should emit the witness.

---

### Module 2: Proof-Friendly State Commitment Layer
**Suggested location:** `core/state/proof_root.go`

Today, canonical validation depends on the normal post-execution state root. For batch proving, `gtos` needs a parallel commitment model that can be used by the proof system.

This module should define and compute:

- `preStateRoot`
- `postStateRoot`
- `batchTxCommitment`
- `batchWitnessCommitment`
- optional `receiptCommitment`

**Recommended first step:**  
Do **not** immediately replace the existing canonical state root in consensus. Instead, introduce a proof-oriented commitment layer in parallel, so the proof path can be developed and validated incrementally.

---

## 2. core/vm

### Module 3: Native/Privacy Transfer Trace Emitter
**Suggested location:** tracing support adjacent to `core/vm` execution paths

The current VM execution path is still classical: snapshot, execute, revert on error, commit on success. That is a good insertion point for a trace emitter.

In phase one, this module should only cover:

- native transfer trace
- shield trace
- private transfer trace
- unshield trace
- gas / fee trace
- receipt / event trace where relevant

It should **not** attempt to prove arbitrary contract execution yet.

**Why it matters:**  
Batch proving requires a deterministic execution transcript. Without a trace model, there is no stable proving input.

---

### Module 4: Unified Batch Event Model for Privacy Operations
**Suggested location:** adapter layer between `core/vm` and `core/priv`

The current privacy prover logic is centered around transaction-local proof construction. For Gigagas L1, privacy operations must also become first-class batch events.

This module should normalize privacy execution into batch-level events such as:

- `ShieldApplied`
- `PrivTransferApplied`
- `UnshieldApplied`
- `FeeDebited`
- `FeeCredited`
- `PrivNonceAdvanced`

**Why it matters:**  
A batch prover cannot treat privacy actions as isolated black boxes. They must be represented uniformly inside batch state-transition semantics.

---

## 3. core/types

### Module 5: Extend Block Header with Batch-Proof Metadata
**Suggested location:** `core/types/block.go`

The current header model is designed for classical execution validation. A proof-first path needs explicit batch-proof metadata in the header or an associated sidecar.

This module should introduce fields such as:

- `ProofType`
- `BatchProofHash`
- `BatchPublicInputsHash`
- `BatchTxCommitment`
- `BatchWitnessCommitment`
- optional `ProofVersion`

**Recommended rollout strategy:**
- short term: allow sidecar or extra-data carriage
- medium term: promote proof metadata into explicit block/header fields

**Why it matters:**  
Without proof-aware header structure, validators have no consensus object to validate beyond the classical state root.

---

### Module 6: Extend Transaction / Receipt Types for Proof Coverage
**Suggested location:** `core/types/transaction.go`, `core/types/receipt.go`

Transactions and receipts need to expose whether they are included in a batch-proof flow.

This module should add metadata such as:

- proof eligibility class
- proof-covered status
- batch index
- optional trace digest
- optional sub-proof or proof reference

**Why it matters:**  
RPC, block explorers, debuggers, and future tooling must be able to distinguish:

- classical execution-confirmed transactions
- proof-confirmed transactions

---

## 4. miner / block

### Module 7: Two-Phase Block Assembly in the Miner
**Suggested location:** `miner/worker.go`

The current miner path is still classical:

1. collect transactions
2. execute them locally
3. assemble block, receipts, and state
4. seal and publish

To support batch proving, this needs to become a two-phase pipeline:

1. build a **proof-eligible batch**
2. execute and export witness
3. invoke batch prover
4. attach proof artifact and commitments
5. seal and publish the block

In the first proving phase, only include:

- native transfers
- shield
- private transfer
- unshield

Exclude:

- arbitrary LVM contract calls
- contract deployment
- complex cross-contract semantics

**Why it matters:**  
The miner becomes the orchestration layer between execution and proving.

---

### Module 8: Proof-Based Block Validation Path
**Suggested location:** `core/block_validator.go`

Today, block validation still assumes local execution and post-state comparison. To reach Gigagas L1, validators need a second path.

This module should add:

- legacy validation path for non-proof blocks
- proof validation path for `native-transfer-batch-v1` blocks

The proof validation path should verify:

- batch proof validity
- proof version / proof type
- public inputs
- batch commitments
- consistency between proof result and block header / receipts

**Why it matters:**  
This is the actual shift from “all validators re-execute” to “validators verify a succinct proof”.

---

## 5. rpc

### Module 9: Proof-Aware RPC Query Surface
**Suggested location:** `internal/tosapi/api.go`

Current RPC is still centered on the traditional transaction and receipt model. A proof-first architecture needs proof-aware queries.

This module should add APIs such as:

- `tos_getBatchProof(batchHash)`
- `tos_getBatchPublicInputs(batchHash)`
- `tos_getTransactionProofStatus(txHash)`
- `tos_getBatchProofMetadata(batchHash)`
- optional `tos_getBatchWitnessAvailability(batchHash)`

**Why it matters:**  
Explorers, indexers, wallets, and application layers need direct visibility into proof-native blocks.

---

### Module 10: Proof Eligibility and Batch Admission in Send Path / TxPool
**Suggested location:** send path and txpool admission logic

The current send path places all supported transactions into a broadly unified mempool flow. For batch proving, transactions must be classified at admission time.

This module should introduce at least two execution classes:

- `proof-fast-path`
  - native transfer
  - shield
  - private transfer
  - unshield

- `legacy-path`
  - arbitrary contract call
  - unsupported transaction classes
  - any transaction that cannot yet be included in the batch prover

**Why it matters:**  
The block builder must know which transactions are eligible for proof-native batching and which must remain on the classical path.

---

## 6. proof worker

### Module 11: Dedicated Batch Prover Worker
**Suggested location:** new component such as `cmd/tosproofd/` or `proofworker/`

Today, proof generation is still close to transaction-local library or CLI usage. A Gigagas architecture needs a dedicated proving worker process.

This worker should accept:

- `preStateRoot`
- transaction batch
- witness payload
- batch commitments
- proof version / proving mode

And it should produce:

- `postStateRoot`
- `batchProof`
- `publicInputs`
- proof metadata
- artifact digest / commitment

**Why it matters:**  
Proof generation is heavier and more specialized than ordinary node execution. It should be a dedicated service, potentially with different hardware and language/runtime choices.

---

### Module 12: Standardized Proof Artifact Format
**Suggested location:** `proofworker/artifact.go` or `core/types/proof.go`

A proof-first chain requires a stable artifact schema shared across:

- builder
- executor
- prover
- validator
- RPC layer
- indexing tools
- future external services

This module should define a standard artifact with fields such as:

- `proofType`
- `version`
- `preStateRoot`
- `postStateRoot`
- `txCommitment`
- `witnessCommitment`
- `receiptCommitment`
- `proofBytes`
- `publicInputs`
- `circuitVersion`
- `proverID`
- `provingTimeMs`

**Why it matters:**  
Without a standard artifact format, each subsystem will evolve incompatible assumptions and the proof pipeline will fragment.

---

# Recommended Implementation Order

## Phase 1: Establish the Proof Skeleton
1. Extend `core/types` for proof-aware header and receipt metadata  
2. Add `core/state` batch witness export  
3. Define proof artifact schema  
4. Build a dedicated batch prover worker  
5. Modify miner block assembly to invoke the proof worker  
6. Add proof-based validation path in block validation  

## Phase 2: Make the Path Observable and Operable
7. Extend RPC with proof-aware queries  
8. Add proof eligibility classification to send path / txpool  
9. Normalize native/privacy transfer trace emission  
10. Normalize privacy operations as batch events  

## Phase 3: Expand Proof Coverage
11. Refine proof-friendly state commitments  
12. Gradually extend from native-transfer-only batches toward restricted contract subsets

---

# Minimum Viable Gigagas Step for gtos

The most practical first milestone is:

## `native-transfer-batch-v1`

This batch-proof mode should cover only:

- native transfer
- shield
- private transfer
- unshield

And should **exclude**:

- arbitrary Lua/LVM contracts
- deployment
- nested contract call graphs
- complex contract storage semantics

This gives `gtos` a realistic first transition from:

- **proof-capable modules**

to:

- **proof-native block production and validation**

---

# Final Summary

To move `gtos` toward a Gigagas L1 architecture, the core shift is not simply “adding more proofs” for existing privacy functionality.

The real shift is architectural:

- `core/state` must emit proving-ready witness data
- `core/vm` must produce deterministic transfer traces
- `core/types` must carry proof metadata
- `miner/block` must assemble proof-backed blocks
- `rpc` must expose proof-native observability
- a dedicated `proof worker` must generate and package batch state-transition proofs

The first practical proving target should be a **zk-native-transfer batch proof pipeline**, not full smart-contract proving.

That is the narrowest path that still changes the chain from a **classical execution-first L1** into a **proof-first L1 candidate**.
