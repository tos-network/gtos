# gtos Gigagas L1 Roadmap

## Goal

Inspired by Ethereum's "Gigagas L1" vision for ~2029, gtos aims to **raise mainnet execution throughput from the current hundreds of TPS to the ~10,000 TPS class**.

The core idea is the same as Ethereum's direction: **instead of having every validator re-execute every transaction, use zero-knowledge proofs so that validators "verify a proof" rather than "repeat execution"**.

However, gtos is **not** building a zkEVM. gtos has its own execution surface (system actions, LVM/Lua contracts, UNO privacy primitives), so the proving target is **gtos's own state transition semantics**, not EVM opcode compatibility. This makes gtos a **profile-based zk-native L1**, not a zkEVM chain.

### What this roadmap delivers

| Milestone | What changes |
|-----------|-------------|
| Phase 1 | Shadow proving infrastructure — witness export, proof worker, sidecar persistence |
| Phase 2 | Validators stop re-executing proof-covered transfer batches |
| Phase 3 | Proof coverage expands to restricted LVM contract subsets |
| Phase 4 | Most high-frequency paths are proof-native |
| Phase 5 | Throughput scaling — gas limit, data plane, recursive proving, parallel execution, state I/O |

After Phase 5, gtos targets **~10,000 TPS** for transfer-dominated workloads with proof-native validation.

---

## Scope

This document defines the **5-phase engineering roadmap** for evolving `gtos` from its current execution architecture toward a Gigagas L1 model.

The immediate first milestone is intentionally narrow:

- native plaintext transfers
- shield
- private transfer
- unshield

The long-term target is to move the chain from:

- **all validators re-execute all transactions**

to:

- **block builders / executors execute batches and generate a state-transition proof**
- **validators verify the proof and public inputs instead of fully re-executing the batch**
- **throughput scales to ~10,000 TPS via gas model, data plane, and recursive proving**

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
3. proof metadata is carried out-of-band (Phase 1-4) or in-header (Phase 5+)
4. validators verify the batch proof instead of replaying all transactions
5. throughput bottlenecks beyond re-execution (gas limit, DA, proof speed, state I/O) are addressed

---

# Six Areas and Twelve Concrete Modules

## 1. core/state

### Module 1: Batch Witness Export Layer
**Suggested location:** `core/state/batch_witness.go`, `core/state/tx_witness_buffer.go`

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

**Phase 1 hard constraints:**

1. **Determinism:** All witness entries must be explicitly sorted (accounts by address, slots by key, priv entries by (address, key)). No reliance on Go map iteration order. Determinism stress tests (100 repeated runs, identical digest) must pass before miner/prover integration begins.

2. **Tx-buffered commit-on-finalize:** Witness collection uses a two-layer model (`TxWitnessBuffer` → `BatchWitness`). During tx execution, mutations go to `TxWitnessBuffer`. On tx success, buffer merges into `BatchWitness`. On tx revert, buffer is discarded entirely. The witness layer never writes directly to the batch during execution and never needs journal-based compensation.

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

**Phase 1 hard constraint:** Privacy batch normalization must **preserve execution order and explicit dependency edges**. Privacy txs have serial dependencies (priv nonce, source commitment, ciphertext state) that make reordering unsafe. The normalizer must never rearrange privacy tx ordering. Native transfers may be grouped freely, but privacy txs must retain their block execution order within the batch.

**Why it matters:**
A batch prover cannot treat privacy actions as isolated black boxes. They must be represented uniformly inside batch state-transition semantics, with serial dependencies made explicit.

---

## 3. core/types

### Module 5: Out-of-Band Proof Sidecar Model
**Suggested location:** `core/types/proof_sidecar.go`, `core/rawdb/accessors_proof.go`

#### Phase 1 Decision

Phase 1 uses an **out-of-band proof sidecar keyed by canonical block hash**. The canonical `Header` struct is **not modified** in Phase 1. Proof metadata is not stuffed into `Header.Extra` either, because that would still alter the header hash.

This decision is intentional because Phase 1 is a **shadow-proving** stage:
- proof metadata does not need to enter block hashing
- proof metadata does not need to become a consensus field yet
- validators may consume proof sidecars when available, while legacy block/header structure remains unchanged

A future phase may choose to promote selected proof fields into the canonical header if and when the network is ready for a consensus-level fork.

The sidecar should carry:

- `ProofType`
- `ProofVersion`
- `CircuitVersion`
- `BatchProofHash`
- `BatchPublicInputsHash`
- `BatchTxCommitment`
- `BatchWitnessCommitment`
- `ProofBytes` or proof blob reference
- `ProverID`
- `ProvingTimeMs`

Storage: independent rawdb bucket, key = block hash, value = encoded `BatchProofSidecar`.

**Why it matters:**
Without proof-aware block metadata, validators have no object to validate beyond the classical state root. The sidecar model achieves this without requiring a consensus fork in the shadow-proving phase.

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

### Module 7: Async Shadow Proving in the Miner
**Suggested location:** `miner/worker.go`

The current miner path is still classical:

1. collect transactions
2. execute them locally
3. assemble block, receipts, and state
4. seal and publish

**Phase 1 hard constraint:** Phase 1 uses **asynchronous shadow proving**. The miner does not wait for a proof before sealing. The Phase 1 pipeline is:

1. build a **proof-eligible batch** (classify txs)
2. execute and seal the block on the classical path
3. export witness and compute commitments post-seal
4. submit async proof request to the worker (non-blocking)
5. on proof completion, persist sidecar to rawdb keyed by block hash

Synchronous proof-gated block production is a Phase 2+ concern.

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
The miner becomes the orchestration layer between execution and proving. Async shadow proving ensures block production is never blocked by proof generation latency.

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

In Phase 1 (async shadow proving), the worker runs independently. The node submits proof requests asynchronously after block sealing and persists the resulting sidecar to rawdb when the proof completes. The worker is never in the block production critical path.

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

## Current State (Phase 0)

- Every validator re-executes every transaction
- `BlockValidator.ValidateState()` compares locally-computed `gas / receipts / state root` against the block header
- Privacy proofs are consumed locally during execution but do not replace full re-execution

## Phase 1: Shadow Proving Infrastructure

*Validator behavior: unchanged — full re-execution*

1. Proof artifact and sidecar type definitions (out-of-band, no Header changes)
2. Rawdb proof sidecar persistence
3. Batch witness export with determinism guarantees
4. Transfer-only trace model with privacy order preservation
5. Dedicated `tosproofd` async proof worker
6. Miner async shadow proving (post-seal witness + proof request)
7. Proof-aware RPC endpoints
8. Proof eligibility classification in txpool

**Phase 1 exit criteria:** proving pipeline runs in staging with zero proof divergence from local execution.

See: [Phase 1 Implementation Checklist](./gtos_gigagas_l1_phase1_implementation_checklist.md)

## Phase 2: Proof-Backed Transfer Validation

*Validator behavior: proof verification replaces re-execution for proof-covered blocks*

1. `ValidateStateWithProof()` — verify proof + public inputs instead of local execution
2. `insertChain` proof-path branch with classical fallback
3. `ZKExecutionConfig` activation block in chain config
4. Background execution for state trie maintenance (proof gates consensus, execution deferred)
5. Proved head tracking
6. Monitoring: proof-path vs classical-path latency comparison

**Phase 2 exit criteria:** validators accept proof-covered blocks via proof verification (~1-5ms) instead of full re-execution (~100ms+). Classical fallback works for blocks without sidecars.

See: [Phase 2 Design](./gtos_gigagas_l1_phase2_proof_backed_transfer_validation.md)

## Phase 3: Restricted Contract Proving

*Validator behavior: more tx classes skip re-execution*

1. Extend proving kernel to cover restricted LVM contract subsets
2. Refine proof-friendly state commitments
3. Gradually expand proof coverage

**Phase 3 exit criteria:** allowlisted restricted contract calls are proof-native. Proof coverage extends beyond transfer-only to a bounded subset of LVM contract semantics.

See: [Phase 3 Design](./gtos_gigagas_l1_phase3_restricted_contract_proving.md)

## Phase 4: Hot-Path Proof-Native Validation

*Validator behavior: most high-frequency paths are proof-native*

1. Expand proof coverage to dominant LVM contract profiles
2. Pipelined proposer/builder/prover workflow
3. Profile-based allowlisted proof validation

**Phase 4 exit criteria:** most high-frequency tx classes are proof-native. Validator execution cost is dominated by proof verification, not tx replay.

See: [Phase 4 Design](./gtos_gigagas_l1_phase4_hotpath_proof_native_validation.md)

## Phase 5: Throughput Scaling

*Target: ~10,000 TPS class*

Phase 1–4 solve the **validator re-execution bottleneck** but do not automatically deliver 10,000 TPS. Five additional bottlenecks must be addressed:

| # | Bottleneck | Phase 1–4 status | Phase 5 action |
|---|-----------|-----------------|----------------|
| 1 | Block gas limit | Not addressed (current: 30M, need: 75M+) | Gas model redesign |
| 2 | Data availability | Not addressed (~2 MB/s at 10k TPS) | Chunked data plane |
| 3 | Proof generation speed | Partial (checkpoint range, no sub-proof sharding) | Recursive proof aggregation |
| 4 | Builder execution speed | Partial (builder still executes all txs) | Parallel execution optimization |
| 5 | State I/O | Not addressed (MPT write amplification) | State layout optimization |

### Current throughput ceiling analysis

```
Block time:       360ms (~2.78 blocks/s)
Genesis gas limit: 30,000,000
Transfer gas cost: ~21,000
Theoretical max:   30M / 21k × 2.78 ≈ 3,968 TPS (transfer-only)
```

Even with zero validator re-execution cost, the current gas limit caps throughput below 4,000 TPS. Raising gas limit alone does not linearly scale throughput — DA, state I/O, and proof speed become binding constraints.

### Phase 5 sub-modules

1. **Gas Model & Block Capacity** — raise gas limit to 75M+, revisit transfer gas pricing
2. **Chunked Data Plane** — `DataRoot` + `DataChunks` (designed in architecture doc, not yet implemented)
3. **Sub-Proof Sharding + Recursive Aggregation** — parallel sub-provers per block range, aggregate into checkpoint-range proof
4. **Builder Parallel Execution** — access-list-predicted parallel tx execution at the builder
5. **State I/O Optimization** — flat state / verkle trie / optimized state diff application

**Phase 5 exit criteria:** gtos sustains ~10,000 TPS for transfer-dominated workloads with proof-native validation, adequate DA, and acceptable proof latency.

See: [Phase 5 Design](./gtos_gigagas_l1_phase5_throughput_scaling.md)

---

# Minimum Viable Gigagas Step for gtos

## `native-transfer-batch-v1`

This batch-proof mode covers only:

- native transfer
- shield
- private transfer
- unshield

And excludes:

- arbitrary Lua/LVM contracts
- deployment
- nested contract call graphs
- complex contract storage semantics

This is the narrowest scope that exercises the full proving pipeline end-to-end.

---

# Key Milestone: When Do Validators Stop Re-Executing?

**Not in Phase 1.** Phase 1 is shadow proving — infrastructure only.

**In Phase 2.** Phase 2 introduces `ValidateStateWithProof()` which replaces `Process() + ValidateState()` for proof-covered blocks. This is the architectural step where consensus acceptance shifts from “re-execute and compare” to “verify proof and accept”.

The recommended Phase 2 model is **background execution**: proof verification gates consensus acceptance (fast), while full execution runs asynchronously to maintain the state trie for subsequent blocks.

---

# Final Summary

The path from current gtos to Gigagas L1 has five phases. Phase 1–4 solve the validator re-execution bottleneck. Phase 5 solves the throughput scaling bottlenecks needed to reach ~10,000 TPS.

| Phase | Validator model | Key change | TPS impact |
|-------|----------------|------------|------------|
| 0 (current) | Full re-execution | Baseline | ~hundreds |
| 1 | Full re-execution + shadow proofs | Build proving infrastructure | No change |
| 2 | Proof verification for transfers | **Consensus acceptance via proof** | Latency drop |
| 3 | Expanding proof coverage | More tx classes skip re-execution | Latency drop |
| 4 | Hot-path proof-native validation | Most high-freq paths proof-native | ~3,000–4,000 |
| 5 | Throughput scaling | Gas limit + DA + recursive proving + parallel execution + state I/O | **~10,000** |

**Phase 1–4 are necessary but not sufficient for 10,000 TPS.** They eliminate the largest single bottleneck (validator re-execution). Phase 5 addresses the remaining bottlenecks: block capacity, data availability, proof generation speed, builder throughput, and state I/O.

### gtos vs Ethereum approach

- Ethereum 2029: **prove the EVM** (zkEVM — universal EVM compatibility)
- gtos: **prove dominant gtos execution profiles** (profile-based zk-native validation)

gtos is better positioned for this transition because:
- No EVM historical baggage — proving target is self-defined, not legacy-constrained
- Existing privacy proof infrastructure — UNO/ciphertext proofs are already native
- Controllable execution surface — can define proof-friendly profiles and allowlists
- Smaller validator set with deterministic finality — simpler consensus integration
- Profile-based approach is more practical than universal zkVM for reaching production faster
