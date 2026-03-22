# Security Audit Methodology

**Purpose**: Documents the audit scope, methodology, and review principles
used to produce `SECURITY-AUDIT-2026-03-19.md` and
`LVM-DETERMINISM-AUDIT-2026-03-19.md`.

**Auditor**: Claude Opus 4.6 (automated deep audit)
**Date**: 2026-03-19

---

## Context

The gtos codebase was originally cloned from go-ethereum (v1.10.25 lineage)
with the following major additions:

1. Parallel transaction execution
2. Privacy transfer / confidential transfer logic (UNO)
3. Custom state transition changes (DPoS, system actions, policy wallets)
4. EVM removed; LVM (Lua VM) interpreter for TOL smart contracts
5. Custom mempool, block execution, receipt, gas accounting, and StateDB changes

---

## Top Priorities

**A. SECURITY**
**B. DETERMINISTIC EXECUTION / CONSENSUS SAFETY**

The main goal is to identify anything that could cause:
- Chain forks
- Nondeterministic execution across different nodes
- State root mismatch
- Receipt root / logs mismatch
- Inconsistent gas usage
- Race conditions
- Unsafe parallel execution
- Privacy logic bugs
- Consensus-critical bugs
- Denial of service risks
- Invalid block acceptance / valid block rejection
- Differences between machines, OSes, CPU architectures, timezones, or Go
  runtime behavior

Any node divergence is treated as a critical vulnerability.

---

## Audit Scope

### 1. Block Execution Pipeline
- Block import
- Transaction execution order
- State transition
- Receipt generation
- Gas accounting
- Miner / validator execution path
- Block validation path
- Re-execution during sync

### 2. Parallel Transaction Execution
- Scheduler design
- Dependency resolution
- Read/write conflict detection
- Shared state access
- Ordering guarantees
- Commit / merge logic
- Rollback / retry logic
- Whether final results are guaranteed identical across all nodes
- Whether transaction ordering still affects outcome
- Whether speculative execution can leak nondeterminism
- Whether goroutines / channels / mutex timing can affect final state

### 3. Privacy / Confidential Transfer Logic
- Balance updates
- Commitment / nullifier / note handling
- Proof verification flow
- Serialization / deserialization
- Overflow / underflow
- Replay protection
- Malformed proof handling
- Edge cases where public and private balance views can diverge
- Whether privacy features affect consensus determinism

### 4. StateDB / Trie / Journal / Snapshot
- Concurrent access hazards
- Mutation ordering
- Dirty state flush ordering
- Map iteration order dependence
- Hidden shared mutable state
- Cache dependence
- Snapshot / revert correctness

### 5. VM / Interpreter (LVM)
- Opcode behavior
- Gas charging consistency
- Stack / memory / storage behavior
- Undefined behavior
- Error propagation differences
- Panic paths
- Differences between success / revert / invalid / OOG handling

### 6. Transaction Pool / Block Building
- Whether block construction depends on local nondeterministic conditions
- Whether parallel selection / sorting introduces unstable ordering
- Whether privacy txs and normal txs interact unsafely

### 7. Serialization / Hashing / Encoding
- RLP / custom encoding
- Binary canonicalization
- Field order dependence
- Nil vs empty distinctions
- Signed vs unsigned interpretation
- Endianness assumptions

---

## Specific Deterministic-Execution Hazards

The audit specifically checks for:

- Go map iteration order used in any consensus-critical path
- Goroutine scheduling affecting state commit order
- Reliance on wall clock time, local timezone, rand, math/rand, UUID, temp
  file names, system entropy, OS environment, floating point, or noncanonical
  serialization
- Use of `range` over maps in state merge / receipt generation / log ordering
  / transaction conflict resolution
- Nondeterministic error handling
- Data races
- Use of shared mutable objects across parallel tx execution
- Inconsistent lock usage
- Panic recovery that changes logical behavior
- Integer overflow / underflow
- Differences between nil and zero-value handling
- Hidden dependency on iteration order in caches, sets, bloom/log
  construction, receipt lists, or trie writes
- Dependence on database read timing or disk layout
- Speculative execution that can commit in different order across nodes
- Transaction conflict detection that is incomplete or asymmetric
- Privacy proof verification paths that can yield inconsistent results
- Nondeterministic cryptographic preprocessing
- Inconsistent gas refund accounting
- Receipt/log ordering instability
- Unsafe use of big.Int pointers or shared references
- Mutation of objects after hashing/signing
- Divergence between block producer path and block verifier path
- Differences between fast sync / full sync / replay path
- State revert / snapshot restore bugs

---

## Review Method

1. Identify all files and functions that are consensus-critical
2. Trace the execution path of a transaction from block inclusion to final
   state root
3. Trace the parallel execution design in detail
4. Explain whether the parallel execution model is actually deterministic
5. Explain whether two honest nodes with different hardware / OS / execution
   timing can ever derive different results
6. Explain all possible fork-risk scenarios
7. Identify security vulnerabilities and rank by severity (Critical / High /
   Medium / Low)
8. For each issue, provide: title, affected files/functions, root cause,
   exploitation or failure scenario, whether it can cause consensus
   divergence, whether it can cause fund loss or privacy failure, recommended
   fix
9. Point out code that is safe and well-designed, not only bugs
10. If unsure, say so explicitly and explain what additional files should be
    inspected

---

## Review Principles

- Treat consensus divergence as the highest severity
- Treat any nondeterministic behavior in block execution as critical
- Be extremely suspicious of parallel execution in consensus code
- Be extremely suspicious of privacy features modifying balances, receipts,
  or verification logic
- Prefer false positives over missed critical issues
- Tie every point to concrete code locations and execution paths
- Start from execution pipeline, StateDB, VM/interpreter, miner/block
  builder, and files related to parallel execution or privacy transfer
- If custom logic differs from geth, explicitly compare the risk introduced
  by the deviation

---

## Audit Reports Produced

| Report | Scope | Result |
|--------|-------|--------|
| `SECURITY-AUDIT-2026-03-19.md` | Full consensus safety: parallel execution, privacy transfers, StateDB, DPoS, block pipeline | All actionable findings resolved |
| `LVM-DETERMINISM-AUDIT-2026-03-19.md` | LVM/Lua interpreter determinism: 15 categories | All categories passed |

---

## Files Audited (~50 files)

### Parallel Execution
- `core/parallel/analyze.go` — Static access-set analysis
- `core/parallel/dag.go` — DAG level building
- `core/parallel/executor.go` — Main parallel executor
- `core/parallel/accessset.go` — Conflict detection
- `core/parallel/writebuf.go` — State write buffer with IndexMap
- `core/parallel/metrics.go` — Instrumentation
- `core/parallel/parallel_test.go` — Determinism and equivalence tests
- `common/indexmap/indexmap.go` — Insertion-ordered map

### Privacy Transfers
- `core/privacy_tx_prepare.go` — Privacy tx preparation and state application
- `core/tx_pool_privacy_verify.go` — TxPool privacy verification
- `core/execute_transactions_privacy.go` — Serial execution with batch proofs
- `core/priv/state.go` — Privacy account state management
- `core/priv/fee.go` — UNO fee conversion (overflow fix applied)
- `core/priv/types.go` — Ciphertext type
- `core/priv/context.go` — Merlin transcript context
- `core/priv/verify.go` — Proof verification
- `core/priv/batch_verify.go` — Batch verification
- `core/priv/prover.go` — Proof generation
- `core/priv/disclosure.go` — Selective disclosure
- `core/priv/decryption_token.go` — Decryption tokens
- `core/types/priv_transfer_tx.go` — PrivTransfer tx type
- `core/types/shield_tx.go` — Shield tx type
- `core/types/unshield_tx.go` — Unshield tx type
- `crypto/ed25519/priv_nocgo_disclosure.go` — DLEQ proofs
- `crypto/ed25519/priv_nocgo_proofs.go` — ZK proof implementations
- `crypto/priv/disclosure.go` — Disclosure wrappers
- `crypto/priv/decryption_token.go` — Token wrappers

### State and Execution
- `core/state_processor.go` — Block processing pipeline
- `core/state_transition.go` — Transaction state transition
- `core/state/statedb.go` — StateDB (Finalise, Commit, IntermediateRoot)
- `core/state/journal.go` — State journal
- `core/block_validator.go` — Block validation
- `core/types/receipt.go` — Receipt generation
- `core/types/bloom9.go` — Bloom filter construction
- `core/rawdb/accessors_state.go` — State accessors

### Consensus
- `consensus/dpos/dpos.go` — DPoS consensus engine
- `consensus/dpos/signer_set.go` — Validator set ordering

### Policy Wallet
- `policywallet/state.go` — Policy wallet state
- `policywallet/handler.go` — System action handler

### VM / LVM
- `core/vm/lvm.go` — Core LVM execution (~4590 lines)
- `core/vm/lvm_abi.go` — ABI encoding/decoding
- `core/vm/lvm_openlib.go` — Pre-compiled openlib
- `core/vm/lvm_crypto.go` — Cryptographic operations
- `core/vm/contracts.go` — Precompiled contracts
- `core/vm/interpreter.go` — Interpreter routing
- `tolang/vm.go` — Opcode dispatch, per-opcode gas
- `tolang/table.go` — Insertion-order LTable
- `tolang/bytecode.go` — Platform-independent bytecode format
- `tolang/linit.go` — Openlib module loading

### Trie
- `trie/nodeset.go` — Merged node set (order-independent)
