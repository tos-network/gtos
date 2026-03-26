# gtos Phase 5 Design
## Throughput Scaling to ~10,000 TPS

## Status

**Document status:** design outline
**Prerequisite:** Phase 4 (hot-path proof-native validation) substantially complete
**Target:** sustain ~10,000 TPS for transfer-dominated workloads

---

# 1. Purpose

Phase 1–4 solve the **validator re-execution bottleneck**: validators verify proofs instead of replaying transactions. This is necessary but not sufficient for 10,000 TPS.

Phase 5 addresses the **remaining five bottlenecks** that cap throughput even after proof-native validation is in place.

---

# 2. Current Throughput Ceiling

## Parameters

| Parameter | Current value |
|-----------|--------------|
| Block time | 360ms (~2.78 blocks/s) |
| Genesis gas limit | 30,000,000 |
| Transfer gas cost | ~21,000 |
| Max validators | 15 |
| Block body encoding | Full tx list in RLP |
| State trie | MPT (Merkle Patricia Trie) |

## Theoretical maximum (transfer-only)

```
30,000,000 / 21,000 x 2.78 = 3,968 TPS
```

Even with zero validator re-execution cost, the gas limit alone caps throughput below 4,000 TPS.

## Why raising gas limit alone is not enough

At 10,000 TPS with 360ms blocks:

| Metric | Value |
|--------|-------|
| Txs per block | ~3,600 |
| Required gas per block | ~75,600,000 |
| Tx data per block | ~720 KB (at ~200 bytes/tx) |
| Tx data per second | ~2 MB/s |
| State writes per block | ~7,200 account mutations (2 per transfer) |
| Proof range (1664 blocks) | ~5,990,400 txs to prove |

Raising gas limit to 75M+ is necessary but exposes secondary bottlenecks in DA, state I/O, proof speed, and builder execution.

---

# 3. Five Sub-Modules

## 3.1 Gas Model & Block Capacity

### Problem

Current gas limit (30M) allows at most ~3,968 TPS for transfers. 10,000 TPS requires ~75M+ gas per block.

### Required changes

1. **Raise genesis gas limit** to 100M+ for new networks, or use dynamic gas limit increase for existing networks
2. **Revisit transfer gas pricing** — native transfers in a proof-native chain may warrant lower gas cost since validators no longer pay execution cost
3. **Separate execution gas from DA gas** — follow the EIP-4844 pattern: execution gas prices compute cost, DA gas prices data availability cost
4. **Block size sanity limits** — ensure block propagation remains feasible at higher gas limits

### Design considerations

- Gas limit increase must be coordinated with DA capacity
- If gas is too cheap, spam attacks become easier — need minimum gas floor per tx
- Proof-covered txs could have a lower gas multiplier since validator cost is lower
- Non-proof-covered txs (classical path) should retain current gas pricing

### Suggested Phase 5 target

```
Block gas limit: 100,000,000 (100M)
Transfer gas:    21,000 (unchanged) or reduced to ~15,000 for proof-covered transfers
Theoretical max: 100M / 21k x 2.78 = ~13,200 TPS (headroom above 10k target)
```

---

## 3.2 Chunked Data Plane

### Problem

At 10,000 TPS, each block carries ~720 KB of raw tx data. Block propagation, storage, and data availability become constraints.

Current block encoding puts all transactions inline in the block body. This works at low throughput but does not scale.

### Required changes

1. **DataRoot header field** — commit to block data via a separate Merkle root (this was designed in the original architecture doc but deferred)
2. **DataChunks in block body** — split tx data into fixed-size chunks for parallel propagation and proving
3. **Data availability sampling** (optional, longer term) — let light clients verify data availability without downloading full blocks
4. **Separate tx ordering from tx data** — block header commits to tx ordering; full tx data may arrive via chunked propagation

### New types (from original architecture design)

```go
type ExecutionDataChunk struct {
    Index uint32
    Data  []byte
}
```

### Block format evolution

```
Phase 1-4:  Header + Transactions + Uncles  (current)
Phase 5:    Header + TxList + DataChunks     (DataRoot != 0)
```

### Compatibility

- `DataRoot == 0` means legacy mode (current tx body)
- `DataRoot != 0` means chunked data mode
- Both modes coexist during transition

### This is the point where Header changes become justified

Phase 1-4 deliberately avoided modifying `Header`. Phase 5 is the appropriate time to add `DataRoot` to the header struct, because:

- Throughput scaling requires a consensus-level data commitment
- The network is ready for a consensus fork after Phase 4 stabilization
- `DataRoot` is a single field addition with clear semantics

---

## 3.3 Sub-Proof Sharding + Recursive Aggregation

### Problem

At 10,000 TPS with 1664-block checkpoint intervals (~10 min), each proof range covers ~5.99M transactions. No current proving system can generate a monolithic proof for this volume within the checkpoint window.

### Required architecture

```
Checkpoint range: blocks [P+1, C]  (1664 blocks)
                    |
        +-----------+-----------+
        |           |           |
   Sub-range 1  Sub-range 2  Sub-range N
   [P+1, P+k]  [P+k+1, P+2k] ...
        |           |           |
   Sub-proof 1  Sub-proof 2  Sub-proof N
        |           |           |
        +-----------+-----------+
                    |
            Recursive aggregation
                    |
            Checkpoint range proof
```

### Key design decisions

1. **Sub-range size** — how many blocks per sub-proof? Suggested: 64–128 blocks (~23–46 seconds of blocks)
2. **Parallelism** — sub-provers run in parallel on separate hardware
3. **Recursive aggregation** — a final aggregation step combines N sub-proofs into one checkpoint-range proof
4. **Proof system choice** — recursive-friendly systems (e.g., folding schemes, STARK-to-SNARK wrapping) are required

### Sub-proof sharding model

```go
type SubProofRange struct {
    RangeStart      uint64
    RangeEnd        uint64
    PrevStateRoot   common.Hash
    EndStateRoot    common.Hash
    TxCommitment    common.Hash
    SubProof        []byte
}

type AggregatedProof struct {
    CheckpointStart uint64
    CheckpointEnd   uint64
    SubProofs       []SubProofRange
    AggregatedProof []byte
}
```

### Proving timeline at 10,000 TPS

```
Sub-range: 128 blocks x 3,600 tx/block = 460,800 txs per sub-proof
Sub-ranges per checkpoint: 1664 / 128 = 13 sub-proofs
Proving parallelism: 13 sub-provers running concurrently
Aggregation: 1 recursive aggregation step over 13 sub-proofs
```

Each sub-prover must prove ~460k transactions. With 13 provers running in parallel and ~10 minutes of wall-clock time, each sub-prover has the full checkpoint window to complete its sub-range.

### Prover infrastructure

- `tosproofd` evolves from single-worker to coordinator + worker pool
- Workers can be distributed across machines
- Coordinator assigns sub-ranges and collects sub-proofs
- Final aggregation produces the checkpoint-range proof

---

## 3.4 Builder Parallel Execution

### Problem

Even though validators no longer re-execute, the builder (block proposer) must still execute all transactions to compute state roots, receipts, and witnesses. At 10,000 TPS, the builder must execute ~3,600 txs per 360ms block.

### Current state

gtos already has `ExecuteTransactions()` which supports parallel execution for non-privacy transactions. Privacy txs are executed serially.

### Required improvements

1. **Access list prediction** — predict which accounts/slots each tx will touch, enabling more aggressive parallelism
2. **Speculative execution** — execute txs optimistically in parallel, detect conflicts, re-execute conflicting txs serially
3. **Pipeline block assembly** — overlap tx execution with previous block's finalization
4. **Hardware optimization** — builder nodes should have high-core-count CPUs and fast NVMe storage

### Builder execution budget

```
Block time: 360ms
Target: 3,600 txs per block
Budget per tx: 100 microseconds (if serial)
With 16-way parallelism: 1.6ms per tx budget (feasible for transfers)
With 64-way parallelism: 6.4ms per tx budget (feasible for simple contracts)
```

Native transfers are trivially parallelizable (balance +/-, nonce++, no shared state beyond sender/receiver). The main challenge is contract execution with shared storage.

### Phase 5 target

- Transfer-only blocks: fully parallel, no serial bottleneck
- Mixed blocks: parallel execution with conflict detection, serial fallback for conflicts
- Builder execution must complete within ~200ms of the 360ms block window (leaving time for assembly, sealing, propagation)

---

## 3.5 State I/O Optimization

### Problem

MPT (Merkle Patricia Trie) has significant write amplification. Each account balance change requires updating multiple trie nodes up to the root. At 10,000 TPS with ~7,200 account mutations per block, trie updates become a bottleneck.

### Approaches

#### A. Flat state database

Maintain a flat key-value mapping alongside the trie for fast reads/writes. Trie updates happen asynchronously or in batch.

gtos already has snapshot-based state access. This can be extended:

- Reads: flat state (fast)
- Writes: flat state first, trie update deferred
- State root: computed from trie at block boundary

#### B. Verkle trie (longer term)

Replace MPT with a verkle trie. Verkle tries have:

- Smaller proofs (polynomial commitments vs hash-based)
- Lower branching factor
- Better cache locality
- Faster updates

This is a larger change and may be Phase 6+.

#### C. State diff batching

When applying proof-backed state diffs (Phase 2+), batch all account updates before computing the new root. Avoid per-account trie traversal.

```go
// Instead of:
for _, diff := range diffs {
    statedb.SetBalance(diff.Address, diff.PostBalance)  // trie update per call
}

// Batch:
statedb.BeginBatch()
for _, diff := range diffs {
    statedb.SetBalanceBatched(diff.Address, diff.PostBalance)  // deferred
}
statedb.CommitBatch()  // single trie recomputation
```

### Phase 5 target

- Flat state for reads (already partially available via snapshots)
- Batched trie updates for proof-backed state diff application
- Async trie root computation where possible
- Verkle trie evaluation for Phase 6+

---

# 4. Interaction with Proof-Native Validation

Phase 5 throughput scaling interacts with Phase 2-4 proof-native validation in several ways:

| Phase 5 module | Interaction with proof system |
|----------------|------------------------------|
| Gas limit increase | More txs per block → larger witnesses → larger proofs |
| Chunked data plane | Provers consume DataChunks instead of inline tx list |
| Recursive aggregation | Changes proof format from monolithic to aggregated |
| Builder parallelism | Parallel witness emission must remain deterministic |
| State I/O optimization | Batched state diff application must produce same root as serial application |

### Critical invariant

**All optimizations must preserve determinism.** The same block must produce the same state root, receipts, witness, and proof regardless of execution parallelism or state I/O batching strategy.

---

# 5. Header Changes in Phase 5

Phase 1-4 deliberately avoided modifying `Header`. Phase 5 is the appropriate time to introduce consensus-level header changes:

### New header fields

```go
type Header struct {
    // ... existing fields ...

    DataRoot            common.Hash `json:"dataRoot"            rlp:"optional"`
    ExecutionBundleHash common.Hash `json:"executionBundleHash" rlp:"optional"`
}
```

- `DataRoot` — commitment to chunked block data (zero = legacy mode)
- `ExecutionBundleHash` — commitment to execution certificates / aggregated proofs

These fields are `rlp:"optional"` for backward compatibility. When both are zero, the block uses the legacy format.

### Activation

- Activated via `ZKExecutionConfig.DataPlaneActivationBlock`
- Requires a coordinated network upgrade (hard fork)
- Legacy blocks (both fields zero) remain valid

---

# 6. Network and Propagation

At 10,000 TPS, block propagation requirements change:

| Metric | Current (~100 TPS) | Phase 5 (~10,000 TPS) |
|--------|--------------------|-----------------------|
| Block body size | ~20 KB | ~720 KB |
| Blocks per second | ~2.78 | ~2.78 |
| Data throughput | ~56 KB/s | ~2 MB/s |

### Required improvements

1. **Block body compression** — RLP + snappy compression for block propagation
2. **Chunked propagation** — propagate DataChunks independently, allow partial validation
3. **Header-first propagation** — propagate header immediately, body follows
4. **Bandwidth requirements** — validator nodes need ~10 Mbps+ sustained bandwidth (feasible for modern infrastructure)

---

# 7. Implementation Order

## Step 1 — Gas model analysis and parameter selection

- Analyze optimal gas limit for target TPS
- Define proof-covered vs classical gas pricing
- Simulate block assembly at higher gas limits

## Step 2 — Builder parallel execution improvements

- Access list prediction
- Conflict detection and serial fallback
- Benchmark builder throughput at target TPS

## Step 3 — State I/O optimization

- Batched state diff application
- Flat state read optimization
- Benchmark state root computation at target throughput

## Step 4 — Chunked data plane

- DataRoot and DataChunks types
- Header field additions (hard fork)
- Block encoding/decoding for chunked mode
- Prover integration with chunked data

## Step 5 — Sub-proof sharding and recursive aggregation

- Sub-range partitioning
- Parallel prover coordination
- Recursive aggregation circuit
- Aggregated proof verification in validator

## Step 6 — Network and propagation optimization

- Compressed block propagation
- Header-first propagation
- Bandwidth testing at target throughput

---

# 8. Success Criteria

Phase 5 is complete when:

1. gtos sustains ~10,000 TPS for transfer-dominated blocks on a test network
2. Block gas limit supports the required throughput
3. Block propagation completes within acceptable latency at target block sizes
4. Proof generation keeps up with checkpoint cadence via recursive aggregation
5. Builder can assemble blocks at target throughput within the block time budget
6. State I/O does not become the bottleneck at target throughput
7. All determinism invariants are preserved

---

# 9. Relationship to Ethereum Gigagas L1

| Aspect | Ethereum 2029 | gtos Phase 5 |
|--------|---------------|--------------|
| Proof target | zkEVM (universal EVM) | Profile-based zk-native gtos |
| DA approach | EIP-4844 blobs + danksharding | DataRoot + DataChunks |
| Proof aggregation | Per-block or per-slot proofs | Checkpoint-range recursive aggregation |
| State optimization | Verkle trie transition | Flat state + batched MPT (verkle in Phase 6+) |
| Gas model | EIP-4844 dual gas market | Proof-covered vs classical gas pricing |
| Builder model | PBS (proposer-builder separation) | DPoS proposer with parallel execution |

The core principle is identical: **validators verify proofs instead of re-executing**. The implementation details differ because gtos has a different consensus model (DPoS), different VM (LVM), and different execution surface.

---

# 10. Final Summary

Phase 1–4 make proof-native validation architecturally possible. Phase 5 makes it operationally sufficient for ~10,000 TPS.

| Module | What it solves | Without it |
|--------|---------------|------------|
| Gas model | Block capacity ceiling | Capped at ~4,000 TPS |
| Chunked data plane | Data availability at scale | Block propagation fails |
| Recursive aggregation | Proof generation speed | Proofs can't keep up with checkpoint cadence |
| Builder parallelism | Block assembly speed | Builder becomes bottleneck |
| State I/O | State write throughput | Trie updates stall block commit |

**Phase 1–4 = necessary. Phase 5 = sufficient. Together = Gigagas L1.**
