# gtos Gigagas L1 — Transfer Flow: Before vs After

## User Perspective: No Change

| Step | Before (Phase 0) | After (Gigagas L1) |
|------|-------------------|---------------------|
| 1. Construct transfer | Client builds tx | **Same** |
| 2. Sign | Client signs tx | **Same** |
| 3. Send | Submit to RPC | **Same** |
| 4. Wait for confirmation | Wait for block | **Same** (potentially faster) |
| 5. Check result | Query receipt | **Same** |

Users, SDKs, wallets, and RPC interfaces are completely unaffected. The change is entirely internal to the chain.

---

## Current Flow (Phase 0)

```
User                     RPC Node             All 15 Validators
 |                          |                        |
 |--- signed tx ---------->|                        |
 |                          |-- broadcast mempool -->|
 |                          |                        |
 |                          |    Proposer picks txs, assembles block, seals
 |                          |                        |
 |                          |<-- broadcast block ----|
 |                          |                        |
 |                       Every validator:
 |                       1. Execute tx (debit sender, credit receiver)
 |                       2. Compute receipts
 |                       3. Compute state root
 |                       4. Compare against header root
 |                       5. If match, accept block
 |                          |                        |
 |<-- confirmation --------|                        |
```

### Code path (current)

```go
// blockchain.go insertChain — every validator runs this
receipts, logs, usedGas, err := bc.processor.Process(block, statedb)
// Executes ALL transactions:
//   statedb.SetBalance(sender, sender.balance - amount)
//   statedb.SetBalance(receiver, receiver.balance + amount)
//   statedb.SetNonce(sender, sender.nonce + 1)

err = bc.validator.ValidateState(block, statedb, receipts, usedGas)
// Compares locally computed state root against header root
```

### Key characteristic

All 15 validators re-execute every transaction. A single transfer is executed 15 times across the network.

---

## After Gigagas L1 (Phase 2+)

```
User                     RPC Node             Proposer/Builder       Prover            Other 14 Validators
 |                          |                        |                   |                     |
 |--- signed tx ---------->|                        |                   |                     |
 |                          |-- broadcast mempool -->|                   |                     |
 |                          |                        |                   |                     |
 |                          |    Proposer:                               |                     |
 |                          |    1. Pick txs, build batch                |                     |
 |                          |    2. Execute txs (only proposer executes) |                     |
 |                          |    3. Obtain receipts, state root          |                     |
 |                          |    4. Export witness (state change record)  |                     |
 |                          |    5. Seal block, broadcast                |                     |
 |                          |                        |                   |                     |
 |                          |                        |-- witness ------->|                     |
 |                          |                        |                   |                     |
 |                          |                        |    Prover:                               |
 |                          |                        |    Generate ZK proof:                    |
 |                          |                        |    "this batch of txs correctly          |
 |                          |                        |     transitions from preState            |
 |                          |                        |     to postState"                        |
 |                          |                        |                   |                     |
 |                          |                        |<-- proof sidecar -|                     |
 |                          |                        |                   |                     |
 |                          |<-- block + sidecar --------------------------------------------->|
 |                          |                        |                   |                     |
 |                          |                     Other 14 validators:                         |
 |                          |                     1. Receive block                             |
 |                          |                     2. Load proof sidecar                        |
 |                          |                     3. Verify proof (~1-5ms)                     |
 |                          |                     4. Apply state diff (no tx execution)        |
 |                          |                     5. Confirm state root is correct             |
 |                          |                     6. Accept block                              |
 |                          |                        |                   |                     |
 |<-- confirmation --------|                        |                   |                     |
```

### Code path (Gigagas L1)

```go
// blockchain.go insertChain — validator proof path
sidecar := rawdb.ReadProofSidecar(db, block.Hash())

if sidecar != nil && sidecar.ProofType == "native-transfer-batch-v1" {
    // PROOF PATH — does NOT execute transactions
    receipts, usedGas, statedb := bc.processor.ProcessProofBackedTransferBlock(block, parent, sidecar)
    // This does NOT execute txs. Instead:
    //   1. Load state diff from sidecar
    //   2. Apply directly: statedb.SetBalance(sender, postBalance)
    //   3. Verify proof: the proof guarantees "preState + txs = postState"

    err = bc.validator.ValidateStateProofBackedTransfer(block, parentRoot, sidecar, receipts, usedGas)
    // Verifies proof (~1-5ms), does NOT recompute state root from scratch
} else {
    // LEGACY PATH — same as current, full execution
    receipts, logs, usedGas, err := bc.processor.Process(block, statedb)
    err = bc.validator.ValidateState(block, statedb, receipts, usedGas)
}
```

### Key characteristic

Only the proposer executes transactions. The other 14 validators verify a ZK proof and apply a pre-committed state diff. A single transfer is executed **1 time**, not 15 times.

---

## Who Executes the Transaction

|                    | Before (Phase 0) | After (Gigagas L1) |
|--------------------|-------------------|--------------------|
| **Proposer**       | Executes          | Executes           |
| **Validator 1**    | Executes          | **Verifies proof** |
| **Validator 2**    | Executes          | **Verifies proof** |
| ...                | ...               | ...                |
| **Validator 14**   | Executes          | **Verifies proof** |
| **Total executions** | **15 times**    | **1 time**         |

---

## What the Validator Does (Comparison)

### Before: re-execute and compare

1. Receive block
2. Execute every transaction locally (balance transfers, nonce increments)
3. Compute receipts locally
4. Compute state root locally (`statedb.IntermediateRoot(true)`)
5. Compare local state root against `block.Header().Root`
6. If match, accept block

**Cost:** full transaction execution (~100ms+ per block)

### After: verify proof and apply diff

1. Receive block
2. Load proof sidecar from rawdb (keyed by block hash)
3. Verify ZK proof (~1-5ms)
4. Verify commitments (tx commitment, receipt commitment, state diff commitment)
5. Apply proven state diff to fresh StateDB (no tx execution)
6. Confirm resulting state root matches `block.Header().Root`
7. Accept block

**Cost:** proof verification + state diff application (~5-10ms per block)

---

## What Does NOT Change

| Component | Changes? |
|-----------|----------|
| Transaction format | No |
| Signature scheme | No |
| RPC API | No |
| Block header format (Phase 1-4) | No |
| Receipt format | No |
| State root semantics | No |
| Checkpoint finality | No |
| DPoS consensus | No |
| Block time (360ms) | No |
| Wallet / SDK interface | No |

---

## Proposer vs Prover: Two Processes, One Machine

The Proposer and Prover are **two independent processes** running on the same validator machine (or same rack). They are not the same process.

### Architecture

```
+---------------------------------------------+
|              Validator Machine               |
|                                              |
|  +------------------+  +------------------+  |
|  |     gtos          |  |   tosproofd       |  |
|  |  (Proposer)       |  |   (Prover)        |  |
|  |                   |  |                   |  |
|  |  - pick txs       |  |  - receive witness |  |
|  |  - execute txs    |  |  - run ZK circuit  |  |
|  |  - export witness |->|  - generate proof  |  |
|  |  - seal block     |  |  - return sidecar  |  |
|  |  - broadcast block|<-|                   |  |
|  |  - store sidecar  |  |                   |  |
|  +------------------+  +------------------+  |
|       gtos node             proof worker      |
|       (Go)                  (Go/Rust)         |
+---------------------------------------------+
```

### Why two separate processes

| Reason | Explanation |
|--------|-------------|
| **Non-blocking** | gtos produces blocks every 360ms. Proof generation may take seconds or tens of seconds. Running proof generation inside gtos would stall block production. |
| **Resource isolation** | Proof generation is CPU-intensive (potentially GPU-accelerated). The gtos node is primarily I/O + network. Separate processes prevent resource contention. |
| **Language flexibility** | gtos is written in Go. The prover circuit may use Rust (Halo2, SP1, and most ZK libraries are Rust-native). Separate processes communicate via IPC. |
| **Independent upgrades** | Swapping the proving system (e.g., from stub to real prover) only requires restarting `tosproofd`, not the gtos node. |

### Communication

Phase 1 uses **Unix domain socket** (same-machine, zero network overhead):

```go
// gtos side (miner/proof_orchestrator.go)
type ProofWorkerClient interface {
    RequestTransferBatchProofAsync(req *ProofWorkerRequest, callback func(*ProofWorkerResponse, error))
}

// tosproofd side (proofworker/server.go)
// Listens on Unix socket, receives witness, returns proof
```

### Timing

```
time ------------------------------------------------->

gtos:       [pick tx] [execute] [seal] [broadcast block]
                  |                |
                  +- export witness ->
                                   |
tosproofd:                         [receive] [generate proof...........] [return sidecar]
                                                                              |
gtos:                                                        [store sidecar to rawdb]
```

Block is sealed and broadcast first. Proof arrives later. This is Phase 1 "async shadow proving" — block production never waits for proof.

### Who pays the cost

| Role | Work | Who |
|------|------|-----|
| Proposer | Execute txs + export witness | The validator whose DPoS turn it is (rotates among 15 validators) |
| Prover | Generate ZK proof | `tosproofd` on the same validator machine |
| Other 14 validators | Verify proof (~1-5ms) | All other validators (net beneficiaries — much less work than before) |

There is no dedicated "prover operator". The proposing validator runs both `gtos` and `tosproofd`. Since DPoS rotates proposer duty across all 15 validators, the proving cost is **evenly distributed**.

### Future evolution (Phase 5+)

At ~10,000 TPS, proof generation becomes heavier (millions of txs per checkpoint range). Options:

| Model | Description |
|-------|-------------|
| **Validator self-proving** (Phase 1-4) | Each validator runs its own `tosproofd`. Simplest model. |
| **Dedicated prover service** | Independent prover nodes; validators pay for proof generation. |
| **Prover market** | Multiple provers compete; fastest/cheapest proof is adopted. |

Phase 1-4 use the self-proving model. Prover decentralization is a Phase 5+ concern.

---

## Timing Budget: Proposer, Prover, and Validator

### Proposer: must finish within 360ms block time

The proposer (the gtos node) must complete all work within the 360ms block interval. Breakdown:

```
Block time = 360ms

  Pick txs from mempool                ~1-5ms
  Execute txs (balance+/-, nonce++)    ~30-100ms
  Compute state root (MPT trie)        ~10-30ms
  Export witness (Phase 1 addition)     ~5-10ms
  Assemble block + seal (ed25519)      ~1-2ms
  ----------------------------------------
  Total                                ~50-150ms

  Remaining time for network broadcast ~200-300ms
```

| Scenario | Txs per block | Execution time | Total |
|----------|--------------|----------------|-------|
| Current actual load | ~100 tx/block | ~10ms | ~30ms |
| Current full capacity | ~1,400 tx/block (30M gas) | ~50-100ms | ~80-150ms |
| Phase 5 target | ~3,600 tx/block (100M gas) | ~100-200ms | ~150-250ms |

The proposer comfortably fits within the 360ms window at current load. Phase 5 high-load scenarios will be tighter.

### Prover: 2-30 seconds (async, NOT on the critical path)

The prover (`tosproofd`) runs asynchronously after block sealing. It is never constrained by the 360ms block time.

```
  Receive witness                      ~1-10ms
  Build ZK circuit inputs              ~100-500ms
  Generate ZK proof                    ~2-30 seconds
  Return sidecar                       ~1ms
  ----------------------------------------
  Total                                ~2-30 seconds
```

Proof generation time depends on the proving system and batch size:

| Proving system | 1,000 transfer batch | Notes |
|----------------|---------------------|-------|
| **Stub prover** (Phase 1) | ~1ms | Fake proof for pipeline testing only |
| **Halo 2** | ~2-10s | Complex circuit authoring, small proof (~KB) |
| **SP1 (Succinct)** | ~10-30s | Write Rust code, larger proof (~hundreds KB) |
| **Risc0** | ~10-60s | Similar to SP1 |
| **Plonk + KZG** | ~3-15s | Requires trusted setup |

### Why slow proving is acceptable

```
Timeline (3 consecutive blocks):

Block N:    [Proposer: 150ms] [Broadcast: 210ms]
                |
                +-- witness --> [Prover: ~~~~~~~~~ 10 seconds ~~~~~~~~~] --> sidecar N
                                                                                |
Block N+1:  [Proposer: 150ms] [Broadcast: 210ms]                               |
                                                                                |
Block N+2:  [Proposer: 150ms] [Broadcast: 210ms]                               |
                                                                                v
                                                                 Store to rawdb (block N sidecar)
```

Block N is sealed and broadcast immediately. The proof for block N arrives seconds later, after several more blocks have already been produced. This is Phase 1 "async shadow proving".

In Phase 2+ (proof used for consensus validation), the sidecar may arrive a few seconds to tens of seconds after the block. This is acceptable because checkpoint finality operates on a 1664-block interval (~10 minutes) — the proof only needs to arrive before the next checkpoint.

### Validator: 1-5ms (proof verification)

After Gigagas L1, non-proposer validators verify a proof instead of re-executing all transactions:

| Operation | Time |
|-----------|------|
| Load proof sidecar from rawdb | ~0.1ms |
| Verify ZK proof | ~1-3ms |
| Verify commitments (tx, receipt, state diff) | ~0.5ms |
| Apply state diff | ~1-3ms |
| **Total** | **~2-7ms** |

Compared to the current full-execution model (~50-100ms per block), this is a **10-50x reduction** in per-block validation time.

### Summary table

| Role | Time | Constraint |
|------|------|------------|
| **Proposer** | **50-150ms** | Must finish within 360ms block time |
| **Prover** | **2-30 seconds** | Async, does not block block production |
| **Validator (proof verify)** | **1-5ms** | Much faster than current full execution (~100ms) |

---

## Do We Still Need 15 Validators?

**Yes.** Proof verification replaces transaction re-execution, but it does not replace consensus. Validators still perform six out of seven original duties — only "execute transactions to validate" is replaced by "verify proof".

### Validator responsibilities after Gigagas L1

| Responsibility | Still needed? | Changes? |
|----------------|---------------|----------|
| DPoS block proposer rotation | Yes | No change |
| Sign and seal blocks (ed25519) | Yes | No change |
| Checkpoint QC voting (2/3+1 signatures) | Yes | No change |
| Fork choice (select canonical chain) | Yes | No change |
| Broadcast and relay blocks | Yes | No change |
| Maintain state trie | Yes | No change |
| Execute transactions to validate | ~~Yes~~ | **Replaced by proof verification** |

### Why validators cannot be reduced

**1. Checkpoint finality requires 2/3+1 signatures**

```
Current: 15 validators, finalize requires ceil(15 x 2/3) = 10 signatures
```

Fewer validators means fewer signatures needed for finality, which lowers the cost of a collusion attack. The validator count is a security parameter, not an execution parameter.

**2. DPoS rotation requires multiple proposers**

If only one node proposes and proves, it becomes a centralized single point. It could:
- Censor transactions (refuse to include specific txs)
- Go offline (halt the chain)
- Forge state (produce invalid proofs)

Multiple validators rotating through proposer duty ensure no single party controls the chain.

**3. ZK proofs do not replace consensus**

A ZK proof proves: **"the state transition is correct."**

A ZK proof does NOT prove:
- The block was produced by a legitimate DPoS proposer (requires DPoS signatures)
- The block is accepted by a majority of validators (requires checkpoint QC)
- There is no longer competing chain (requires fork choice)

**Proofs replace re-execution, not consensus.**

### What actually changes: validator hardware cost

The real benefit is not fewer validators, but **lighter validators**:

| Metric | Before | After Gigagas L1 |
|--------|--------|-------------------|
| CPU requirement | High (execute all txs) | **Low** (verify proof only) |
| Per-block processing time | ~100ms+ (full execution) | **~5-10ms** (proof verify + state diff apply) |
| Achievable TPS | Bounded by CPU execution speed | Bounded by proof verification speed and network bandwidth |
| Hardware cost per validator | High | **Significantly lower** |
| Barrier to becoming a validator | High (need fast CPU to keep up) | **Lower** (proof verification is lightweight) |

### Result

- **Same number of validators** (15) — consensus security is preserved
- **Each validator does much less work** — from "execute all transactions" to "verify one proof"
- **More people can afford to run validators** — hardware requirements drop
- **The chain can process more transactions** — validator throughput is no longer the bottleneck

---

## Summary

**One sentence:** Users sign and send transactions exactly the same way. The difference is that inside the chain, 14 out of 15 validators verify a proof instead of re-executing every transaction — reducing per-block validation cost from ~100ms to ~5ms and enabling throughput scaling to ~10,000 TPS.

**Validators are still needed** — they provide consensus, not just execution. But they become much lighter: from heavy compute nodes to lightweight proof verifiers.
