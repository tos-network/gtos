# ATOS Execution Layer Integration

**Status:** Design Document
**Version:** 0.1.0
**Companion to:** [ATOS Yellow Paper](https://github.com/tos-network/atos/blob/main/yellowpaper.md)

> This document defines how GTOS integrates with ATOS as a separated execution layer. GTOS retains consensus, settlement, agent economy, and state authority. ATOS provides hardware-isolated, energy-metered, multi-runtime contract execution with optional ZK proofs.

---

## 1. Motivation

GTOS currently uses an embedded LVM (Lua VM) for contract execution. This has limitations:

| LVM Limitation | ATOS Solution |
|----------------|--------------|
| Lua-only (small developer ecosystem) | EVM, WASM, Python, JVM, zkVM (massive ecosystem) |
| Software sandbox only | Hardware isolation (Ring-3, page tables, SMEP/SMAP) |
| Software gas counting | Hardware timer-interrupt preemption |
| No execution proofs | ReplayGrade and ZK proofs |
| Single VM architecture | Multiple runtimes on one substrate |

By separating execution from consensus, GTOS gains the full ATOS runtime portfolio while keeping its protocol layer (system actions, agent registry, capabilities, settlement) unchanged.

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  GTOS Node (Go, Linux)                                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Consensus (DPoS)                                  │  │
│  │ P2P Network (devp2p)                              │  │
│  │ Mempool + Block Production                        │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ StateDB (source of truth)                         │  │
│  │ ├── Protocol State (agent, cap, settlement, ...)  │  │
│  │ └── Contract State (storage, code, balances)      │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Transaction Router (state_transition.go)          │  │
│  │ ├── System Action → local Go handler (44 types)   │  │
│  │ ├── Plain Transfer → local statedb.Transfer()     │  │
│  │ └── Contract Call → ATOS Bridge ──────────────────┼──┼──→
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ ATOS Bridge (atos/bridge.go)                      │  │
│  │ ├── BuildStateSlice() — cut relevant state        │  │
│  │ ├── Send(tx + state_slice) → ATOS                 │  │
│  │ ├── HandleStateFetch() — on-demand queries        │  │
│  │ └── ApplyDiff(state_diff) → StateDB              │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │ TCP │
                          ↓     ↑
┌─────────────────────────────────────────────────────────┐
│  ATOS Node (Rust, bare-metal / QEMU)                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Executor Agent (stateless)                        │  │
│  │ ├── Receive(tx + state_slice)                     │  │
│  │ ├── Load state into temporary keyspace            │  │
│  │ ├── Execute via runtime (revm/wasmi/RustPython/…) │  │
│  │ ├── Collect state_diff + logs + gas_used          │  │
│  │ ├── [Optional] Generate ZK proof via SP1          │  │
│  │ └── Return(state_diff + proof)                    │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Available Runtimes                                │  │
│  │ ├── revm      — Solidity / Vyper (EVM)            │  │
│  │ ├── wasmi     — Rust / Go / C → WASM              │  │
│  │ ├── RustPython — Python (AI agents)               │  │
│  │ ├── Ristretto — Java / Kotlin (JVM)               │  │
│  │ └── SP1       — RISC-V zkVM (ZK proofs)           │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Kernel Guarantees                                 │  │
│  │ ├── Ring-3 hardware isolation per execution       │  │
│  │ ├── Energy metering via timer-tick preemption     │  │
│  │ ├── Capability-scoped authority                   │  │
│  │ └── eBPF-lite policy enforcement                  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 3. Core Design Decision: StateDB Stays in GTOS

ATOS is a **stateless executor**. It does not persist state between executions.

### Why StateDB Cannot Move to ATOS

1. **System actions need direct StateDB access.** The 44 protocol-level handlers (agent registration, capability grants, settlement callbacks, policy enforcement) are Go code that reads and writes StateDB directly. Moving StateDB to ATOS would require 44 network round-trips per handler invocation.

2. **Consensus needs state.** Block production and validation compute state roots from StateDB. State roots go into block headers. This must be local to the consensus node.

3. **State root computation is on the critical path.** Every block must compute `statedb.IntermediateRoot()`. This cannot tolerate network latency.

### The Stateless Execution Model

```
ATOS execution is a pure function:

    execute(transaction, state_slice, block_context) → (state_diff, logs, gas_used, proof)

Input:   transaction + relevant state subset (read-only snapshot)
Output:  list of state changes + execution metadata
No side effects. No persistent state on ATOS between calls.
```

This is the same model used by all rollup provers (zkSync, Scroll, Linea): the prover is stateless, the sequencer owns the state.

## 4. State Slice: How Execution Context Crosses the Wire

### 4.1 The Challenge

An EVM transaction may read any storage slot during execution. The set of accessed slots is not known before execution. Sending the entire state is infeasible (gigabytes).

### 4.2 Solution: Access List Prediction + On-Demand Fallback

```
Phase 1: GTOS predicts which state the transaction will access
  → Generate access list (addresses + storage slots)
  → Cut a state slice containing those values
  → Send tx + state_slice to ATOS (~90-95% hit rate)

Phase 2: ATOS executes, may discover missing state
  → Request missing slots from GTOS over TCP (rare, <5% of txs)
  → GTOS responds with values
  → ATOS continues execution

Phase 3: ATOS returns results
  → state_diff + logs + gas_used + optional proof
  → GTOS applies diff to StateDB
```

### 4.3 Access List Generation

```go
// atos/state_slice.go

func BuildStateSlice(statedb *state.StateDB, tx *types.Transaction, ctx BlockContext) *StateSlice {
    slice := &StateSlice{BlockContext: ctx}

    // Always include sender and receiver accounts
    slice.AddAccount(tx.From(), statedb)
    if tx.To() != nil {
        slice.AddAccount(*tx.To(), statedb)
        slice.AddCode(*tx.To(), statedb)
    }

    // EIP-2930 access list (if provided by the transaction)
    for _, entry := range tx.AccessList() {
        slice.AddAccount(entry.Address, statedb)
        for _, slot := range entry.StorageKeys {
            slice.AddStorage(entry.Address, slot, statedb)
        }
    }

    // Predictive access list (local pre-execution simulation)
    predicted := SimulateAccess(statedb, tx, ctx)
    for _, access := range predicted {
        slice.AddStorage(access.Address, access.Slot, statedb)
    }

    return slice
}
```

### 4.4 State Slice Format

```json
{
    "accounts": {
        "0xFromAddr": {
            "balance": "50000000000000000000",
            "nonce": 42,
            "code_hash": "0xc5d2..."
        },
        "0xContractAddr": {
            "balance": "0",
            "nonce": 1,
            "code": "0x608060405234...",
            "storage": {
                "0x0000...0000": "0x0000...0001",
                "0x0000...0001": "0x0000...ffff",
                "0x0000...0005": "0x0000...1234"
            }
        }
    }
}
```

### 4.5 On-Demand State Fetch (Fallback)

When ATOS encounters an SLOAD for a slot not in the state slice:

```
ATOS → GTOS:  { "type": "state_fetch", "address": "0x...", "slot": "0x07" }
GTOS → ATOS:  { "type": "state_value", "slot": "0x07", "value": "0x...1234" }
```

This adds one network round-trip per missing slot (~0.1ms on same-rack machines). With good access list prediction, this happens for fewer than 5% of transactions.

## 5. Communication Protocol

### 5.1 Transport

TCP connection between GTOS (Go) and ATOS (Rust). ATOS receives via its `netd` system agent.

```
GTOS (Linux, Go net.Dial)  ←─ TCP ─→  ATOS (bare-metal, netd agent)
```

Connection is persistent (pooled) to avoid TCP handshake overhead per transaction.

### 5.2 Message Types

**GTOS → ATOS:**

| Message | Purpose |
|---------|---------|
| `exec_request` | Submit transaction + state slice for execution |
| `state_response` | Reply to ATOS state fetch with slot values |
| `batch_request` | Submit multiple transactions as a batch |

**ATOS → GTOS:**

| Message | Purpose |
|---------|---------|
| `exec_result` | Return state diff + logs + gas + proof |
| `state_fetch` | Request missing state during execution |
| `batch_result` | Return results for a batch |

### 5.3 Execution Request

```json
{
    "msg_type": "exec_request",
    "request_id": "uuid-1234",
    "runtime": "evm",

    "transaction": {
        "from": "0x...",
        "to": "0x...",
        "value": "0",
        "data": "0xa9059cbb000000000000000000000000...",
        "gas_limit": 100000,
        "nonce": 42
    },

    "block_context": {
        "number": 1234567,
        "timestamp": 1711360000,
        "coinbase": "0x...",
        "chain_id": 1000,
        "base_fee": "10000000000"
    },

    "state_slice": {
        "accounts": { ... }
    },

    "proof_grade": "none"
}
```

### 5.4 Execution Result

```json
{
    "msg_type": "exec_result",
    "request_id": "uuid-1234",
    "status": "success",
    "gas_used": 43521,
    "return_data": "0x0000...0001",

    "state_diff": [
        {
            "address": "0xContractAddr",
            "storage_changes": [
                { "slot": "0x00", "old_value": "0x01", "new_value": "0x02" }
            ]
        },
        {
            "address": "0xFromAddr",
            "balance_change": { "old": "50eth", "new": "49.99eth" },
            "nonce_change": { "old": 42, "new": 43 }
        }
    ],

    "logs": [
        {
            "address": "0xContractAddr",
            "topics": ["0xddf252ad..."],
            "data": "0x..."
        }
    ],

    "zk_proof": null
}
```

## 6. Transaction Routing in GTOS

The transaction router in `core/state_transition.go` determines where each transaction executes:

```
Incoming Transaction
    │
    ├── To == SystemActionAddress (0x...0001)
    │   → Execute locally: sysaction.Execute(ctx, sa)
    │   → Direct StateDB access (Go handler)
    │   → No ATOS involvement
    │
    ├── To == nil (Contract Creation)
    │   → Route to ATOS: create new contract via runtime
    │   → ATOS returns deployed code + state diff
    │
    ├── To has code (Contract Call)
    │   → Route to ATOS: execute contract via runtime
    │   → ATOS returns state diff + logs
    │
    └── Plain Transfer (no code, no system action)
        → Execute locally: statedb.Transfer(from, to, value)
        → No ATOS involvement
```

**Only contract creation and contract calls go to ATOS.** System actions (44 types) and plain transfers execute locally in GTOS with direct StateDB access.

## 7. ATOS Executor Agent

On the ATOS side, a dedicated `executor` agent handles requests from GTOS:

```
executor agent lifecycle:
  1. Boot with netd network capability
  2. Listen on TCP port for GTOS connections
  3. For each request:
     a. Parse transaction + state slice
     b. Load state slice into temporary keyspace
     c. Select runtime (revm / wasmi / RustPython / Ristretto)
     d. Execute with energy budget = gas_limit
     e. Collect state diff + logs
     f. [Optional] Generate ZK proof via SP1
     g. Return results to GTOS
     h. Clear temporary keyspace
  4. Loop
```

The executor agent is **stateless** — temporary keyspace is cleared after each execution. No state persists between transactions.

## 8. Batch Execution

For block production efficiency, GTOS can batch multiple contract transactions:

```
GTOS:
  Block N has 100 transactions:
    - 60 plain transfers → execute locally
    - 15 system actions → execute locally
    - 25 contract calls → batch to ATOS

  Send batch of 25 contract calls + state slices to ATOS
  ATOS executes sequentially (or in parallel if independent)
  Returns 25 results

  GTOS applies all diffs → compute state root → finalize block
```

### 8.1 Parallel Execution

Independent contract calls (different addresses, no state overlap) can execute in parallel on ATOS:

```
ATOS receives batch [tx1, tx2, tx3, tx4, tx5]
  tx1 touches contract A → spawn agent 1
  tx2 touches contract B → spawn agent 2 (parallel with agent 1)
  tx3 touches contract A → wait for tx1 to complete first
  tx4 touches contract C → spawn agent 3 (parallel)
  tx5 touches contract B → wait for tx2 to complete first
```

GTOS provides dependency hints in the batch request (based on access list overlap). ATOS's multi-agent architecture naturally supports parallel execution.

## 9. ZK Proof Integration

When `proof_grade` is set to `"zk"` in the execution request:

```
Synchronous (for single high-value transactions):
  GTOS sends request with proof_grade="zk"
  → ATOS executes in SP1 zkVM
  → Returns result + ZK proof
  → GTOS anchors proof hash in block

Asynchronous (for batches, does not block consensus):
  GTOS sends request with proof_grade="zk_async"
  → ATOS executes natively (fast) → returns result immediately
  → ATOS generates ZK proof in background
  → ATOS sends proof to GTOS later via ATOS_RESULT system action
  → GTOS anchors proof in a subsequent block
```

The async model allows 360ms block production while ZK proofs (which take seconds) are generated in the background.

## 10. LVM Deprecation Path

With ATOS as the execution layer, the embedded LVM is no longer needed:

| Phase | LVM Status | Contract Execution |
|-------|-----------|-------------------|
| **Phase 1** | Active (default) | New contracts can choose ATOS or LVM |
| **Phase 2** | Deprecated | New contracts must use ATOS; existing Lua contracts still work |
| **Phase 3** | Removed | All execution via ATOS; migration tools provided for Lua → WASM/Solidity |

### Migration Tool

```bash
# Convert existing Lua contract to WASM
gtos migrate --from lua --to wasm ./contract.tor

# Or to Solidity (for EVM compatibility)
gtos migrate --from lua --to solidity ./contract.tor
```

After Phase 3, `core/vm/lvm.go` (~211KB) is deleted. GTOS becomes a pure consensus + settlement layer.

## 11. Latency Analysis

| Step | Time (same rack) | Time (cross-region) |
|------|-------------------|---------------------|
| GTOS: build state slice | ~1ms | ~1ms |
| Network: GTOS → ATOS | ~0.1ms | ~20ms |
| ATOS: load state | ~0.5ms | ~0.5ms |
| ATOS: execute (revm) | ~1-5ms | ~1-5ms |
| ATOS: state fetch fallback (if needed) | ~0.2ms | ~40ms |
| Network: ATOS → GTOS | ~0.1ms | ~20ms |
| GTOS: apply diff | ~0.5ms | ~0.5ms |
| **Total (no ZK, same rack)** | **~3-7ms** | — |
| **Total (no ZK, cross-region)** | — | **~80-90ms** |
| **ZK proof (async, background)** | ~5-30s | ~5-30s |

GTOS target block time is 360ms. Same-rack execution (3-7ms per contract call) easily fits within the block time budget. **ATOS and GTOS should run in the same data center for production deployment.**

## 12. GTOS Code Changes Summary

| File | Change | Lines |
|------|--------|-------|
| `atos/bridge.go` | **New**: TCP connection, send/recv, state fetch handling | ~200 |
| `atos/state_slice.go` | **New**: BuildStateSlice, access list prediction | ~150 |
| `atos/types.go` | **New**: ExecRequest, ExecResult, StateDiff types | ~100 |
| `atos/handler.go` | **New**: ATOS_SUBMIT, ATOS_RESULT, ATOS_VERIFY system actions | ~200 |
| `atos/state.go` | **New**: On-chain task state (pending, completed, proof hash) | ~100 |
| `core/state_transition.go` | **Modify**: Route contract calls to ATOS bridge | ~30 |
| `sysaction/types.go` | **Modify**: Add ATOS action constants | ~5 |
| `params/tos_params.go` | **Modify**: Add ATOS registry address + capability bits | ~10 |
| **Total** | | **~800** |

## 13. ATOS Code Changes Summary

| File | Change | Lines |
|------|--------|-------|
| `src/agents/executor.rs` | **New**: GTOS execution proxy agent | ~300 |
| `src/gtos_protocol.rs` | **New**: Message parsing, state slice loading | ~200 |
| **Total** | | **~500** |

## 14. Security Considerations

| Concern | Mitigation |
|---------|-----------|
| ATOS node compromised | ZK proof mode: result is mathematically verified regardless of executor trust |
| Network interception | TLS on TCP connection; state slices contain no secrets (all on-chain data) |
| ATOS returns wrong diff | GTOS can verify: re-execute locally for high-value txs, or verify ZK proof |
| Denial of service | GTOS timeout on ATOS response; fallback to local execution if ATOS unreachable |
| State slice too large | Cap slice size; reject transactions with excessively large access lists |

## 15. Fallback Mode

If the ATOS node is unreachable, GTOS can fall back to local execution:

```go
func (b *ATOSBridge) Execute(tx, ctx) (*ExecResult, error) {
    result, err := b.remoteExecute(tx, ctx)
    if err != nil {
        // ATOS unreachable — fall back to local LVM (Phase 1/2)
        // or local revm-go (Phase 3)
        return b.localFallback(tx, ctx)
    }
    return result, nil
}
```

This ensures GTOS never stops producing blocks even if the ATOS execution layer is temporarily unavailable.
