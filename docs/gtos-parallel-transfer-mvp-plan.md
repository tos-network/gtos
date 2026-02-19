# GTOS Parallel Transfer Execution MVP Plan

## 1. Context From Current Code

This plan is based on the current `~/gtos` code paths:

- Block import executes txs strictly serially in `core/state_processor.go`.
- Miner block assembly executes txs strictly serially in `miner/worker.go`.
- GTOS execution rules are implemented in `core/state_transition.go`:
  - no contract creation/call
  - `params.SystemActionAddress` goes through `sysaction.Execute`
  - plain transfer is the main successful user tx path
- System actions mutate staking/agent state and must stay deterministic (`sysaction/executor.go`, `staking/*`).
- `state.StateDB` is not safe for concurrent mutation, but supports copy/snapshot (`core/state/statedb.go`).

Conclusion: the safest MVP is **parallelize only plain transfer txs**, keep all system actions and unsupported tx shapes on the serial path.

---

## 2. MVP Goals / Non-goals

### Goals

- Increase throughput for transfer-only workloads.
- Keep consensus result identical to the current serial semantics (same receipts/state root).
- Keep change surface small and reversible.

### Non-goals (MVP)

- No parallel execution for `sysaction`.
- No tx reordering across the original block order.
- No change to tx format, block format, or consensus rules.

---

## 3. Design Overview

### 3.1 Tx Lanes

Define two lanes during execution:

- `Serial lane`:
  - `To == nil`
  - `To == params.SystemActionAddress`
  - `len(tx.Data()) > 0`
  - destination has code
  - any tx type we intentionally exclude in MVP
- `Parallel-transfer lane`:
  - plain transfer only (`To != nil`, not system action, empty data, no destination code)

Only the parallel-transfer lane is batched for parallel compute.

### 3.2 Deterministic Batching Rule

For a contiguous transfer run, split into micro-batches with **no account overlap**:

- a batch cannot contain two txs touching the same `from` or `to` account
- if conflict appears, flush current batch and start next
- keep original tx index order for receipt and cumulative gas

This guarantees order-equivalent result for transfer txs while allowing concurrent per-tx execution.

### 3.3 Parallel Execution Model (MVP)

Per micro-batch:

1. Serial precheck phase:
   - decode signer/message
   - validate nonce/gas/balance constraints with current semantics
   - reserve gas with the same rule as current code (`tx.Gas` admission semantics)
2. Parallel compute phase:
   - compute per-tx transfer deltas and fee outcomes in workers
3. Serial merge phase:
   - apply deltas to canonical `StateDB` in original tx order
   - build receipts with original tx index and cumulative gas

If any mismatch/failure is detected, fallback to serial execution path for safety.

### 3.4 Safety Guards

- Feature flag off by default.
- Shadow mode: run parallel result vs serial result comparison on selected blocks, panic/log on mismatch.
- Fast fallback to existing serial implementation on any unsupported edge condition.

---

## 4. File-level MVP Checklist

### Core Execution

- [ ] `core/state_processor.go`
  - route tx loop through a new batch executor:
    - serial tx -> existing `applyTransaction`
    - transfer batch -> parallel batch executor
- [ ] `core/state_transition.go`
  - extract reusable checks/helpers for plain transfer eligibility and fee math (avoid duplicate consensus logic)
- [ ] `core/parallel_transfer_executor.go` (new)
  - implement:
    - tx classification
    - non-overlap batching
    - worker pool execution
    - deterministic merge + receipt assembly
- [ ] `core/parallel_transfer_types.go` (new)
  - batch task/result structs
- [ ] `core/parallel_transfer_metrics.go` (new)
  - metrics: batch count, tx count, fallback count, execution latency

### Miner Path

- [ ] `miner/worker.go`
  - integrate same executor for contiguous plain-transfer runs during `commitTransactions`
  - keep existing nonce-too-low/high handling behavior
- [ ] `miner/miner.go`
  - wire config fields into worker/executor initialization

### Config / Flags

- [ ] `core/blockchain.go` (`CacheConfig`)
  - add tx-exec runtime knobs for block import:
    - `TxExecParallelTransfer`
    - `TxExecWorkers`
    - `TxExecBatchMax`
    - `TxExecShadowVerify`
- [ ] `miner/miner.go` (`miner.Config`)
  - add equivalent knobs for mining path
- [ ] `tos/tosconfig/config.go`
  - default values and TOML mapping
- [ ] `cmd/utils/flags.go`
  - add CLI flags:
    - `--txexec.parallel`
    - `--txexec.workers`
    - `--txexec.batch`
    - `--txexec.shadow`
  - map to both blockchain and miner config

### Optional Pool-side Fast Reject (Recommended)

- [ ] `core/tx_pool.go`
  - optional early reject of tx shapes GTOS will never execute successfully
  - reduce mempool noise and wasted block packing attempts

---

## 5. Test Checklist

- [ ] `core/parallel_transfer_executor_test.go` (new)
  - randomized transfer sets, compare serial vs parallel:
    - post-state root
    - receipt status/gas/cumulative gas/index
    - miner balance delta
- [ ] `core/state_processor_test.go`
  - extend with mixed workloads:
    - transfer + sysaction interleave
    - conflicting addresses
    - large `tx.Gas` with low actual gas used
- [ ] `miner/worker_test.go`
  - ensure packed block tx order unchanged
  - ensure error-handling (`nonce too low/high`, gas limit reached) behavior unchanged
- [ ] race test:
  - `go test -race ./core/... ./miner/...`
- [ ] benchmark:
  - `BenchmarkSerialVsParallelTransfer` for 1k/5k/10k tx blocks, varying account hotspot ratio

---

## 6. Rollout Plan

1. Implement core block-import path behind feature flag, miner path untouched.
2. Enable shadow verify in dev/testnet; collect mismatch/fallback metrics.
3. Enable miner path integration after core path is stable.
4. Tune worker count and batch size from benchmark data.
5. Default-on only after sustained shadow parity.

---

## 7. Expected Outcome (MVP)

- Best case (highly non-overlapping transfer workload): noticeable speedup in tx execution stage.
- Worst case (hot accounts/system actions): auto-degrades to serial behavior.
- Consensus risk controlled by:
  - deterministic batching
  - serial merge
  - serial fallback
  - shadow verification.
