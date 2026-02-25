# Block-STM Parallel Transaction Execution for GTOS

## Context

GTOS at 360ms blocks has ample slot budget (~350ms) but serial transaction execution limits TPS. Unlike EVM chains, GTOS has no VM — only 4 deterministic transaction types with fully static, pre-computable read/write sets. This makes level-based parallel execution (a simplified Block-STM) safe and straightforward to implement without the optimistic re-execution machinery needed by EVM chains.

Goal: parallelize within-block tx execution to increase throughput while preserving identical state roots and receipt ordering.

---

## Architecture Overview

```text
AnalyzeTx(tx) → AccessSet{ReadAddrs, ReadSlots, WriteAddrs, WriteSlots}
BuildLevels(txs, accessSets) → []Level   // DAG → execution levels
For each Level:
  snapshot = statedb.Copy()              // frozen read base for this level
  goroutines: each tx → WriteBufStateDB(snapshot)
              ApplyMessage → writes go to local overlay
  serial merge: for tx in level (tx-index order):
                  apply WriteBuf writes to main statedb
                  deduct gas from GasPool, build receipt
engine.Finalize / TTL prune (unchanged, serial)
```

---

## New Files: `core/parallel/`

### `core/parallel/accessset.go`

```go
type AccessSet struct {
    ReadAddrs  map[common.Address]struct{}
    ReadSlots  map[common.Address]map[common.Hash]struct{}
    WriteAddrs map[common.Address]struct{}
    WriteSlots map[common.Address]map[common.Hash]struct{}
}

// Conflicts returns true if a's writes overlap b's reads or writes (or vice versa).
func (a *AccessSet) Conflicts(b *AccessSet) bool
```

### `core/parallel/analyze.go`

```go
AnalyzeTx(tx types.Message, blockNumber uint64) AccessSet
```

Access sets per tx type (determined by `tx.To()`):

| Tx Type | Condition | Writes |
|---|---|---|
| Plain Transfer | `To != nil, not sys/KV` | `sender(balance,nonce), recipient(balance)` |
| SetCode | `To == nil` | `sender(balance,nonce), new contract addr(code), SystemActionAddress countSlot at expireAt` |
| System Action | `To == SystemActionAddress` | `sender(balance,nonce), ValidatorRegistryAddress slots` |
| KV Put | `To == KVRouterAddress` | `sender(balance,nonce), sender's KV slots (at sender addr), KVRouterAddress countSlot at expireAt` |

Conflict rules:

- Same sender → serialize (nonce dependency)
- Two KV Puts with same `expireAt` → conflict on `KVRouterAddress countSlot`
- Two SetCode txs with same `expireAt` → conflict on `SystemActionAddress countSlot`
- Any System Action vs any other System Action → conflict on `ValidatorRegistryAddress`

For KV `expireAt` extraction: parse `tx.Data()` as KV payload to extract the TTL field (same parsing as the sysaction handler). If parse fails, treat as full conflict.

### `core/parallel/dag.go`

```go
// BuildLevels assigns each tx to a level. Txs in the same level are guaranteed
// non-conflicting. Returns ordered slice of levels; each level is a slice of tx indices.
func BuildLevels(accessSets []AccessSet) [][]int
```

Algorithm (`O(N²)`):

```text
level[i] = 0
for i in 0..N:
  for j in 0..i:
    if accessSets[i].Conflicts(accessSets[j]):
      level[i] = max(level[i], level[j]+1)
group by level → [][]int
```

### `core/parallel/writebuf.go`

`WriteBufStateDB` implements `vm.StateDB`. Wraps a frozen `*state.StateDB` snapshot.
Reads check local overlay first; writes go to local maps only.

Fields:

```go
type WriteBufStateDB struct {
    parent      *state.StateDB
    balances    map[common.Address]*big.Int
    nonces      map[common.Address]uint64
    codes       map[common.Address][]byte
    storage     map[common.Address]map[common.Hash]common.Hash
    created     map[common.Address]bool
    logs        []*types.Log
    CoinbaseFee *big.Int
}
```

Key implementations:

- `GetBalance(addr)`: check balances first, else `parent.GetBalance(addr)`
- `SubBalance` / `AddBalance`: read current (overlay or parent), update overlay
- `GetState(addr, slot)`: check `storage[addr][slot]` first, else `parent.GetState(addr, slot)`
- `GetCommittedState(addr, slot)`: always `parent.GetCommittedState(addr, slot)` (pre-tx state)
- `AddLog(log)`: append to logs
- Methods unused in GTOS (`Suicide`, `HasSuicided`, `ForEachStorage`, `AddPreimage`, refund, access list tracking): implement as no-ops or delegate to parent as appropriate

`Merge(dst *state.StateDB, coinbase common.Address)`:

- Apply all overlay maps to `dst`
- Add `CoinbaseFee` to `dst` coinbase balance

### `core/parallel/executor.go`

```go
// ExecuteParallel runs txs in parallel levels and returns receipts, logs, total gas used.
// Falls back to serial execution if len(txs) < parallelThreshold.
func ExecuteParallel(
    config *params.ChainConfig,
    blockCtx vm.BlockContext,
    statedb *state.StateDB,
    block *types.Block,
    gp *GasPool,
    signer types.Signer,
) (types.Receipts, []*types.Log, uint64, error)
```

Flow:

1. Build access sets and levels
2. For each level:
   1. `snapshot := statedb.Copy()`
   2. Allocate `WriteBufStateDB` per tx in level
   3. `sync.WaitGroup + goroutines`: `statedb.Prepare(txHash, txIdx)` on WriteBuf, `ApplyMessage`
   4. Serial merge loop (tx-index order):
      - `gp.SubGas(result.UsedGas)` — return `ErrGasLimitReached` if exceeded
      - `buf.Merge(statedb, header.Coinbase)`
      - `statedb.Finalise(true)`
      - Build receipt with running `cumulativeGasUsed`
      - Copy `buf.logs` for receipt

`const parallelThreshold = 2` — skip parallel path for 0 or 1 tx blocks.

---

## Modified File: `core/state_processor.go`

Replace the serial tx loop in `Process()`:

```go
// Before (serial):
for i, tx := range block.Transactions() {
    ...applyTransaction...
}

// After (parallel):
receipts, allLogs, *usedGas, err = parallel.ExecuteParallel(
    p.config, blockCtx, statedb, block, gp, signer)
if err != nil {
    return nil, nil, 0, err
}
```

TTL pruning and `engine.Finalize` remain after `ExecuteParallel`, unchanged.

The `applyTransaction` helper stays for `ApplyTransaction` (external callers). The `txAsMessageWithAccountSigner` helper is reused by `ExecuteParallel`.

---

## Key Design Decisions

### Why level-based (not optimistic re-execution)?

GTOS has no VM — access sets are 100% static. No re-execution needed. This avoids the speculative-abort-retry complexity of full Block-STM.

### Why snapshot per level (not per block)?

Each tx reads from the committed state after all prior levels have merged. Taking the snapshot once per level is correct and cheap (`statedb.Copy()` is already implemented).

### `statedb.Prepare()` in `WriteBufStateDB`

The `Prepare(txHash, txIndex)` call sets the tx context for log collection. Since `WriteBufStateDB` has its own log slice, this just stores the `txHash` for log attribution.

### Gas Pool

Gas deduction happens serially during merge (safe). If a mid-level tx exceeds the remaining gas, it and all subsequent txs in that level are aborted — this is acceptable because the txpool already validates gas against the block limit at submission.

### `CumulativeGasUsed` in receipts

Computed during the serial merge pass, maintaining tx-index order. Identical to serial execution output.

---

## Files to Create/Modify

| File | Action |
|---|---|
| `core/parallel/accessset.go` | Create |
| `core/parallel/analyze.go` | Create |
| `core/parallel/dag.go` | Create |
| `core/parallel/writebuf.go` | Create |
| `core/parallel/executor.go` | Create |
| `core/state_processor.go` | Modify: replace serial loop with `parallel.ExecuteParallel` |

---

## Testing

Correctness (state root parity):

```go
// core/parallel/executor_test.go
// Build a block with N mixed tx types, run both serial and parallel Process(),
// compare statedb root hash — must be identical.
```

Unit tests:

- `TestAnalyzeTxAccessSets`: verify access set computation per tx type
- `TestBuildLevels`: verify level assignment for known conflict patterns (same-sender serialized, same-expireAt KV serialized, cross-sender KV parallel)
- `TestWriteBufMerge`: apply writes via `WriteBufStateDB`, merge, verify statedb state

Benchmark:

```bash
go test -bench=BenchmarkParallelExec ./core/parallel/ -benchtime=10x
```

Compare throughput: 100 independent KV Put txs (all level 0, max parallelism) vs serial.

Existing suite:

```bash
go test -short -p 128 -parallel 128 -timeout 600s ./...
```

All tests must continue to pass (state roots identical → receipt/log ordering preserved).

---

## Verification

1. Run `go test ./core/parallel/...` — new unit tests pass
2. Run `go test ./core/...` — `TestProcess*` and existing state processor tests pass
3. Run full suite: `go test -short -p 128 -parallel 128 -timeout 600s ./...`
4. Run with race: `go test -race ./core/parallel/... ./core/...`
5. State root parity test: serial vs parallel execution of a 50-tx mixed block produces identical root
