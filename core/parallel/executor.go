// Package parallel implements level-based parallel transaction execution for GTOS.
// Because GTOS has no VM — only four deterministic tx types with fully static,
// pre-computable read/write sets — access sets are 100% static and no optimistic
// re-execution is needed.
package parallel

import (
	"errors"
	"fmt"
	"sync"

	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/params"
)

// ErrGasLimitReached is returned when a tx would exceed the block gas limit.
var ErrGasLimitReached = errors.New("gas limit reached")

// TxResult holds the outcome of executing one transaction message.
// VMErr is a non-fatal application-level error (sets receipt.Status=failed).
// A fatal block-level error is returned as the function's error return value.
type TxResult struct {
	UsedGas uint64
	VMErr   error
}

// Failed reports whether the transaction failed at the VM/application level.
func (r *TxResult) Failed() bool { return r.VMErr != nil }

// ApplyMsgFn is the per-transaction message execution function.
// Implementations MUST NOT touch the block-level gas pool; block gas accounting
// is handled serially by ExecuteParallel.
//
// The callee should create its own per-transaction gas pool seeded with msg.Gas()
// and not expose it to callers.
//
// A non-nil error return indicates a fatal error that invalidates the block.
// A non-nil VMErr in the result is a non-fatal application failure (tx is still
// included in the block with receipt.Status = failed).
type ApplyMsgFn func(
	blockCtx vm.BlockContext,
	config *params.ChainConfig,
	msg types.Message,
	statedb vm.StateDB,
) (*TxResult, error)

// BlockGasPool is the interface ExecuteParallel uses to track block-level gas.
// *core.GasPool satisfies this interface.
type BlockGasPool interface {
	SubGas(uint64) error
	Gas() uint64
}

// parallelThreshold is the minimum number of transactions for the parallel path.
const parallelThreshold = 2

// goroutineResult holds the output from a single tx goroutine.
type goroutineResult struct {
	result *TxResult
	err    error // fatal block-level error
}

// ExecuteParallel runs block transactions in parallel levels and returns receipts,
// all logs, total gas used, and any error.
//
// It falls back to an empty result when no transactions are present.
//
// Parameters:
//   - config: chain configuration
//   - blockCtx: block-level execution context (includes coinbase, block number, etc.)
//   - statedb: mutable state database (modified in place)
//   - block: the block whose transactions are to be executed
//   - gp: block-level gas pool; SubGas is called serially for each tx
//   - msgs: per-transaction messages, pre-built from the signer in the caller
//   - applyMsg: callback that executes a single message against a vm.StateDB
func ExecuteParallel(
	config *params.ChainConfig,
	blockCtx vm.BlockContext,
	statedb *state.StateDB,
	block *types.Block,
	gp BlockGasPool,
	msgs []types.Message,
	applyMsg ApplyMsgFn,
) (types.Receipts, []*types.Log, uint64, error) {
	txs := block.Transactions()
	if len(txs) == 0 {
		return nil, nil, 0, nil
	}

	header := block.Header()
	blockHash := block.Hash()
	blockNumber := header.Number

	// Build access sets and execution levels.
	accessSets := make([]AccessSet, len(txs))
	for i, msg := range msgs {
		accessSets[i] = AnalyzeTx(msg)
	}
	levels := BuildLevels(accessSets)

	// Pre-allocate result slots indexed by tx position.
	goroutineResults := make([]goroutineResult, len(txs))
	txBufs := make([]*WriteBufStateDB, len(txs))

	var (
		receipts types.Receipts
		allLogs  []*types.Log
		cumulGas uint64
	)

	for _, level := range levels {
		// Give each tx in this level its own immutable copy of current state.
		// state.StateDB is not safe for concurrent reads (internal hasher cache),
		// so every WriteBufStateDB must have an exclusive parent copy.
		for _, txIdx := range level {
			txBufs[txIdx] = NewWriteBufStateDB(statedb.Copy())
		}

		// Execute all txs in this level concurrently.
		var wg sync.WaitGroup
		for _, txIdx := range level {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				buf := txBufs[idx]
				tx := txs[idx]
				buf.Prepare(tx.Hash(), idx)
				res, err := applyMsg(blockCtx, config, msgs[idx], buf)
				goroutineResults[idx] = goroutineResult{result: res, err: err}
			}(txIdx)
		}
		wg.Wait()

		// Serial merge: process txs in deterministic index order.
		for _, txIdx := range sortedInts(level) {
			tx := txs[txIdx]
			gr := goroutineResults[txIdx]

			// Fatal error from execution.
			if gr.err != nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", txIdx, tx.Hash().Hex(), gr.err)
			}
			if gr.result == nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: nil result", txIdx, tx.Hash().Hex())
			}
			result := gr.result

			// Block-level gas accounting (serial — no races).
			// Check that the tx's declared gas fits in the remaining block gas,
			// matching the semantics of core.buyGas which checks msg.Gas() (not
			// usedGas) against the pool. The net effect is still usedGas deducted.
			if msgs[txIdx].Gas() > gp.Gas() {
				return nil, nil, 0, ErrGasLimitReached
			}
			if err := gp.SubGas(result.UsedGas); err != nil {
				return nil, nil, 0, ErrGasLimitReached
			}
			cumulGas += result.UsedGas

			// Apply overlay writes to statedb and finalise.
			buf := txBufs[txIdx]
			buf.Merge(statedb)
			statedb.Finalise(true)

			// Collect logs: fix up block-context fields.
			var txLogs []*types.Log
			for _, l := range buf.Logs() {
				lCopy := *l
				lCopy.BlockHash = blockHash
				lCopy.BlockNumber = blockNumber.Uint64()
				lCopy.Index = uint(len(allLogs))
				txLogs = append(txLogs, &lCopy)
				allLogs = append(allLogs, &lCopy)
			}

			// Build receipt.
			receipt := &types.Receipt{
				Type:              tx.Type(),
				CumulativeGasUsed: cumulGas,
				TxHash:            tx.Hash(),
				GasUsed:           result.UsedGas,
				BlockHash:         blockHash,
				BlockNumber:       blockNumber,
				TransactionIndex:  uint(txIdx),
				Logs:              txLogs,
			}
			if result.Failed() {
				receipt.Status = types.ReceiptStatusFailed
			} else {
				receipt.Status = types.ReceiptStatusSuccessful
			}
			receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
			receipts = append(receipts, receipt)
		}
	}

	return receipts, allLogs, cumulGas, nil
}

// sortedInts returns a copy of s sorted in ascending order using insertion sort.
// Level slices are small so this is efficient enough.
func sortedInts(s []int) []int {
	out := make([]int, len(s))
	copy(out, s)
	for i := 1; i < len(out); i++ {
		key := out[i]
		j := i - 1
		for j >= 0 && out[j] > key {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = key
	}
	return out
}
