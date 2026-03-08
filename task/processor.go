package task

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	vmtypes "github.com/tos-network/gtos/core/vmtypes"
	"github.com/tos-network/gtos/params"
)

// ExecutorFn is injected by the caller to invoke an LVM contract.
// This indirection breaks the task ↔ core/lvm import cycle: the task package
// never imports core/lvm directly; the wiring is done in core/state_processor.go.
type ExecutorFn func(
	db vmtypes.StateDB,
	blockCtx vmtypes.BlockContext,
	chainCfg *params.ChainConfig,
	caller common.Address,
	target common.Address,
	calldata []byte,
	gasLimit uint64,
) ExecResult

// ProcessDueTasks executes all tasks scheduled at blockNum against db.
// It is called by both Process() (block validation) and the miner (block building)
// before user transactions, ensuring the state root is identical in both paths.
// Returns the number of tasks processed, total callback gas consumed, and any
// fatal error that invalidates the block.
func ProcessDueTasks(
	db vmtypes.StateDB,
	blockCtx vmtypes.BlockContext,
	chainCfg *params.ChainConfig,
	blockNum uint64,
	exec ExecutorFn,
) (int, uint64, error) {
	taskIds := DequeueTasksAt(db, blockNum)
	if len(taskIds) == 0 {
		return 0, 0, nil
	}

	processed := 0
	totalGasUsed := uint64(0)
	deferred := taskIds[:0:0] // tasks that overflow TaskMaxPerBlock

	for i, taskId := range taskIds {
		if uint64(processed) >= params.TaskMaxPerBlock {
			// Re-enqueue overflow tasks to the next block.
			deferred = append(deferred, taskIds[i:]...)
			break
		}

		rec, ok := ReadTask(db, taskId)
		if !ok || rec.Status != TaskPending {
			continue
		}

		// Build 36-byte calldata: selector[4] ++ taskData[32].
		calldata := make([]byte, 36)
		copy(calldata[:4], rec.Selector[:])
		copy(calldata[4:], rec.TaskData[:])

		// Take a snapshot so that only callback writes are reverted on failure.
		// Task framework state (WriteTask, AdjustActiveCount, refund) is applied
		// outside the snapshot and is always committed.
		snap := db.Snapshot()
		preLogCount := len(db.Logs())
		res := exec(db, blockCtx, chainCfg,
			params.TaskSchedulerAddress, rec.Target, calldata, rec.GasLimit)
		gasUsed := res.GasUsed
		if gasUsed > rec.GasLimit {
			gasUsed = rec.GasLimit
		}
		totalGasUsed += gasUsed
		if len(db.Logs()) != preLogCount {
			db.RevertToSnapshot(snap)
			// Treat log emission as a per-task failure: expire this task
			// and continue processing remaining tasks instead of aborting
			// the entire block.
			rec.Status = TaskExpired
			WriteTask(db, taskId, rec)
			AdjustActiveCount(db, rec.Scheduler, -1)
			processed++
			continue
		}
		if res.Err != nil {
			db.RevertToSnapshot(snap)
			if res.Fatal {
				return processed, totalGasUsed, res.Err
			}
		}

		// Refund remaining deposit to the scheduler.
		refundGas := rec.GasLimit - gasUsed
		if refundGas > 0 {
			refund := new(big.Int).Mul(
				new(big.Int).SetUint64(refundGas),
				big.NewInt(params.TxPriceWei),
			)
			db.SubBalance(params.TaskSchedulerAddress, refund)
			db.AddBalance(rec.Scheduler, refund)
		}

		// Update run counter and decide next state.
		rec.Runs++
		exhausted := rec.MaxRuns > 0 && rec.Runs >= rec.MaxRuns
		isOneShot := rec.IntervalBlocks == 0

		if isOneShot || exhausted {
			if exhausted && !isOneShot {
				rec.Status = TaskExpired
			} else {
				rec.Status = TaskDone
			}
			WriteTask(db, taskId, rec)
			AdjustActiveCount(db, rec.Scheduler, -1)
		} else {
			// Repeat: re-schedule at the next interval and re-deposit gas.
			nextBlock := blockNum + rec.IntervalBlocks
			if nextBlock < blockNum {
				// uint64 overflow — expire rather than wrap around.
				rec.Status = TaskExpired
				WriteTask(db, taskId, rec)
				AdjustActiveCount(db, rec.Scheduler, -1)
				processed++
				continue
			}
			rec.TargetBlock = nextBlock

			// Re-deposit gas for the next run (charged from scheduler balance).
			reDeposit := new(big.Int).Mul(
				new(big.Int).SetUint64(rec.GasLimit),
				big.NewInt(params.TxPriceWei),
			)
			if db.GetBalance(rec.Scheduler).Cmp(reDeposit) >= 0 {
				db.SubBalance(rec.Scheduler, reDeposit)
				db.AddBalance(params.TaskSchedulerAddress, reDeposit)
				WriteTask(db, taskId, rec)
				EnqueueTask(db, nextBlock, taskId)
			} else {
				// Scheduler can no longer afford another run — mark expired.
				rec.Status = TaskExpired
				WriteTask(db, taskId, rec)
				AdjustActiveCount(db, rec.Scheduler, -1)
			}
		}

		processed++
	}

	// Re-enqueue any tasks that exceeded TaskMaxPerBlock.
	// Update TargetBlock so tos.taskinfo("nextblock") reflects the actual
	// next execution block rather than the original (now-missed) target.
	for _, tid := range deferred {
		if rec, ok := ReadTask(db, tid); ok && rec.Status == TaskPending {
			rec.TargetBlock = blockNum + 1
			WriteTask(db, tid, rec)
			EnqueueTask(db, blockNum+1, tid)
		}
	}

	return processed, totalGasUsed, nil
}
