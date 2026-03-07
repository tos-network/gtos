package task

import (
	"errors"

	"github.com/tos-network/gtos/common"
)

// TaskStatus is the lifecycle state of a scheduled task.
type TaskStatus uint8

const (
	TaskPending   TaskStatus = 0
	TaskDone      TaskStatus = 1
	TaskCancelled TaskStatus = 2
	TaskExpired   TaskStatus = 3
)

// TaskRecord holds all on-chain state for a single scheduled task.
type TaskRecord struct {
	Scheduler      common.Address // address that created the task
	Target         common.Address // contract to call when task fires
	Selector       [4]byte        // 4-byte ABI function selector
	TaskData       common.Hash    // 32 bytes of auxiliary call data
	GasLimit       uint64         // gas budget pre-deposited
	TargetBlock    uint64         // block number when the task is first due
	IntervalBlocks uint64         // re-schedule interval; 0 = one-shot
	MaxRuns        uint64         // max executions; 0 = unlimited
	Runs           uint64         // number of completed executions so far
	Status         TaskStatus
}

var (
	ErrTaskGasLimitTooLow      = errors.New("task: gas_limit below minimum")
	ErrTaskGasLimitTooHigh     = errors.New("task: gas_limit above maximum")
	ErrTaskDelayZero           = errors.New("task: delay_blocks must be >= 1")
	ErrTaskDelayTooFar         = errors.New("task: delay_blocks exceeds horizon")
	ErrTaskIntervalTooShort    = errors.New("task: interval_blocks below minimum")
	ErrTaskActiveLimit         = errors.New("task: per-contract active task limit reached")
	ErrTaskInsufficientDeposit = errors.New("task: insufficient balance for gas deposit")
	ErrTaskNotPending          = errors.New("task: task is not in Pending state")
	ErrTaskNotScheduler        = errors.New("task: caller is not the task scheduler")
	ErrTaskLogsNotAllowed      = errors.New("task: callback emitted logs")
)

type ExecResult struct {
	GasUsed uint64
	Err     error
	Fatal   bool
}
