package task

import (
	"encoding/binary"
	"encoding/json"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&taskHandler{})
}

// TaskScheduledTopic is the log topic for the TaskScheduled event.
// Equivalent to keccak256("TaskScheduled(bytes32,address,address,uint64)").
var TaskScheduledTopic = common.BytesToHash(crypto.Keccak256([]byte("TaskScheduled(bytes32,address,address,uint64)")))

type taskHandler struct{}

func (h *taskHandler) CanHandle(kind sysaction.ActionKind) bool {
	switch kind {
	case sysaction.ActionTaskSchedule, sysaction.ActionTaskCancel:
		return true
	}
	return false
}

func (h *taskHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionTaskSchedule:
		return h.handleSchedule(ctx, sa)
	case sysaction.ActionTaskCancel:
		return h.handleCancel(ctx, sa)
	}
	return nil
}

type schedulePayload struct {
	Target         string `json:"target"`
	Selector       string `json:"selector"`        // hex 4 bytes (optional 0x prefix)
	TaskData       string `json:"task_data"`       // hex 32 bytes
	GasLimit       uint64 `json:"gas_limit"`
	DelayBlocks    uint64 `json:"delay_blocks"`
	IntervalBlocks uint64 `json:"interval_blocks"`
	MaxRuns        uint64 `json:"max_runs"`
}

func (h *taskHandler) handleSchedule(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p schedulePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	// 1. Validate gas_limit.
	if p.GasLimit < params.TaskMinGasLimit {
		return ErrTaskGasLimitTooLow
	}
	if p.GasLimit > params.TaskMaxGasLimit {
		return ErrTaskGasLimitTooHigh
	}

	// 2. Validate delay_blocks.
	if p.DelayBlocks < 1 {
		return ErrTaskDelayZero
	}
	if p.DelayBlocks > params.TaskMaxHorizonBlocks {
		return ErrTaskDelayTooFar
	}

	// 3. Validate interval_blocks.
	if p.IntervalBlocks != 0 && p.IntervalBlocks < params.TaskMinIntervalBlocks {
		return ErrTaskIntervalTooShort
	}
	if p.IntervalBlocks > params.TaskMaxHorizonBlocks {
		return ErrTaskIntervalTooFar
	}

	// 4. Per-contract active limit.
	if ReadActiveCount(ctx.StateDB, ctx.From) >= params.TaskMaxPerContract {
		return ErrTaskActiveLimit
	}

	// 5. Compute deposit and check balance.
	deposit := new(big.Int).Mul(
		new(big.Int).SetUint64(p.GasLimit),
		big.NewInt(params.TxPriceWei),
	)
	if ctx.StateDB.GetBalance(ctx.From).Cmp(deposit) < 0 {
		return ErrTaskInsufficientDeposit
	}

	// 6. Deduct deposit.
	ctx.StateDB.SubBalance(ctx.From, deposit)
	ctx.StateDB.AddBalance(params.TaskSchedulerAddress, deposit)

	// 7. Mint task ID.
	blockNum := ctx.BlockNumber.Uint64()
	targetBlock := blockNum + p.DelayBlocks
	nonce := IncrementContractNonce(ctx.StateDB, ctx.From)
	taskId := NewTaskID(ctx.From, targetBlock, nonce)

	// Parse selector.
	selBytes := common.FromHex(p.Selector)
	var selector [4]byte
	copy(selector[:], selBytes)

	// Parse taskData.
	taskDataBytes := common.FromHex(p.TaskData)
	var taskData common.Hash
	copy(taskData[:], taskDataBytes)

	// 8. Write task and enqueue.
	rec := &TaskRecord{
		Scheduler:      ctx.From,
		Target:         common.HexToAddress(p.Target),
		Selector:       selector,
		TaskData:       taskData,
		GasLimit:       p.GasLimit,
		TargetBlock:    targetBlock,
		IntervalBlocks: p.IntervalBlocks,
		MaxRuns:        p.MaxRuns,
		Runs:           0,
		Status:         TaskPending,
	}
	WriteTask(ctx.StateDB, taskId, rec)
	EnqueueTask(ctx.StateDB, targetBlock, taskId)

	// 9. Track active count.
	AdjustActiveCount(ctx.StateDB, ctx.From, +1)

	// 10. Emit log: TaskScheduled(taskId, scheduler, target, targetBlock).
	// Topics[0] = sig, Topics[1] = taskId (indexed bytes32).
	// Data = scheduler[32] ++ target[32] ++ nextBlock (uint64 right-aligned in 32 bytes).
	var logData [96]byte
	copy(logData[:32], rec.Scheduler[:])
	copy(logData[32:64], rec.Target[:])
	binary.BigEndian.PutUint64(logData[88:], targetBlock)
	ctx.StateDB.AddLog(&types.Log{
		Address: params.TaskSchedulerAddress,
		Topics:  []common.Hash{TaskScheduledTopic, taskId},
		Data:    logData[:],
	})

	return nil
}

type cancelPayload struct {
	TaskID string `json:"task_id"` // hex hash
}

func (h *taskHandler) handleCancel(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p cancelPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	taskId := common.HexToHash(p.TaskID)

	// 1. Read task; must be Pending.
	rec, ok := ReadTask(ctx.StateDB, taskId)
	if !ok || rec.Status != TaskPending {
		return ErrTaskNotPending
	}

	// 2. Only the scheduler may cancel.
	if ctx.From != rec.Scheduler {
		return ErrTaskNotScheduler
	}

	// 3. Refund full deposit.
	deposit := new(big.Int).Mul(
		new(big.Int).SetUint64(rec.GasLimit),
		big.NewInt(params.TxPriceWei),
	)
	ctx.StateDB.SubBalance(params.TaskSchedulerAddress, deposit)
	ctx.StateDB.AddBalance(rec.Scheduler, deposit)

	// 4. Mark cancelled and decrement active count.
	rec.Status = TaskCancelled
	WriteTask(ctx.StateDB, taskId, rec)
	AdjustActiveCount(ctx.StateDB, rec.Scheduler, -1)

	return nil
}
