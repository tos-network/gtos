package task

import (
	"errors"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	vmtypes "github.com/tos-network/gtos/core/vmtypes"
	"github.com/tos-network/gtos/params"
)

// newStateDB returns a fresh in-memory StateDB for testing.
func newStateDB(t *testing.T) *state.StateDB {
	t.Helper()
	db, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	return db
}

func fund(db *state.StateDB, addr common.Address, tos int64) {
	db.AddBalance(addr, new(big.Int).Mul(big.NewInt(tos), big.NewInt(1e18)))
}

// noopBlockCtx returns a minimal vmtypes.BlockContext with the given block number.
func noopBlockCtx(blockNum uint64) vmtypes.BlockContext {
	return vmtypes.BlockContext{BlockNumber: big.NewInt(int64(blockNum))}
}

// doSchedule mimics the core TASK_SCHEDULE logic against the state directly,
// without going through JSON marshalling or sysaction routing.
func doSchedule(t *testing.T, db vmtypes.StateDB, blockNum uint64, from common.Address,
	gasLimit, delayBlocks, intervalBlocks, maxRuns uint64,
) (common.Hash, error) {
	t.Helper()
	if gasLimit < params.TaskMinGasLimit {
		return common.Hash{}, ErrTaskGasLimitTooLow
	}
	if gasLimit > params.TaskMaxGasLimit {
		return common.Hash{}, ErrTaskGasLimitTooHigh
	}
	if delayBlocks < 1 {
		return common.Hash{}, ErrTaskDelayZero
	}
	if delayBlocks > params.TaskMaxHorizonBlocks {
		return common.Hash{}, ErrTaskDelayTooFar
	}
	if intervalBlocks != 0 && intervalBlocks < params.TaskMinIntervalBlocks {
		return common.Hash{}, ErrTaskIntervalTooShort
	}
	if ReadActiveCount(db, from) >= params.TaskMaxPerContract {
		return common.Hash{}, ErrTaskActiveLimit
	}
	deposit := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), big.NewInt(params.TxPriceTomi))
	if db.GetBalance(from).Cmp(deposit) < 0 {
		return common.Hash{}, ErrTaskInsufficientDeposit
	}
	db.SubBalance(from, deposit)
	db.AddBalance(params.TaskSchedulerAddress, deposit)

	targetBlock := blockNum + delayBlocks
	nonce := IncrementContractNonce(db, from)
	taskId := NewTaskID(from, targetBlock, nonce)
	rec := &TaskRecord{
		Scheduler:      from,
		Target:         common.HexToAddress("0xBEEF"),
		GasLimit:       gasLimit,
		TargetBlock:    targetBlock,
		IntervalBlocks: intervalBlocks,
		MaxRuns:        maxRuns,
		Status:         TaskPending,
	}
	WriteTask(db, taskId, rec)
	EnqueueTask(db, targetBlock, taskId)
	AdjustActiveCount(db, from, +1)
	return taskId, nil
}

// doCancel mimics the TASK_CANCEL logic.
func doCancel(db vmtypes.StateDB, from common.Address, taskId common.Hash) error {
	rec, ok := ReadTask(db, taskId)
	if !ok || rec.Status != TaskPending {
		return ErrTaskNotPending
	}
	if from != rec.Scheduler {
		return ErrTaskNotScheduler
	}
	deposit := new(big.Int).Mul(new(big.Int).SetUint64(rec.GasLimit), big.NewInt(params.TxPriceTomi))
	db.SubBalance(params.TaskSchedulerAddress, deposit)
	db.AddBalance(rec.Scheduler, deposit)
	rec.Status = TaskCancelled
	WriteTask(db, taskId, rec)
	AdjustActiveCount(db, rec.Scheduler, -1)
	return nil
}

// ── NewTaskID ─────────────────────────────────────────────────────────────────

func TestNewTaskIDUniqueness(t *testing.T) {
	sched := common.HexToAddress("0xAAAA")
	id1 := NewTaskID(sched, 100, 0)
	id2 := NewTaskID(sched, 100, 1)
	id3 := NewTaskID(sched, 101, 0)
	if id1 == id2 {
		t.Error("different nonces must produce different IDs")
	}
	if id1 == id3 {
		t.Error("different target blocks must produce different IDs")
	}
	if NewTaskID(sched, 100, 0) != id1 {
		t.Error("NewTaskID must be deterministic")
	}
}

// ── WriteTask / ReadTask ───────────────────────────────────────────────────────

func TestWriteReadTaskRoundTrip(t *testing.T) {
	db := newStateDB(t)
	taskId := NewTaskID(common.HexToAddress("0x01"), 42, 0)
	rec := &TaskRecord{
		Scheduler:      common.HexToAddress("0x01"),
		Target:         common.HexToAddress("0x02"),
		Selector:       [4]byte{0xde, 0xad, 0xbe, 0xef},
		TaskData:       common.HexToHash("0x1234"),
		GasLimit:       50_000,
		TargetBlock:    42,
		IntervalBlocks: 20,
		MaxRuns:        5,
		Runs:           1,
		Status:         TaskPending,
	}
	WriteTask(db, taskId, rec)

	got, ok := ReadTask(db, taskId)
	if !ok {
		t.Fatal("ReadTask: not found")
	}
	if got.Scheduler != rec.Scheduler {
		t.Errorf("Scheduler: got %v want %v", got.Scheduler, rec.Scheduler)
	}
	if got.Target != rec.Target {
		t.Errorf("Target: got %v want %v", got.Target, rec.Target)
	}
	if got.Selector != rec.Selector {
		t.Errorf("Selector: got %x want %x", got.Selector, rec.Selector)
	}
	if got.TaskData != rec.TaskData {
		t.Errorf("TaskData: got %v want %v", got.TaskData, rec.TaskData)
	}
	if got.GasLimit != rec.GasLimit {
		t.Errorf("GasLimit: got %d want %d", got.GasLimit, rec.GasLimit)
	}
	if got.TargetBlock != rec.TargetBlock {
		t.Errorf("TargetBlock: got %d want %d", got.TargetBlock, rec.TargetBlock)
	}
	if got.IntervalBlocks != rec.IntervalBlocks {
		t.Errorf("IntervalBlocks: got %d want %d", got.IntervalBlocks, rec.IntervalBlocks)
	}
	if got.MaxRuns != rec.MaxRuns {
		t.Errorf("MaxRuns: got %d want %d", got.MaxRuns, rec.MaxRuns)
	}
	if got.Runs != rec.Runs {
		t.Errorf("Runs: got %d want %d", got.Runs, rec.Runs)
	}
	if got.Status != rec.Status {
		t.Errorf("Status: got %d want %d", got.Status, rec.Status)
	}
}

func TestReadTaskMissing(t *testing.T) {
	db := newStateDB(t)
	_, ok := ReadTask(db, common.HexToHash("0xDEAD"))
	if ok {
		t.Error("expected false for missing task")
	}
}

// ── EnqueueTask / DequeueTasksAt ──────────────────────────────────────────────

func TestEnqueueDequeueRoundTrip(t *testing.T) {
	db := newStateDB(t)
	id1 := NewTaskID(common.HexToAddress("0x01"), 10, 0)
	id2 := NewTaskID(common.HexToAddress("0x01"), 10, 1)

	EnqueueTask(db, 10, id1)
	EnqueueTask(db, 10, id2)

	ids := DequeueTasksAt(db, 10)
	if len(ids) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(ids))
	}
	if ids[0] != id1 || ids[1] != id2 {
		t.Error("dequeue returned wrong order")
	}
	// Queue should be empty after dequeue.
	if len(DequeueTasksAt(db, 10)) != 0 {
		t.Error("queue should be empty after dequeue")
	}
}

func TestDequeueEmptyBlock(t *testing.T) {
	db := newStateDB(t)
	if ids := DequeueTasksAt(db, 999); ids != nil {
		t.Errorf("expected nil for empty block, got %v", ids)
	}
}

// ── TASK_SCHEDULE validation ───────────────────────────────────────────────────

func TestScheduleValid(t *testing.T) {
	db := newStateDB(t)
	from := common.HexToAddress("0xABCD")
	fund(db, from, 100)

	taskId, err := doSchedule(t, db, 100, from, params.TaskMinGasLimit, 5, 0, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rec, ok := ReadTask(db, taskId)
	if !ok {
		t.Fatal("task not found after schedule")
	}
	if rec.Status != TaskPending {
		t.Errorf("expected Pending, got %d", rec.Status)
	}
	if rec.TargetBlock != 105 {
		t.Errorf("expected targetBlock 105, got %d", rec.TargetBlock)
	}
	if ReadActiveCount(db, from) != 1 {
		t.Error("active count should be 1")
	}
}

func TestScheduleGasLimitTooLow(t *testing.T) {
	db := newStateDB(t)
	from := common.HexToAddress("0x01")
	fund(db, from, 100)
	_, err := doSchedule(t, db, 100, from, params.TaskMinGasLimit-1, 5, 0, 0)
	if !errors.Is(err, ErrTaskGasLimitTooLow) {
		t.Errorf("expected ErrTaskGasLimitTooLow, got %v", err)
	}
}

func TestScheduleGasLimitTooHigh(t *testing.T) {
	db := newStateDB(t)
	from := common.HexToAddress("0x01")
	fund(db, from, 10_000)
	_, err := doSchedule(t, db, 100, from, params.TaskMaxGasLimit+1, 5, 0, 0)
	if !errors.Is(err, ErrTaskGasLimitTooHigh) {
		t.Errorf("expected ErrTaskGasLimitTooHigh, got %v", err)
	}
}

func TestScheduleDelayZero(t *testing.T) {
	db := newStateDB(t)
	from := common.HexToAddress("0x01")
	fund(db, from, 100)
	_, err := doSchedule(t, db, 100, from, params.TaskMinGasLimit, 0, 0, 0)
	if !errors.Is(err, ErrTaskDelayZero) {
		t.Errorf("expected ErrTaskDelayZero, got %v", err)
	}
}

func TestScheduleDelayTooFar(t *testing.T) {
	db := newStateDB(t)
	from := common.HexToAddress("0x01")
	fund(db, from, 100)
	_, err := doSchedule(t, db, 100, from, params.TaskMinGasLimit, params.TaskMaxHorizonBlocks+1, 0, 0)
	if !errors.Is(err, ErrTaskDelayTooFar) {
		t.Errorf("expected ErrTaskDelayTooFar, got %v", err)
	}
}

func TestScheduleIntervalTooShort(t *testing.T) {
	db := newStateDB(t)
	from := common.HexToAddress("0x01")
	fund(db, from, 100)
	_, err := doSchedule(t, db, 100, from, params.TaskMinGasLimit, 5, params.TaskMinIntervalBlocks-1, 0)
	if !errors.Is(err, ErrTaskIntervalTooShort) {
		t.Errorf("expected ErrTaskIntervalTooShort, got %v", err)
	}
}

func TestScheduleActiveLimit(t *testing.T) {
	db := newStateDB(t)
	from := common.HexToAddress("0x01")
	fund(db, from, 1_000_000)
	for i := uint64(0); i < params.TaskMaxPerContract; i++ {
		AdjustActiveCount(db, from, +1)
	}
	_, err := doSchedule(t, db, 100, from, params.TaskMinGasLimit, 5, 0, 0)
	if !errors.Is(err, ErrTaskActiveLimit) {
		t.Errorf("expected ErrTaskActiveLimit, got %v", err)
	}
}

// ── TASK_CANCEL ────────────────────────────────────────────────────────────────

func TestCancelByScheduler(t *testing.T) {
	db := newStateDB(t)
	from := common.HexToAddress("0xABCD")
	fund(db, from, 100)
	taskId, err := doSchedule(t, db, 100, from, params.TaskMinGasLimit, 5, 0, 1)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	balBefore := new(big.Int).Set(db.GetBalance(from))
	if err := doCancel(db, from, taskId); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	rec, _ := ReadTask(db, taskId)
	if rec.Status != TaskCancelled {
		t.Errorf("expected Cancelled, got %d", rec.Status)
	}
	if ReadActiveCount(db, from) != 0 {
		t.Error("active count should be 0 after cancel")
	}
	deposit := new(big.Int).Mul(new(big.Int).SetUint64(params.TaskMinGasLimit), big.NewInt(params.TxPriceTomi))
	expected := new(big.Int).Add(balBefore, deposit)
	if db.GetBalance(from).Cmp(expected) != 0 {
		t.Errorf("balance after cancel: got %v want %v", db.GetBalance(from), expected)
	}
}

func TestCancelByNonScheduler(t *testing.T) {
	db := newStateDB(t)
	from := common.HexToAddress("0xABCD")
	other := common.HexToAddress("0x1234")
	fund(db, from, 100)
	taskId, _ := doSchedule(t, db, 100, from, params.TaskMinGasLimit, 5, 0, 1)
	if err := doCancel(db, other, taskId); !errors.Is(err, ErrTaskNotScheduler) {
		t.Errorf("expected ErrTaskNotScheduler, got %v", err)
	}
}

func TestCancelAlreadyCancelled(t *testing.T) {
	db := newStateDB(t)
	from := common.HexToAddress("0xABCD")
	fund(db, from, 100)
	taskId, _ := doSchedule(t, db, 100, from, params.TaskMinGasLimit, 5, 0, 1)
	doCancel(db, from, taskId) //nolint:errcheck
	if err := doCancel(db, from, taskId); !errors.Is(err, ErrTaskNotPending) {
		t.Errorf("expected ErrTaskNotPending on double-cancel, got %v", err)
	}
}

// ── ProcessDueTasks ────────────────────────────────────────────────────────────

func TestProcessDueTasksOneShot(t *testing.T) {
	db := newStateDB(t)
	sched := common.HexToAddress("0xCAFE")
	fund(db, sched, 100)

	taskId, _ := doSchedule(t, db, 10, sched, params.TaskMinGasLimit, 5, 0, 1)
	targetBlock := uint64(15)

	execCalled := false
	exec := func(_ vmtypes.StateDB, _ vmtypes.BlockContext, _ *params.ChainConfig,
		_, _ common.Address, _ []byte, gasLimit uint64,
	) ExecResult {
		execCalled = true
		return ExecResult{GasUsed: gasLimit / 2}
	}

	n, gasUsed, err := ProcessDueTasks(db, noopBlockCtx(targetBlock), params.MainnetChainConfig, targetBlock, exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 task processed, got %d", n)
	}
	if gasUsed != params.TaskMinGasLimit/2 {
		t.Errorf("expected gasUsed=%d, got %d", params.TaskMinGasLimit/2, gasUsed)
	}
	if !execCalled {
		t.Error("executor was not called")
	}
	rec, _ := ReadTask(db, taskId)
	if rec.Status != TaskDone {
		t.Errorf("expected Done, got %d", rec.Status)
	}
	if rec.Runs != 1 {
		t.Errorf("expected Runs=1, got %d", rec.Runs)
	}
}

func TestProcessDueTasksRepeatReenqueues(t *testing.T) {
	db := newStateDB(t)
	sched := common.HexToAddress("0xCAFE")
	fund(db, sched, 10_000)

	taskId, _ := doSchedule(t, db, 10, sched, params.TaskMinGasLimit, 5, params.TaskMinIntervalBlocks, 0)
	targetBlock := uint64(15)

	exec := func(_ vmtypes.StateDB, _ vmtypes.BlockContext, _ *params.ChainConfig,
		_, _ common.Address, _ []byte, gasLimit uint64,
	) ExecResult {
		return ExecResult{GasUsed: gasLimit} // use all gas — no refund
	}

	if _, _, err := ProcessDueTasks(db, noopBlockCtx(targetBlock), params.MainnetChainConfig, targetBlock, exec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec, _ := ReadTask(db, taskId)
	if rec.Status != TaskPending {
		t.Errorf("expected still Pending for repeating task, got %d", rec.Status)
	}
	nextBlock := targetBlock + params.TaskMinIntervalBlocks
	if rec.TargetBlock != nextBlock {
		t.Errorf("expected TargetBlock=%d, got %d", nextBlock, rec.TargetBlock)
	}
	ids := DequeueTasksAt(db, nextBlock)
	found := false
	for _, id := range ids {
		if id == taskId {
			found = true
		}
	}
	if !found {
		t.Error("task not re-enqueued at next interval block")
	}
}

func TestProcessDueTasksMaxRunsExhaustion(t *testing.T) {
	db := newStateDB(t)
	sched := common.HexToAddress("0xCAFE")
	fund(db, sched, 10_000)

	taskId, _ := doSchedule(t, db, 10, sched, params.TaskMinGasLimit, 5, params.TaskMinIntervalBlocks, 2)

	exec := func(_ vmtypes.StateDB, _ vmtypes.BlockContext, _ *params.ChainConfig,
		_, _ common.Address, _ []byte, gasLimit uint64,
	) ExecResult {
		return ExecResult{GasUsed: gasLimit}
	}

	// Run 1.
	target1 := uint64(15)
	if _, _, err := ProcessDueTasks(db, noopBlockCtx(target1), params.MainnetChainConfig, target1, exec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rec, _ := ReadTask(db, taskId)
	if rec.Status != TaskPending || rec.Runs != 1 {
		t.Errorf("after run 1: status=%d runs=%d", rec.Status, rec.Runs)
	}

	// Run 2 (max).
	target2 := target1 + params.TaskMinIntervalBlocks
	if _, _, err := ProcessDueTasks(db, noopBlockCtx(target2), params.MainnetChainConfig, target2, exec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rec, _ = ReadTask(db, taskId)
	if rec.Status != TaskExpired {
		t.Errorf("expected Expired after maxRuns exhausted, got %d", rec.Status)
	}
	if rec.Runs != 2 {
		t.Errorf("expected Runs=2, got %d", rec.Runs)
	}
}

func TestProcessDueTasksPartialRefund(t *testing.T) {
	db := newStateDB(t)
	sched := common.HexToAddress("0xCAFE")
	fund(db, sched, 100)

	gasLimit := uint64(20_000)
	doSchedule(t, db, 10, sched, gasLimit, 5, 0, 1) //nolint:errcheck
	targetBlock := uint64(15)
	balBefore := new(big.Int).Set(db.GetBalance(sched))

	gasUsed := uint64(5_000)
	exec := func(_ vmtypes.StateDB, _ vmtypes.BlockContext, _ *params.ChainConfig,
		_, _ common.Address, _ []byte, _ uint64,
	) ExecResult {
		return ExecResult{GasUsed: gasUsed}
	}

	if _, _, err := ProcessDueTasks(db, noopBlockCtx(targetBlock), params.MainnetChainConfig, targetBlock, exec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	refund := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit-gasUsed), big.NewInt(params.TxPriceTomi))
	expected := new(big.Int).Add(balBefore, refund)
	if db.GetBalance(sched).Cmp(expected) != 0 {
		t.Errorf("partial refund: got %v want %v", db.GetBalance(sched), expected)
	}
}

func TestProcessDueTasksOverflowDeferred(t *testing.T) {
	db := newStateDB(t)
	sched := common.HexToAddress("0xCAFE")
	fund(db, sched, 1_000_000)

	targetBlock := uint64(50)
	overflow := uint64(3)
	total := params.TaskMaxPerBlock + overflow
	for i := uint64(0); i < total; i++ {
		doSchedule(t, db, targetBlock-5, sched, params.TaskMinGasLimit, 5, 0, 1) //nolint:errcheck
	}

	exec := func(_ vmtypes.StateDB, _ vmtypes.BlockContext, _ *params.ChainConfig,
		_, _ common.Address, _ []byte, gasLimit uint64,
	) ExecResult {
		return ExecResult{GasUsed: gasLimit}
	}

	n, _, err := ProcessDueTasks(db, noopBlockCtx(targetBlock), params.MainnetChainConfig, targetBlock, exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uint64(n) != params.TaskMaxPerBlock {
		t.Errorf("expected %d tasks processed, got %d", params.TaskMaxPerBlock, n)
	}
	nextIds := DequeueTasksAt(db, targetBlock+1)
	if uint64(len(nextIds)) != overflow {
		t.Errorf("expected %d deferred tasks, got %d", overflow, len(nextIds))
	}
}

func TestProcessDueTasksCallbackFailurePreservesFramework(t *testing.T) {
	db := newStateDB(t)
	sched := common.HexToAddress("0xCAFE")
	fund(db, sched, 100)

	taskId, _ := doSchedule(t, db, 10, sched, params.TaskMinGasLimit, 5, 0, 1)
	targetBlock := uint64(15)

	errCallback := errors.New("callback failed")
	exec := func(_ vmtypes.StateDB, _ vmtypes.BlockContext, _ *params.ChainConfig,
		_, _ common.Address, _ []byte, gasLimit uint64,
	) ExecResult {
		return ExecResult{GasUsed: gasLimit / 2, Err: errCallback}
	}

	n, _, err := ProcessDueTasks(db, noopBlockCtx(targetBlock), params.MainnetChainConfig, targetBlock, exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 task processed even on callback failure, got %d", n)
	}
	rec, _ := ReadTask(db, taskId)
	// One-shot with maxRuns=1, so status should be Done regardless of callback outcome.
	if rec.Status != TaskDone {
		t.Errorf("expected Done after callback failure, got %d", rec.Status)
	}
}

func TestProcessDueTasksCallbackLogIsFatal(t *testing.T) {
	db := newStateDB(t)
	sched := common.HexToAddress("0xD00D")
	fund(db, sched, 100)

	taskId, _ := doSchedule(t, db, 10, sched, params.TaskMinGasLimit, 5, 0, 1)
	targetBlock := uint64(15)

	exec := func(db vmtypes.StateDB, _ vmtypes.BlockContext, _ *params.ChainConfig,
		_, _ common.Address, _ []byte, gasLimit uint64,
	) ExecResult {
		db.AddLog(&types.Log{Address: common.HexToAddress("0xBEEF")})
		return ExecResult{GasUsed: gasLimit / 2}
	}

	n, gasUsed, err := ProcessDueTasks(db, noopBlockCtx(targetBlock), params.MainnetChainConfig, targetBlock, exec)
	if err != nil {
		t.Fatalf("expected nil error (log emission is per-task failure), got %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 processed task (expired due to log), got %d", n)
	}
	if gasUsed != params.TaskMinGasLimit/2 {
		t.Fatalf("expected gasUsed=%d, got %d", params.TaskMinGasLimit/2, gasUsed)
	}
	if rec, _ := ReadTask(db, taskId); rec.Status != TaskExpired {
		t.Fatalf("expected TaskExpired after log emission, got %d", rec.Status)
	}
	if len(db.Logs()) != 0 {
		t.Fatal("task logs must be reverted on log emission")
	}
}
