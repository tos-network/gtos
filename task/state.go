package task

import (
	"encoding/binary"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// ── Slot helpers ──────────────────────────────────────────────────────────────

// taskFieldSlot returns the storage slot for a single field of a TaskRecord.
// key = keccak256("task\x00" || taskId[32] || field)
func taskFieldSlot(taskId common.Hash, field string) common.Hash {
	key := append([]byte("task\x00"), taskId.Bytes()...)
	key = append(key, []byte(field)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// contractNonceSlot returns the slot for the per-contract schedule nonce.
func contractNonceSlot(addr common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(
		append([]byte("task\x00nonce\x00"), addr.Bytes()...)))
}

// contractActiveSlot returns the slot for the per-contract active task count.
func contractActiveSlot(addr common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(
		append([]byte("task\x00active\x00"), addr.Bytes()...)))
}

// blockQlenSlot returns the slot for the queue length at blockNum.
func blockQlenSlot(blockNum uint64) common.Hash {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], blockNum)
	return common.BytesToHash(crypto.Keccak256(
		append([]byte("task\x00qlen\x00"), buf[:]...)))
}

// blockQEntrySlot returns the slot for the i-th queue entry at blockNum.
func blockQEntrySlot(blockNum, i uint64) common.Hash {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], blockNum)
	binary.BigEndian.PutUint64(buf[8:], i)
	return common.BytesToHash(crypto.Keccak256(
		append([]byte("task\x00q\x00"), buf[:]...)))
}

// ── Task ID ───────────────────────────────────────────────────────────────────

// NewTaskID derives a deterministic task ID from the scheduler address,
// target block, and a per-contract monotonic nonce.
func NewTaskID(scheduler common.Address, targetBlock, nonce uint64) common.Hash {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], targetBlock)
	binary.BigEndian.PutUint64(buf[8:], nonce)
	key := append([]byte("task\x00id\x00"), scheduler.Bytes()...)
	key = append(key, buf[:]...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// ── Read / Write ──────────────────────────────────────────────────────────────

// addrToHash stores a 32-byte address into a 32-byte hash.
func addrToHash(addr common.Address) common.Hash {
	var h common.Hash
	copy(h[:], addr[:])
	return h
}

// hashToAddr converts a 32-byte hash back to an address.
func hashToAddr(h common.Hash) common.Address {
	return common.BytesToAddress(h[:])
}

// ReadTask reads a TaskRecord from state. Returns (record, true) if found,
// (nil, false) if the task ID has never been written.
func ReadTask(db vm.StateDB, taskId common.Hash) (*TaskRecord, bool) {
	schedulerRaw := db.GetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, "scheduler"))
	// If scheduler slot is zero the task was never written (scheduler is always a real account).
	if schedulerRaw == (common.Hash{}) {
		return nil, false
	}
	t := &TaskRecord{}
	t.Scheduler = hashToAddr(schedulerRaw)
	t.Target = hashToAddr(db.GetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, "target")))

	selRaw := db.GetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, "selector"))
	// selector is stored in the last 4 bytes of the 32-byte slot (big-endian right-aligned).
	copy(t.Selector[:], selRaw[28:32])

	t.TaskData = db.GetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, "taskdata"))

	t.GasLimit = db.GetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, "gaslimit")).Big().Uint64()
	t.TargetBlock = db.GetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, "nextblock")).Big().Uint64()
	t.IntervalBlocks = db.GetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, "interval")).Big().Uint64()
	t.MaxRuns = db.GetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, "maxruns")).Big().Uint64()
	t.Runs = db.GetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, "runs")).Big().Uint64()
	t.Status = TaskStatus(db.GetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, "status")).Big().Uint64())
	return t, true
}

// WriteTask persists a TaskRecord to state, one field per slot.
func WriteTask(db vm.StateDB, taskId common.Hash, t *TaskRecord) {
	store := func(field string, val common.Hash) {
		db.SetState(params.TaskSchedulerAddress, taskFieldSlot(taskId, field), val)
	}

	store("scheduler", addrToHash(t.Scheduler))
	store("target", addrToHash(t.Target))

	// selector: stored right-aligned in the last 4 bytes of the slot.
	var selHash common.Hash
	copy(selHash[28:], t.Selector[:])
	store("selector", selHash)

	store("taskdata", t.TaskData)

	var u64 common.Hash
	binary.BigEndian.PutUint64(u64[24:], t.GasLimit)
	store("gaslimit", u64)

	binary.BigEndian.PutUint64(u64[24:], t.TargetBlock)
	store("nextblock", u64)

	binary.BigEndian.PutUint64(u64[24:], t.IntervalBlocks)
	store("interval", u64)

	binary.BigEndian.PutUint64(u64[24:], t.MaxRuns)
	store("maxruns", u64)

	binary.BigEndian.PutUint64(u64[24:], t.Runs)
	store("runs", u64)

	binary.BigEndian.PutUint64(u64[24:], uint64(t.Status))
	store("status", u64)
}

// ── Queue ──────────────────────────────────────────────────────────────────────

// EnqueueTask appends taskId to the block queue at blockNum.
func EnqueueTask(db vm.StateDB, blockNum uint64, taskId common.Hash) {
	qlenSlot := blockQlenSlot(blockNum)
	n := db.GetState(params.TaskSchedulerAddress, qlenSlot).Big().Uint64()
	db.SetState(params.TaskSchedulerAddress, blockQEntrySlot(blockNum, n), taskId)
	var lenHash common.Hash
	binary.BigEndian.PutUint64(lenHash[24:], n+1)
	db.SetState(params.TaskSchedulerAddress, qlenSlot, lenHash)
}

// DequeueTasksAt reads all task IDs scheduled at blockNum and resets the queue length to 0.
func DequeueTasksAt(db vm.StateDB, blockNum uint64) []common.Hash {
	qlenSlot := blockQlenSlot(blockNum)
	n := db.GetState(params.TaskSchedulerAddress, qlenSlot).Big().Uint64()
	if n == 0 {
		return nil
	}
	ids := make([]common.Hash, n)
	for i := uint64(0); i < n; i++ {
		ids[i] = db.GetState(params.TaskSchedulerAddress, blockQEntrySlot(blockNum, i))
	}
	// Zero out queue length so the slot is clean.
	db.SetState(params.TaskSchedulerAddress, qlenSlot, common.Hash{})
	return ids
}

// ── Per-contract counters ─────────────────────────────────────────────────────

// IncrementContractNonce atomically bumps the per-contract nonce and returns
// the value BEFORE the increment (used as the nonce component of NewTaskID).
func IncrementContractNonce(db vm.StateDB, addr common.Address) uint64 {
	slot := contractNonceSlot(addr)
	n := db.GetState(params.TaskSchedulerAddress, slot).Big().Uint64()
	var h common.Hash
	binary.BigEndian.PutUint64(h[24:], n+1)
	db.SetState(params.TaskSchedulerAddress, slot, h)
	return n
}

// ReadActiveCount returns the number of active (Pending) tasks for addr.
func ReadActiveCount(db vm.StateDB, addr common.Address) uint64 {
	return db.GetState(params.TaskSchedulerAddress, contractActiveSlot(addr)).Big().Uint64()
}

// AdjustActiveCount increments (delta=+1) or decrements (delta=-1) the active count.
func AdjustActiveCount(db vm.StateDB, addr common.Address, delta int) {
	slot := contractActiveSlot(addr)
	n := db.GetState(params.TaskSchedulerAddress, slot).Big().Uint64()
	if delta > 0 {
		n++
	} else if delta < 0 && n > 0 {
		n--
	}
	var h common.Hash
	binary.BigEndian.PutUint64(h[24:], n)
	db.SetState(params.TaskSchedulerAddress, slot, h)
}
