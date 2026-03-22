# Native Scheduled Tasks

## TOL Openlib Status

**Contract layer: COMPLETE (2026-03-21).** The TOL openlib now includes
`openlib/settlement/RecurringPayment.tol` — a coordinator-triggered
subscription/periodic payment contract with subscribe, executePayment,
pause, resume, and cancel lifecycle.  This contract uses the existing
`escrow`/`release` host primitives and does NOT yet depend on the native
scheduled tasks described below.

**Protocol layer: NOT YET IMPLEMENTED.** The GTOS native scheduled task
infrastructure described in this document is not yet built.  When it is,
`RecurringPayment` can be upgraded to use `tos.schedule()` for autonomous
periodic execution instead of requiring an off-chain coordinator to call
`executePayment`.

---

## Overview

This document specifies the on-chain infrastructure for native scheduled task execution in gtos.
Scheduled tasks allow LVM contracts to register callback invocations at a future block height,
with optional repetition. No off-chain keeper or third-party automation service is required.

| System | Address | Package |
|--------|---------|---------|
| Task Scheduler | `0x...0108` | `task/` |

The design follows the same pattern established by `validator/`, `agent/`, `kyc/`, `tns/`,
and `referral/`:

- keccak256-slotted storage in a fixed system-contract account
- `sysaction.Handler` + `init()` self-registration
- Blank import in `tos/backend.go`
- New `tos.*` LVM primitives in `core/lvm/lvm.go`
- Block-level execution hook in `core/state_processor.go`

### Source Reference

Design derived from:
- `~/memo/15-New-Features/07-Scheduled-Tasks.md`
- `~/memo/02-VM-Smart-Contracts/SCHEDULED_EXECUTION_IMPLEMENTATION_PLAN.md` (TAKO/OFFERCALL)

### Adaptation Decisions (gtos vs. prior systems)

| Aspect | Prior systems | gtos |
|--------|-------------|------|
| Storage backend | RocksDB three-column priority index | keccak256 state slots (consistent with agent/, kyc/) |
| VM | TAKO eBPF + Rust | LVM (Lua VM) |
| Task index | Database range scan | Per-block bucket in state DB |
| Priority auction | offer_amount + 30% burn | MVP: FIFO, no auction |
| Scheduling API | `tos_offer_call` syscall | `tos.schedule()` LVM primitive + `TASK_SCHEDULE` sysaction |

---

## 1. `params/tos_params.go` — New Address and Constants

```go
// Task Scheduler system contract address.
TaskSchedulerAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000108")
```

```go
// Scheduled task constants.
const (
    TaskScheduleGas        uint64 = 200       // cost of tos.schedule() — 6 SSTOREs + queue write
    TaskCancelGas          uint64 = 100       // cost of tos.canceltask()
    TaskInfoGas            uint64 = 100       // cost of tos.taskinfo() — 1 SLOAD
    TaskMinGasLimit        uint64 = 10_000    // minimum gas reserved per task execution
    TaskMaxGasLimit        uint64 = 500_000   // hard cap per task execution
    TaskMaxPerBlock        uint64 = 50        // max tasks executed per block
    TaskMaxPerContract     uint64 = 100       // max active tasks per contract
    TaskMinIntervalBlocks  uint64 = 10        // min repeat interval (~3.6 s at 360 ms/block)
    TaskMaxHorizonBlocks   uint64 = 1_000_000 // max scheduling distance (~4.2 days)
)
```

---

## 2. `sysaction/types.go` — New ActionKind Constants

```go
// Scheduled task management (used from outside LVM, e.g. operator/admin transactions).
ActionTaskSchedule ActionKind = "TASK_SCHEDULE"
ActionTaskCancel   ActionKind = "TASK_CANCEL"
```

---

## 3. `task/` — New Package (4 Files)

### `task/types.go`

```go
package task

import "errors"

// TaskStatus is the on-chain status byte for a scheduled task.
type TaskStatus uint8

const (
    TaskPending   TaskStatus = 0 // registered, waiting for target block
    TaskDone      TaskStatus = 1 // one-shot task completed successfully
    TaskCancelled TaskStatus = 2 // cancelled by scheduler before execution
    TaskExpired   TaskStatus = 3 // maxRuns exhausted after final execution
)

var (
    ErrTaskNotFound            = errors.New("task: not found")
    ErrTaskNotScheduler        = errors.New("task: caller is not the task scheduler")
    ErrTaskAlreadyCancelled    = errors.New("task: already cancelled or completed")
    ErrTaskGasTooLow           = errors.New("task: gasLimit below minimum")
    ErrTaskGasTooHigh          = errors.New("task: gasLimit exceeds maximum")
    ErrTaskTooFarFuture        = errors.New("task: target block exceeds scheduling horizon")
    ErrTaskIntervalTooShort    = errors.New("task: repeat interval below minimum")
    ErrTaskTooManyPerContract  = errors.New("task: contract active task limit reached")
    ErrTaskInsufficientBalance = errors.New("task: contract balance below required gas deposit")
)
```

### `task/state.go` — Storage Layout

Storage account: `params.TaskSchedulerAddress`

**Task ID formula**: `keccak256(scheduler[32] || targetBlock[8] || nonce[8])`
where `nonce` is the per-contract task counter, incremented on every `TASK_SCHEDULE`.

#### Slot Key Formulas

| Slot | Formula | Value |
|------|---------|-------|
| Task field | `keccak256("task\x00" \|\| taskId[32] \|\| fieldName)` | see fields below |
| Contract nonce | `keccak256("task\x00nonce\x00" \|\| contract[32])` | u64 |
| Contract active count | `keccak256("task\x00active\x00" \|\| contract[32])` | u64 |
| Block queue length | `keccak256("task\x00qlen\x00" \|\| blockNum[8])` | u64 |
| Block queue entry i | `keccak256("task\x00q\x00" \|\| blockNum[8] \|\| i[8])` | taskId (bytes32) |

#### Per-Task Fields (10 slots per task)

| Field name | Type | Description |
|------------|------|-------------|
| `"scheduler"` | address | Contract that registered this task (only it may cancel) |
| `"target"` | address | Contract to be called at execution time |
| `"selector"` | bytes4 | ABI function selector: `keccak256("funcName()")[:4]` |
| `"taskdata"` | bytes32 | Fixed 32-byte argument passed to the callback |
| `"gaslimit"` | u64 | Gas budget reserved for each execution |
| `"interval"` | u64 | Repeat interval in blocks (0 = one-shot) |
| `"maxruns"` | u32 | Max execution count (0 = unlimited) |
| `"runs"` | u32 | Executions completed so far |
| `"status"` | u8 | TaskStatus |
| `"nextblock"` | u64 | Block number of the next scheduled execution |

#### Exported Functions

```go
func NewTaskID(scheduler common.Address, targetBlock, nonce uint64) common.Hash
func ReadTask(db vm.StateDB, taskId common.Hash) (*TaskRecord, bool)
func WriteTask(db vm.StateDB, taskId common.Hash, t *TaskRecord)
func EnqueueTask(db vm.StateDB, blockNum uint64, taskId common.Hash)
func DequeueTasksAt(db vm.StateDB, blockNum uint64) []common.Hash
func IncrementContractNonce(db vm.StateDB, addr common.Address) uint64
func ReadActiveCount(db vm.StateDB, addr common.Address) uint64
func AdjustActiveCount(db vm.StateDB, addr common.Address, delta int)
```

`TaskRecord` struct:
```go
type TaskRecord struct {
    Scheduler  common.Address
    Target     common.Address
    Selector   [4]byte
    TaskData   common.Hash
    GasLimit   uint64
    Interval   uint64
    MaxRuns    uint32
    Runs       uint32
    Status     TaskStatus
    NextBlock  uint64
}
```

### `task/handler.go` — SysAction Handler

- `init()` → `sysaction.DefaultRegistry.Register(&taskHandler{})`
- `CanHandle`: `ActionTaskSchedule`, `ActionTaskCancel`

```
TASK_SCHEDULE payload: {
    target:          hex address,
    selector:        "0x" + 4-byte hex,
    task_data:       "0x" + 32-byte hex,
    gas_limit:       uint64,
    delay_blocks:    uint64,
    interval_blocks: uint64,
    max_runs:        uint32
}
    1. gas_limit in [TaskMinGasLimit, TaskMaxGasLimit]
    2. delay_blocks in [1, TaskMaxHorizonBlocks]
    3. interval_blocks == 0 || interval_blocks >= TaskMinIntervalBlocks
    4. ReadActiveCount(ctx.From) < TaskMaxPerContract
    5. deposit = gas_limit * GTOSPriceWei
       ctx.StateDB.GetBalance(ctx.From) >= deposit
    6. SubBalance(ctx.From, deposit); AddBalance(TaskSchedulerAddress, deposit)
    7. nonce  = IncrementContractNonce(ctx.From)
       taskId = NewTaskID(ctx.From, ctx.BlockNumber + delay_blocks, nonce)
    8. WriteTask(taskId, record{scheduler=ctx.From, ...})
       EnqueueTask(ctx.BlockNumber + delay_blocks, taskId)
    9. AdjustActiveCount(ctx.From, +1)
   10. Emit log: TaskScheduled(taskId, scheduler, target, nextBlock)

TASK_CANCEL payload: { task_id: "0x..." }
    1. ReadTask(taskId) must exist and status == TaskPending
    2. ctx.From == task.Scheduler              → ErrTaskNotScheduler
    3. Compute refund = gas_limit * GTOSPriceWei  (full deposit)
       SubBalance(TaskSchedulerAddress, refund); AddBalance(ctx.From, refund)
    4. WriteTask status = TaskCancelled
    5. AdjustActiveCount(task.Scheduler, -1)
```

### `task/processor.go` — Block-Level Task Executor

Called once per block from `core/state_processor.go` before processing user transactions.

```go
// ProcessDueTasks executes all tasks whose NextBlock == blockNum.
// Executed at the start of each block, before user transactions.
// Returns the number of tasks processed (executed + deferred).
func ProcessDueTasks(
    db        vm.StateDB,
    blockCtx  vm.BlockContext,
    chainCfg  *params.ChainConfig,
    blockNum  uint64,
) int
```

**Execution flow per task**:

1. `DequeueTasksAt(db, blockNum)` → list of taskIds due this block
2. For each taskId (up to `TaskMaxPerBlock`):
   a. `ReadTask(taskId)` — skip if not Pending
   b. Build calldata: ABI-encode `selector ++ taskData` (36 bytes)
   c. Call `lvm.Execute(db, blockCtx, chainCfg, CallCtx{Self: task.Target, Caller: TaskSchedulerAddress, Readonly: false}, calldata, task.GasLimit)`
   d. Compute `gasUsed`; compute `refund = (task.GasLimit - gasUsed) * GTOSPriceWei`
      `SubBalance(TaskSchedulerAddress, refund); AddBalance(task.Scheduler, refund)`
   e. `task.Runs++`
   f. **Repeat check**: `task.Interval > 0 && (task.MaxRuns == 0 || task.Runs < task.MaxRuns)`
      - true → `task.NextBlock = blockNum + task.Interval`; `EnqueueTask(nextBlock, taskId)`;
               pre-charge next deposit `SubBalance(task.Scheduler, nextDeposit)`;
               `AddBalance(TaskSchedulerAddress, nextDeposit)` (skip if balance insufficient → cancel)
      - false → `task.Status = TaskDone or TaskExpired`; `AdjustActiveCount(task.Scheduler, -1)`
   g. `WriteTask(taskId, task)`
3. Tasks beyond `TaskMaxPerBlock` limit: defer to `blockNum + 1` (re-enqueue)

**Calldata layout** passed to the LVM callback:

```
bytes 0..3  = selector (4 bytes)
bytes 4..35 = taskData (32 bytes)
total: 36 bytes
```

The LVM contract decodes `taskData` with `tos.abi.decode` or reads it as a bytes32.

---

## 4. `core/state_processor.go` — Inject Task Processing

In the `Process()` function, at the start of each block before applying transactions:

```go
// Execute scheduled tasks due at this block.
task.ProcessDueTasks(statedb, blockContext, p.config, block.NumberU64())
```

Import: `"github.com/tos-network/gtos/task"`

---

## 5. `core/lvm/lvm.go` — New `tos.*` Primitives

**Additional import:**

```go
"github.com/tos-network/gtos/task"
```

**Constant registered on `tosTable`:**

```go
// tos.TASK_SCHEDULER — address of the TaskScheduler system contract.
// Contracts use this to authenticate scheduled callbacks:
//   assert(tos.caller == tos.TASK_SCHEDULER, "not scheduler")
L.SetField(tosTable, "TASK_SCHEDULER", lua.LString(params.TaskSchedulerAddress.Hex()))
```

#### `tos.schedule(target, selector, taskData, gasLimit, delayBlocks, intervalBlocks, maxRuns) → taskIdHex | nil`

Gas cost: `params.TaskScheduleGas` (200). Write primitive — fails in staticcall.

- `target`: hex address of the contract to call
- `selector`: hex string of 4-byte ABI selector (e.g. `"0x12345678"`)
- `taskData`: hex string of 32-byte argument passed to the callback
- `gasLimit`: u64 in `[TaskMinGasLimit, TaskMaxGasLimit]`
- `delayBlocks`: u64 in `[1, TaskMaxHorizonBlocks]`
- `intervalBlocks`: u64 (0 = one-shot, else >= `TaskMinIntervalBlocks`)
- `maxRuns`: u64 (0 = unlimited)

Deducts `gasLimit * GTOSPriceWei` from `contractAddr` balance as a deposit.
Returns task ID as a hex string, or `nil` on any validation failure.

```lua
-- Example: schedule self-call every 100 blocks, unlimited repeats
local taskId = tos.schedule(
    tos.self,
    tos.selector("compound()"),
    tos.bytes32(0),
    50000,   -- gasLimit
    100,     -- delayBlocks
    100,     -- intervalBlocks
    0        -- maxRuns (unlimited)
)
tos.require(taskId ~= nil, "schedule failed")
tos.set("compoundTask", taskId)
```

#### `tos.canceltask(taskIdHex) → bool`

Gas cost: `params.TaskCancelGas` (100). Write primitive.

Cancels the task and refunds the full gas deposit to the calling contract.
Returns `true` on success, `false` if not found, already done, or caller is not the scheduler.

#### `tos.taskinfo(taskIdHex, field) → value | nil`

Gas cost: `params.TaskInfoGas` (100) per call. Read-only.

| Field | Return type | Description |
|-------|-------------|-------------|
| `"status"` | u256 (u8) | 0=Pending, 1=Done, 2=Cancelled, 3=Expired |
| `"nextblock"` | u256 (u64) | Block number of next execution |
| `"runs"` | u256 (u32) | Executions completed |
| `"gaslimit"` | u256 (u64) | Reserved gas per execution |
| `"interval"` | u256 (u64) | Repeat interval in blocks |
| `"maxruns"` | u256 (u32) | Max run count (0 = unlimited) |
| `"scheduler"` | string (hex addr) | Contract that registered the task |
| `"target"` | string (hex addr) | Contract called at execution |

Unknown fields return `nil`.

---

## 6. `tos/backend.go` — Blank Import

```go
_ "github.com/tos-network/gtos/task"  // registers TASK_SCHEDULE/TASK_CANCEL handlers via init()
```

---

## 7. Verification

```bash
cd ~/gtos
go build ./...

go test ./task/...       # TASK_SCHEDULE / TASK_CANCEL / ProcessDueTasks
go test ./core/lvm/...  # tos.schedule, tos.canceltask, tos.taskinfo
go test ./core/...       # state_processor integration
go test ./...            # full suite
```

Test coverage targets:

| Package | Cases |
|---------|-------|
| `task/` | Schedule valid task, cancel by scheduler, cancel by non-scheduler (rejected), gas too low (rejected), horizon exceeded (rejected), interval too short (rejected), active limit exceeded (rejected), ProcessDueTasks one-shot, ProcessDueTasks repeat (re-enqueue), ProcessDueTasks maxRuns exhaustion, deposit refund on cancel, deposit partial refund on execution |
| `core/lvm/` | `tos.schedule` success, `tos.schedule` in staticcall (rejected), `tos.canceltask` success, `tos.canceltask` wrong caller, `tos.taskinfo` all fields, `tos.TASK_SCHEDULER` constant |

---

## 8. Implementation Order

| Step | Target | Dependencies |
|------|--------|-------------|
| 1 | `params/tos_params.go` — TaskSchedulerAddress + constants | none |
| 2 | `sysaction/types.go` — TASK_SCHEDULE / TASK_CANCEL | none |
| 3 | `task/types.go` — TaskStatus + error vars | params |
| 4 | `task/state.go` — slot helpers + TaskRecord CRUD + queue | params, crypto |
| 5 | `task/handler.go` — sysaction handler | task/state, sysaction |
| 6 | `task/processor.go` — ProcessDueTasks | task/state, core/lvm |
| 7 | `core/state_processor.go` — inject ProcessDueTasks | task/processor |
| 8 | `core/lvm/lvm.go` — tos.schedule / canceltask / taskinfo / TASK_SCHEDULER | task/state |
| 9 | `tos/backend.go` — blank import | task/handler |

---

## 9. Security Limits

| Attack vector | Mitigation |
|---------------|-----------|
| Spam task registration | Gas deposit pre-charged at `gasLimit * GTOSPriceWei` |
| Block-level DoS via many tasks | `TaskMaxPerBlock = 50`; overflow deferred to next block |
| Far-future state bloat | `TaskMaxHorizonBlocks = 1,000,000` (~4.2 days) |
| Per-contract state exhaustion | `TaskMaxPerContract = 100` active tasks |
| Unauthorized cancellation | `ctx.From == task.Scheduler` enforced |
| Spoofed scheduler callback | Contract checks `tos.caller == tos.TASK_SCHEDULER` |
| High-frequency repeating tasks | `TaskMinIntervalBlocks = 10` (~3.6 s) |
| Insufficient balance on re-schedule | Balance checked before re-enqueue; task cancelled on failure |

---

## 10. Storage Slot Summary

| Contract | Address | Namespace prefix |
|----------|---------|-----------------|
| TaskScheduler | `0x...0108` | `task\x00` |

All slot keys are keccak256-hashed before use, matching the pattern in `validator/state.go`,
`agent/state.go`, `kyc/state.go`, `tns/state.go`, and `referral/state.go`.

---

## 11. Design Decisions and Rationale

| Decision | Rationale |
|----------|-----------|
| Per-block bucket queue | Fits the keccak256 state-slot model; no range-scan needed; O(1) lookup per block |
| Fixed 32-byte taskData | Avoids variable-length slot encoding; contracts store complex state internally |
| Gas deposit at schedule time | Anti-spam; no free scheduling; deposit refunded on cancel or partial refund on execution |
| No offer/auction mechanism | MVP simplicity; FIFO is fair for 360 ms blocks with TaskMaxPerBlock=50 |
| TASK_SCHEDULER as `tos.caller` | Contracts can authenticate scheduled callbacks without any additional signature |
| Repeat deposit charged per interval | Ensures scheduler contract maintains sufficient balance; insufficient balance cancels the task |
| sysaction + LVM primitive dual API | Operators use sysaction for admin tasks; LVM contracts use `tos.schedule` for autonomous scheduling |
| `TaskMaxPerBlock = 50` | At 500,000 gas/task × 50 = 25M gas/block overhead; leaves ample capacity for user txs |
