# GTOS 10k TPS Minimal Protocol Change Plan

## 1. Target and Constraints

This plan targets **10,000 transfer TPS on a single chain** with GTOS transfer-only execution.

Throughput upper bound is constrained by:

`TPS_max ~= block_gas_limit / tx_intrinsic_gas / block_time_seconds`

Current baseline (from this repo):

- `params.TxGas = 21000` (`params/protocol_params.go`)
- Typical block gas target `~30,000,000` (`tos/tosconfig/config.go`, miner `GasCeil`)
- 1s block time in dev-like setup

This gives ~1428 TPS ceiling, which matches current benchmark behavior.

---

## 2. Minimal Strategy (No New Tx Type)

To reach 10k TPS with minimal protocol surface:

1. Keep transfer model unchanged (no EVM, no batch tx type in V1).
2. Reduce transfer intrinsic gas.
3. Keep 1s block time.
4. Set block gas limit target high enough.
5. Keep execution deterministic and preserve serial fallback.

Recommended V1 target parameters:

- `block_time = 1s`
- `tx_intrinsic_gas = 3000` for plain transfer
- `block_gas_limit_target = 30,000,000`

Then theoretical ceiling:

`30,000,000 / 3,000 / 1 = 10,000 TPS`

---

## 3. Change Set A (Absolute Minimal, New Network / Regenesis)

This is the smallest code delta if you can start from a new genesis.

## 3.1 Consensus Cost Constant

- File: `params/protocol_params.go`
- Field:
  - `TxGas` from `21000` -> `3000` (or `2800`/`2500` after stress validation)

Impact:

- Affects intrinsic gas globally where `params.TxGas` is used:
  - `core/state_transition.go` (`IntrinsicGas`)
  - `core/tx_pool.go` validation
  - `miner/worker.go` gas floor checks

## 3.2 Block Gas Target and Block Period

- File: genesis config (chain spec JSON) or chain bootstrap path
- Fields:
  - `genesis.gasLimit >= 30,000,000`
  - Clique-like `period = 1` (or equivalent in your DPoS engine)

Related code paths:

- `core/block_validator.go` (`CalcGasLimit`)
- `consensus/misc/gaslimit.go` (`VerifyGaslimit`) enforces bounded per-block change

Important:

- If genesis gas limit starts too low, ramp-up to target can take many blocks because of `GasLimitBoundDivisor`.

## 3.3 Node Runtime Defaults

- File: `tos/tosconfig/config.go`
  - `Defaults.Miner.GasCeil` set to target value (`30,000,000` or slightly higher)
- File: `cmd/utils/flags.go`
  - `MinerGasLimitFlag` default follows `tosconfig.Defaults.Miner.GasCeil`
  - Optional: `DeveloperGasLimitFlag` default to benchmark target for easier local validation

---

## 4. Change Set B (Live Network Safe Path, Hard-Forked)

If network is already running, do not directly overwrite `TxGas` without fork gating.

## 4.1 Add Fork Gate in Chain Config

- File: `params/config.go`
- Add field in `ChainConfig`:
  - `TransferGasForkBlock *big.Int` (name can vary, keep explicit)
- Add method:
  - `IsTransferGasFork(num *big.Int) bool`
- Extend compatibility checks:
  - `CheckConfigForkOrder`
  - `checkCompatible`

## 4.2 Add New Transfer Gas Constants

- File: `params/protocol_params.go`
- Keep old:
  - `TxGas = 21000` (pre-fork)
- Add new:
  - `TxGasTransferPostFork = 3000` (or final tuned value)

## 4.3 Apply Forked Intrinsic-Gas Logic

- File: `core/state_transition.go`
- Location: `IntrinsicGas(...)` / `TransitionDb()`
- Rule:
  - plain transfer + post-fork block -> use `TxGasTransferPostFork`
  - otherwise keep existing behavior

- File: `core/tx_pool.go`
- Location: `validateTx(...)`
- Must use the same fork-aware intrinsic gas rule as block execution, otherwise mempool/consensus mismatch risk.

---

## 5. Change Set C (Required Stability Guards for 10k)

These are still minimal but necessary to keep nodes alive under high throughput.

## 5.1 Keep Parallel Transfer Execution (from existing MVP design)

- Files:
  - `core/state_processor.go`
  - `miner/worker.go`
  - new executor files from `docs/gtos-parallel-transfer-mvp-plan.md`

Reason:

- Lowering intrinsic gas raises tx count per block; without parallel transfer path CPU quickly becomes bottleneck.

## 5.2 Tighten Anti-Spam Economics

- File: `core/tx_pool.go`
  - `DefaultTxPoolConfig.PriceLimit`
  - `AccountSlots`, `GlobalSlots`, `AccountQueue`, `GlobalQueue`

- File: `cmd/utils/flags.go`
  - ensure operational overrides exist (`txpool.pricelimit`, `txpool.globalslots`, etc.)

Reason:

- Lower per-tx gas increases attack surface for mempool flooding.

## 5.3 Keep Gas-Limit Movement Predictable

- File: `params/protocol_params.go`
  - `GasLimitBoundDivisor` (do not change casually)

Reason:

- Increasing gas-limit delta per block is also a consensus change and amplifies instability risk.

---

## 6. Minimal Validation Checklist

## 6.1 Correctness

- `go test ./core/... ./miner/... ./consensus/...`
- Add tests for fork boundary (if Change Set B used):
  - pre-fork block rejects tx with gas < 21000
  - post-fork block accepts plain transfer with gas >= new minimum

## 6.2 Throughput

- Use: `scripts/tps_bench.sh`
- Baseline record in docs:
  - `docs/benchmarks/tps/2026-02-19-dev-transfer-tps.md`
- Re-run after changes with same parameters and with higher load:
  - workers 4/8/12
  - batch-size 200/400/800

## 6.3 Resource Envelope

- Track:
  - CPU saturation
  - block import lag
  - txpool pending size
  - LevelDB write latency / compaction pressure

---

## 7. Expected Result Envelope

With:

- 1s block time
- 30M block gas limit
- 3000 intrinsic gas for plain transfers
- parallel transfer execution enabled

Expected:

- Theoretical ceiling: ~10,000 TPS
- Practical sustained range depends on hardware/storage/network and account hotspot ratio.

---

## 8. Explicit Non-Goals for This Minimal Plan

1. No new transaction type in V1.
2. No batch-transfer protocol object in V1.
3. No sharding/multi-chain split in V1.

These can be phase-2 if you want >10k with safer gas economics.

