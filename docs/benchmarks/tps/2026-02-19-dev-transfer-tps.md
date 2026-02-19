# GTOS TPS Benchmark Report (2026-02-19)

## Summary

- Benchmark type: transfer-only load test
- Network mode: local `--dev` chain
- Baseline result: **Average TPS = 1381.23**
- Tuned-params result: **Average TPS = 3312.50**
- Current peak steady-state block TPS in this report: **3937.00**

## Environment

- Repository: `gtos`
- Binary: `build/bin/gtos` (built via `make gtos`)
- Host: local single machine
- Consensus mode: dev Clique (`--dev`)

## Command

```bash
make tps
```

The `tps` make target runs:

```bash
bash ./scripts/tps_bench.sh
```

Default benchmark parameters from the script:

- `duration=30s`
- `workers=4`
- `batch-size=200`
- `dev.period=1s`
- `dev.gaslimit=30000000`
- `cooldown=5s`

## Run A (Baseline)

```
Blocks analyzed : 35
Total txs       : 48343
Time span (sec) : 35
Average TPS     : 1381.23
```

Per-block TPS (sample):

```
Block 3  : 1219.00 TPS
Block 4+ : mostly 1428.00 TPS (steady-state)
```

## Run B (Tuned Parameters, `make tps`)

Applied parameter set:

- `block_time = 1s`
- `tx_intrinsic_gas = 3000` for plain transfer (`params.TxGas`)
- `block_gas_limit_target = 30,000,000`

Observed output:

```
Blocks analyzed : 32
Total txs       : 106000
Time span (sec) : 32
Average TPS     : 3312.50
```

Per-block TPS (sample from steady window):

```
Block 4  : 3805.00 TPS
Block 8  : 3721.00 TPS
Block 12 : 3652.00 TPS
Block 25 : 3649.00 TPS
Block 30 : 3688.00 TPS
```

## Run C (Higher Injection Check)

Command:

```bash
./scripts/tps_bench.sh --duration 12 --workers 12 --batch-size 400 --cooldown 3
```

Observed output:

```
Blocks analyzed : 14
Total txs       : 43200
Time span (sec) : 14
Average TPS     : 3085.71
Peak block TPS  : 3937.00
```

## Interpretation

- This benchmark is a **synthetic local dev test** and mainly reflects execution/packing throughput under transfer-heavy load.
- It is useful for **relative comparisons** (before/after optimizations), not as a direct production-network guarantee.
- With current code path, TPS improved significantly after lowering intrinsic gas, but remains below the 10k theoretical ceiling.
