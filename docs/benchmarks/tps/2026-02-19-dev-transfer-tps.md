# GTOS TPS Benchmark Report (2026-02-19)

## Summary

- Benchmark type: transfer-only load test
- Network mode: local `--dev` chain
- Result: **Average TPS = 1381.23**
- Peak steady-state block TPS: **1428.00**

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

## Output Snapshot

```
Blocks analyzed : 35
Total txs       : 48343
Time span (sec) : 35
Average TPS     : 1381.23
```

## Per-block TPS (sample from run)

```
Block 3  : 1219.00 TPS
Block 4+ : mostly 1428.00 TPS (steady-state)
```

## Interpretation

- This benchmark is a **synthetic local dev test** and mainly reflects execution/packing throughput under transfer-heavy load.
- It is useful for **relative comparisons** (before/after optimizations), not as a direct production-network guarantee.

