# GTOS Performance Baseline (Phase 4)

Status: `DONE` (baseline established)
Last Updated: `2026-02-23`

This document records the current profiling baseline for TTL prune maintenance so later optimizations can be measured against stable references.

## Scope

- Block-time TTL maintenance cost for code/KV prune.
- Synthetic benchmark baselines for prune throughput at multiple bucket sizes.

## Runtime Timers

1. `chain/ttlprune/code_time` (timer)
- Meaning: elapsed duration of `pruneExpiredCodeAt` per block.
- Emission path: `core/state_processor.go`.

2. `chain/ttlprune/kv_time` (timer)
- Meaning: elapsed duration of `kvstore.PruneExpiredAt` per block.
- Emission path: `core/state_processor.go`.

Related counters/meters:

- `chain/ttlprune/code`
- `chain/ttlprune/kv`

## Structured Log Fields

When prune activity occurs, the node emits `Applied TTL prune maintenance` with:

- `block`
- `codePruned`
- `kvPruned`
- `codePruneNs`
- `kvPruneNs`

## Benchmarks

Location:

- `core/ttl_prune_bench_test.go`

Current benchmark targets:

- `BenchmarkPruneExpiredCodeAt/records_128`
- `BenchmarkPruneExpiredCodeAt/records_1024`
- `BenchmarkPruneExpiredCodeAt/records_4096`
- `BenchmarkPruneExpiredKVAt/records_128`
- `BenchmarkPruneExpiredKVAt/records_1024`
- `BenchmarkPruneExpiredKVAt/records_4096`

Suggested run command:

```bash
go test ./core -run ^$ -bench 'BenchmarkPruneExpired(Code|KV)At' -benchmem
```

Automation helper:

```bash
make ttl-prune-bench
```

- Script: `scripts/ttl_prune_bench_smoke.sh`
- Defaults: `-benchtime=1x`, `-count=1`
- Optional output capture: `scripts/ttl_prune_bench_smoke.sh --out /tmp/ttl_prune_bench.txt`

CI entry points:

```bash
go run build/ci.go bench-ttlprune
make ttl-prune-bench-ci
```

## Latest Smoke Snapshot (`2026-02-23`, `-benchtime=1x`)

Environment:

- `goos=linux`, `goarch=amd64`
- CPU: `Intel(R) Xeon(R) Platinum 8455C`

Results:

- `BenchmarkPruneExpiredCodeAt/records_128`: `4.19ms`, `1.23MB`, `8462 allocs`
- `BenchmarkPruneExpiredCodeAt/records_1024`: `26.59ms`, `8.88MB`, `59753 allocs`
- `BenchmarkPruneExpiredCodeAt/records_4096`: `99.98ms`, `35.58MB`, `235368 allocs`
- `BenchmarkPruneExpiredKVAt/records_128`: `4.62ms`, `2.31MB`, `12294 allocs`
- `BenchmarkPruneExpiredKVAt/records_1024`: `50.80ms`, `17.60MB`, `89794 allocs`
- `BenchmarkPruneExpiredKVAt/records_4096`: `180.38ms`, `70.26MB`, `355387 allocs`

Note:

- `-benchtime=1x` is a fast smoke mode used for regression direction, not stable absolute performance reporting.

## Next Optimization Entry Points

1. Reduce per-record hash/slot recomputation in prune loops.
2. Explore bucket compaction strategy for high-cardinality expiry heights.
3. `DONE` Wire TTL prune benchmark smoke into CI entry (`build/ci.go bench-ttlprune` + `make ttl-prune-bench-ci`).
