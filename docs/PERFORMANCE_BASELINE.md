# GTOS Performance Baseline (Phase 4)

Status: `IN_PROGRESS`
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

## Latest Smoke Snapshot (`2026-02-23`, `-benchtime=1x`)

Environment:

- `goos=linux`, `goarch=amd64`
- CPU: `Intel(R) Xeon(R) Platinum 8455C`

Results:

- `BenchmarkPruneExpiredCodeAt/records_128`: `2.74ms`, `1.23MB`, `8460 allocs`
- `BenchmarkPruneExpiredCodeAt/records_1024`: `23.71ms`, `8.86MB`, `59730 allocs`
- `BenchmarkPruneExpiredCodeAt/records_4096`: `94.84ms`, `35.54MB`, `235356 allocs`
- `BenchmarkPruneExpiredKVAt/records_128`: `5.24ms`, `2.31MB`, `12295 allocs`
- `BenchmarkPruneExpiredKVAt/records_1024`: `47.53ms`, `17.56MB`, `89805 allocs`
- `BenchmarkPruneExpiredKVAt/records_4096`: `155.95ms`, `70.20MB`, `355366 allocs`

Note:

- `-benchtime=1x` is a fast smoke mode used for regression direction, not stable absolute performance reporting.

## Next Optimization Entry Points

1. Reduce per-record hash/slot recomputation in prune loops.
2. Explore bucket compaction strategy for high-cardinality expiry heights.
3. Add periodic benchmark capture in CI for regression detection.
