# GTOS Observability Baseline (Phase 4)

Status: `DONE` (baseline established)
Last Updated: `2026-02-23`

This document defines the minimum observability baseline currently implemented for GTOS hardening work.

## Scope

- TTL prune execution visibility.
- Retention-window rejection visibility.
- Structured logs for key prune/retention events.

## Metrics (Current)

1. `chain/ttlprune/code` (meter)
- Meaning: total count of code entries pruned by TTL maintenance during block processing.
- Emission path: `core/state_processor.go`.

2. `chain/ttlprune/kv` (meter)
- Meaning: total count of KV entries pruned by TTL maintenance during block processing.
- Emission path: `core/state_processor.go`.

3. `rpc/tos/history_pruned` (meter)
- Meaning: total count of RPC requests rejected by retention window (`history_pruned`).
- Emission path: `internal/tosapi/api.go` (`newRPCHistoryPrunedError`).

4. `chain/ttlprune/code_time` (timer)
- Meaning: elapsed duration of code prune maintenance per block.
- Emission path: `core/state_processor.go`.

5. `chain/ttlprune/kv_time` (timer)
- Meaning: elapsed duration of KV prune maintenance per block.
- Emission path: `core/state_processor.go`.

## Structured Logs (Current)

1. TTL prune summary (debug)
- Message: `Applied TTL prune maintenance`
- Fields:
  - `block`
  - `codePruned`
  - `kvPruned`
  - `codePruneNs`
  - `kvPruneNs`
- Emitted only when at least one prune occurred.

2. Retention rejection (debug)
- Message: `Rejected pruned history query`
- Fields:
  - `requestedBlock`
  - `headBlock`
  - `retainBlocks`
  - `oldestAvailableBlock`

## Operational Notes

- `rpc/tos/history_pruned` is expected to rise over time on non-archive nodes.
- Sudden spikes can indicate client requests targeting stale history ranges.
- TTL prune meters should show periodic activity under TTL workloads; flat zero during active TTL usage indicates maintenance path issues.

## Validation Coverage

- Meter increment regression: `internal/tosapi/metrics_test.go::TestHistoryPrunedMeterIncrements`.
- Retention boundary properties: `internal/tosapi/api_retention_property_test.go`.
- TTL deterministic prune behavior and boundedness: `core/state_processor_test.go`, `core/ttl_prune_boundedness_test.go`.
