# GTOS Retention and Snapshot Operational Spec (v1.0.0)

Status: `ACTIVE`
Last Updated: `2026-02-23`

This document versions the operational rules for non-archive GTOS nodes around
history retention, prune watermark behavior, and restart/recovery expectations.

## 1. Scope and Fixed Parameters

- `retain_blocks = 200`
- `snapshot_interval = 1000`
- Applies to body-level history visibility (transactions, receipts, historical state RPC reads).
- This spec does not change TTL state pruning rules for code/KV payload lifecycle.

## 2. Retention Window Formula

Given canonical head `H` and retain window `R`:

- `oldest_available = 0` when `H + 1 <= R`
- otherwise `oldest_available = H - R + 1`

Current implementation derives `H` from canonical `CurrentHeader().Number` and exposes it through:

- `tos_getRetentionPolicy`
- `tos_getPruneWatermark`

## 3. Prune Guard Rules (`history_pruned`)

When a request targets explicit block number `N` and `N < oldest_available`, the node must reject the request with:

- error code: `-38005`
- message: `history pruned`
- data fields:
  - `reason`
  - `retainBlocks`
  - `oldestAvailableBlock`
  - `requestedBlock`
  - `headBlock`

Guarded RPC paths include:

- Account/signer and storage reads by historical block.
- Transaction-by-hash, raw-transaction-by-hash, and receipt-by-hash (after resolving finalized location block number).

Block tags such as `latest`/`safe`/`finalized` are evaluated against current chain view and are not rejected by this numeric window gate directly.

## 4. Snapshot Operational Policy

`snapshot_interval` is chain profile metadata and is fixed at `1000` in this version.

Operational rule:

- Nodes should maintain snapshot checkpoints aligned to interval boundaries for bootstrap and recovery.
- Recovery always prioritizes canonical persisted chain data (head/finalized/safe) and resumes import from recovered head.

Validated baseline:

- Restart preserves head/finalized/safe continuity and post-restart import progress (`core/restart_recovery_test.go::TestRestartRecoversLatestFinalizedAndResumesImport`).
- Retention watermark tracks head changes deterministically (`internal/tosapi/api_retention_test.go::TestRetentionWatermarkTracksHead`).

## 5. Operator Runbook (Minimum)

1. Query `tos_getRetentionPolicy` and `tos_getPruneWatermark` periodically.
2. Confirm `oldestAvailableBlock` moves monotonically with head.
3. Treat `-38005 history pruned` as expected behavior for out-of-window queries.
4. During restart drills, verify:
   - recovered head equals pre-restart head,
   - recovered finalized/safe pointers are present,
   - chain can continue importing new blocks.

## 6. Versioning Rules

- Any change to formula, error contract, or fixed constants requires a new spec version.
- Backward-incompatible behavior changes must bump major version (for example `v2.0.0`).
- Additive clarifications/tests can bump minor/patch version.

## 7. Implementation References

- `internal/tosapi/api.go` (window math, watermark APIs, `history_pruned` guard/error contract)
- `internal/tosapi/api_tx_history_test.go` (tx/receipt prune guard)
- `internal/tosapi/api_retention_test.go` (watermark progression)
- `internal/tosapi/api_retention_crossnode_test.go` (cross-node boundary determinism)
- `core/restart_recovery_test.go` (restart/recovery continuity drill)
