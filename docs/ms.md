# GTOS Sub-Second Block Production Plan (ms Level)

Status: `DRAFT`
Date: `2026-02-24`

## 1. Goals and Scope

Goals:

- Upgrade GTOS from second-based block timing semantics to millisecond-based semantics.
- Roll out in phases, prioritizing stability before aggressive latency targets.

Phase targets:

- Phase A: `500ms` target block interval.
- Phase B: `250ms` target block interval.
- Phase C: `<200ms` in experimental networks only, not default production config.

Non-goals:

- No VM introduction.
- No redesign of core DPoS mechanism (rotation, staking, epoch model).
- No BFT protocol replacement in the first stage.

## 2. Current Limitations

Current implementation is second-based:

- `dpos.period` is defined and consumed in seconds.
- `header.timestamp` is `uint64`, but consensus paths treat it as seconds.
- `Prepare/Verify/Seal` paths use `time.Now().Unix()` and `time.Unix()`.

Impact:

- Practical lower bound is `1s`.
- Smaller targets cannot be achieved correctly under second-level timing semantics.

## 3. High-Level Design

Core principles:

- Keep `Header.Time uint64`, but switch DPoS semantics to Unix milliseconds.
- Migrate consensus timing first, then optimize network propagation/pipeline.

New config field:

- `dpos.periodMs`: target block interval in milliseconds.

Compatibility strategy:

- GTOS is pre-mainnet, so no on-chain backward-compatibility window is required.
- We switch directly to millisecond semantics in the experiment branch and reject legacy `dpos.period`.

## 4. Required Changes

## 4.1 Parameter Layer

Changes:

- Extend `params.DPoSConfig` with millisecond interval fields.
- Use `periodMs` by default for new networks.

Acceptance:

- Config parser accepts `periodMs`-only configuration.
- Legacy `period` is rejected with an explicit configuration error.

## 4.2 Consensus Time Path

Changes:

- `VerifyHeader`: future-block checks in milliseconds.
- `verifyCascadingFields`: parent-child minimum interval checks in milliseconds.
- `Prepare`: generate `header.Time` via `UnixMilli()`.
- `Seal`: scheduling delay based on `time.UnixMilli(header.Time)`.

Notes:

- `allowedFutureBlockTime` must be migrated to millisecond granularity.
- `wiggleTime` should be retuned for sub-second slots to avoid consuming slot budget.

## 4.3 Block/RPC Semantics

Changes:

- Clearly document `header.timestamp` as Unix milliseconds.
- Keep field name `timestamp` in RPC for compatibility.
- Update explorers/clients that currently assume second-based timestamps.

## 4.4 Genesis and Upgrade Procedure

Changes:

- Add `dpos.periodMs` to genesis/config.
- Since GTOS is not live yet, no activation-height migration is needed in this phase.

## 5. Propagation and Pipeline Optimization (Agave-Inspired)

These are not blockers for Phase A, but required for Phase B/C.

Recommended work:

- Transaction pre-forwarding to upcoming leaders.
- Layered/tree broadcast instead of flat broadcast.
- Deeper pipeline parallelism (decode, verify, execute, package, broadcast).
- Evaluate short consecutive leader windows to reduce rotation overhead.

## 6. Staged Rollout Plan

Phase A (`500ms`):

- Complete timing semantics migration in consensus.
- Keep current network topology and apply minimal tuning.
- Complete 3-validator and 21-validator soak tests.

Phase B (`250ms`):

- Add pre-forwarding and baseline layered broadcast optimization.
- Improve parallel verification/packaging throughput.
- Run long-duration soak in low-latency regional clusters first.

Phase C (`<200ms`, experimental):

- Experimental network only.
- Evaluate fork rate, rollback depth, empty block rate, and stability margins.
- Do not move to default production parameters unless targets are met.

## 6.1 Branch Strategy for This Experiment

- Run all code changes in a dedicated branch: `exp/ms-subsecond`.
- Keep `main` unchanged until Phase A acceptance criteria pass.
- Rebase the branch regularly to keep diff small and reviewable.
- Merge into `main` only after soak and determinism gates pass.

## 7. Testing and Acceptance Criteria

Correctness:

- Unit tests for millisecond code paths.
- Config parsing tests for `periodMs` and explicit rejection of legacy `period`.

Consistency:

- Multi-node deterministic state-root checks (3 and 21 validators).
- Restart/recovery consistency at chain head and finalized boundaries.

Stability and performance:

- 24h soak without halt.
- Fork/empty-block/reorg metrics within thresholds.
- P95/P99 block interval meets phase target.

Suggested thresholds:

- Phase A (`500ms`): P99 block interval <= `900ms`.
- Phase B (`250ms`): P99 block interval <= `500ms`.
- Reorg depth long-run mean close to `0` with explainable outliers.

## 8. Risks and Rollback

Primary risks:

- Clock drift increases future-block rejections.
- Network jitter has amplified impact at sub-second slots.
- Hardware variance introduces higher tail latency.

Mitigations:

- Keep a conservative profile fallback (`500ms`) while iterating.
- Require long soak and cross-region stress testing before production rollout.

Rollback strategy:

- If Phase B/C fails targets, revert to the previous stable profile.
- If instability occurs in experiments, reset testnet from known-good genesis/config and rerun.

## 9. Deliverables

- `docs/ms.md` (this plan)
- Parameter/protocol migration PRs
- Consensus timing migration PRs
- Dual-semantics test suite and soak report
- Stage-by-stage benchmark and stability baselines
