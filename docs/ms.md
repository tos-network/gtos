# GTOS Sub-Second Block Production Plan (ms Level)

Status: `IMPLEMENTING`
Date: `2026-02-24`

## 1. Goals and Scope

Goals:

- Upgrade GTOS from legacy block timing semantics to millisecond-based semantics.
- Set a single production target block interval at `360ms`.

Target:

- `360ms` target block interval.

Non-goals:

- No VM introduction.
- No redesign of core DPoS mechanism (rotation, staking, epoch model).
- No BFT protocol replacement in the first stage.

## 2. Current State

Current implementation is millisecond-based:

- DPoS interval configuration uses `dpos.periodMs`.
- `header.timestamp` remains `uint64` and is interpreted as Unix milliseconds.
- `Prepare/Verify/Seal` paths use millisecond clock and comparison logic.

Impact:

- Sub-second block targets are supported.
- Further latency reduction work is now network/pipeline dominated.

## 3. High-Level Design

Core principles:

- Keep `Header.Time uint64`, but switch DPoS semantics to Unix milliseconds.
- Migrate consensus timing first, then optimize network propagation/pipeline.

New config field:

- `dpos.periodMs`: target block interval in milliseconds.

Compatibility strategy:

- GTOS is pre-mainnet, so no on-chain backward-compatibility window is required.
- We switch directly to millisecond semantics in the experiment branch and reject legacy seconds-based config fields.

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
- Update explorers/clients that currently assume non-millisecond timestamps.

## 4.4 Genesis and Upgrade Procedure

Changes:

- Add `dpos.periodMs` to genesis/config.
- Since GTOS is not live yet, no activation-height migration is needed in this phase.

## 4.5 DPoS Timing Parameters and Geographic Boundary

See [docs/VALIDATOR_NODES.md](VALIDATOR_NODES.md) for hardware requirements, network RTT limits,
consensus timing constants, and recommended deployment profiles.

## 4.6 Why 360ms Is Faster Than Solana and Achievable Without Architecture Changes

### The competitive claim

Solana's published target slot interval is 400ms. GTOS at `periodMs=360` is 10% faster.
This is not a marketing approximation — it follows directly from the structural difference
between the two systems.

### Why Solana cannot reduce its slot time

Solana's 400ms is structurally saturated:

- **Turbine 4-hop propagation** consumes ~350ms of the slot budget (87ms per hop × 4).
- **PoH VDF computation** fills the slot with a CPU-intensive verifiable delay record.
- **GPU-accelerated signature verification** is required for thousands of transactions per slot.
- The **PoH grace window** (2 slots = 800ms) is calibrated to the 400ms slot; shrinking the
  slot requires recalibrating the entire timing stack across all validators globally.

Slot utilization at Solana: approximately 100% by design.

### Why GTOS can run at 360ms

GTOS does not have any of those constraints:

```
360ms slot:  ~7ms local processing  +  ~135ms worst-case propagation  =  142ms used
             → 60% of the slot is idle
```

The slot is idle because:

- No PoH: no VDF computation is needed to fill time.
- No VM: no EVM execution; only lightweight system actions (KV writes, code TTL).
- 15 validators: flat 2-hop broadcast replaces 4-hop Turbine.
- ed25519 seal: < 50µs, negligible.

### Required change to reach 360ms

One field in genesis / node config:

```json
"dpos": {
  "periodMs": 360
}
```

All timing parameters auto-adjust or have a straightforward recommended update:

| Parameter | Current | At 360ms | Note |
|---|---|---|---|
| `wiggle = clamp(period×2, …)` | 800ms | **720ms** | auto |
| `allowedFutureBlockTime` | 1200ms | **1080ms** (= 3× period) | recommended manual update |
| `recents limit` | 6 | 6 | unchanged |
| `epoch` | 1500 | **1667** (≈ 10 min) | optional |

### P95/P99 block interval explanation

The target `periodMs=360` is the minimum inter-block interval enforced by `verifyCascadingFields`.
The actual observed block interval distribution has two modes:

- **In-turn mode** (normal): interval ≈ 360ms.
- **Out-of-turn mode** (in-turn validator slow or offline): interval = 360ms + rand(0, 720ms),
  worst case 1080ms.

Percentile thresholds measure what fraction of blocks fall within a given bound:

- **P99 ≤ 650ms**: 99% of block intervals are under 650ms. This requires out-of-turn wins to be
  rare and, when they occur, to draw low wiggle values (< 290ms out of 720ms range).
- A healthy network with all 15 validators online should sustain P99 well under 650ms.

## 5. Propagation and Pipeline Optimization

These optimizations are required to hold the `360ms` target with stability.

Recommended work:

- Transaction pre-forwarding to upcoming leaders.
- Layered/tree broadcast instead of flat broadcast.
- Deeper pipeline parallelism (decode, verify, execute, package, broadcast).
- Evaluate short consecutive leader windows to reduce rotation overhead.

## 6. Rollout Plan (Single Target: `360ms`)

- Complete timing semantics migration in consensus.
- Add pre-forwarding and baseline layered broadcast optimization.
- Improve parallel verification/packaging throughput.
- Run 3-validator and 15-validator soak tests in low-latency and cross-region clusters.
- Keep `dpos.periodMs=360` as the only target profile for this plan.

## 6.1 Branch Strategy for This Experiment

- Run all code changes in a dedicated branch: `exp/ms-subsecond`.
- Keep `main` unchanged until `360ms` acceptance criteria pass.
- Rebase the branch regularly to keep diff small and reviewable.
- Merge into `main` only after soak and determinism gates pass.

## 7. Testing and Acceptance Criteria

Correctness:

- Unit tests for millisecond code paths.
- Config parsing tests for `periodMs` and explicit rejection of legacy `period`.

Consistency:

- Multi-node deterministic state-root checks (3 and 15 validators).
- Restart/recovery consistency at chain head and finalized boundaries.

Stability and performance:

- 24h soak without halt.
- Fork/empty-block/reorg metrics within thresholds.
- P95/P99 block interval meets the `360ms` target.

Suggested thresholds:

- Target (`360ms`): P99 block interval <= `650ms`.
- Reorg depth long-run mean close to `0` with explainable outliers.

## 8. Risks and Rollback

Primary risks:

- Clock drift increases future-block rejections.
- Network jitter has amplified impact at sub-second slots.
- Hardware variance introduces higher tail latency.

Mitigations:

- Keep a conservative buffer in networking/verification pipeline while iterating.
- Require long soak and cross-region stress testing before production rollout.

Rollback strategy:

- If `360ms` fails targets, pause rollout and fix bottlenecks before retrying.
- If instability occurs in experiments, reset testnet from known-good genesis/config and rerun.

## 9. Deliverables

- `docs/ms.md` (this plan)
- Parameter/protocol migration PRs
- Consensus timing migration PRs
- Millisecond-semantics test suite and soak report
- `360ms` benchmark and stability baseline
