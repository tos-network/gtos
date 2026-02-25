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

### Timing constants (current code values)

| Constant | Value | Source |
|---|---|---|
| `allowedFutureBlockTime` | `1200ms` | `consensus/dpos/dpos.go` |
| `minWiggleTime` | `100ms` | `consensus/dpos/dpos.go` |
| `maxWiggleTime` | `1000ms` | `consensus/dpos/dpos.go` |
| `outOfTurnWiggleWindow` | `clamp(period×2, 100ms, 1000ms)` | `consensus/dpos/dpos.go` |
| `recents limit` (default) | `validators/3 + 1` | `params/config.go::RecentSignerWindowSize` |
| `DPoSMaxValidators` | `15` | `params/tos_params.go` |

With `periodMs=360`: `wiggle = clamp(720ms, 100ms, 1000ms) = 720ms`.
With 15 validators: `recents limit = 15/3 + 1 = 6` (a validator may not sign again for 6 blocks).

Operational note: with `periodMs=360`, set `epoch=1667` to keep epoch rotation near 10 minutes
(`1667 × 0.36s ≈ 600s`).

### Block propagation model

GTOS uses go-ethereum flat p2p gossip, not a tree-based propagation protocol.
`BroadcastBlock` (`tos/handler.go`) sends the full block to `sqrt(peers)` peers directly;
remaining peers receive a hash announcement and pull on demand.

With 15 validators in a near-full-mesh topology:

- Direct full-block sends per hop: `sqrt(14) ≈ 3`
- Hops to reach all 15 validators: **2**
- Effective propagation model: **2-hop flat broadcast**

This is structurally simpler than Solana's Turbine tree (4 hops, fanout 200), which targets
validator sets in the thousands.

### In-turn win probability

The in-turn validator seals at exactly `header.Time = parent.Time + periodMs`.
Out-of-turn validators add a uniform random delay `rand(0, wiggle)` before sealing.
The in-turn block wins if it arrives at peers before any out-of-turn wiggle fires:

```
P(in-turn wins) = (wiggle - P) / wiggle
```

where `P` is the one-way network propagation latency between validators.

At `periodMs=360`, `wiggle=720ms`:

| Route | One-way latency P | P(in-turn wins) | Assessment |
|---|---|---|---|
| US internal | ~20ms | 97.2% | Stable |
| US ↔ Europe | ~80ms | 88.9% | Stable |
| Europe ↔ Asia-Pacific | ~100ms | 86.1% | Usable |
| US ↔ Asia-Pacific | ~130ms | 81.9% | Usable |
| US ↔ Australia | ~135ms | 81.3% | Usable |

All major global cloud regions are within the usable zone.
The effective geographic boundary for a 15-validator global public network is:
one-way latency under ~200ms to at least a quorum of peers (`N/3 + 1 = 6` validators).

### Local processing time budget

Benchmark results on Intel Xeon Platinum 8455C (`go test -bench -benchtime=20x`, diskdb):

| Operation | Time |
|---|---|
| Empty block import (diskdb) | ~250–300 µs |
| Block with transactions import (diskdb) | ~350–400 µs |
| TTL prune, 128 active records | ~4–6 ms |
| ed25519 seal | < 50 µs |
| **Total local processing per block** | **< 7 ms** |

With `periodMs=360` the slot budget is 360ms. Local processing consumes under 2% of that budget.
Full slot timeline at worst-case global propagation (US ↔ Australia, P = 135ms):

```
T =   0ms   parent block received by in-turn validator
T ≈ 0.5ms   parent imported and verified
T ≈   6ms   FinalizeAndAssemble + state root + TTL prune complete
T ≈ 6.1ms   ed25519 seal complete, block ready to broadcast
T ≈ 141ms   block received by all 15 validators  (6ms + 135ms propagation)
             → 219ms remaining in the 360ms slot
```

### Comparison with Solana's implicit geographic constraints

Solana operates at 400ms slots but its architecture creates tighter implicit constraints:

| Dimension | Solana | GTOS (15 validators, 360ms) |
|---|---|---|
| Propagation model | Turbine tree, 4 hops, fanout 200 | Flat p2p gossip, 2 hops |
| Per-hop latency budget | `(400ms − 50ms) / 4 ≈ 87ms` | `(360ms − 7ms) / 2 ≈ 176ms` |
| Timing reference | PoH VDF (hard slot clock) | `allowedFutureBlockTime` soft reject (1080ms) |
| Grace on late block | PoH grace: 2 slots = 800ms hard cutoff | `allowedFutureBlockTime`: 1080ms soft reject |
| Effective geographic cap | ~100ms one-way (US ↔ Asia borderline) | Global coverage including Australia |

Solana validators are concentrated in the US and Europe because Turbine's 4-hop budget and the
PoH grace window together impose a hard ~100ms one-way cap.
GTOS with 15 validators and 2-hop flat broadcast has a per-hop budget of ~176ms,
accommodating full global distribution at 360ms.

### Recommended deployment profiles

| Profile | `periodMs` | `allowedFutureBlockTime` | `wiggle` | `maxValidators` | `recents limit` |
|---|---:|---:|---:|---:|---:|
| Regional / low-latency | `360ms` | `800ms` | `720ms` | `21` | `N/3 + 1` |
| Global public network | `360ms` | `1080ms` | `720ms` | `15` | `N/3 + 1` |

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
