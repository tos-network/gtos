# Privacy Batch Verification Alignment Tracker

**Last updated**: 2026-03-16
**Scope**: GTOS privacy proof batch verification, aligned where practical with the `~/x` transaction verifier model

## Objective

Track the remaining work after GTOS implemented real sigma/range crypto batch verification in both Go and native C backends.

This tracker is intentionally narrower than the broader privacy roadmap. It covers:

- proof pre-verification and batch verification flow
- txpool integration
- backend parity between pure-Go and `ed25519c`
- follow-up work needed beyond the current txpool-only integration

It does not cover:

- ZKP cache work
- unrelated privacy roadmap items such as memo consumption, contract privacy, or network-layer privacy

## Current Status

| Item | Status | Notes |
|---|---|---|
| Pure-Go sigma batch verifier | DONE | `Shield`, `CT validity`, and `CommitmentEq` are collected and verified in batch |
| Pure-Go range batch verifier | DONE | Transfer, shield, and unshield range proofs are verified through the batch API |
| Native C sigma batch verifier | DONE | `ed25519c` collector now accumulates real sigma equations instead of using a stub collector |
| Native C range batch verifier | DONE | Native range pre-verification appends MSM terms to the collector and verifies them in batch |
| TxPool integration | DONE | Prepared privacy txs are batch-verified before admission; invalid batches fall back to sequential verification for isolation |
| Pool-local privacy state replay | DONE | Dependent private txs are replayed on a virtual private state before verification |
| Batch vs sequential equivalence tests | DONE | Positive and negative-path tests confirm identical verification outcomes |

## Explicit Non-Goals

| Item | Status | Notes |
|---|---|---|
| ZKP cache | OUT OF SCOPE | Deliberately not planned for this project |

## Remaining Work

| Priority | Task | Status | Notes |
|---|---|---|---|
| P1 | Extend batch verification beyond txpool | TODO | Block import and state-transition execution still use sequential single-proof verification |
| P1 | Unify the prepare/pre-verify architecture | TODO | Current design is txpool-specific; `~/x` uses a more uniform transaction-level `pre_verify -> verify_batch` flow |
| P2 | Add `BalanceProof` batch support if needed | TODO | The current batch API covers the proof families used on the hot txpool path; `BalanceProof` is still single-verify only |
| P2 | Add focused performance benchmarks | TODO | Compare batch vs sequential throughput for Go and `ed25519c` backends under realistic mempool mixes |
| P3 | Re-evaluate range-proof representation alignment | TODO | GTOS currently batches its existing transfer wire format, which is two concatenated single range proofs rather than one aggregated proof view |

## Reference Alignment With `~/x`

### Already aligned

- txpool admission performs real proof verification instead of shape-only prechecks
- pool-level sigma/range batch verification exists
- dependency-sensitive private txs use virtual-state replay before verification

### Still different

- GTOS batch verification is currently integrated into txpool, not the full execution pipeline
- GTOS does not implement the `~/x` ZKP cache model
- GTOS keeps its current transfer range-proof wire format instead of adopting the `~/x` verification-view format directly

## Suggested Completion Order

1. Move batch verification from txpool-only into the block/state execution pipeline.
2. Refactor toward a reusable transaction-level `prepare/pre-verify` interface shared by txpool and execution.
3. Decide whether `BalanceProof` belongs on a hot path before adding it to the batch API.
4. Add benchmarks and telemetry before considering any deeper protocol-format refactor.
