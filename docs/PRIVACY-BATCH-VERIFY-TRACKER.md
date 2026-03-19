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

## Overall Status

The functional privacy batch-verification alignment work is complete.
Relative to the `~/x` verifier design, GTOS now matches the in-scope sigma/range
batch-verification architecture in both pure-Go and native `ed25519c` backends.
The only intentional difference left in this area is the out-of-scope `ZKP cache`
model.

GTOS now has:

- real sigma batch verification in both pure-Go and native `ed25519c` backends
- real range-proof batch verification in both backends
- aggregated transfer range-proof representation aligned with the `~/x` model
- txpool batch verification with pool-local private-state replay
- execution-path batch verification beyond txpool
- shared prepared proof-state flow across txpool and execution

There are no remaining in-scope implementation tasks in this tracker. GTOS also
keeps backward-compatible acceptance of the older concatenated transfer
range-proof encoding so historical data can still be verified.

## Current Status

| Item | Status | Notes |
|---|---|---|
| Pure-Go sigma batch verifier | DONE | `Shield`, `CT validity`, and `CommitmentEq` are collected and verified in batch |
| Pure-Go range batch verifier | DONE | Transfer, shield, and unshield range proofs are verified through the batch API |
| Native C sigma batch verifier | DONE | `ed25519c` collector now accumulates real sigma equations instead of using a stub collector |
| Native C range batch verifier | DONE | Native range pre-verification appends MSM terms to the collector and verifies them in batch |
| TxPool integration | DONE | Prepared privacy txs are batch-verified before admission; invalid batches fall back to sequential verification for isolation |
| Pool-local privacy state replay | DONE | Dependent private txs are replayed on a virtual private state before verification |
| Execution-path integration | DONE | Blocks containing privacy txs use the shared prepared flow and batch-verify consecutive privacy runs before apply |
| Shared prepare / pre-verify architecture | DONE | Txpool admission and execution reuse the same prepared privacy tx model and proof-state derivation |
| `BalanceProof` batch support | DONE | `BalanceProof` now feeds the same sigma collector path in both pure-Go and native `ed25519c` backends |
| Focused performance benchmarks | DONE | `core/priv` includes batch-vs-sequential benchmarks for transfer-heavy and mixed privacy-proof sets |
| Transfer range-proof representation alignment | DONE | `PrivTransfer` now generates one aggregated two-commitment range proof; verifiers still accept the legacy concatenated encoding for compatibility |
| Batch vs sequential equivalence tests | DONE | Positive and negative-path tests confirm identical verification outcomes |

## Explicit Non-Goals

| Item | Status | Notes |
|---|---|---|
| ZKP cache | OUT OF SCOPE | Deliberately not planned for this project |

## Remaining Work

| Priority | Task | Status | Notes |
|---|---|---|---|
| - | No remaining in-scope work | DONE | The tracker scope is complete; only `~/x` items intentionally out of scope, such as `ZKP cache`, remain different |

## Reference Alignment With `~/x`

### Already aligned

- real sigma batch verification in pure-Go and native `ed25519c`
- real range-proof batch verification in pure-Go and native `ed25519c`
- txpool admission performs real proof verification instead of shape-only prechecks
- pool-level sigma/range batch verification exists
- dependency-sensitive private txs use virtual-state replay before verification
- execution path reuses prepared proof state and performs batch verification beyond txpool
- transfer range proofs now use an aggregated multi-commitment representation instead of a concatenated pair of single proofs

### Still different

- GTOS does not implement the `~/x` ZKP cache model

## Selective Disclosure Verification ✅

The selective disclosure system (see `docs/SELECTIVE-DISCLOSURE.md`) adds three
new proof types to the verification surface:

| Proof | Size | Verification | Batch support |
|-------|------|-------------|---------------|
| **DisclosureProof** (DLEQ exact amount) | 96B | Off-chain only (`core/priv.VerifyDisclosure`) | N/A (off-chain) |
| **DecryptionToken** DLEQ honesty proof | 96B | Off-chain only (`core/priv.VerifyDecryptionToken`) | N/A (off-chain) |
| **AuditorHandle DLEQ** (same-randomness) | 96B | On-chain (`core/priv.VerifyAuditorHandleDLEQ`) | Via `BatchVerifier.AddAuditorHandleDLEQ` |

The AuditorHandle DLEQ is verified at consensus time in `core/privacy_tx_prepare.go`
and can be added to the batch verifier via `AddAuditorHandleDLEQ` in
`core/priv/batch_verify.go`. Shape validation (0 or 96 bytes) occurs at txpool
admission in `core/tx_pool_privacy_verify.go`.

## Suggested Completion Order

1. Treat the current batch-verification work as complete for functional parity.
2. Only revisit this tracker if `ZKP cache` or another intentionally excluded `~/x` feature becomes in scope.
