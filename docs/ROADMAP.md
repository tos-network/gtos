# GTOS Roadmap (DPoS + TTL-Native Decentralized Storage)

## Status Legend

- `DONE`: completed and merged.
- `IN_PROGRESS`: partially implemented or implemented as skeleton/validation only.
- `PLANNED`: not implemented yet.
- Status snapshot date: `2026-02-23`.

## Product Alignment

This roadmap is aligned with `README.md` and defines GTOS as a storage-first chain:

- DPoS consensus with fast finality.
- Native decentralized storage as the primary capability.
- TTL lifecycle for both code storage and generic KV storage.
- TTL unit is block count, with deterministic expiry by height.
- Predictable pruning with no archive-node dependency.

## Retention Strategy (No Archive Nodes)

- Persistent data: current state and all finalized block headers.
- Rolling history window: latest `200` finalized blocks for bodies/transactions/receipts (`retain_blocks=200`).
- Snapshot policy: create state snapshots every `1000` blocks (`snapshot_interval=1000`).
- Pruning rule: prune only finalized blocks outside the retention window.

## Phase 0: Protocol Freeze

Status: `DONE`

### Goal

Freeze the minimum protocol and state rules before feature expansion.

### Deliverables

- `DONE` Consensus spec: validator set, weighted voting, quorum/finality, epoch transition.
- `DONE` Consensus timing spec: target block interval `1s` (`target_block_interval=1s`).
- `DONE` State spec: account nonce/metadata, signer binding, code storage with TTL, KV storage with TTL.
- `DONE` TTL semantics spec: `expire_block = current_block + ttl`, and state persistence stores `expire_block` (not raw `ttl`).
- `DONE` Mutability spec: code is immutable while active (no update/delete), KV is updatable (overwrite by key) but not deletable.
- `DONE` Signer spec: multi-algorithm registry and current tx verification path support `secp256k1`/`secp256r1`/`ed25519`/`bls12-381`.
- `DONE` Retention/snapshot spec: retention boundary, prune trigger, snapshot/recovery flow (`docs/RETENTION_SNAPSHOT_SPEC.md` `v1.0.0`).
- `DONE` Transaction spec: `account_set_signer`, `code_put_ttl`, `kv_put_ttl`, and signer-aware tx envelope rules.

### Definition of Done

- `DONE` Specs reviewed and versioned.
- `DONE` Golden vectors for active typed signer transaction (`SignerTx`) across `secp256k1`/`secp256r1`/`ed25519`/`bls12-381`, including invalid decode/canonicalization cases.
- `DONE` Parameters frozen: `retain_blocks=200`, `snapshot_interval=1000`, `target_block_interval=1s`.

## Phase 1: DPoS + Account/Signer Foundation

Status: `DONE`

### Goal

Run a stable DPoS network with deterministic account and signer processing.

### Deliverables

- `DONE` Validator lifecycle: register, activate, epoch rotation (`validator/validator_test.go` + `consensus/dpos/integration_test.go::TestDPoSEpochRotationUsesValidatorRegistrySet`).
- `DONE` Proposal/vote/finality flow and safety checks (`consensus/dpos/dpos_test.go::TestVoteSigningLifecycle` + `consensus/dpos/integration_test.go::TestDPoSProposalSafetyChecks`).
- `DONE` Signature verification pipeline wired to account signer (`signerType`-based verifier routing for `secp256k1`/`secp256r1`/`ed25519`/`bls12-381`).
- `DONE` `tos_setSigner` RPC wrapper and execution path through normal transfer (`to = SystemActionAddress`, `data = ACCOUNT_SET_SIGNER payload`).
- `DONE` Account signer validator support: `secp256k1`, `secp256r1`, `ed25519`, `bls12-381`.
- `DONE` Sender resolution is `SignerTx`-only and uses explicit `from` + `signerType`; no signer metadata is derived from `V`.
- `DONE` Deterministic nonce/state transition checks (including signer switch + replay rejection consistency in `core/state_processor_test.go::TestDeterministicNonceStateTransitionAndReplayRejection`).

### Definition of Done

- `DONE` 3-validator network stability gate runs in CI-style integration test.
- `DONE` 1000+ sequential finalized blocks without divergence (1024-block deterministic gate).
- `DONE` Replay rejection and signer compatibility tests pass (chain-id mismatch rejection + account-signer type compatibility coverage in `core/accountsigner_sender_test.go`).

## Signer Tx Envelope Refactor (Design Update)

Status: `DONE`

### Goal

Stop overloading signature field `V` with chain/signer metadata, and make signer-related consensus fields explicit in transaction payload.

### Current Code Reality

- `DONE` Active transaction path (`SignerTx`) carries explicit `chainId`.
- `DONE` Active transaction path routes verifier by explicit `signerType`, not `V` metadata.
- `DONE` account signer registry state is available (`signerType`, `signerValue`) and can be used by the verifier.

### Target Design

- `DONE` `LegacyTx`/`AccessListTx` are rejected in transaction admission path; signer-aware transactions use typed envelope only.
- `DONE` Transaction envelope contains explicit `chainId`; chain identity is not derived from `V`.
- `DONE` Transaction envelope contains explicit `signerType`.
- `DONE` Transaction envelope contains explicit `from` for signer-aware validation routing.
- `DONE` `V` is treated as signature component only; signer metadata is not carried in `V` on the active path.
- `DONE` Validation pipeline uses explicit `(from, signerType)` to select verifier and validate against account signer state.

### Migration Plan

- `DONE` Signer-aware typed tx encoding with explicit fields (`chainId`, `from`, `signerType`) and RPC marshalling support is active.
- `DONE` `LegacyTx`/`AccessListTx` are rejected for new submissions; sender/chain derivation from `V` is removed from the active verification path.
- `DONE` No migration/cutover gate needed in current dev-stage GTOS network (fresh-state policy, no backward compatibility requirement).
- `DONE` Golden vectors for typed signer tx (`SignerTx`) validation.

## AI Agent Crypto Capability Targets

Status: `IN_PROGRESS`

### Target Set

- `DONE` (A) Daily identity/transaction signing: `ed25519` (native keystore + tx signing/verification path).
- `IN_PROGRESS` (B) Large-scale aggregated proofs (non-consensus path): `bls12-381` (tx verify/sign path and aggregate helpers on `blst` backend are wired).
- `DONE` (C) AA wallet signing support baseline: `secp256k1`, `secp256r1`, `ed25519`, `bls12-381`.

### Layer Mapping

- `DONE` Transaction/account signer layer (current tx format): `secp256k1`, `secp256r1`, `ed25519`, `bls12-381`.
- `DONE` DPoS consensus sealing/verification remains header `secp256k1` seal + `extra` validation; no consensus-side `bls12-381` import.

### Staged Execution

- `DONE` Stage 1: explicit tx `chainId + signerType + from` envelope and `LegacyTx` rejection for submissions.
- `DONE` Stage 2 decision: keep consensus path on DPoS header seal (`secp256k1`) and do not add BLS vote objects/aggregation to consensus.

## Next Tasks (Execution Order)

1. `DONE` Complete deterministic prune validation for code/KV TTL: cross-node state-root equality before/after prune windows (`core/ttl_prune_determinism_test.go`).
2. `DONE` Finish Stage C RPC deprecation enforcement (`tos_call`, `tos_estimateGas`, and `tos_createAccessList` now return deterministic `not_supported`).
3. `DONE` Run DPoS stability gates: deterministic 3-validator/3-node 1024-block insertion gate with per-height hash/root agreement (`consensus/dpos/integration_test.go::TestDPoSThreeValidatorStabilityGate`).
4. `DONE` Finalize retention/snapshot spec details: prune trigger policy and snapshot/recovery operational flow (`docs/RETENTION_SNAPSHOT_SPEC.md` `v1.0.0`).
5. `DONE` Add long-run bounded-storage gate for KV/code expiry maintenance (`core/ttl_prune_boundedness_test.go::TestTTLPruneLongRunBoundedStorageAndDeterministicRoots`).
6. `DONE` Start Phase 4 hardening baseline: retention-window enforcement automation and restart/recovery drill (`internal/tosapi/api_retention_test.go::TestRetentionWatermarkTracksHead` + `core/restart_recovery_test.go::TestRestartRecoversLatestFinalizedAndResumesImport`).
7. `DONE` Finalize retention/snapshot operational spec and version it (`docs/RETENTION_SNAPSHOT_SPEC.md` `v1.0.0`).
8. `IN_PROGRESS` Expand Phase 4 hardening to observability + security fuzz/property baseline (`core/ttl_prune_metrics.go` + `internal/tosapi/metrics.go` + `core/types/signer_tx_fuzz_test.go` + `core/types/transaction_unmarshal_fuzz_test.go` + `internal/tosapi/api_retention_property_test.go`).

## Phase 2: Code Storage with TTL

Status: `DONE`

### Goal

Store code objects with TTL and provide deterministic read/expiry behavior.

### Deliverables

- `DONE` `code_put_ttl(code, ttl)` execution support.
- `DONE` TTL semantics: `ttl` is block count; compute and persist `expire_block` at write time.
- `DONE` Code immutability rules: active code objects cannot be updated or deleted.
- `DONE` TTL validation rules and overflow protection.
- `DONE` Code read/index APIs (payload/hash/metadata).
- `DONE` Expiry and pruning behavior integrated with state maintenance (`core/state_processor.go` + `core/chain_makers.go` + `core/state_processor_test.go::TestStateProcessorPrunesExpiredCodeAtBlockBoundary`).

### Definition of Done

- `DONE` Code records expire deterministically across nodes.
- `DONE` State root remains identical across nodes before/after prune cycles.

## Phase 3: KV Storage with TTL

Status: `DONE`

### Goal

Provide native TTL-based key-value storage with deterministic lifecycle.

### Deliverables

- `DONE` `kv_put_ttl(key, value, ttl)` execution support.
- `DONE` TTL semantics: `ttl` is block count; compute and persist `expire_block` at write time.
- `DONE` Upsert semantics for `kv_put_ttl` (same key writes a new value/version).
- `DONE` Explicitly no `kv_delete` transaction path.
- `DONE` Read semantics: active returns value, expired returns not-found.
- `DONE` Maintenance pipeline for pruning expired KV entries (`kvstore/kvstore_test.go::TestPruneExpiredAtClearsOnlyMatchingRecords` + `core/state_processor_test.go::TestStateProcessorPrunesExpiredKVAtBlockBoundary`).

### Definition of Done

- `DONE` TTL behavior is deterministic across nodes.
- `DONE` Long-run pruning keeps storage bounded while preserving consensus correctness (`core/ttl_prune_boundedness_test.go::TestTTLPruneLongRunBoundedStorageAndDeterministicRoots`).

## Phase 4: Hardening and Production Readiness

Status: `IN_PROGRESS`

### Goal

Harden the chain for sustained production load.

### Deliverables

- `PLANNED` Performance profiling and bottleneck fixes.
- `IN_PROGRESS` Snapshot/state-sync bootstrap and recovery drills (baseline restart/finalized recovery gate in `core/restart_recovery_test.go`).
- `IN_PROGRESS` Automated retention-window pruning enforcement (watermark progression/retention guard baseline in `internal/tosapi/api_retention_test.go` + `history_pruned` guards).
- `IN_PROGRESS` Observability baseline: TTL prune meters (`chain/ttlprune/code`, `chain/ttlprune/kv`) and RPC prune-rejection meter (`rpc/tos/history_pruned`) wired in execution/RPC paths (`core/ttl_prune_metrics.go` + `core/state_processor.go` + `internal/tosapi/metrics.go` + `internal/tosapi/api.go`).
- `IN_PROGRESS` Security baseline: fuzz/property tests for signer-tx decode/JSON/binary and retention boundary invariants (`core/types/signer_tx_fuzz_test.go` + `core/types/transaction_unmarshal_fuzz_test.go` + `internal/tosapi/api_retention_property_test.go`).

### Definition of Done

- `PLANNED` 24h stability run without consensus halt.
- `DONE` Restart/recovery drills succeed at latest finalized height (`core/restart_recovery_test.go::TestRestartRecoversLatestFinalizedAndResumesImport`).
- `PLANNED` Retention window remains deterministic and bounded across nodes.

## Milestone Priorities

1. Consensus safety and deterministic finality.
2. Code/KV TTL pruning determinism (cross-node state-root checks).
3. RPC surface convergence for storage-first profile (deprecate VM-era calls).
4. DPoS long-run stability and recovery drills.
5. Operability and production hardening.

## Out of Scope

- General-purpose contract VM compatibility.
- Contract runtime execution semantics.
- Cross-chain bridge features.
- Archive-node deployment requirements.
