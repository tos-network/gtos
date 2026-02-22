# GTOS Roadmap (DPoS + TTL-Native Decentralized Storage)

## Status Legend

- `DONE`: completed and merged.
- `IN_PROGRESS`: partially implemented or implemented as skeleton/validation only.
- `PLANNED`: not implemented yet.
- Status snapshot date: `2026-02-22`.

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

Status: `IN_PROGRESS`

### Goal

Freeze the minimum protocol and state rules before feature expansion.

### Deliverables

- `DONE` Consensus spec: validator set, weighted voting, quorum/finality, epoch transition.
- `DONE` Consensus timing spec: target block interval `1s` (`target_block_interval=1s`).
- `DONE` State spec: account nonce/metadata, signer binding, code storage with TTL, KV storage with TTL.
- `DONE` TTL semantics spec: `expire_block = current_block + ttl`, and state persistence stores `expire_block` (not raw `ttl`).
- `DONE` Mutability spec: code is immutable while active (no update/delete), KV is updatable (overwrite by key) but not deletable.
- `DONE` Signer spec: multi-algorithm verification and fallback rule (`signer` unset -> `account address`).
- `IN_PROGRESS` Retention/snapshot spec: retention boundary, prune trigger, snapshot/recovery flow.
- `DONE` Transaction spec: `account_set_signer`, `code_put_ttl`, `kv_put_ttl`.

### Definition of Done

- `IN_PROGRESS` Specs reviewed and versioned.
- `PLANNED` Golden vectors for each transaction type.
- `DONE` Parameters frozen: `retain_blocks=200`, `snapshot_interval=1000`, `target_block_interval=1s`.

## Phase 1: DPoS + Account/Signer Foundation

Status: `IN_PROGRESS`

### Goal

Run a stable DPoS network with deterministic account and signer processing.

### Deliverables

- `IN_PROGRESS` Validator lifecycle: register, activate, epoch rotation.
- `IN_PROGRESS` Proposal/vote/finality flow and safety checks.
- `IN_PROGRESS` Signature verification pipeline with signer resolution and fallback.
- `IN_PROGRESS` Deterministic nonce/state transition checks.

### Definition of Done

- `PLANNED` 3-validator network runs continuously.
- `PLANNED` 1000+ sequential finalized blocks without divergence.
- `PLANNED` Replay rejection and signer compatibility tests pass.

## Phase 2: Code Storage with TTL

Status: `IN_PROGRESS`

### Goal

Store code objects with TTL and provide deterministic read/expiry behavior.

### Deliverables

- `PLANNED` `code_put_ttl(code, ttl)` execution support.
- `IN_PROGRESS` TTL semantics: `ttl` is block count; compute and persist `expire_block` at write time.
- `PLANNED` Code immutability rules: active code objects cannot be updated or deleted.
- `IN_PROGRESS` TTL validation rules and overflow protection.
- `IN_PROGRESS` Code read/index APIs (payload/hash/metadata).
- `PLANNED` Expiry and pruning behavior integrated with state maintenance.

### Definition of Done

- `PLANNED` Code records expire deterministically across nodes.
- `PLANNED` State root remains identical across nodes before/after prune cycles.

## Phase 3: KV Storage with TTL

Status: `IN_PROGRESS`

### Goal

Provide native TTL-based key-value storage with deterministic lifecycle.

### Deliverables

- `PLANNED` `kv_put_ttl(key, value, ttl)` execution support.
- `IN_PROGRESS` TTL semantics: `ttl` is block count; compute and persist `expire_block` at write time.
- `PLANNED` Upsert semantics for `kv_put_ttl` (same key writes a new value/version).
- `DONE` Explicitly no `kv_delete` transaction path.
- `IN_PROGRESS` Read semantics: active returns value, expired returns not-found.
- `PLANNED` Maintenance pipeline for pruning expired KV entries.

### Definition of Done

- `PLANNED` TTL behavior is deterministic across nodes.
- `PLANNED` Long-run pruning keeps storage bounded while preserving consensus correctness.

## Phase 4: Hardening and Production Readiness

Status: `PLANNED`

### Goal

Harden the chain for sustained production load.

### Deliverables

- `PLANNED` Performance profiling and bottleneck fixes.
- `PLANNED` Snapshot/state-sync bootstrap and recovery drills.
- `PLANNED` Automated retention-window pruning enforcement.
- `PLANNED` Observability: metrics, structured logs, consensus/storage health dashboards.
- `PLANNED` Security hardening: validation limits, DoS protections, fuzz/property tests.

### Definition of Done

- `PLANNED` 24h stability run without consensus halt.
- `PLANNED` Restart/recovery drills succeed at latest finalized height.
- `PLANNED` Retention window remains deterministic and bounded across nodes.

## Milestone Priorities

1. Consensus safety and deterministic finality.
2. Code storage TTL correctness.
3. KV storage TTL correctness and pruning determinism.
4. Operability and production hardening.

## Out of Scope

- General-purpose contract VM compatibility.
- Contract runtime execution semantics.
- Cross-chain bridge features.
- Archive-node deployment requirements.
