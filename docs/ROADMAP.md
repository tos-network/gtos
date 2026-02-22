# GTOS Roadmap (DPoS + TTL-Native Decentralized Storage)

## Product Alignment

This roadmap is aligned with `README.md` and defines GTOS as a storage-first chain:

- DPoS consensus with fast finality.
- Native decentralized storage as the primary capability.
- TTL lifecycle for both code storage and generic KV storage.
- Predictable pruning with no archive-node dependency.

## Retention Strategy (No Archive Nodes)

- Persistent data: current state and all finalized block headers.
- Rolling history window: latest `200` finalized blocks for bodies/transactions/receipts (`retain_blocks=200`).
- Snapshot policy: create state snapshots every `1000` blocks (`snapshot_interval=1000`).
- Pruning rule: prune only finalized blocks outside the retention window.

## Phase 0: Protocol Freeze

### Goal

Freeze the minimum protocol and state rules before feature expansion.

### Deliverables

- Consensus spec: validator set, weighted voting, quorum/finality, epoch transition.
- Consensus timing spec: target block interval `1s` (`target_block_interval=1s`).
- State spec: account nonce/metadata, signer binding, code storage with TTL, KV storage with TTL.
- Mutability spec: code is immutable while active (no update/delete), KV is updatable (overwrite by key) but not deletable.
- Signer spec: multi-algorithm verification and fallback rule (`signer` unset -> `account address`).
- Retention/snapshot spec: retention boundary, prune trigger, snapshot/recovery flow.
- Transaction spec: `account_set_signer`, `code_put_ttl`, `kv_put_ttl`.

### Definition of Done

- Specs reviewed and versioned.
- Golden vectors for each transaction type.
- Parameters frozen: `retain_blocks=200`, `snapshot_interval=1000`, `target_block_interval=1s`.

## Phase 1: DPoS + Account/Signer Foundation

### Goal

Run a stable DPoS network with deterministic account and signer processing.

### Deliverables

- Validator lifecycle: register, activate, epoch rotation.
- Proposal/vote/finality flow and safety checks.
- Signature verification pipeline with signer resolution and fallback.
- Deterministic nonce/state transition checks.

### Definition of Done

- 3-validator network runs continuously.
- 1000+ sequential finalized blocks without divergence.
- Replay rejection and signer compatibility tests pass.

## Phase 2: Code Storage with TTL

### Goal

Store code objects with TTL and provide deterministic read/expiry behavior.

### Deliverables

- `code_put_ttl(code, ttl)` execution support.
- Code immutability rules: active code objects cannot be updated or deleted.
- TTL validation rules and overflow protection.
- Code read/index APIs (payload/hash/metadata).
- Expiry and pruning behavior integrated with state maintenance.

### Definition of Done

- Code records expire deterministically across nodes.
- State root remains identical across nodes before/after prune cycles.

## Phase 3: KV Storage with TTL

### Goal

Provide native TTL-based key-value storage with deterministic lifecycle.

### Deliverables

- `kv_put_ttl(key, value, ttl)` execution support.
- Upsert semantics for `kv_put_ttl` (same key writes a new value/version).
- Explicitly no `kv_delete` transaction path.
- Read semantics: active returns value, expired returns not-found.
- Maintenance pipeline for pruning expired KV entries.

### Definition of Done

- TTL behavior is deterministic across nodes.
- Long-run pruning keeps storage bounded while preserving consensus correctness.

## Phase 4: Hardening and Production Readiness

### Goal

Harden the chain for sustained production load.

### Deliverables

- Performance profiling and bottleneck fixes.
- Snapshot/state-sync bootstrap and recovery drills.
- Automated retention-window pruning enforcement.
- Observability: metrics, structured logs, consensus/storage health dashboards.
- Security hardening: validation limits, DoS protections, fuzz/property tests.

### Definition of Done

- 24h stability run without consensus halt.
- Restart/recovery drills succeed at latest finalized height.
- Retention window remains deterministic and bounded across nodes.

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
