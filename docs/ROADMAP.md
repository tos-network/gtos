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

Status: `IN_PROGRESS`

### Goal

Freeze the minimum protocol and state rules before feature expansion.

### Deliverables

- `DONE` Consensus spec: validator set, weighted voting, quorum/finality, epoch transition.
- `DONE` Consensus timing spec: target block interval `1s` (`target_block_interval=1s`).
- `DONE` State spec: account nonce/metadata, signer binding, code storage with TTL, KV storage with TTL.
- `DONE` TTL semantics spec: `expire_block = current_block + ttl`, and state persistence stores `expire_block` (not raw `ttl`).
- `DONE` Mutability spec: code is immutable while active (no update/delete), KV is updatable (overwrite by key) but not deletable.
- `IN_PROGRESS` Signer spec: multi-algorithm registry in place (`secp256k1`, `secp256r1`, `ed25519`, `bls12-381`, `frost`, `pqc`); current tx verification path supports `secp256k1`/`secp256r1`/`ed25519`.
- `IN_PROGRESS` Retention/snapshot spec: retention boundary, prune trigger, snapshot/recovery flow.
- `IN_PROGRESS` Transaction spec: `account_set_signer`, `code_put_ttl`, `kv_put_ttl`, and signer-aware tx envelope rules.

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
- `DONE` Signature verification pipeline wired to account signer (`signerType`-based verifier routing for `secp256k1`/`secp256r1`/`ed25519`).
- `DONE` `tos_setSigner` RPC wrapper and execution path through normal transfer (`to = SystemActionAddress`, `data = ACCOUNT_SET_SIGNER payload`).
- `DONE` Account signer validator support: `secp256k1`, `secp256r1`, `ed25519`.
- `DONE` Sender resolution is `SignerTx`-only and uses explicit `from` + `signerType`; no signer metadata is derived from `V`.
- `IN_PROGRESS` Deterministic nonce/state transition checks.

### Definition of Done

- `PLANNED` 3-validator network runs continuously.
- `PLANNED` 1000+ sequential finalized blocks without divergence.
- `PLANNED` Replay rejection and signer compatibility tests pass.

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
- `PLANNED` Add golden vectors for typed signer tx (`SignerTx`) validation.

## AI Agent Crypto Capability Targets

Status: `IN_PROGRESS`

### Target Set

- `IN_PROGRESS` (A) Daily identity/transaction signing: `ed25519`.
- `PLANNED` (B) Large-scale aggregated proofs / consensus voting: `bls12-381`.
- `PLANNED` (C) Multi-agent treasury/account authorization: `frost` threshold signatures.
- `PLANNED` (D) Long-term confidential communication / future migration: switchable `pqc` options (`kyber`, `dilithium`, ...).
- `DONE` (E) AA wallet signing support baseline: `secp256k1`, `secp256r1`, `ed25519`.

### Layer Mapping

- `DONE` Transaction/account signer layer (current tx format): `secp256k1`, `secp256r1`, `ed25519`.
- `PLANNED` Consensus vote signature layer: add native `bls12-381` verification path and aggregation checks.
- `PLANNED` Account policy layer: threshold authorization policy for `frost`-backed accounts.
- `PLANNED` Crypto-agility layer: algorithm registry/versioning to enable `pqc` rollout without hard-forking account semantics each time.

### Staged Execution

- `DONE` Stage 1: explicit tx `chainId + signerType + from` envelope and `LegacyTx` rejection for submissions.
- `PLANNED` Stage 2: introduce consensus-side `bls12-381` key lifecycle, vote objects, and aggregate verification.
- `PLANNED` Stage 3: introduce threshold account model (`frost` group pubkey + policy state + nonce/replay rules).
- `PLANNED` Stage 4: introduce hybrid/PQC mode (`classic + pqc`) for signatures and key migration policy.

## Phase 2: Code Storage with TTL

Status: `IN_PROGRESS`

### Goal

Store code objects with TTL and provide deterministic read/expiry behavior.

### Deliverables

- `DONE` `code_put_ttl(code, ttl)` execution support.
- `DONE` TTL semantics: `ttl` is block count; compute and persist `expire_block` at write time.
- `DONE` Code immutability rules: active code objects cannot be updated or deleted.
- `DONE` TTL validation rules and overflow protection.
- `DONE` Code read/index APIs (payload/hash/metadata).
- `IN_PROGRESS` Expiry and pruning behavior integrated with state maintenance.

### Definition of Done

- `IN_PROGRESS` Code records expire deterministically across nodes.
- `PLANNED` State root remains identical across nodes before/after prune cycles.

## Phase 3: KV Storage with TTL

Status: `IN_PROGRESS`

### Goal

Provide native TTL-based key-value storage with deterministic lifecycle.

### Deliverables

- `DONE` `kv_put_ttl(key, value, ttl)` execution support.
- `DONE` TTL semantics: `ttl` is block count; compute and persist `expire_block` at write time.
- `DONE` Upsert semantics for `kv_put_ttl` (same key writes a new value/version).
- `DONE` Explicitly no `kv_delete` transaction path.
- `DONE` Read semantics: active returns value, expired returns not-found.
- `IN_PROGRESS` Maintenance pipeline for pruning expired KV entries.

### Definition of Done

- `IN_PROGRESS` TTL behavior is deterministic across nodes.
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
2. Signer tx envelope refactor (remove `LegacyTx`; explicit `chainId` + `from` + `signerType`).
3. Code storage TTL correctness.
4. KV storage TTL correctness and pruning determinism.
5. Operability and production hardening.

## Out of Scope

- General-purpose contract VM compatibility.
- Contract runtime execution semantics.
- Cross-chain bridge features.
- Archive-node deployment requirements.
