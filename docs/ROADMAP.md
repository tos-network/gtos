# GTOS Roadmap (DPoS + Transfer + Decentralized Storage)

## Scope Reset

This roadmap replaces prior CL/EL split planning. GTOS now targets one clear product:

- DPoS consensus
- Transfer payment
- Immutable smart-contract code storage
- TTL-based generic key-value storage

## Phase 0: Protocol Freeze

### Goal

Freeze the minimum protocol and state rules before implementation expansion.

### Deliverables

- Consensus spec: validator set, voting weight, quorum, finality, epoch transition.
- State spec:
  - account state
  - immutable contract-code state
  - TTL KV state
- Transaction spec:
  - `transfer`
  - `contract_deploy`
  - `kv_put_ttl`
  - `kv_delete` (if enabled)
- Hash/signing spec for block header and transaction payload.

### Definition of Done

- Specs reviewed and versioned.
- At least one golden test vector for each transaction type.

## Phase 1: DPoS + Transfer MVP

### Goal

Run a stable DPoS network with finalized `transfer` transactions.

### Deliverables

- DPoS validator lifecycle (register, activate, rotate by epoch).
- Proposal/vote/finality flow with safety checks.
- Transfer execution pipeline:
  - signature verification
  - nonce/balance validation
  - deterministic state commit
- RPC endpoints for transfer submit/query.

### Definition of Done

- 3-validator network runs continuously.
- 1000+ sequential finalized transfer blocks without fork divergence.
- Replay and double-spend rejection tests pass.

## Phase 2: Immutable Contract Storage

### Goal

Store contract bytecode on-chain immutably and make it queryable.

### Deliverables

- `contract_deploy` transaction.
- Contract address derivation rule (deterministic).
- Contract metadata index (code hash, deployer, block height, timestamp).
- Query API for contract code and metadata.

### Protocol Rules

- Contract bytecode is write-once.
- Any update requires new deployment; previous code remains unchanged.

### Definition of Done

- Attempted overwrite of existing contract code is rejected by consensus rules.
- Contract code/metadata can be retrieved from any full node and match code hash.

## Phase 3: TTL KV Storage

### Goal

Introduce native key-value storage entries with expiration.

### Deliverables

- `kv_put_ttl(key, value, ttl)` execution support.
- TTL validity checks (min/max range, overflow protection).
- Read semantics:
  - active key returns value
  - expired key returns not-found
- State maintenance/pruning strategy for expired entries.

### Definition of Done

- TTL expiration behavior is deterministic across nodes.
- Cross-node state root remains identical before and after prune cycle.

## Phase 4: Hardening and Production Readiness

### Goal

Make the chain safe to operate under sustained load.

### Deliverables

- Performance profiling and bottleneck fixes.
- Snapshot/state-sync for node bootstrap.
- Observability: metrics, structured logs, consensus/storage health dashboards.
- Security hardening:
  - transaction validation limits
  - DoS protections
  - fuzz and property-based tests for state transition logic

### Definition of Done

- 24h stability run with no consensus halt.
- Recovery drills (node restart/sync) succeed on latest finalized height.

## Milestone Priorities

1. Consensus safety and deterministic transfer finality.
2. Immutable contract storage correctness.
3. TTL KV deterministic expiration and pruning.
4. Operability and production hardening.

## Out of Scope (Current Roadmap)

- General-purpose EVM compatibility.
- Complex contract runtime execution semantics.
- Cross-chain bridge features.
- Off-chain indexing productization beyond basic query support.
