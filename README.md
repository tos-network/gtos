# GTOS

GTOS is a DPoS-based blockchain focused on two native capabilities:

- Transfer payment: deterministic account/balance transfer settlement.
- Decentralized storage:
  - immutable smart-contract code storage (contract code cannot be modified after deployment)
  - general key-value storage with TTL (time-to-live)

## Product Goal

Build GTOS as a production-oriented chain for payment + storage:

1. Fast finality with DPoS consensus.
2. Transfer-first transaction model with predictable execution.
3. On-chain immutable contract code storage.
4. Native KV storage supporting expiration by TTL.

## Core Features

### 1. DPoS Consensus

- Validator set governed by stake/delegation.
- Weighted voting and quorum finality.
- Epoch-based validator rotation.

### 2. Transfer Payment

- Account model (`address`, `balance`, `nonce`).
- `transfer` transaction as first-class primitive.
- Deterministic state transition and replay-safe nonce checks.

### 3. Immutable Contract Storage

- `contract_deploy` writes contract bytecode to chain state.
- Contract bytecode is immutable once committed.
- Contract evolution uses new deployment/version address, never in-place rewrite.

### 4. KV Storage with TTL

- `kv_put(key, value, ttl)` writes expiring records.
- Expiration is evaluated by block time/height policy (defined in protocol rules).
- Expired keys are ignored by reads and can be pruned by background/state-maintenance logic.

## State Model (MVP)

- `Accounts`: balances, nonces.
- `Contracts`: immutable bytecode + metadata.
- `KV`: namespace/key -> value + created_at + expire_at.

All state transitions are consensus-verified and auditable on-chain.

## Transaction Types (MVP)

- `transfer`
- `contract_deploy`
- `kv_put_ttl`
- `kv_delete` (optional governance/owner rule based)

## Repository Direction

The repository should now prioritize this target directly:

- Keep only modules required for DPoS + transfer + storage.
- Remove legacy paths that do not serve the core product direction.
- Implement protocol rules in small, testable milestones.

## Roadmap

See `docs/ROADMAP.md` for phased delivery plan and acceptance criteria.

## License

- Library code (outside `cmd`): LGPL-3.0 (`COPYING.LESSER`)
- Binary-related code (inside `cmd`): GPL-3.0 (`COPYING`)
