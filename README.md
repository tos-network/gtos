# GTOS

GTOS is an infrastructure for AI-focused decentralized trustworthy on-chain storage.

## Product Goal

Build GTOS as a production-oriented chain for storage-first workloads:

1. Fast finality with DPoS consensus.
2. Native decentralized storage as the primary capability.
3. TTL-based lifecycle for all stored data, including code storage.
4. Predictable pruning and low storage pressure without archive nodes.

## Core Differentiators

Compared with Filecoin / Arweave / Sia / Storj / Swarm, GTOS currently focuses on a different core profile:

- Data model: chain-native state storage (`code` + `kv`) with deterministic TTL, not large-file object storage network first.
- Lifecycle: explicit block-based expiry (`expireBlock = currentBlock + ttl`) and deterministic prune behavior.
- Cost profile: non-archive node operation with bounded history window (for example `retain_blocks=200`) plus retention guards.
- Transaction/control plane: signer-aware typed transaction path (`SignerTx`) and system-action based account signer updates.
- Consensus boundary: DPoS block production path remains `secp256k1` seal; no consensus-side BLS vote aggregation requirement.
- Product fit: state/config/policy/AI intermediate outputs requiring deterministic on-chain lifecycle and verifiable state transitions.

## Core Features

### 1. DPoS Consensus

- Validator set governed by stake/delegation.
- Weighted voting and quorum finality.
- Epoch-based validator rotation.
- Target block interval: `1s` (`target_block_interval=1s`).

### 2. Decentralized Storage (TTL Native)

- `code_put_ttl(code, ttl)` writes code objects with explicit expiration.
- Code objects are immutable while active: no update, no delete.
- `kv_put_ttl(key, value, ttl)` writes expiring KV records.
- KV entries are updatable by writing a new value for the same key.
- KV entries are not manually deletable.
- `ttl` unit is **block count** (not seconds, not milliseconds).
- Expiry rule is deterministic: `expire_block = current_block + ttl`.
- State/database persists `expire_block` (and `created_block`), not raw `ttl`.
- Expired items are ignored by reads and can be pruned by background/state-maintenance logic.

### 3. Signer-Capable Accounts

- Account model (`address`, `nonce`, `signer`, optional `balance`).
- `signer` is the real signing identity and supports multi-algorithm verification (IPFS-style extensible signer type).
- Backward-compatible default: if `signer` is not set, use `account address` as signer.

### 4. Cryptography and Signature Algorithms

- Account/transaction signer algorithms currently supported:
  - `secp256k1`
  - `secp256r1`
  - `ed25519`
  - `bls12-381`
- Active typed transaction path (`SignerTx`) supports verification for:
  - `secp256k1`, `secp256r1`, `ed25519`, `bls12-381`
- DPoS consensus block sealing path currently uses:
  - `secp256k1` header seal
- Consensus-side BLS vote aggregation is not enabled in the current GTOS design.

## State Model

- `Accounts`: nonce, signer, and account metadata.
- `CodeStore`: code hash/object -> payload + created_block + expire_block.
- `KVStore`: namespace/key -> value + created_block + expire_block.

All state transitions are consensus-verified and auditable on-chain.

## Transaction Types

- `account_set_signer`
- `code_put_ttl`
- `kv_put_ttl`

## History Retention Policy (No Archive Nodes)

GTOS runs without archive nodes in current target deployment.

- Keep permanently: current state + all finalized block headers.
- Keep as rolling window: finalized block bodies/transactions/receipts for latest `200` blocks (`retain_blocks=200`).
- Prune automatically: once a block is finalized and outside the retention window, oldest body-level history is removed.
- Generate state snapshots every `1000` blocks (`snapshot_interval=1000`) for bootstrap and recovery.

Tradeoff:

- Old transactions outside the retention window are not queryable from normal nodes.

## Roadmap

See `docs/ROADMAP.md` for phased delivery plan and acceptance criteria.

## License

This repository uses the BSD 3-Clause License.

See `LICENSE`.
