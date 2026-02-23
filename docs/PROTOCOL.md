# GTOS Protocol Reference

This document describes the core protocol design of GTOS: consensus, storage primitives, account model, cryptography, and history retention policy.

For the product narrative and Agent use cases, see `README.md`.
For the full RPC specification, see `docs/RPC.md`.
For the feature profile and roadmap status, see `docs/feature.md` and `docs/ROADMAP.md`.

## Consensus: DPoS

- Validator set governed by stake and delegation.
- Weighted voting and quorum finality.
- Epoch-based validator rotation.
- Target block interval: `1s` (`target_block_interval=1s`).
- Block sealing uses `secp256k1` header signature.
- Consensus-side BLS vote aggregation is not enabled in the current design.

## Storage Primitives (TTL Native)

GTOS provides two native storage types, both with deterministic TTL lifecycle.

### Code Storage

- `code_put_ttl(code, ttl)` writes a code object bound to the sender account.
- Code objects are immutable while active: no update, no delete.
- Only one active code entry per account.
- Code can be written again only after TTL expiry clears the active entry.
- Code payload is limited to `65536` bytes (`64 KiB`).

### KV Storage

- `kv_put_ttl(key, value, ttl)` writes an expiring key-value record scoped by `(account, namespace, key)`.
- KV entries are updatable: writing the same key overwrites the existing value and TTL.
- KV entries are not manually deletable.
- Reads return only active (non-expired) entries.

### TTL Semantics

- `ttl` unit is **block count** (not seconds, not milliseconds).
- Expiry is deterministic: `expire_block = current_block + ttl`.
- Persisted state stores `expire_block` and `created_block` (absolute block heights), not raw `ttl`.
- Expired items are ignored by reads and pruned by block-time maintenance logic.

## Account and Signer Model

- Account fields: `address`, `nonce`, `signer`, `balance`.
- `signer` is the real signing identity, supporting multi-algorithm verification.
- Backward-compatible default: if `signer` is not set, the account address is used as signer.
- Signer algorithms supported: `secp256k1`, `secp256r1`, `ed25519`, `bls12-381`.

## Transaction Types

- `account_set_signer`: bind a new signing key (of any supported algorithm) to an account.
- `code_put_ttl`: write code to the sender account with TTL.
- `kv_put_ttl`: write a KV entry with TTL.

## Transaction Envelope

- Only `SignerTx` typed envelopes are accepted for new submissions.
- `LegacyTx` and `AccessListTx` are rejected.
- `SignerTx` carries explicit fields: `chainId`, `from`, `signerType`.
- `V` is a signature component only; chain identity and signer metadata are not derived from `V`.

## Cryptography

Account and transaction signer algorithms:

- `secp256k1`
- `secp256r1`
- `ed25519`
- `bls12-381` (using `blst` / supranational backend; compressed G2 signatures, 96 bytes; compressed G1 pubkeys, 48 bytes)

DPoS consensus block sealing uses `secp256k1` header seal only.

## State Model

- `Accounts`: nonce, signer, and account metadata.
- `CodeStore`: code hash/object → payload + `created_block` + `expire_block`.
- `KVStore`: `(account, namespace, key)` → value + `created_block` + `expire_block`.

All state transitions are consensus-verified and auditable on-chain.

## History Retention Policy (No Archive Nodes)

GTOS runs without archive nodes in the current target deployment.

- Keep permanently: current state and all finalized block headers.
- Keep as rolling window: finalized block bodies, transactions, and receipts for the latest `200` blocks (`retain_blocks=200`).
- Prune automatically: once a block is finalized and outside the retention window, oldest body-level history is removed.
- Generate state snapshots every `1000` blocks (`snapshot_interval=1000`) for bootstrap and recovery.

Requests targeting block numbers outside the retention window return:

- error code: `-38005`
- reason: `history_pruned`

Tradeoff:

- Transactions outside the retention window are not queryable from normal nodes.

## Differentiators vs. Other Storage Networks

Compared with Filecoin / Arweave / Sia / Storj / Swarm, GTOS focuses on a different core profile:

- **Data model**: chain-native state storage (`code` + `kv`) with deterministic TTL, not large-file object storage.
- **Lifecycle**: explicit block-based expiry and deterministic prune behavior, not permanent storage.
- **Cost profile**: non-archive node operation with bounded history window, not full-history replication.
- **Control plane**: signer-aware typed transaction path (`SignerTx`) and system-action based signer updates.
- **Consensus boundary**: DPoS header seal (`secp256k1`); no consensus-side BLS aggregation requirement.
- **Product fit**: state, config, policy, and AI intermediate outputs requiring deterministic on-chain lifecycle and verifiable state transitions.

## Further Reading

- `docs/RPC.md`: full JSON-RPC method list, schemas, and error codes.
- `docs/RETENTION_SNAPSHOT_SPEC.md`: versioned operational spec for retention window and snapshot policy (`v1.0.0`).
- `docs/OBSERVABILITY_BASELINE.md`: metrics and structured log baseline for prune and retention signals.
- `docs/PERFORMANCE_BASELINE.md`: TTL prune benchmark baselines.
- `docs/ROADMAP.md`: phased delivery plan and acceptance criteria.
