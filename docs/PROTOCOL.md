# GTOS Protocol Reference

This document describes the core protocol design of GTOS: consensus, storage primitives, account model, cryptography, and history retention policy.

GTOS is the shared memory and coordination layer for autonomous AI agents. The protocol primitives described here are what agents call — directly via JSON-RPC, or through named skills in agent frameworks — to read and write chain-native state.

For the product narrative and agent use cases, see `README.md`.
For the full RPC specification and method schemas, see `docs/RPC.md`.
For the feature profile and roadmap status, see `docs/feature.md` and `docs/ROADMAP.md`.

## Consensus: DPoS

- Validator set governed by stake and delegation.
- Weighted voting and quorum finality.
- Epoch-based validator rotation.
- Target block interval: `1s` (`target_block_interval=1s`).
- Block sealing signer is configurable via `config.dpos.sealSignerType`:
  - `ed25519` (default)
  - `secp256k1`
- Consensus-side BLS vote aggregation is not enabled in the current design.

## Storage Primitives (TTL Native)

GTOS provides two native storage types, both with deterministic TTL lifecycle. These are the chain-level primitives that agent skills wrap.

### Code Storage (`tos_setCode`)

Agents use this to write executable logic on-chain. Agent frameworks typically expose this as a skill named `code_put_ttl`; the underlying chain RPC method is `tos_setCode`.

- Writes a code object bound to the sender account, with TTL metadata.
- Code objects are immutable while active: no update, no delete.
- Only one active code entry per account.
- Code can be written again only after TTL expiry clears the active entry.
- Code payload is limited to `65536` bytes (`64 KiB`).
- The agent is the executor: there is no VM. Logic runs in the agent process; only the code artifact and its lifecycle metadata are stored on-chain.

### KV Storage (`tos_putKV`)

Agents use this as their shared structured database. Agent frameworks typically expose this as a skill named `kv_put_ttl`; the underlying chain RPC method is `tos_putKV`.

- Writes an expiring key-value record scoped by `(account, namespace, key)`.
- KV entries are updatable: writing the same key overwrites the existing value and TTL.
- KV entries are not manually deletable.
- Reads return only active (non-expired) entries.
- Multiple agents from different providers can read and write the same namespaces; consensus guarantees consistency.

### TTL Semantics

- `ttl` unit is **block count** (not seconds, not milliseconds).
- Expiry is deterministic: `expire_block = current_block + ttl`.
- Persisted state stores `expire_block` and `created_block` (absolute block heights), not raw `ttl`.
- Expired items are ignored by reads and pruned by block-time maintenance logic.
- TTL is how agents implement controlled forgetting: stale memory, expired policies, and timed-out coordination locks are removed without manual cleanup.

## Account and Signer Model

- Account fields: `address`, `nonce`, `signer`, `balance`.
- Account `address` is a fixed 32-byte value (`0x` + 64 hex chars).
- RPC/JSON address inputs are strict 32-byte only (no 20-byte compatibility mode).
- `signer` is the real signing identity, supporting multi-algorithm verification.
- Backward-compatible default: if `signer` is not set, the account address is used as signer.
- Signer algorithms supported: `secp256k1`, `schnorr`, `secp256r1`, `ed25519`, `bls12-381`.
- Agents hold their own address and signing key; they sign their own transactions and pay their own fees.

## Transaction Types

Three transaction types exist at the protocol level. Agent skills map onto these:

| Protocol tx type | Agent skill name (example) | Chain RPC method |
|---|---|---|
| `account_set_signer` | `set_signer` | `tos_setSigner` |
| `code_put_ttl` | `code_put_ttl` | `tos_setCode` |
| `kv_put_ttl` | `kv_put_ttl` | `tos_putKV` |

Agent frameworks may use any skill names they choose. The names in the middle column are the canonical names used in GTOS documentation.

## Transaction Envelope

- Only `SignerTx` typed envelopes are accepted for new submissions.
- `LegacyTx` and `AccessListTx` are rejected.
- `SignerTx` carries explicit fields: `chainId`, `from`, `signerType`.
- `V` is a signature component only; chain identity and signer metadata are not derived from `V`.

## Cryptography

Account and transaction signer algorithms:

| Algorithm | Typical agent use |
|---|---|
| `secp256k1` | Default; EVM-compatible key infrastructure |
| `schnorr` | secp256k1 x-only (BIP340) signatures with 32-byte public keys |
| `secp256r1` | Hardware security modules, mobile secure enclaves |
| `ed25519` | High-throughput agent identity and daily transaction signing |
| `bls12-381` | Aggregated proof paths; `blst` backend; G2 sig (96 bytes), G1 pubkey (48 bytes) |

DPoS consensus block sealing supports `ed25519` (default) and `secp256k1` via genesis config. No consensus-side BLS aggregation.

## State Model

- `Accounts`: nonce, signer, and account metadata.
- `CodeStore`: code hash/object → payload + `created_block` + `expire_block`.
- `KVStore`: `(account, namespace, key)` → value + `created_block` + `expire_block`.

All state transitions are consensus-verified and auditable on-chain. Any agent can verify what another agent wrote, when it was written, and that it has not been tampered with.

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
- TTL-expired state (code/KV) is pruned independently of the block retention window.

## Differentiators vs. Other Storage Networks

Compared with Filecoin / Arweave / Sia / Storj / Swarm, GTOS focuses on a different core profile:

- **Data model**: chain-native state storage (`code` + `kv`) with deterministic TTL, not large-file object storage.
- **Caller model**: AI agents as first-class actors with their own addresses, signing keys, and balances — not human users calling pre-deployed contracts.
- **Lifecycle**: explicit block-based expiry and deterministic prune behavior, not permanent storage.
- **Cost profile**: non-archive node operation with bounded history window, not full-history replication.
- **Control plane**: signer-aware typed transaction path (`SignerTx`) and system-action based signer updates.
- **Consensus boundary**: DPoS header seal (`ed25519` default, `secp256k1` supported); no consensus-side BLS aggregation requirement.
- **Product fit**: agent memory, coordination state, policy logic, and AI intermediate outputs requiring deterministic on-chain lifecycle and verifiable state transitions.

## Further Reading

- `docs/RPC.md`: full JSON-RPC method list, schemas, error codes, and standard agent KV namespace conventions.
- `docs/API.md`: concise API overview with method reference tables.
- `docs/RETENTION_SNAPSHOT_SPEC.md`: versioned operational spec for retention window and snapshot policy (`v1.0.0`).
- `docs/OBSERVABILITY_BASELINE.md`: metrics and structured log baseline for prune and retention signals.
- `docs/PERFORMANCE_BASELINE.md`: TTL prune benchmark baselines.
- `docs/ROADMAP.md`: phased delivery plan including Phase 5 Agent Economy Layer.
