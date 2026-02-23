# GTOS Feature Profile (Current)

Status snapshot date: `2026-02-23`

This document describes what GTOS can do **today**, and clearly separates current capabilities from future product modes.

## 1. Product Positioning

GTOS is a **DPoS, storage-first chain**:

- Consensus: DPoS (`secp256k1` header seal path).
- Primary value: decentralized storage with deterministic TTL lifecycle.
- Scope focus: account/signer + code/KV storage + retention/pruning operations.
- Non-goal: general-purpose contract VM compatibility.

## 2. Current Core Capabilities

## 2.1 TTL-Native Storage Primitives

- `tos_setCode(code, ttl)`:
  - writes account code with TTL metadata.
  - active code is immutable (no update/delete while active).
  - `to=nil` path is reserved for this flow only.
- `tos_putKV(namespace, key, value, ttl)`:
  - TTL KV upsert by `(namespace, key)`.
  - overwrite is allowed; explicit delete is not supported.
- TTL semantics:
  - unit is block count.
  - `expireBlock = currentBlock + ttl`.
  - chain persists absolute `createdAt`/`expireAt`.

## 2.2 Signer-Capable Account Model

- Account signer registry supports: `secp256k1`, `secp256r1`, `ed25519`, `bls12-381`.
- `tos_setSigner` is implemented as normal tx wrapper:
  - execution path uses `to = SystemActionAddress`
  - payload action: `ACCOUNT_SET_SIGNER`.
- Active transaction envelope policy:
  - only `SignerTx` accepted for new submissions.
  - explicit `chainId`, `from`, `signerType`.
  - `V` is signature component only (not metadata carrier).

## 2.3 Retention and Node Cost Control

- Non-archive deployment profile:
  - rolling history window: `retain_blocks = 200`.
  - snapshot policy metadata: `snapshot_interval = 1000`.
- Old history requests outside window return deterministic:
  - error code `-38005`
  - reason `history_pruned`.
- Determinism coverage includes:
  - retention boundary/property tests
  - cross-node retention-window behavior consistency
  - long-run bounded TTL pruning tests.

## 2.4 Operations and Hardening Baseline

- Metrics/logging baseline for prune and retention rejection is active.
- TTL prune performance baseline and CI smoke entry are available.
- DPoS long-window soak automation exists (`soak-dpos`), evidence collection in progress.

## 3. Explicit Boundaries (Current)

- No general-purpose contract execution runtime.
- No archive-node historical query guarantee.
- No `kv_delete` transaction path.
- No consensus-side BLS vote object / aggregation import.
- Storage classes/SLA tiers are not implemented as protocol-level classes.

## 4. Feature Mode Map (Current vs Future)

Status legend:

- `DONE`: available in current GTOS path.
- `IN_PROGRESS`: partially available, or tooling exists but evidence/closure pending.
- `PLANNED`: product concept, not implemented in protocol/runtime yet.

## 4.1 Data-as-Lease (`DONE`)

- Native fit for logs/caches/temp artifacts/AI intermediate outputs.
- TTL write + deterministic expiry/prune are already implemented.

## 4.2 Proof of Expiry (`IN_PROGRESS`)

- Current chain stores deterministic `createdAt/expireAt` and enforces expiry behavior.
- Operationally auditable through block history/metadata while in retention scope.
- Dedicated standalone expiry-proof artifact/protocol is not yet a separate feature.

## 4.3 Namespace Leasing Market (`PLANNED`)

- No namespace auction/rent market exists in current protocol.
- `namespace` is currently a logical KV partition key, not a leased asset.

## 4.4 Release Channel Model (Code + KV Streams) (`IN_PROGRESS`)

- Technically feasible now via app-level conventions (`namespace`, account-scoped code, TTL roll-forward).
- Protocol does not yet enforce channel/version policy as a first-class primitive.

## 4.5 Retention-Window Friendly Retrieval (`DONE` for node-side policy, `PLANNED` for indexer productization)

- Node-side rolling retention and deterministic `history_pruned` behavior are implemented.
- Off-chain long-range index/search integration is outside current on-chain runtime scope.

## 4.6 Storage SLA Tiers (`PLANNED`)

- No built-in storage class differentiation (standard/HA/etc.) at protocol level.
- Future ToB packaging can build on existing TTL primitives, pricing, and replication policies.

## 5. Practical GTOS Identity (One-Line)

GTOS today is a **deterministic TTL storage chain on DPoS**: signer-aware transactions, bounded node history cost, and storage lifecycle primitives are production-focused; market-layer and SLA-layer features remain roadmap-level.
