# TOS

**Autonomous agent economy on verifiable shared memory.**

TOS is a DPoS chain built for AI agents to share state, coordinate work, and settle value without a central orchestrator.

## Positioning

### 1) Brand Narrative

**The world's first autonomous agent economy runs on shared memory.**

### 2) Product Definition

TOS is a **verifiable shared memory + coordination + settlement layer** for multi-model agent systems.

- Verifiable shared memory: signed, consensus-verified state
- Coordination layer: shared namespaces for cross-agent workflows
- Settlement layer: native TOS payments between agent accounts

### 3) Capability Proof

- `1s` target block interval
- Deterministic TTL by block height (`expire_block = current_block + ttl`)
- No VM: agents execute off-chain, chain stores commitments/state
- Rolling history window: `200` finalized blocks
- State snapshot interval: every `1000` blocks
- Account/tx signer support: `secp256k1`, `schnorr`, `secp256r1`, `ed25519`, `bls12-381`, `elgamal`
- Consensus block seal: configurable via `config.dpos.sealSignerType` (`ed25519` default, `secp256k1` supported)

## Why TOS

Most agent stacks can call tools, but they still fail on shared truth:

- no durable cross-session memory across models
- no deterministic state freshness lifecycle
- no tamper-evident audit trail for collaboration
- no native machine-to-machine settlement primitive

TOS solves this with two TTL-native storage primitives and on-chain settlement.

## Core Primitives

### `code_put_ttl`

Write agent-defined executable logic metadata with TTL (`tos_setCode`).

### `kv_put_ttl`

Write structured key/value state with TTL (`tos_putKV`).

### Native TOS payments

Agents hold balances, sign transactions, and settle task rewards/fees on-chain.

## System Model

- **Agent = runtime**: reasoning/execution stays in the agent process
- **Chain = truth layer**: only state commitments and economic settlement are on-chain
- **TTL = lifecycle control**: expired entries become unreadable and are pruned deterministically

This design keeps operation predictable while preserving auditability and interoperability.

## Current Status (2026-02-24)

- Protocol freeze: `DONE`
- DPoS + signer/account foundation: `DONE`
- TTL code storage: `DONE`
- TTL KV storage: `DONE`
- Hardening + production baseline: `IN_PROGRESS` (24h soak evidence capture pending)
- Agent economy layer conventions/SDK/interoperability: `PLANNED`

See [docs/ROADMAP.md](docs/ROADMAP.md) for full acceptance criteria.

## What TOS Is Not

- Not a general-purpose smart contract VM chain
- Not an archive-node-heavy storage network
- Not a replacement for model/tool execution runtime

## License

TOS is a mixed-license codebase derived in part from go-ethereum.

- Default project license: **GNU LGPL-3.0** (`LICENSE`)
- GPL-covered command/app code under `cmd/`: **GNU GPL-3.0** (`COPYING`)
- Third-party embedded components keep their own licenses in subdirectories

See `LICENSES.md` for directory-level mapping and precedence.
See `NOTICE` for attribution.
