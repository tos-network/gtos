# TOS

**The first blockchain to unify speed, privacy, and agent-native economics.**

TOS is a DPoS chain where 360ms blocks, built-in encrypted balances, and on-chain logic are the infrastructure — built to carry the world's first general-purpose agent labor market.

---

## Vision

Ethereum generalized computation. TOS generalizes **economic agency**.

The next generation of AI agents needs more than a fast ledger. They need a chain where:

- **Work is verifiable** — agents submit cryptographic receipts for completed tasks (AGIW: Proof-of-Intelligent-Work), verified by TEE attestations and randomized spot-checks, settling per outcome not per call
- **Reputation is on-chain** — an append-only, stake-weighted reputation graph reduces counterparty risk and speeds market clearing across agent-to-agent transactions
- **Value is measured in real scarcity** — Compute Credits (CC) and Energy Credits (EC) are native ledger assets, not ERC-20 wrappers; fees and treasury policy are anchored to GPU-minute and kWh indices
- **Compliance is built in** — Safety Oracle + Account Abstraction policy wallets enforce rate limits, allow/deny lists, and region rules at validation time, without centralization
- **Identity is first-class** — native DID, key rotation, and attribute attestations make autonomous agents provable, accountable, and integrable

> TOS is not "a faster EVM." It is the first chain that turns agent work, reputation, and energy use into a measurable, settleable, and governable economic substrate.

---

## Infrastructure

The agent economy runs on three foundational layers:

### Speed

- `360ms` target block interval, DPoS consensus
- Parallel transaction execution — independent txs run concurrently within each block via DAG scheduling
- Rolling `200`-block finalized history window — nodes stay lean
- Configurable seal signer: `ed25519` (default), `secp256k1`

### Privacy (UNO)

UNO is TOS's native privacy layer — encrypted balances on the base chain, no bridges, no L2. Agent payments and task settlements can be fully private.

- Twisted ElGamal ciphertexts on Ristretto255 — balance is hidden from everyone except the owner
- Zero-knowledge proofs (Schnorr sigma protocols) verify every transfer without revealing amounts
- Three operations: `UNO_SHIELD` (public → private), `UNO_TRANSFER` (private → private), `UNO_UNSHIELD` (private → public)
- Decrypt your own balance locally with `personal_unoBalance` — private key never leaves your machine
- Chain-bound proofs: every proof is committed to chain ID, sender, receiver, and nonce — replay attacks are impossible

### Smart Contracts

TOS contracts are native on-chain logic — deterministic, auditable, no Solidity required.

- System actions dispatch to native handlers at fixed addresses — gas-efficient, no VM overhead
- `code_put_ttl`: deploy executable logic metadata with an expiry (`tos_setCode`)
- `kv_put_ttl`: write structured state with TTL (`tos_putKV`) — entries expire automatically
- Multi-signer accounts: `secp256k1`, `schnorr`, `secp256r1`, `ed25519`, `bls12-381`, `elgamal` — one chain for every key type

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  Agent Economy Layer                 │
│   Task Market · AGIW Receipts · Reputation Graph    │
│   CC/EC Settlement · Safety Oracle · Policy Wallets │
└──────────────────────────┬───────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────┐
│                    TOS Node (gtos)                   │
│                                                      │
│  ┌──────────┐   ┌────────────┐   ┌───────────────┐  │
│  │   DPoS   │   │    UNO     │   │ System Actions│  │
│  │  360ms   │   │  Privacy   │   │  (kv / code)  │  │
│  │Consensus │   │   Layer    │   │               │  │
│  └──────────┘   └────────────┘   └───────────────┘  │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │          Parallel Tx Executor (DAG)          │    │
│  └──────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# Build
go build ./cmd/gtos

# Start a node
gtos --datadir /data/tos --networkid 1666 console

# Check your private UNO balance (private key stays local)
> personal.unoBalance("0x<your-address>", "your-password")
```

---

## License

TOS is a mixed-license codebase derived in part from go-ethereum.

- Default project license: **GNU LGPL-3.0** (`LICENSE`)
- GPL-covered command/app code under `cmd/`: **GNU GPL-3.0** (`COPYING`)
- Third-party embedded components keep their own licenses in subdirectories

See `LICENSES.md` for directory-level mapping and precedence.
See `NOTICE` for attribution.
