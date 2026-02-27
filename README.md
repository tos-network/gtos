# TOS

**The first blockchain to unify speed, privacy, and easy smart contracts.**

TOS is a DPoS chain where 360ms blocks, built-in encrypted balances, and on-chain logic live together — no trade-offs, no layer juggling.

---

## The Problem With Every Other Chain

Existing blockchains force you to choose:

- **Fast chains** sacrifice privacy and trust-minimized execution
- **Privacy chains** are slow, complex, and require specialized tooling
- **Smart contract chains** leak every state change to the public and hit throughput walls

TOS is built from the ground up to remove this trade-off.

---

## Speed

- `360ms` target block interval, DPoS consensus
- Parallel transaction execution — independent txs run concurrently within each block
- Rolling `200`-block finalized history window — nodes stay lean
- Configurable seal signer: `ed25519` (default), `secp256k1`

## Privacy

UNO is TOS's native privacy layer — encrypted balances on the base chain, no bridges, no L2.

- Twisted ElGamal ciphertexts on Ristretto255 — balance is hidden from everyone except the owner
- Zero-knowledge proofs (Schnorr sigma protocols) verify every transfer without revealing amounts
- Three operations: `UNO_SHIELD` (public → private), `UNO_TRANSFER` (private → private), `UNO_UNSHIELD` (private → public)
- Decrypt your own balance locally with `personal_unoBalance` — private key never leaves your machine
- Chain-bound proofs: every proof is committed to chain ID, sender, receiver, and nonce — replay attacks are impossible

## Smart Contracts

TOS contracts are first-class on-chain logic — fast to write, cheap to run, no Solidity required.

- System actions dispatch to native handlers at fixed addresses — deterministic, auditable, gas-efficient
- `code_put_ttl`: deploy executable logic metadata with an expiry (`tos_setCode`)
- `kv_put_ttl`: write structured state with TTL (`tos_putKV`) — entries expire automatically, no manual cleanup
- Multi-signer accounts: `secp256k1`, `schnorr`, `secp256r1`, `ed25519`, `bls12-381`, `elgamal` — one chain for every key type

---

## Architecture at a Glance

```
┌─────────────────────────────────────────┐
│               Applications              │
│    (wallets, agents, dapps, scripts)    │
└────────────────────┬────────────────────┘
                     │ JSON-RPC / IPC
┌────────────────────▼────────────────────┐
│              TOS Node (gtos)            │
│                                         │
│  ┌──────────┐  ┌───────┐  ┌─────────┐  │
│  │   DPoS   │  │  UNO  │  │ System  │  │
│  │ 360ms    │  │Privacy│  │ Actions │  │
│  │ Consensus│  │Layer  │  │(kv/code)│  │
│  └──────────┘  └───────┘  └─────────┘  │
│                                         │
│  ┌─────────────────────────────────┐    │
│  │   Parallel Tx Executor (DAG)    │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

---

## Quick Start

```bash
# Build
go build ./cmd/gtos

# Start a node (example)
gtos --datadir /data/tos --networkid 1666 console

# Check your private UNO balance
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
