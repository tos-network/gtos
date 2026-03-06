# TOS Network

**The economic settlement and coordination layer for an AI-driven digital economy.**

The next phase of the internet economy will not be defined solely by human users. Autonomous AI agents — capable of performing tasks, making decisions, and transacting on behalf of individuals and organizations — need infrastructure that allows them to hold assets, make payments, establish trust, preserve privacy, and coordinate economic activity at scale. TOS Network is built to be that foundation.

---

## Why TOS

Ethereum generalized computation. TOS generalizes **economic agency**.

AI agents can generate intelligence and perform work, but they lack native mechanisms for economic coordination. They cannot independently settle obligations, escrow funds, price risk, or build portable reputation without a trusted system of rules. A decentralized network with programmable contracts, cryptographic assurances, and machine-readable economic logic enables AI agents to interact in a trust-minimized environment. That network is TOS.

Openness at the application layer must not come at the expense of base-layer guarantees. **Censorship resistance, open-source verifiability, privacy, and security** are not optional design preferences — they are the institutional foundations that allow autonomous systems, developers, and users to trust the network over time.

---

## The Agent Economy

Six patterns are emerging as the structural primitives of machine-native commerce:

**Agent-to-agent hiring.** An AI trading agent hires a prediction agent for market analysis, which in turn employs data-scraping agents for structured information. Payments, deposits, performance guarantees, and penalties for non-performance are enforced automatically on-chain.

**Machine-to-machine micropayments.** Autonomous software continuously requires APIs, datasets, models, storage, and compute. Agents pay fractions of a cent per query, inference, or computation — a fluid market for digital services, no human intervention required.

**Collateralized trust.** Agents interacting with one another require economic guarantees. Collateral deposited on-chain can be automatically released, slashed, or redirected upon specified outcomes — aligning incentives across an automated ecosystem at scale.

**Identity and reputation.** Agents must have verifiable identities, machine-readable capabilities, and trackable performance histories. On-chain reputation lets agents assess counterparty reliability before engaging economically. Delegated authority models keep humans and institutions in ultimate control over machine actors.

**AI as user interface.** Rather than interacting directly with wallets and isolated apps, individuals delegate to AI assistants that analyze contracts, manage portfolios, source liquidity, negotiate services, and execute transactions — verifying the safety of each action. The old model of siloed browser-extension wallets gives way to a coordination layer where users express intent and agents determine execution.

**Governance coordination.** In decentralized organizations, human attention is scarce. AI assistants analyze proposals, summarize debate, simulate downstream outcomes, and recommend or execute governance actions under constrained delegation — making large-scale governance more legible and operationally effective.

---

## Privacy as a First-Class Property

Privacy should not be treated as a narrow payment feature or an optional overlay. A network designed for autonomous commerce cannot assume that every balance, relationship, strategy, or coordination pattern should be publicly visible by default.

TOS builds privacy in at the base layer through **UNO** — encrypted balances on-chain, no bridges, no L2.

- Twisted ElGamal ciphertexts on Ristretto255 — balance is hidden from everyone except the owner
- Zero-knowledge proofs (Schnorr sigma protocols) verify every transfer without revealing amounts
- Three operations: `UNO_SHIELD` (public → private), `UNO_TRANSFER` (private → private), `UNO_UNSHIELD` (private → public)
- Chain-bound proofs committed to chain ID, sender, receiver, and nonce — replay attacks are impossible
- Decrypt your own balance locally with `personal_unoBalance` — private key never leaves your machine

Privacy extends beyond settlement into intent, routing metadata, and coordination patterns. The next generation of decentralized systems requires not merely private transactions, but a **privacy-ready application architecture** at every layer.

---

## Infrastructure

The agent economy runs on three foundational layers.

### Speed

- `360ms` target block interval, DPoS consensus
- Parallel transaction execution — independent txs run concurrently within each block via DAG scheduling
- Configurable validator signer: `ed25519` (default), `secp256k1`
- Agent wallets support: `secp256k1`, `schnorr`, `secp256r1`, `ed25519`, `bls12-381`, `elgamal`

### Privacy

UNO encrypted balances — see above.


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
│  │  360ms   │   │  Privacy   │   │Kyc/Agent/TNS/ │  │
│  │Consensus │   │   Layer    │   │   Referral    │  │
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
