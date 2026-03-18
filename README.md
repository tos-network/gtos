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

TOS builds privacy in at the base layer through **Priv** — encrypted balances on-chain, no bridges, no L2.

- Twisted ElGamal ciphertexts on Ristretto255 — balance is hidden from everyone except the owner
- Zero-knowledge proofs (Bulletproof range proofs, Schnorr sigma protocols) verify every transfer without revealing amounts
- `PRIV_TRANSFER`: confidential transfer between two ElGamal accounts with chain-bound proofs
- Proofs are committed to chain ID, sender, receiver, nonce, and fee — preventing cross-chain and replay attacks
- Decrypt your own balance locally with `priv_personalBalance` — private key never leaves your machine

Privacy extends beyond settlement into intent, routing metadata, and coordination patterns. The next generation of decentralized systems requires not merely private transactions, but a **privacy-ready application architecture** at every layer.

---

## Infrastructure

The agent economy runs on foundational layers.

### Speed

- `360ms` target block interval, DPoS consensus
- Parallel transaction execution — independent txs run concurrently within each block via DAG scheduling
- Validator sealing signer: `ed25519` only
- Validator ops:
  - template-driven validator services via `gtos-validator@.service`
  - separate RPC role via `gtos-rpc@.service`
  - native validator monitor flags:
    - `--monitor.doublesign`
    - `--monitor.maliciousvote`
    - `--monitor.journal-dir`
    - `--vote-journal-path`
    - `gtos vote export-evidence`
    - `gtos vote stage-evidence`
    - `gtos vote submit-evidence`
    - maintenance governance ladder via `validator_guard.sh` incidents and alerts
  - operator watchdog tooling with `validator_guard.sh`
    and `validator_guard_report.sh`
  - authoritative operator status with `gtos_chain_status.sh`
  - validator guard alert fan-out:
    - local journals
    - optional webhook delivery
    - optional SMTP email delivery
- Agent wallets support: `secp256k1`, `schnorr`, `secp256r1`, `ed25519`, `bls12-381`, `elgamal`

### Privacy

Priv encrypted balances — see above.

### System Contracts

The protocol-level agent economy is anchored by system contracts at reserved addresses in `params/tos_params.go`:

| Contract | Address | Package |
|----------|---------|---------|
| Policy Wallet Registry | `0x...010C` | `policywallet/` |
| Audit Receipt Registry | `0x...010D` | `auditreceipt/` |
| Gateway Registry | `0x...010E` | `gateway/` |
| Settlement Registry | `0x...010F` | `settlement/` |

These contracts are not deployed by users — they exist at genesis and are updated through governance. The shared boundary schema (`boundary/`) defines the canonical types (IntentEnvelope, PlanRecord, ApprovalRecord, ExecutionReceipt, terminal classes, trust tiers, agent roles) that all system contracts consume.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  Agent Economy Layer                 │
│   Task Market · Receipts · Reputation · Policy Wallets│
│   Gateway Relay · Settlement Callbacks · Audit Proofs │
└──────────────────────────┬───────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────┐
│                    TOS Node (gtos)                   │
│                                                      │
│  ┌──────────┐   ┌────────────┐   ┌───────────────┐  │
│  │   DPoS   │   │    Priv    │   │ System Actions│  │
│  │  360ms   │   │  Privacy   │   │Kyc/Agent/TNS/ │  │
│  │Consensus │   │   Layer    │   │   Referral    │  │
│  └──────────┘   └────────────┘   └───────────────┘  │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │    Policy Wallet · Audit Receipt · Gateway   │    │
│  │    Settlement · Boundary Schemas             │    │
│  └──────────────────────────────────────────────┘    │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │          Parallel Tx Executor (DAG)          │    │
│  └──────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

---

## Policy-Bound Accounts

Traditional wallets hold keys. Policy-bound accounts hold **rules**. The `policywallet/` package implements on-chain policy wallets at `PolicyWalletRegistryAddress` (`0x...010C`) with the following enforcement primitives:

- **Spend caps** — daily and per-transaction limits (`SpendCaps.DailyLimit`, `SpendCaps.SingleTxLimit`) enforced at the protocol level, not by application-layer guards.
- **Allowlists** — restrict outbound transfers to a pre-approved set of destination addresses. Any transfer to a non-allowlisted address reverts.
- **Terminal-class restrictions** — per-terminal spending policies (`TerminalPolicy`) set independent value ceilings and minimum trust tiers for each channel (app, card, POS, voice, kiosk, robot, API).
- **Guardian recovery** — a designated guardian address can initiate account recovery with a timelock of ~24 hours (`RecoveryTimelockBlocks = 240_000` blocks). The owner can cancel during the timelock window.
- **Suspension** — guardians can freeze a wallet immediately; the owner or guardian can unfreeze it.
- **Delegated agent authority** — authorize other addresses (agents, assistants, bots) to spend from the account up to a capped allowance with an expiry block (`DelegateAuth`). Revocation is instant.

The authority to spend lives in the policy-bound account, not in the device or terminal that initiates the transaction. This means the same account can be accessed from a mobile app, a contactless card, a voice assistant, or an autonomous agent — each governed by the same on-chain rules.

---

## Multi-Terminal Access

A single policy-bound account can be reached from multiple entry points — each classified by terminal type and assigned a trust tier:

| Terminal Class | Constant | Example |
|---------------|----------|---------|
| App | `TerminalApp` | Mobile wallet, browser extension |
| Card | `TerminalCard` | Contactless NFC card |
| POS | `TerminalPOS` | Merchant point-of-sale device |
| Voice | `TerminalVoice` | Voice assistant, phone IVR |
| Kiosk | `TerminalKiosk` | Self-service kiosk |
| Robot | `TerminalRobot` | Autonomous delivery robot, drone |
| API | `TerminalAPI` | Server-to-server integration |

Each terminal class carries its own `TerminalPolicy` — a maximum single-transaction value, a maximum daily value, a minimum trust tier (from `TrustUntrusted` through `TrustFull`), and an enabled flag. A voice terminal might be limited to small recurring payments at `TrustMedium`, while an API terminal used by a treasury agent might operate at `TrustFull` with higher limits.

Trust tiers (`boundary.TrustTier`) and terminal classes (`boundary.TerminalClass`) are defined in the `boundary/` package and referenced across all system contracts. Agent roles — requester, actor, provider, sponsor, signer, gateway, oracle, counterparty, guardian — are similarly defined as shared boundary types.

---

## Verifiable Audit Trail

Every sponsored transaction, policy decision, and settlement outcome produces a verifiable, machine-readable audit record. The `auditreceipt/` package at `AuditReceiptRegistryAddress` (`0x...010D`) provides:

- **AuditReceipt** — extends chain transaction receipts with intent-to-receipt traceability. Each receipt links back to the originating `IntentID`, `PlanID`, and `ApprovalID`, and records the sponsor, actor agent, signer type, policy hash, terminal class, trust tier, artifact reference, and effects hash.
- **PolicyDecisionRecord** — captures why a policy accepted or rejected an action: which spend cap was consumed, how much remains, which terminal class and trust tier were in effect, and whether a delegate was acting.
- **SponsorAttribution** — records sponsor details (address, signer type, nonce, expiry, policy hash, gas sponsored) for any transaction where a third party pays gas on behalf of the user or agent.
- **SettlementTrace** — links a transaction to its settlement outcome: value transferred, success or failure, contract address, artifact reference, and log count.
- **SessionProof** — captures terminal session evidence (session ID, terminal class, terminal ID, trust tier, account address, timestamps) with a deterministic `ProofHash` computed over the session fields. Session proofs are stored on-chain and can be read back via `ReadSessionProof`.
- **ProofReference** — a pointer to verifiable evidence of type `tx_receipt`, `policy_decision`, `sponsor_auth`, or `settlement_anchor`, each with a hash, block number, index, and optional off-chain URI.

These records are designed for machine consumption. An auditing agent can reconstruct the full lifecycle of any transaction — from intent through policy evaluation, sponsorship, execution, settlement, and receipt — without relying on off-chain logs or trust assumptions.

---

## Gateway Relay

Gateway relay is a **first-class protocol capability**, not off-band infrastructure. Agents with the `GatewayRelay` capability can relay requests on behalf of other agents — providing signer, paymaster, oracle, and other relay services directly within the protocol layer.

The `gateway/` package at `GatewayRegistryAddress` (`0x...010E`) implements:

- **On-chain registration** — an agent registers as a gateway via `GATEWAY_REGISTER`, declaring its endpoint, supported relay kinds (`signer`, `paymaster`, `oracle`, etc.), maximum relay gas budget, and fee policy (`free`, `fixed`, or `percent`).
- **Discovery** — other agents can query the gateway registry to find active gateways by supported kind and fee policy, enabling automated relay selection.
- **Update and deregistration** — gateways can update their configuration or deregister via `GATEWAY_UPDATE` and `GATEWAY_DEREGISTER`.

This design allows agents behind NAT, on mobile devices, or in constrained environments to participate fully in the agent economy by routing through registered gateways. The gateway itself is an accountable on-chain entity — its relay behavior is auditable and its fee policy is transparent.

---

## Settlement Callbacks

Settlement on TOS is composable. The `settlement/` package at `SettlementRegistryAddress` (`0x...010F`) provides a callback and async fulfillment system that integrates with policy wallets and audit receipts:

- **Callback registration** — after initiating a transaction, a contract or agent registers a `SettlementCallback` with a callback type (`on_settle`, `on_fail`, `on_timeout`, `on_refund`), a target address, a gas budget, a policy hash, and a TTL in blocks.
- **Callback execution** — when the triggering condition is met, the callback fires against the target address with the registered gas budget. The callback is policy-checked and produces an audit receipt.
- **Async fulfillment** — for multi-step settlement flows (e.g., an oracle resolves a prediction market, which triggers payout distribution), `AsyncFulfillment` records link the original transaction to the fulfillment result, fulfiller address, and receipt reference.
- **Lifecycle tracking** — callbacks move through `pending`, `executed`, `expired`, and `failed` states. TTL is bounded by `MaxTTLBlocks` (1,000,000 blocks, approximately 4 days at 360ms intervals).

This enables patterns such as: escrow a payment, register an `on_settle` callback that releases funds to a worker and an `on_fail` callback that refunds the requester — all enforced at the protocol level with full auditability.

---

## Quick Start

```bash
# Build
go build ./cmd/gtos

# Start a node
gtos --datadir /data/tos --networkid 1666 console

# Check your private balance (private key stays local)
> personal.privBalance("0x<your-address>", "your-password")
```

---

## License

TOS is a mixed-license codebase derived in part from go-ethereum.

- Default project license: **GNU LGPL-3.0** (`LICENSE`)
- GPL-covered command/app code under `cmd/`: **GNU GPL-3.0** (`COPYING`)
- Third-party embedded components keep their own licenses in subdirectories

See `LICENSES.md` for directory-level mapping and precedence.
See `NOTICE` for attribution.
