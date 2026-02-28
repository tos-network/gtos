# TOS as Prediction Market & Task Delegation Infrastructure

## Why prediction markets matter for TOS

A prediction market and a task delegation market share identical primitives:

| Prediction Market | Task Delegation |
|---|---|
| Question + reward locked on-chain | Task + bounty locked on-chain |
| Participants submit answers | Agents submit work |
| Oracle verifies outcome | Verifier checks work quality |
| Winners receive reward | Agent receives bounty |

The infrastructure is the same. Building it once serves both use cases.

---

## Platform Analysis

### Polymarket

**Chain:** Polygon (EVM, ~2s blocks)
**Model:** Hybrid CLOB — off-chain order matching, on-chain settlement via Conditional Token Framework (CTF)
**Resolution:** UMA Optimistic Oracle — anyone proposes outcome, 48h dispute window, $UMA holders vote on disputes
**Settlement token:** USDC
**Position privacy:** None — all balances and trades public on-chain
**Agent access:** REST/WebSocket API, signed EIP-712 orders

**Core pain points:**
- All positions are public — large traders expose strategy
- 48h dispute window creates settlement latency
- UMA oracle is permissioned governance (token holder vote)
- No native agent identity or work-receipt concept

---

### Kalshi

**Chain:** Centralized (CFTC-regulated) + Solana mirror via DFlow
**Model:** Central exchange with FIX protocol, WebSocket streaming
**Resolution:** Predetermined data sources, automatic — no disputes
**Settlement:** USD via ACH/wire; USDC on Solana mirror
**Position privacy:** Centralized — Kalshi holds custody
**Agent access:** FIX protocol + REST API

**Core pain points:**
- Fully centralized custody — trust the operator
- Regulatory jurisdiction limits participation geography
- No on-chain composability
- KYC required — agents cannot participate natively

---

### Drift BET

**Chain:** Solana (~400ms blocks)
**Model:** Off-chain Keeper network + on-chain program; JIT auctions for market orders
**Resolution:** Binary YES/NO markets; oracle TBD per market
**Collateral:** 30+ crypto assets, cross-collateral; yield on positions
**Position privacy:** None — Solana accounts are public
**Agent access:** Drift SDK, program instructions

**Core pain points:**
- Keeper network is semi-permissioned
- No privacy on positions
- Resolution mechanism varies per market — inconsistent
- No native agent identity or task-receipt primitive

---

## Infrastructure Requirements

Below: each primitive needed for a prediction market / task delegation system, with TOS implementation status.

---

### 1. Lock terms and rewards before participation

> The contract conditions and prize pool must be immutable from the moment the market opens.

**Polymarket:** CTF smart contract — audited, but upgradeable by admin key
**Kalshi:** Centralized rule set
**Drift BET:** On-chain program — upgradeable

**TOS implementation:** `code_put_ttl` writes terms as native chain state — no VM, no admin key, no upgrade proxy. Once written, immutable for the TTL duration.

**Status: ✅ Implemented**

---

### 2. Tamper-evident answer / work submission

> Once a participant submits an answer or a work receipt, it must not be modifiable.

**Polymarket:** Outcome token purchase — immutable on-chain buy event
**Drift BET:** On-chain position — immutable
**Kalshi:** Centralized order log

**TOS current state:** `kv_put_ttl` writes to sender's own address. Key = arbitrary bytes, Value = answer/commitment.

**Gap 1:** Value is currently overwritable (upsert semantics). Needs write-once enforcement.
**Gap 2:** Answers are written to the sender's own namespace. For a shared prediction, answers need to be written into the market creator's namespace, with cryptographic proof that the writer owns the key they're submitting under.

**Status: 🔶 Partial — write-once and cross-namespace submission not yet implemented**

---

### 3. Private positions

> Participants should not be able to see each other's answers or stake sizes before the reveal phase, preventing copy-trading and answer manipulation.

**Polymarket:** ❌ All positions public
**Kalshi:** Centralized opacity (trust operator)
**Drift BET:** ❌ All positions public

**TOS implementation:** UNO — Twisted ElGamal encrypted balances on base layer. Stake amounts hidden. Reveal phase uses UNO_UNSHIELD.

**Status: ✅ Implemented (UNO)**

---

### 4. Commit-reveal scheme

> Standard two-phase pattern: commit `hash(answer + salt)` in the open phase; reveal `answer + salt` after deadline. Prevents late-movers from copying.

**Polymarket:** Not used — uses token purchase model instead
**Drift BET:** Not used
**Kalshi:** Not applicable (centralized)

**TOS design:** Phase 1: `kv_put_ttl(key=pubkey, value=hash(answer||salt))` into market namespace. Phase 2: `kv_put_ttl(key=pubkey||":reveal", value=answer||salt)`. Both writes are immutable. Chain verifies hash consistency at reward distribution.

**Status: 🔴 Not implemented — requires cross-namespace write + hash verification at distribution**

---

### 5. Oracle / outcome resolution

> After the event, an authoritative source determines the correct answer. This result triggers reward distribution.

**Polymarket:** UMA Optimistic Oracle (optimistic proposal + 48h dispute window + $UMA governance vote)
**Kalshi:** Predetermined data feeds, automatic
**Drift BET:** Per-market oracle, varies

**TOS:** No oracle primitive exists. Options:
- **Centralized:** Market creator writes outcome via `code_put_ttl` — simple but trusted
- **Optimistic:** Anyone proposes, dispute window, validator vote — requires new sysaction
- **Agent-based:** AGIW receipts from multiple independent agents — decentralized verification

**Status: 🔴 Not implemented — this is the most critical missing piece**

---

### 6. Reward distribution after resolution

> Once outcome is known, winners receive their share of the prize pool automatically.

**Polymarket:** CTF contract — winning tokens redeem 1:1 for USDC
**Kalshi:** Automatic by exchange
**Drift BET:** On-chain program execution

**TOS:** No automatic distribution primitive. Current TOS transfers are point-to-point. A distribution sysaction would need to: read the resolution from chain state, iterate over winning submissions, calculate pro-rata shares, and emit transfers.

**Status: 🔴 Not implemented**

---

### 7. Fast finality for agent micro-settlements

> Agents need sub-second certainty that their submission was accepted. Slow chains make agent-to-agent micro-tasks economically unviable.

**Polymarket:** ~2s (Polygon) — acceptable for human markets, slow for agents
**Kalshi:** Sub-second (centralized)
**Drift BET:** ~400ms (Solana)

**TOS:** 360ms DPoS blocks + parallel execution. Competitive with Drift BET, faster than Polymarket.

**Status: ✅ Implemented**

---

### 8. Agent native identity

> Agents must be able to participate without human intermediaries: hold balances, sign transactions, prove identity.

**Polymarket:** EIP-712 signed orders — compatible with agent wallets
**Kalshi:** KYC required — agents cannot participate natively
**Drift BET:** Drift SDK — compatible with programmatic agents

**TOS:** Native DID anchor via account signer model. Supports `secp256k1`, `ed25519`, `bls12-381`, `elgamal` — agent wallets can use any key type. No KYC gate on-chain.

**Status: ✅ Implemented (account signer model)**

---

### 9. Work receipt (AGIW) — task delegation specific

> For task markets, agents need to submit a verifiable receipt: "I completed this task, here is the proof." This receipt must be independently verifiable, not just self-reported.

**Polymarket / Kalshi / Drift:** N/A — these are prediction markets, not task markets

**TOS design:** AGIW (Proof-of-Intelligent-Work) — agent submits `kv_put_ttl(key=taskId, value=receipt_hash)` + optional TEE attestation or spot-check proof. Verifiers check the receipt against the task spec written by `code_put_ttl`.

**Status: 🔴 Not implemented — AGIW receipt format and verification primitives are whitepaper-stage**

---

### 10. Reputation graph

> Over time, agents and market creators should accumulate a track record: prediction accuracy, task completion rate, dispute history. This reduces counterparty risk and speeds market clearing.

**Polymarket:** Off-chain leaderboards only
**Kalshi:** Centralized reputation
**Drift BET:** None

**TOS design:** Append-only on-chain reputation via `kv_put_ttl` events: `(owner=agent, namespace="reputation", key=marketId, value=outcome_record)`. Indexed off-chain for querying.

**Status: 🔴 Not implemented — data model defined in whitepaper, no on-chain primitive yet**

---

## Summary Table

| # | Primitive | Status | Notes |
|---|-----------|--------|-------|
| 1 | Immutable market terms (code_put_ttl) | ✅ Done | Deployed |
| 2 | Tamper-evident answer submission (kv_put_ttl) | 🔶 Partial | Write-once + cross-namespace missing |
| 3 | Private positions (UNO) | ✅ Done | Deployed |
| 4 | Commit-reveal scheme | 🔴 Missing | Needs cross-namespace write + hash verify |
| 5 | Oracle / outcome resolution | 🔴 Missing | Most critical gap |
| 6 | Automatic reward distribution | 🔴 Missing | Needs distribution sysaction |
| 7 | Fast finality (360ms) | ✅ Done | Deployed |
| 8 | Agent native identity | ✅ Done | Multi-signer account model |
| 9 | Work receipt (AGIW) | 🔴 Missing | Whitepaper-stage |
| 10 | Reputation graph | 🔴 Missing | Data model defined, not implemented |

---

## Implementation Priority

**Phase 1 — Make existing primitives correct (kv_put_ttl)**
- Write-once enforcement: reject overwrite of active (non-expired) records
- Cross-namespace submission: allow writing into another address's namespace with signature proof

**Phase 2 — Oracle resolution**
- Simple: market creator writes outcome (`code_put_ttl` update or dedicated sysaction)
- Optimistic: propose + dispute window + validator vote (mirrors UMA model, on-chain)

**Phase 3 — Reward distribution**
- Distribution sysaction: reads resolution, iterates winning keys, emits native TOS transfers

**Phase 4 — AGIW + Reputation**
- Work receipt format standardization
- Reputation accumulation primitives

---

## Key Differentiator vs. Polymarket / Drift BET

Every existing prediction market exposes positions publicly. This is not a minor UX issue — it is a structural flaw that prevents institutional and agent participation at scale.

TOS is the only chain where:
- Terms are locked before participation (immutable by design, not by audit)
- Positions are encrypted at the base layer (UNO, not an optional L2)
- Agent identity is native (no KYC gate, multi-key-type support)
- Settlement is fast enough for agent micro-tasks (360ms)

The missing pieces (oracle, distribution, AGIW) are protocol-layer work, not application-layer workarounds.
