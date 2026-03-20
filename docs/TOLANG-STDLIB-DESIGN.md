# TOL Standard Library Design

**Date**: 2026-03-20
**Perspective**: 2046 Architecture — agents as first-class economic actors
**Principle**: Not "security patches for humans" but "economic grammar for agents"

---

## Design Philosophy

The 2046 world has three actors: **agents**, **terminals**, and **policies**.
Agents earn, spend, delegate, and settle. Terminals are untrusted entry
points. Policies are on-chain truth.

A stdlib for this world is not a toolkit of safety guards. It is a
**grammar** — the basic words and sentences that agents use to participate
in economic life. If an agent can't express something trivially, the
language has failed.

### What We Are NOT Building

- Not OpenZeppelin (safety patches for a broken execution model)
- Not a token standard library (tokens are one use case, not the center)
- Not a DeFi primitives kit (DeFi is human-centric financial engineering)

### What We ARE Building

**The economic operating system vocabulary for autonomous agents.**

---

## The Five Domains

An agent's economic life spans five domains. The stdlib provides one package
per domain.

```
stdlib/
├── authority/    — Who can do what, under what constraints
├── settlement/   — How value moves, locks, and finalizes
├── identity/     — Who you are, what you can do, how trustworthy you are
├── evidence/     — How actions become provable and disputable
├── coordination/ — How agents find each other and agree on work
```

---

## 1. `authority/` — Policy as Code

In 2046, authority is not `require(msg.sender == owner)`. Authority is a
**policy object** — a composable set of constraints that travels with the
account, not with the contract.

### Core Types

```tol
// A policy is a set of constraints that gates an action.
struct Policy {
    spend_cap_daily:    u256,
    spend_cap_single:   u256,
    terminal_class:     u8,        // 0=app, 1=card, 2=POS, 3=voice, 4=kiosk, 5=robot, 6=API
    trust_tier_min:     u8,        // 0=untrusted, 1=low, 2=medium, 3=high, 4=full
    allowlist:          agent[],   // permitted counterparties
    delegate_cap:       u256,      // max delegated spend
    delegate_expiry_ms: u256,      // delegation time bound
}

// A guardian is the recovery authority for an account.
struct Guardian {
    address:     agent,
    timelock_ms: u256,    // delay before recovery takes effect
}
```

### Core Functions

```tol
// Check whether an action is permitted under current policy.
function check_policy(actor: agent, action: bytes4, value: u256, terminal: u8, trust: u8) -> bool

// Enforce a spend cap (reverts if exceeded).
function enforce_spend_cap(actor: agent, value: u256)

// Delegate bounded authority to another agent.
function delegate(to: agent, cap: u256, expiry_ms: u256)

// Revoke a delegation immediately.
function revoke(delegate: agent)

// Initiate guardian recovery (starts timelock).
function initiate_recovery(guardian: agent, new_owner: agent)

// Cancel recovery (owner only, before timelock expires).
function cancel_recovery()

// Suspend all operations on an account.
function suspend(account: agent)
```

### Why This Exists

Every contract in 2046 that touches value needs policy enforcement. Without
this package, every contract author re-implements spend caps, allowlists,
and recovery — badly. With it, policy is a one-line import.

---

## 2. `settlement/` — Value Finality

In 2046, payment is not `transfer(to, amount)`. Payment is a **lifecycle**:
intent → escrow → condition → release/slash. The stdlib makes this lifecycle
a grammar, not a state machine.

### Core Types

```tol
// An escrow is a locked value with a condition for release.
struct Escrow {
    id:          bytes32,
    payer:       agent,
    payee:       agent,
    amount:      u256,
    created_ms:  u256,
    deadline_ms: u256,
    status:      u8,      // 0=active, 1=released, 2=slashed, 3=expired, 4=refunded
}

// A recurring schedule.
struct Schedule {
    payee:        agent,
    amount:       u256,
    interval_ms:  u256,
    next_due_ms:  u256,
    remaining:    u256,    // 0 = infinite
}
```

### Core Functions

```tol
// Lock value against identity. Returns escrow ID.
function hold(payee: agent, amount: u256, deadline_ms: u256) -> bytes32

// Release escrowed value to payee. Requires capability or condition met.
function release(escrow_id: bytes32)

// Slash escrowed value (penalty). Routes proceeds per policy.
function slash(escrow_id: bytes32, reason: bytes)

// Refund expired escrow to payer.
function refund(escrow_id: bytes32)

// Create a recurring payment schedule.
function schedule(payee: agent, amount: u256, interval_ms: u256, count: u256) -> bytes32

// Execute the next due payment in a schedule.
function execute_scheduled(schedule_id: bytes32)

// Sponsor-aware value transfer with attribution.
function sponsored_transfer(from: agent, to: agent, amount: u256, sponsor: agent)
```

### Why This Exists

Every agent economy interaction — task completion, oracle resolution,
merchant payment, subscription — follows the escrow lifecycle. Without this
package, every contract re-invents escrow with different bugs. With it,
`hold → release` is a two-line pattern.

---

## 3. `identity/` — Trust Without Acquaintance

In 2046, agents don't know each other personally. They discover each other
by capability, evaluate each other by reputation, and bind each other by
stake. The stdlib makes trust assessment a built-in operation.

### Core Types

```tol
// A capability advertisement.
struct CapabilityAd {
    name:        string,
    version:     string,
    sla_ms:      u256,      // max response time commitment
    fee_tomi:    u256,      // advertised fee
    stake:       u256,      // collateral backing this capability
}

// A rating event.
struct Rating {
    rater:    agent,
    ratee:    agent,
    score:    i8,        // -1, 0, +1
    context:  bytes32,   // escrow/task ID that justifies this rating
}
```

### Core Functions

```tol
// Check if an agent is active and not suspended.
function is_trustworthy(who: agent) -> bool

// Check if an agent has a specific capability registered.
function has_capability(who: agent, cap_name: string) -> bool

// Get an agent's current reputation score.
function reputation_of(who: agent) -> i256

// Submit a rating (must be backed by a settlement context).
function rate(ratee: agent, score: i8, context: bytes32)

// Require minimum stake for an operation.
function require_stake(who: agent, minimum: u256)

// Require minimum reputation for an operation.
function require_reputation(who: agent, minimum: i256)
```

### Why This Exists

Agent discovery and trust assessment is the most common cross-contract
operation in 2046. Without this package, every marketplace re-queries the
registry manually. With it, `require_stake(provider, min)` is one line.

---

## 4. `evidence/` — Actions Become Provable

In 2046, every economic action must be auditable. Not "optional event logs"
but **mandatory proof references**. The stdlib makes evidence production
automatic.

### Core Types

```tol
// A proof reference — a pointer to verifiable evidence.
struct ProofRef {
    proof_type:  string,     // "escrow_receipt", "oracle_resolution", "policy_decision"
    hash:        bytes32,    // content hash of the evidence
    block_num:   u256,
    timestamp_ms: u256,
}

// A disclosure claim for selective privacy verification.
struct DisclosureClaim {
    pubkey:      bytes32,
    commitment:  bytes32,
    handle:      bytes32,
    amount:      u256,
    proof:       bytes,      // 96-byte DLEQ proof
    block_num:   u256,
}
```

### Core Functions

```tol
// Anchor a proof reference on-chain.
function anchor_proof(proof_type: string, evidence_hash: bytes32) -> ProofRef

// Verify a selective disclosure claim.
function verify_disclosure(claim: DisclosureClaim) -> bool

// Emit a structured audit event with proof reference.
function audit_log(action: string, actor: agent, value: u256, proof: ProofRef)

// Create an immutable receipt for a settlement.
function settlement_receipt(escrow_id: bytes32, outcome: u8) -> ProofRef
```

### Why This Exists

In the 2046 world, "trust but verify" is the norm. Every dispute, every
audit, every compliance check needs to trace back to on-chain evidence.
Without this package, proof references are ad-hoc strings. With it,
evidence is structured, hashable, and machine-verifiable.

---

## 5. `coordination/` — Agents Working Together

In 2046, agents don't just transfer value — they **coordinate work**.
Post tasks, resolve oracles, form committees, reach consensus on
observations. The stdlib makes multi-agent coordination a first-class
pattern.

### Core Types

```tol
// A task posted for agent completion.
struct Task {
    id:           bytes32,
    poster:       agent,
    reward:       u256,
    deadline_ms:  u256,
    kind:         string,    // "question", "translation", "observation", "computation"
    spec_hash:    bytes32,   // content-addressed task specification
    status:       u8,        // 0=open, 1=claimed, 2=submitted, 3=approved, 4=disputed
    worker:       agent,
}

// An oracle query awaiting resolution.
struct OracleQuery {
    id:           bytes32,
    requester:    agent,
    question:     bytes,
    bond:         u256,
    deadline_ms:  u256,
    resolved:     bool,
    answer:       bytes,
    resolver:     agent,
}

// A write-once outcome slot.
struct Outcome {
    id:       bytes32,
    value:    bytes,
    is_set:   bool,
    setter:   agent,
    set_at:   u256,
}
```

### Core Functions

```tol
// Post a task with escrow. Returns task ID.
function post_task(kind: string, spec_hash: bytes32, reward: u256, deadline_ms: u256) -> bytes32

// Claim a task (worker declares intent to complete).
function claim_task(task_id: bytes32)

// Submit work for a task.
function submit_work(task_id: bytes32, result_hash: bytes32)

// Approve submitted work and release reward.
function approve_work(task_id: bytes32)

// Dispute submitted work (triggers arbitration).
function dispute_work(task_id: bytes32, reason: bytes)

// Resolve an oracle query (write-once, capability-gated).
function resolve_oracle(query_id: bytes32, answer: bytes)

// Write a value to an outcome slot (write-once guard).
function set_outcome(outcome_id: bytes32, value: bytes)

// Read an outcome (returns nil if not yet set).
function get_outcome(outcome_id: bytes32) -> bytes
```

### Why This Exists

Multi-agent coordination (tasks, oracles, disputes) is the core economic
activity of 2046 — not token transfers. Without this package, every
marketplace implements its own task state machine. With it, the entire
post → claim → submit → approve lifecycle is five function calls.

---

## What's NOT in the Stdlib

These are explicitly **out of scope**:

| Category | Why NOT |
|----------|---------|
| Token standards (TRC20/721) | Tokens are a special case of `settlement/`. The stdlib provides the underlying escrow/release/transfer primitives; token interfaces are application contracts, not stdlib. |
| DEX / AMM primitives | Market-making is an application pattern, not a fundamental agent operation. |
| Governance (voting, proposals) | Governance is an organizational pattern built on `authority/` + `coordination/`. Not a primitive. |
| Upgradeable proxy patterns | TOL contracts are immutable by design. Upgrades happen via lease redeployment, not proxy delegation. |
| SafeMath / overflow guards | TOL's uint256 is native; the compiler handles overflow. No library needed. |
| ReentrancyGuard | TOL's write-once semantics + explicit `set` keyword + `@effects` verification make re-entrancy a compiler concern, not a runtime guard. |

---

## Design Principles

1. **One import, one capability.** `import "stdlib/settlement"` gives you
   escrow. No configuration, no factory pattern, no inheritance chain.

2. **Write-once by default.** Critical state transitions (escrow release,
   oracle resolution, outcome setting) are write-once. The stdlib enforces
   this; the developer doesn't think about it.

3. **Capability-gated, not role-based.** Access control is `@requires(caller: Cap)`,
   not `onlyOwner`. Capabilities are declared in contracts and verified by
   the compiler.

4. **Evidence is automatic.** Every settlement function emits a structured
   proof reference. Audit is not optional.

5. **Terminal-agnostic.** Nothing in the stdlib assumes a browser, a CLI, or
   a specific device. The same contract works across all terminal classes.

6. **Privacy-aware.** Settlement functions work with both public TOS and
   private UNO. Disclosure primitives are in `evidence/`, not bolted on.

7. **Machine-readable.** Every stdlib type has a corresponding ABI
   representation. Discovery agents can inspect contracts without source.

---

## Priority

| Phase | Package | Why First |
|-------|---------|-----------|
| **P0** | `settlement/` | Every agent interaction involves value movement |
| **P0** | `authority/` | Every value movement needs policy enforcement |
| **P1** | `coordination/` | Task markets are the primary agent economy |
| **P1** | `identity/` | Trust assessment enables agent discovery |
| **P2** | `evidence/` | Audit enables dispute resolution at scale |
