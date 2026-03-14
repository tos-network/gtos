# Lease Contract Design

## Status

Proposed.

## 1. Overview

This document proposes an explicit **lease contract** mode for `gtos`.

The current contract model is simple:

- `To == nil` deploys a contract through the standard CREATE path
- deployed code is permanent
- contract-owned state is permanent unless explicitly overwritten or cleared

This matches the usual EVM expectation, but it also means abandoned contracts
continue to occupy state indefinitely.

The proposal does **not** introduce TTL on individual storage slots. Instead, it
adds a second deployment mode:

- `permanent contract` — the default, unchanged behavior
- `lease contract` — an explicit contract instance with an expiry block and a
  renewal path

If a lease contract is not renewed and moves past its final expiry window, the
chain may prune:

- the contract code for that address
- the contract account's own storage trie
- the contract account object itself, subject to tombstone rules

This design preserves compatibility for existing contracts while creating a
protocol-native path for reclaimable application state.

## 2. Goals

The design goals are:

1. Reduce long-term state growth caused by abandoned short-lived contracts.
2. Preserve the current default contract semantics for existing applications.
3. Keep the transaction model close to the current `gtos` CREATE/CALL flow.
4. Make expiry and pruning deterministic at the protocol level.
5. Avoid per-slot TTL complexity in the state database and execution engine.

## 3. Non-Goals

This proposal does not attempt to:

1. Add TTL to individual storage keys.
2. Automatically prune arbitrary state in other contracts that merely reference
   an expired contract address.
3. Change the default semantics of ordinary contract deployment.
4. Make expiry depend on wall-clock time.

## 4. Why Instance-Level Lease Instead of Slot-Level TTL

Per-slot TTL creates significant complexity:

- every read path needs expiry-aware behavior
- every write path must define renewal semantics per key
- state iteration and pruning become more fragmented
- contract behavior becomes harder to reason about

By contrast, an instance-level lease keeps the model simple:

- the contract instance has one lease policy
- the contract is either active, frozen, expired, or prunable
- the contract's own storage can be reclaimed as one unit

This is a better fit for `gtos`, which currently has a straightforward CREATE
path and stores contract code directly at the deployed address.

## 5. Design Summary

The proposal adds an explicit lease mode to contract deployment.

### 5.1 Deployment Modes

- `leaseBlocks == 0` means the contract is permanent
- `leaseBlocks > 0` means the contract is a lease contract

The lease is attached to the **contract address instance**, not to the code
hash. Two contracts deployed from identical code are still separate lease
objects with separate expiry and renewal history.

### 5.2 Core Rule

The lease controls the lifetime of:

- the code stored at the contract address
- the contract account's own storage trie

It does **not** imply that all state elsewhere in the system that mentions this
address can be pruned.

## 6. Integration with the Current Transaction Flow

`gtos` already routes transactions as follows:

- `To == nil` -> CREATE
- `To != nil` -> CALL or native/system path

The lease design should integrate into this existing model rather than create a
parallel deployment transaction family.

### 6.1 CREATE Path

Lease metadata is only relevant for contract creation.

The proposed transaction model extends the current native transaction envelope
with optional CREATE-only lease fields:

```go
type SignerTx struct {
    ChainID    *big.Int
    Nonce      uint64
    Gas        uint64
    To         *common.Address
    Value      *big.Int
    Data       []byte
    AccessList AccessList

    From       common.Address
    SignerType string

    LeaseBlocks uint64
    LeaseOwner  common.Address

    Sponsor           common.Address
    SponsorSignerType string
    SponsorNonce      uint64
    SponsorExpiry     uint64
    SponsorPolicyHash common.Hash

    V *big.Int
    R *big.Int
    S *big.Int

    SponsorV *big.Int
    SponsorR *big.Int
    SponsorS *big.Int
}
```

Semantics:

- `To != nil`
  - `LeaseBlocks` must be `0`
- `To == nil && LeaseBlocks == 0`
  - deploy a permanent contract
- `To == nil && LeaseBlocks > 0`
  - deploy a lease contract
- `LeaseOwner == zero`
  - default to `From`

This keeps the current CREATE path intact while making lease deployment an
explicit opt-in behavior.

### 6.2 CALL Path

The CALL path remains unchanged structurally, but it becomes lease-aware.

Before executing contract code, the runtime checks the contract instance's lease
metadata:

- active -> execute normally
- grace/frozen -> reject ordinary execution
- expired -> reject ordinary execution

Ordinary contract calls must not be the mechanism for renewal, because once the
contract is expired or frozen the chain should not rely on the contract's own
code remaining callable.

### 6.3 Renewal Path

Renewal should be a native protocol action, not a contract method.

Recommended path:

- add a system action such as `LEASE_RENEW`
- route it through the existing native/system execution path

This has several advantages:

- renewal remains possible even when the contract itself is frozen
- authorization is simple and explicit
- gas accounting is deterministic
- no special-case "call expired contract to renew itself" rule is needed

## 7. Contract Lease State Model

Each lease contract instance needs a small piece of protocol metadata.

Recommended per-contract fields:

```go
type ContractLeaseMeta struct {
    Mode             uint8          // 0 = permanent, 1 = lease
    LeaseOwner       common.Address
    CreatedAtBlock   uint64
    ExpireAtBlock    uint64
    GraceUntilBlock  uint64
    Status           uint8          // active, frozen, expired, prunable
}
```

This metadata should be keyed by the deployed contract address.

Important rule:

- lease metadata is bound to the contract address, not the code hash

## 8. Lifecycle

The lifecycle should be explicit and deterministic.

### 8.1 States

1. `Active`
2. `Frozen`
3. `Expired`
4. `Prunable`

### 8.2 State Transitions

#### Active

The contract behaves like a normal contract.

- code execution is allowed
- state reads and writes are allowed
- lease renewal is allowed

#### Frozen

The contract has reached `ExpireAtBlock` but is still inside a grace window.

- ordinary calls are rejected
- lease renewal is allowed
- pruning is not allowed yet

This gives the owner a recovery window without requiring the chain to keep the
contract active indefinitely.

#### Expired

The grace window has ended.

- ordinary calls are rejected
- renewal may still be allowed if policy chooses to support late recovery
- pruning is still delayed until finalization and prune lag conditions are met

#### Prunable

The contract is now eligible for physical removal from the live state.

- code may be deleted
- the contract storage trie may be deleted
- the account object may be removed or replaced by a tombstone

## 9. Pruning Semantics

The pruning boundary must be narrow and precise.

What the chain may prune for a lease contract:

- code at the contract address
- storage trie owned by the contract address
- the contract account object, subject to tombstone policy

What the chain must **not** assume it can prune:

- balances or records in other contracts that refer to the expired address
- approvals, permissions, or registry entries stored elsewhere
- application-level references outside the contract's own state

This means the protocol can reclaim the contract's own footprint, but it cannot
magically remove all consequences of that contract having existed.

## 10. Tombstones and Address Reuse

Blindly deleting the contract and allowing unrestricted address reuse is risky.

Example risks:

- an old external registry still points to that address
- a new deployment later reuses the same address with different logic
- external observers treat the address as continuous identity when it is not

The recommended design is to keep a small tombstone record after pruning.

Recommended tombstone properties:

- marks the address as a previously expired lease contract
- records a minimal digest of the last contract identity
- blocks unsafe reuse by default

Safer policy options:

1. never allow reuse of a pruned lease address
2. allow reuse only under a strict recovery rule controlled by `LeaseOwner`
3. allow reuse only with the same code hash and same owner

The conservative default is option 1.

## 11. Determinism and Time Base

Expiry must be based on **block height** or another consensus-native monotonic
measure, not wall-clock time.

Recommended rule:

- `ExpireAtBlock = createBlock + leaseBlocks`

Reasons:

- fully deterministic across nodes
- no local clock dependence
- easy to test and audit
- simple to reason about in reorg handling

## 12. Finality and Safe Pruning

Logical expiry and physical pruning should be separate.

Recommended rule:

- logical freeze at `ExpireAtBlock`
- logical expiry at `GraceUntilBlock`
- physical pruning only after the expiry point is finalized and a prune lag has
  passed

For example:

```text
create at block B
expire at block E = B + leaseBlocks
grace ends at block G = E + graceBlocks
prune eligibility at block P = finalized_after(G) + pruneLagBlocks
```

The exact constants are chain-policy parameters, but the sequencing matters:

1. stop ordinary execution first
2. wait through grace
3. wait through finality and lag
4. prune asynchronously

## 13. Economics

The design only works if lease contracts are economically attractive for the
right workloads.

If a lease contract is strictly more dangerous and offers no benefit, rational
users will simply keep deploying permanent contracts.

### 13.1 Required Economic Difference

Lease contracts should provide at least one of the following:

1. lower initial deployment cost
2. lower storage deposit requirement
3. recoverable deposit on early close
4. better quota treatment for short-lived workloads

### 13.2 Recommended Positioning

- permanent contracts pay for stable, long-term availability
- lease contracts pay for lower long-term state commitment

This makes the two modes useful for different application classes instead of
turning lease mode into a purely punitive feature.

## 14. Why Developers Would Use Lease Contracts

Developers will choose lease contracts when the application is naturally
short-lived and does not need perpetual availability.

Good candidates:

- per-order or per-auction contracts
- short-lived escrow contracts
- temporary agent sessions
- RFQ or intent settlement contracts
- challenge games and dispute windows
- campaign or event contracts
- ephemeral oracle aggregation contracts

Poor candidates:

- asset contracts
- registries
- governance contracts
- identity contracts
- account abstraction wallets
- long-lived protocol infrastructure

In short:

- if the contract is infrastructure, use permanent
- if the contract is a bounded-duration execution surface, lease is a strong fit

## 15. Authorization Model for Renewal

Renewal must have a clear owner.

Recommended default:

- `LeaseOwner` is set at deployment
- if omitted, it defaults to `From`
- only `LeaseOwner` may renew or recover the contract

Possible future extensions:

- multi-sig renewal authority
- governance-managed renewal
- delegated renewal rights

The base design should start with a single explicit owner.

## 16. Recommended Native Actions

The protocol should support native actions for lease lifecycle management.

Recommended initial set:

- `LEASE_RENEW(address, deltaBlocks)`
- `LEASE_CLOSE(address)`
- `LEASE_GET(address)` via RPC

Optional later additions:

- `LEASE_RECOVER(address, deltaBlocks)` if late recovery is allowed
- `LEASE_TRANSFER_OWNER(address, newOwner)`

`LEASE_CLOSE` is useful when the owner wants immediate shutdown and possibly a
partial deposit refund without waiting for passive expiry.

## 17. Compatibility with Existing GTOS Semantics

This design is intentionally conservative.

It preserves the current default model:

- normal CREATE remains permanent
- ordinary CALL behavior stays the same for permanent contracts
- no existing contract is forced into a lease

This matters because `gtos` currently documents permanent code lifetime in its
Lua VM integration flow. Lease contracts should therefore be introduced as a new
explicit capability, not as a silent change to default contract behavior.

## 18. Recommended Implementation Shape in GTOS

At a high level, implementation should be split into four parts.

### 18.1 Transaction Envelope

Extend the existing native transaction envelope with:

- `LeaseBlocks`
- `LeaseOwner`

These fields are consensus fields because CREATE behavior depends on them.

### 18.2 State Transition

In the CREATE branch:

- if `LeaseBlocks == 0`, deploy as permanent
- if `LeaseBlocks > 0`, deploy as lease and write lease metadata

In the CALL branch:

- check lease status before executing destination code

### 18.3 Native Lease Handler

Add a native/system execution path for:

- renew
- close
- optional recover

### 18.4 Background Pruner

Maintain a deterministic queue or bucketed index of expiry points.

The actual prune worker should:

1. scan only contracts whose prune point has been reached
2. enforce a bounded per-block or per-run budget
3. emit auditable logs and metrics

Pruning should never require a full-state scan.

## 19. Key Safety Invariants

The design should preserve the following invariants:

1. A lease is attached to a contract address instance, never to a code hash.
2. Expiry is determined by consensus state, not local clocks.
3. Ordinary execution stops before physical pruning begins.
4. Expired contracts are not renewed by executing their own code.
5. Pruning removes only the contract's own footprint, not arbitrary external
   references.
6. Address reuse after pruning is restricted by tombstone policy.

## 20. Open Policy Choices

Several policy values remain chain-governance decisions:

- minimum and maximum `leaseBlocks`
- grace window length
- prune lag after finality
- pricing or deposit schedule
- whether late recovery is allowed
- whether tombstoned addresses may ever be reused

These are implementation and governance choices, but they do not change the
core structure of the design.

## 21. Recommendation

Adopt lease contracts as an explicit second deployment mode in `gtos`.

Do not add default TTL to ordinary contracts.

Do not add per-slot TTL.

Do:

- keep permanent contracts as the default
- add CREATE-time lease metadata
- use native renewal actions
- enforce a frozen/expired/prunable lifecycle
- prune only contract-owned code and storage
- preserve safety with tombstones and finality-aware pruning

This gives `gtos` a practical state-reclamation mechanism without breaking the
current mental model of permanent smart contracts.
