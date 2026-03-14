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

- ordinary CREATE means the contract is permanent
- `LEASE_DEPLOY` means the contract is a lease contract

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
- `To == SystemActionAddress` -> native/system handler
- other `To` values -> CALL or native special path

The lease design should integrate into this existing model without changing the
native transaction envelope.

### 6.1 Deployment Path

The design should **not** modify `SignerTx`.

Changing the native transaction envelope would force changes across:

- RLP encoding and decoding
- transaction hashing
- signing payloads
- SDK transaction models
- wallet integrations
- historical transaction parsing

That is unnecessary because `gtos` already has a native `sysaction` framework.

Recommended deployment path:

- permanent contracts continue to use ordinary CREATE (`To == nil`)
- lease contracts are deployed through `LEASE_DEPLOY` sent to
  `SystemActionAddress`

The `LEASE_DEPLOY` action payload contains:

```go
type LeaseDeployAction struct {
    Code        []byte
    LeaseBlocks uint64
    LeaseOwner  common.Address
}
```

Semantics:

- `LeaseBlocks > 0` is required
- `LeaseOwner == zero` defaults to `From`
- the handler validates lease limits and pricing
- the handler calls the same lower-level contract creation helper used by
  ordinary CREATE so address derivation and deployment semantics stay aligned

This keeps lease deployment as an explicit opt-in capability while preserving
full backward compatibility for the transaction model.

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

### 6.3 Renewal and Close Path

Renewal should be a native protocol action, not a contract method.

Recommended native actions:

- `LEASE_DEPLOY(code, leaseBlocks, leaseOwner)`
- `LEASE_RENEW(contractAddr, deltaBlocks)`
- `LEASE_CLOSE(contractAddr)`

This has several advantages:

- `SignerTx` and its signing rules remain unchanged
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

### 7.1 Storage Location

All lease state should be stored at a dedicated system address following the
existing registry pattern:

```go
// in params/tos_params.go
LeaseRegistryAddress = common.HexToAddress("0x000000000000000000000000000000000000010B")
```

This address has no deployed code and cannot be called. It is used purely as a
namespace for `StateDB.GetState` / `SetState` operations, consistent with how
`ValidatorRegistryAddress` (`0x03`), `GroupRegistryAddress` (`0x010A`), and
other system registries work.

Storage slot layout:

```text
keccak256(contractAddr, "mode")             → 0 = permanent, 1 = lease
keccak256(contractAddr, "lease_owner")      → LeaseOwner address
keccak256(contractAddr, "created_at_block") → block number at deployment
keccak256(contractAddr, "expire_at_block")  → expiry block
keccak256(contractAddr, "grace_until_block")→ end of grace window
keccak256(contractAddr, "status")           → active / frozen / expired / prunable
keccak256(contractAddr, "deposit_wei")      → locked deposit amount
keccak256(contractAddr, "code_bytes")       → code size (for renewal deposit calc)
```

### 7.2 Expiry Index

In addition, the protocol needs a deterministic expiry index so the consensus
engine can enumerate contracts eligible for pruning at a given epoch boundary
without scanning the full state.

Recommended layout at `LeaseRegistryAddress`:

```text
keccak256("expiry_count", epochNumber)      → number of contracts expiring in this epoch
keccak256("expiry_entry", epochNumber, i)   → i-th contract address expiring in this epoch
keccak256("total_leases")                   → global count of active lease contracts
```

When a lease contract is deployed or renewed, the handler:

1. removes the old expiry entry (if renewing)
2. computes `pruneEpoch = (GraceUntilBlock / DPoSEpochLength) + 1`
3. appends the contract address to that epoch's expiry list
4. increments the epoch's expiry count

At each epoch boundary, the consensus prune step reads `expiry_count` for the
current epoch and iterates exactly that many entries. No full-state scan is
needed.

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

Initial default:

- `graceBlocks = 1 DPoS epoch`
- on current network parameters this is `1664` blocks, approximately `10`
  minutes

#### Expired

The grace window has ended.

- ordinary calls are rejected
- the initial implementation does not allow late recovery
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

The design should therefore keep a small tombstone record after pruning and
adopt a single initial policy:

- **a pruned lease address is never reusable**

Recommended tombstone properties:

- marks the address as a previously expired lease contract
- records a minimal digest of the last contract identity
- permanently blocks address reuse

This is the safest and simplest policy for the first implementation.

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

## 12. Consensus-Level Pruning

Pruning must be a **consensus behavior**, not merely a node-local background
cleanup.

If pruning only deletes local disk data while the expired contract remains in
the live state trie, the chain has not actually reclaimed state. That is not the
goal of this design.

Recommended rule:

- logical freeze at `ExpireAtBlock`
- logical expiry at `GraceUntilBlock`
- consensus pruning at a deterministic block-processing point after the grace
  window

Recommended execution model:

1. maintain a per-block or per-epoch lease expiry index
2. on each epoch boundary, or another deterministic checkpoint, process the set
   of contracts whose prune point has been reached
3. apply pruning inside block execution so all validators produce the same state
   root
4. enforce a bounded pruning budget per block or per epoch sweep

For example:

```text
create at block B
expire at block E = B + leaseBlocks
grace ends at block G = E + graceBlocks
prune on first eligible epoch boundary after G
```

This means two different layers exist:

- consensus pruning
  - removes contract code and contract-owned state from the canonical live state
- local database garbage collection
  - later reclaims orphaned trie nodes or raw database entries from disk

Only the first layer satisfies the protocol objective of state reclamation.

## 13. Economics

The design only works if lease contracts are economically attractive for the
right workloads.

If a lease contract is strictly more dangerous and offers no benefit, rational
users will simply keep deploying permanent contracts.

### 13.1 Baseline Economic Proposal

The first implementation should define a concrete default model:

1. lease deployment code-storage gas surcharge is `50%` of the permanent CREATE
   code-storage surcharge
2. lease deployment also locks a refundable lease deposit
3. renewal charges additional rent proportional to `deltaBlocks`
4. explicit close or passive expiry returns `80%` of the remaining deposit to
   `LeaseOwner`
5. the remaining `20%` is retained by the protocol to fund maintenance and
   cleanup costs

This gives lease contracts a real price advantage while keeping a protocol
budget for long-term housekeeping.

### 13.2 Deposit Calculation

The lease deposit should be proportional to the state footprint and the
requested lifetime:

```
deposit = codeBytes × gasDeployByte × leaseBlocks / referenceBlocks
```

Where:

- `codeBytes` is the size of the deployed `.tor` package in bytes
- `gasDeployByte` is the existing per-byte deployment cost (`200` gas)
- `leaseBlocks` is the requested lease duration
- `referenceBlocks` is a governance parameter representing the reference
  duration (recommended initial value: `1` year of blocks at current block
  interval, approximately `87,600,000` blocks at `360ms`)

This formula ensures that:

- larger contracts pay more deposit (they consume more state)
- longer leases pay more deposit (they occupy state longer)
- very short leases pay very little, which is the intended economic advantage

Renewal deposit for `LEASE_RENEW` uses the same formula with `deltaBlocks`
replacing `leaseBlocks` and the original `codeBytes`.

### 13.3 Positioning

- permanent contracts pay for stable, long-term availability
- lease contracts pay less upfront because they accept bounded lifetime and
  protocol-managed reclamation

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
- only `LeaseOwner` may renew the contract

Possible future extensions:

- multi-sig renewal authority
- governance-managed renewal
- delegated renewal rights

The base design should start with a single explicit owner.

## 16. Recommended Native Actions

The protocol should support native actions for lease lifecycle management.

Recommended initial set:

- `LEASE_DEPLOY(code, leaseBlocks, leaseOwner)`
- `LEASE_RENEW(address, deltaBlocks)`
- `LEASE_CLOSE(address)`
- `LEASE_GET(address)` via RPC

Optional later additions:

- `LEASE_TRANSFER_OWNER(address, newOwner)`

`LEASE_CLOSE` is useful when the owner wants immediate shutdown and a partial
deposit refund without waiting for passive expiry.

## 17. Compatibility with Existing GTOS Semantics

This design is intentionally conservative.

It preserves the current default model:

- normal CREATE remains permanent
- ordinary CALL behavior stays the same for permanent contracts
- no existing contract is forced into a lease
- the native transaction envelope remains unchanged

This matters because `gtos` currently documents permanent code lifetime in its
Lua VM integration flow. Lease contracts should therefore be introduced as a new
explicit capability, not as a silent change to default contract behavior.

## 18. Recommended Implementation Shape in GTOS

At a high level, implementation should be split into five parts.

### 18.1 Lease Registry and Expiry Index

Add dedicated protocol storage for:

- `ContractLeaseMeta`
- a deterministic expiry index keyed by prune eligibility
- tombstone records

### 18.2 Native Lease Handlers

Add native/system execution paths for:

- deploy
- renew
- close

`LEASE_DEPLOY` should call the same lower-level create helper used by ordinary
CREATE so contract creation semantics stay aligned.

### 18.3 State Transition and CALL Gate

In the CALL branch:

- check lease status before executing destination code

Permanent contracts bypass this logic and behave exactly as they do today.

### 18.4 Consensus Prune Step

Add a deterministic prune step to block processing.

Recommended initial trigger:

- process prune-eligible lease contracts at each epoch boundary

The sweep must:

1. read contracts from the expiry index
2. prune the same set on every validator
3. respect a bounded budget
4. write tombstones and update the live state root

### 18.5 Local Database GC

After consensus pruning makes contract state unreachable, ordinary database
cleanup can reclaim orphaned trie nodes and raw database entries.

## 19. Key Safety Invariants

The design should preserve the following invariants:

1. A lease is attached to a contract address instance, never to a code hash.
2. Expiry is determined by consensus state, not local clocks.
3. The native transaction envelope remains unchanged.
4. Ordinary execution stops before physical pruning begins.
5. Expired contracts are not renewed by executing their own code.
6. Pruning is a consensus state transition, not only a node-local cleanup.
7. Pruning removes only the contract's own footprint, not arbitrary external
   references.
8. Address reuse after pruning is permanently blocked.

## 20. Open Policy Choices

Several policy values remain chain-governance decisions:

- minimum and maximum `leaseBlocks`
- the exact rent curve per block or per epoch
- the exact deposit schedule
- the maximum prune budget per epoch sweep
- whether late recovery is allowed in a future revision

These are implementation and governance choices, but they do not change the
core structure of the design.

## 21. Recommendation

Adopt lease contracts as an explicit second deployment mode in `gtos`.

Do not add default TTL to ordinary contracts.

Do not add per-slot TTL.

Do:

- keep permanent contracts as the default
- deploy lease contracts through `LEASE_DEPLOY`
- leave `SignerTx` unchanged
- use native renewal actions
- enforce a frozen/expired/prunable lifecycle
- make pruning a deterministic consensus action
- prune only contract-owned code and storage
- preserve safety with tombstones and permanent address non-reuse

This gives `gtos` a practical state-reclamation mechanism without breaking the
current mental model of permanent smart contracts.
