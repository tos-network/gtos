# GTOS Protocol Registries

**Status: DESIGN READY FOR IMPLEMENTATION**

## Purpose

This document defines the protocol-backed registry layer required to make
Tolang's agent-native semantics enforceable in GTOS.

Tolang can already express:

- `capability`
- `@requires(caller: Cap)`
- `@delegated`
- `@verifiable`
- `@pay`

What is still missing is a canonical GTOS-side registry model that gives these
constructs stable on-chain meaning.

The goal is to move from:

- compiler-declared semantics

to:

- protocol-backed semantics

without turning every capability or policy question into ad hoc app logic.

---

## Problem Statement

Today, several agent-native concepts are only partially grounded:

- capability names may exist in source before the protocol has a stable
  registry entry
- delegation may be represented in app contracts but not in a shared GTOS
  authority model
- verification semantics may be described in metadata without a protocol-side
  verifier registry
- payment/settlement constraints may exist in stdlib contracts without a
  network-wide policy surface
- agent identity may still depend on local conventions rather than a stable
  stateful registry

This creates four concrete risks:

1. the same Tolang annotation can mean different things in different runtimes
2. revocation and versioning are hard to reason about
3. discovery cannot reliably answer "is this authority or verifier real?"
4. GTOS cannot expose a uniform agent-facing inspection surface

---

## Scope

This document defines five protocol registries:

1. `Capability Registry`
2. `Delegation Registry`
3. `Verification Registry`
4. `Settlement / Pay Policy Registry`
5. `Agent Identity Registry`

It also defines:

- GTOS state responsibilities
- sysaction and system-package responsibilities
- LVM native query surface
- RPC and metadata exposure
- implementation phases

---

## Non-goals

This document does not:

- define new Tolang syntax
- replace contract-local policies where local customization is appropriate
- force every business rule into a system registry
- define all verifier cryptography
- define OpenFox UX or routing logic

The target is protocol-grade shared truth for agent-native primitives, not the
removal of application flexibility.

---

## Design Principles

1. **Registry-backed, contract-composable**
   The registry provides canonical truth. Contracts may still add stricter
   local policy.

2. **Names resolve to stable identifiers**
   Capability or verifier names must not be free-floating strings forever.

3. **Revocation is first-class**
   Every registry entry that can authorize behavior must have an explicit
   revocation path.

4. **Inspection matters as much as enforcement**
   Agent runtimes need read APIs and RPC, not only enforcement hooks.

5. **GTOS is the protocol home; Tolang is the expression layer**
   Tolang compiles intent. GTOS registries make that intent real.

---

## Registry Set

### 1. Capability Registry

Purpose:

- map canonical capability names to stable protocol identifiers
- support versioning, activation, deprecation, and revocation
- serve as the protocol source of truth for `tos.capabilitybit(...)` and
  `tos.hascapability(...)`

Minimum entry shape:

```text
CapabilityRecord {
  capability_id: bytes32
  name: string
  bit_index: uint16
  category: uint16
  version: uint32
  status: uint8      // active, deprecated, revoked
  manifest_ref: bytes32
}
```

Required operations:

- register capability
- deprecate capability
- revoke capability
- resolve name -> id
- resolve name -> bit index
- query status/version

GTOS dependencies:

- system package or system contract
- sysaction registration
- `tos.capabilitybit(name)` must read this registry
- `tos.hascapability(agent, cap)` must validate against this registry

### 2. Delegation Registry

Purpose:

- provide a shared protocol model for delegated authority
- support revocable, scoped, time-bounded delegation
- back `@delegated` semantics with shared state

Minimum entry shape:

```text
DelegationRecord {
  delegation_id: bytes32
  principal: address
  delegate: address
  scope_ref: bytes32
  capability_ref: bytes32
  policy_ref: bytes32
  not_before_ms: uint64
  expiry_ms: uint64
  status: uint8      // active, revoked, expired
}
```

Required operations:

- grant delegation
- revoke delegation
- query effective delegation
- enumerate active delegations for principal or delegate

GTOS dependencies:

- system state
- `tos.delegation_active(...)`-style query primitive or equivalent
- RPC for runtime inspection

### 3. Verification Registry

Purpose:

- map verification names or refs to protocol-supported verifier classes
- give `@verifiable` a shared runtime backing

Minimum entry shape:

```text
VerifierRecord {
  verifier_id: bytes32
  name: string
  verifier_type: uint16   // zk, oracle, attestation, receipt, consensus
  verifier_addr: address
  policy_ref: bytes32
  version: uint32
  status: uint8
}
```

Required operations:

- register verifier
- rotate verifier implementation
- deactivate verifier
- query verifier by name/id

GTOS dependencies:

- verifier lookup primitive
- RPC metadata exposure
- optional dispatch hook for native verification classes

### 4. Settlement / Pay Policy Registry

Purpose:

- make `@pay` and settlement-policy semantics protocol-backed
- standardize sponsor/payment/settlement policy references

Minimum entry shape:

```text
SettlementPolicyRecord {
  policy_id: bytes32
  kind: uint16         // sponsor, pay, settlement, relay
  owner: address
  manifest_ref: bytes32
  status: uint8
  rules_ref: bytes32
}
```

Required operations:

- register policy
- activate/deactivate policy
- resolve policy by id
- expose policy class and owner

GTOS dependencies:

- settlement-aware lookup for sponsor/payment flows
- RPC for policy introspection

### 5. Agent Identity Registry

Purpose:

- provide a stable protocol view of agent identity and lifecycle
- normalize principal/operator/terminal-facing identity relationships

Minimum entry shape:

```text
AgentIdentityRecord {
  agent_id: bytes32
  addr: address
  identity_type: uint16    // human wallet, service agent, policy wallet, relay
  principal_ref: bytes32
  metadata_ref: bytes32
  status: uint8
}
```

Required operations:

- register identity
- rotate metadata ref
- suspend / deactivate
- query by address

GTOS dependencies:

- runtime inspection
- discovery join with deployed contracts and package metadata

---

## System Architecture

Recommended GTOS layout:

1. one `registry/` package tree under `gtos`
2. one fixed system address per registry family, or one multiplexed registry
   package with typed namespaces
3. `sysaction` handlers for all writes
4. LVM read primitives for low-latency runtime lookup
5. RPC methods for indexer / OpenFox / operator consumption

Two viable layouts:

### Option A: one package per registry

Pros:

- simpler storage and ownership boundaries
- clearer audit scope

Cons:

- more system contracts and action kinds

### Option B: unified registry hub with typed namespaces

Pros:

- easier shared indexing and RPC
- simpler generic admin tooling

Cons:

- larger audit surface
- more complicated storage isolation

Recommended v1:

- unified registry hub with strongly typed subspaces

---

## State Model

Every registry entry should support:

- deterministic id
- version
- owner / controller
- active / deprecated / revoked lifecycle
- creation and last-update block metadata

Suggested common shape:

```text
RegistryMeta {
  id: bytes32
  owner: address
  version: uint32
  status: uint8
  created_at: uint64
  updated_at: uint64
}
```

Each specific registry record embeds this pattern.

---

## LVM Surface

Minimum LVM query surface to standardize:

- `tos.capabilitybit(name)`
- `tos.hascapability(agent, capability)`
- `tos.getdelegation(principal, delegate, scope_ref)`
- `tos.getverifier(name_or_id)`
- `tos.getpolicy(policy_id)`
- `tos.agentinfo(addr)`

Principles:

- lookup functions must fail closed on missing entries
- returned data must be stable enough for compiler-generated preambles
- no silent fallback to default bits or permissive behavior

---

## RPC Surface

Recommended RPC family:

- `tos_getCapability`
- `tos_getDelegation`
- `tos_getVerifier`
- `tos_getSettlementPolicy`
- `tos_getAgentIdentity`

Batch forms should exist for discovery/indexer use.

The deployed contract metadata RPC should be able to join:

- contract metadata
- package metadata
- registry-backed capability / verifier / policy data

---

## Threat Model

Primary risks:

1. stale registry state causing authorization drift
2. ambiguous capability names across versions
3. revocation not propagating quickly enough to runtime queries
4. verifier spoofing through weak name resolution
5. policy references that exist in metadata but not in registry state

Required mitigations:

- deterministic ids
- explicit status field
- fail-closed missing resolution
- explicit owner/controller
- RPC and runtime return status/version, not only name

---

## Implementation Phases

### Phase 1: Capability Registry

Why first:

- already partially assumed by Tolang runtime semantics
- smallest registry with the highest immediate value

Deliverables:

- state model
- sysactions
- `tos.capabilitybit`
- `tos.hascapability`
- RPC

### Phase 2: Delegation + Verification Registries

Why second:

- these unlock meaningful protocol backing for `@delegated` and
  `@verifiable`

### Phase 3: Settlement / Pay Policy Registry

Why third:

- integrates with sponsor, pay, and settlement policy workflows

### Phase 4: Agent Identity Registry

Why fourth:

- most useful after capability/delegation/policy state already exists

---

## Acceptance Criteria

- capability lookup is registry-backed, not string-convention-backed
- missing registry entries fail closed
- delegation state is queryable from LVM and RPC
- verifier records are protocol-addressable
- settlement/pay policy ids resolve through protocol state
- agent identity is queryable as protocol state
- deployed metadata RPC can join registry-backed protocol facts

---

## Related Documents

- `/home/tomi/tolang/docs/TOLANG_SHORTCOMINGS.md`
- `/home/tomi/tolang/docs/AGENT_NATIVE_STDLIB_2046.md`
- `/home/tomi/tolang/docs/AGENT_ABI_SCHEMA.md`
- `/home/tomi/gtos/docs/Agent-Discovery-v1.md`
- `/home/tomi/gtos/docs/Agent-Gateway-v1.md`
