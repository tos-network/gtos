# GTOS Agent-Native Oracle Infrastructure Design
## Contract-First Oracle Infrastructure for GTOS and TOL

**Status:** Proposed  
**Target repository:** `gtos`  
**Related repository:** `tolang`  
**Scope:** GTOS runtime, native modules, host primitives, and standard helpers required to support **user-defined oracle protocols** in an **agent-native** execution model.

---

## 1. Purpose

This document defines the **agent-native oracle infrastructure** that GTOS should provide.

It does **not** define a built-in oracle protocol, a built-in oracle committee, or a built-in market settlement engine.

Instead, it defines the reusable technical primitives required so that:

- users deploy their own oracle contracts
- oracle workers are ordinary GTOS Agents
- oracle admission, committee logic, reward policy, slashing policy, and result semantics remain contract-defined
- GTOS provides shared low-level support for:
  - agent identity and capability checks
  - escrow / release / slash
  - scheduled activation hooks
  - canonical oracle result encoding and hashing
  - proof verification hooks
  - future zkTLS / SNARK verifier backends

This is a **contract-first** design.

---

## 2. Why “Agent-Native” Is the Correct Model

GTOS and TOL already position **Agent** as the first-class participant model, not a bolt-on abstraction.

In TOL, `agent` is already treated as a native identity type, capability-gated execution is part of the language surface, and oracle / vote / task are exposed as agent-coordination primitives rather than ad hoc application patterns. The current TOL design includes:

- `agent` as a native identity type
- `capability` declarations and `@requires(caller: X)` capability gating
- `purpose` declarations for contract-local escrow semantics
- `oracle<T>`, `vote<T>`, and `task<T>` primitives
- `@delegated`, `@pay`, and `@verifiable` annotations for agent workflows

Therefore, GTOS should not introduce a second, parallel oracle-native actor model.

The correct architectural stance is:

> **Oracle workers are GTOS Agents.  
> Oracle protocols are user-deployed contracts.  
> GTOS supplies agent-native oracle infrastructure, not a built-in oracle business protocol.**

---

## 3. Non-Goals

This design explicitly does **not** introduce:

- a built-in `OracleHub` settlement protocol
- a built-in query book
- a built-in oracle operator registry distinct from Agents
- a built-in market factory
- a built-in committee registry for all oracle systems
- a built-in reward engine for all oracle systems
- a built-in dispute court for all oracle systems
- a required global oracle storage schema
- a chain-mandated source policy model
- a chain-mandated committee model
- a chain-mandated prediction-market resolution model

All of those remain **contract concerns**.

---

## 4. Design Principles

1. **Agent-first, not oracle-first**  
   Oracle participants are Agents with capability, stake, reputation, and escrow behavior.

2. **Contract-first, not protocol-hardcoded**  
   User contracts define query lifecycle, committees, settlement, reward, and slashing policy.

3. **Reusable infrastructure over product logic**  
   GTOS provides primitives and helpers, not one opinionated oracle business protocol.

4. **Bounded and composable outputs**  
   Oracle results should use canonical bounded result schemas so they can be consumed across contracts.

5. **Verification is modular**  
   Proof hooks and verifier backends should be reusable by any oracle contract that opts into them.

6. **Upgrade path to verifiable AI oracle**  
   The infrastructure should support future authenticated evidence and succinct proof systems without redesigning the contract model.

---

## 5. Core Positioning

### 5.1 What GTOS should be

GTOS should be:

- an agent-native chain
- a contract platform for oracle protocols
- a provider of reusable host primitives and native verifier hooks
- a provider of shared result-format helpers

### 5.2 What user contracts should be

User contracts should define:

- oracle query lifecycle
- operator admission logic
- committee selection
- committee size and threshold
- source policy
- result finalization logic
- challenge logic
- reward split
- slashing policy
- market settlement behavior

### 5.3 What oracle workers should be

Oracle workers should be:

- registered GTOS Agents
- optionally capability-gated
- optionally reputation-weighted
- optionally escrow-bonded
- selected and managed by user contracts, not by GTOS core

---

## 6. Infrastructure Support Matrix

The table below separates what GTOS already provides from what should still be implemented as generic technical support for contract-first oracle systems.

| Capability | Status | Current GTOS / TOL Support | What GTOS should still add |
|---|---|---|---|
| Contract deployment and composition | Available | LVM supports `.tor` package deployment and package-level composition. | No new runtime primitive required. Example oracle packages are optional. |
| Agent identity | Available | GTOS already has agent-native identity infrastructure and TOL already treats `agent` as a native type. | No separate oracle identity model should be added. |
| Capability gating | Available | Capability registry and `tos.hascapability` / `tos.capabilitybit` style logic already fit oracle admission checks. | Optional helper libraries only. |
| Reputation reads | Available | Agent-native reputation already exists and is suitable for contract-defined weighting or filters. | Optional snapshot or weighting helpers only. |
| Contract-local escrow / release / slash | Available / foundational | TOL agent-native design assumes `tos.escrow`, `tos.release`, and `tos.slash` style contract-local escrow primitives. | If any of these are incomplete in runtime, they are high-priority foundational gaps. |
| Scheduled activation / delayed execution | Available | Scheduled task infrastructure already exists and can support keeper-triggered oracle activation. | Optional higher-level oracle keeper helpers only. |
| Canonical oracle result ABI helper | Missing | There is no finalized runtime/library helper yet. | Add canonical encode / decode / hash helpers for bounded oracle results. |
| Generic proof verification hook | Available / foundational | `sysaction.ValidateProofHook` now provides contract-callable proof dispatch with deterministic failure semantics and pluggable verifier registration by proof type or verifier address. | Keep adding concrete verifier backends and conventions. |
| zkTLS / TLSNotary verifier backend | Missing | No verifier backend exists in runtime today. | Add native verifier backend and public-input conventions. |
| SNARK verifier backend | Missing | No general oracle-oriented succinct-proof verifier exists. | Add a generic verifier interface and backend plumbing. |
| Oracle-specific global operator registry | Not needed in GTOS core | Agent registry already exists. | Leave to user contracts if they want local registries. |
| Oracle-specific query/result storage registry | Not needed in GTOS core | Contracts can define their own storage layouts. | Leave to user contracts; only result-format helpers should be standardized. |
| Oracle-specific committee/source-policy registry | Optional only | Contracts can define their own committees and source sets. | Optional ecosystem library or registry later, not core runtime. |

---

## 7. What GTOS Actually Needs to Provide

If GTOS avoids dictating oracle architecture, the runtime deliverables should stay small and generic.

### 7.1 Must-have chain/runtime deliverables

#### A. Agent-native participation support
GTOS must already make it cheap and reliable for contracts to read:

- whether an address is a registered Agent
- whether an Agent is suspended
- Agent stake
- Agent capability bits
- Agent reputation / rating count

These are not oracle-specific; they are agent-native prerequisites.

#### B. Contract-level economic primitives
Oracle contracts need a safe way to manage:

- participant bonds
- query reward pools
- slash reserves
- reward releases
- punitive transfers

These should be implemented as generic contract-local escrow primitives, not oracle-only logic.

#### C. Canonical result helpers
GTOS should provide a standard way to encode, decode, and hash bounded oracle results so that different oracle contracts can emit interoperable outputs.

#### D. Generic proof verification hook
GTOS now provides a generic host hook surface via `sysaction.ValidateProofHook`, including built-in hash-based modes and pluggable verifier dispatch for future authenticated-evidence or succinct-proof backends.

#### E. Verifier backends
GTOS should later add native backends for:

- authenticated source proofs (zkTLS / TLSNotary class)
- succinct aggregation proofs (SNARK family)

### 7.2 Optional but not required for v1

- shared committee-root registries
- shared verifier-key metadata registries
- source-policy template registries
- oracle package templates
- ecosystem-level helper contracts

These are useful later, but they should not be prerequisites for the first infrastructure release.

---

## 8. Infrastructure Layers

This design intentionally separates the stack into four layers.

### Layer 0 — Existing Agent-Native Base
Provided by GTOS / TOL:

- agent identity
- capability model
- delegation model
- reputation model
- scheduled tasks
- contract-local escrow semantics
- package deployment and composition

### Layer 1 — Oracle Result Standardization
Provided by GTOS as a helper layer:

- bounded oracle result types
- canonical result header and body
- canonical hashing rules
- optional decode helpers for contract consumption

### Layer 2 — Generic Verification Plumbing
Provided by GTOS as runtime support:

- `verifyproof`-style host hook
- verifier dispatch by proof mode / verifier type / key ID
- deterministic failure semantics

### Layer 3 — User-Deployed Oracle Protocols
Provided by contract developers:

- query objects
- operator sets
- admission rules
- committee logic
- thresholds
- source policy
- finalization logic
- reward/slash distribution
- challenge logic

This is where prediction-market oracles, task oracles, event oracles, and scalar oracles actually live.

---

## 9. Standard Oracle Result ABI

GTOS should standardize result formatting without standardizing oracle governance.

### 9.1 Result families

Recommended bounded result families:

```text
RESULT_TYPE_BINARY = 1
RESULT_TYPE_ENUM   = 2
RESULT_TYPE_SCALAR = 3
RESULT_TYPE_RANGE  = 4
RESULT_TYPE_STATUS = 5
```

Recommended status values:

```text
STATUS_PENDING       = 0
STATUS_FINAL         = 1
STATUS_INVALID       = 2
STATUS_UNRESOLVABLE  = 3
STATUS_DISPUTED      = 4
STATUS_REVERTED      = 5
```

### 9.2 Common header

```text
OracleResultHeader {
  uint8   version
  bytes32 query_id
  bytes32 market_id
  uint8   result_type
  uint8   status
  uint8   proof_mode
  uint64  finalized_at
  uint16  confidence_bps
  bytes32 policy_hash
  bytes32 evidence_root
  bytes32 source_proofs_root
}
```

### 9.3 Type-specific result bodies

#### Binary

```text
BinaryResultBody {
  uint8 outcome
  uint8 invalid
}
```

#### Enum

```text
EnumResultBody {
  uint32 enum_index
  uint8  invalid
}
```

#### Scalar

```text
ScalarResultBody {
  int128 value_int
  uint8  decimals
}
```

#### Range

```text
RangeResultBody {
  uint32 bucket_index
  int128 raw_value_int
  uint8  decimals
}
```

#### Status

```text
StatusResultBody {
  uint8  status_code
  uint32 reason_code
}
```

### 9.4 Canonical hash rule

```text
canonical_result_hash = H(header || type_specific_body)
```

Where `H = keccak256`.

### Important boundary
This ABI standard does **not** imply:

- a built-in query lifecycle
- a built-in operator model
- a built-in reward model

It only standardizes how results are represented and compared.

---

## 10. GTOS Host and Library Surface

GTOS should distinguish clearly between:

- **standard-library helpers**
- **generic host primitives**
- **native verifier backends**

### 10.1 Standard-library helpers
These should live in shared contract/runtime libraries, not necessarily in core consensus logic.

Recommended helpers:

- `oracle_hash_header(header) -> bytes32`
- `oracle_hash_binary(header, body) -> bytes32`
- `oracle_hash_enum(header, body) -> bytes32`
- `oracle_hash_scalar(header, body) -> bytes32`
- `oracle_hash_range(header, body) -> bytes32`
- `oracle_hash_status(header, body) -> bytes32`

Optional decode helpers:

- `oracle_decode_binary(bytes) -> BinaryResultBody`
- `oracle_decode_enum(bytes) -> EnumResultBody`
- `oracle_decode_scalar(bytes) -> ScalarResultBody`
- `oracle_decode_range(bytes) -> RangeResultBody`
- `oracle_decode_status(bytes) -> StatusResultBody`

### 10.2 Generic host primitives
GTOS should expose or retain generic host primitives useful to oracle contracts:

- `tos.agentload(...)`
- `tos.hascapability(...)`
- `tos.capabilitybit(...)`
- `tos.taskinfo(...)`
- `tos.escrow(...)`
- `tos.release(...)`
- `tos.slash(...)`

### Note
GTOS should **not** add highly opinionated oracle business reads such as:

- `tos.oracleresult(...)`
- `tos.oracleoperator(...)`

unless GTOS later explicitly chooses to define a common oracle-contract profile. In this design, those are intentionally omitted from core runtime because they would implicitly define a chain-level oracle storage model.

### 10.3 Generic proof verification hook
Current implementation shape:

```text
ValidateProofHook(
  proof_type,
  proof_data,
  expected_root,
  verifier_address
) -> bool | error
```

Conceptual contract-facing host hook:

```text
tos.verifyproof(
  verifier_type,
  verifier_key_id,
  public_inputs_hash,
  proof_blob_hash
) -> bool
```

This is not oracle-specific. It is a reusable verification gateway.

### 10.4 Native verifier backends
Later GTOS runtime additions may route from `tos.verifyproof(...)` to:

- zkTLS / TLSNotary verifier backend
- SNARK verifier backend
- future proof systems

---

## 11. Oracle Contracts in the Agent-Native Model

In this model, a user-deployed oracle contract should do its own work.

Typical contract responsibilities:

### 11.1 Admission
Define which Agents may participate:

- registered only
- non-suspended only
- minimum stake threshold
- required capability bit
- optional reputation threshold

### 11.2 Bonding
Require participants to lock value using contract-local escrow.

### 11.3 Query lifecycle
Define:

- query creation
- activation timing
- observation windows
- close conditions
- finalize conditions

### 11.4 Committee / threshold logic
Define:

- open reporter set
- fixed committee
- weighted committee
- simple M-of-N
- stake-weighted or reputation-weighted logic

### 11.5 Proof mode logic
Define whether a query needs:

- no proof
- evidence digest only
- authenticated evidence
- succinct committee proof

### 11.6 Reward and slash rules
Define:

- who gets paid
- who gets refunded
- who gets slashed
- who receives slashed funds

### 11.7 Settlement output
Emit or store final bounded oracle results in canonical result ABI form.

---

## 12. TOL Contract Profile for Oracle Builders

Because TOL is already agent-native, the recommended contract surface for oracle builders should look like this.

### 12.1 Recommended TOL features to use

- `agent` type for worker identity
- `capability X;` declarations for admission categories
- `purpose X;` declarations for escrow buckets
- `oracle<T>` for simple write-once result slots when appropriate
- `task<T>` for oracle workflow / job state machines
- `@requires(caller: X)` for capability-gated actions
- `@delegated` when delegated oracle calls are allowed
- `@verifiable` for result accessors intended for off-chain proof systems

### 12.2 Recommended minimal oracle contract shape

A standard oracle contract profile may include functions like:

```text
createQuery(...)
commitResult(...)
revealResult(...)
submitProof(...)
finalize(...)
getFinalResult(...)
```

GTOS does **not** need to hardcode these names or semantics in consensus.  
They are only a recommended developer profile.

---

## 13. Verification Roadmap

This design supports a staged rollout.

### Phase 1 — Agent-native contract oracle infrastructure
Ship:

- agent-native reads
- escrow/release/slash
- canonical oracle result ABI helper
- optional example oracle package

No built-in oracle protocol.

### Phase 2 — Generic proof verification hook
Shipped foundation:

- contract-callable proof verification interface
- deterministic verifier dispatch API
- failure semantics

### Phase 3 — Authenticated evidence backend
Ship:

- zkTLS / TLSNotary-class source-auth verifier backend
- public-input conventions for authenticated external sources

### Phase 4 — Succinct committee-proof backend
Ship:

- SNARK verifier backend
- committee agreement proof support
- proof-binding to canonical oracle result hashes

### Important boundary
Even in Phase 4, GTOS is still providing infrastructure, not mandating one oracle protocol. User contracts remain in control.

---

## 14. Security and Responsibility Boundaries

### 14.1 What GTOS guarantees
GTOS guarantees only what its primitives guarantee:

- correct Agent state reads
- correct capability checks
- correct escrow/release/slash semantics
- correct canonical result hashing
- correct proof-hook dispatch
- correct verifier backend execution

### 14.2 What user contracts guarantee
User contracts must guarantee:

- safe oracle workflow logic
- committee safety
- threshold correctness
- reward/slash correctness
- challenge correctness
- source-policy correctness
- admission correctness

### 14.3 What this avoids
This separation avoids a major design trap:

> GTOS does not need to decide how all oracle systems should behave.

It only needs to supply enough trustworthy machinery that users can build oracle systems safely.

---

## 15. Recommended GTOS Deliverables

To keep scope disciplined, the first concrete GTOS deliverables should be:

### Deliver now
1. finalize / expose agent-native reads and contract escrow semantics
2. implement canonical `OracleResult` helper library
3. document a standard bounded result ABI
4. optionally publish a sample oracle contract package

### Deliver next
5. implement generic proof-verification hook
6. define verifier type / key ID conventions

### Deliver later
7. implement zkTLS / TLSNotary verifier backend
8. implement SNARK verifier backend

### Do not hardcode in GTOS core
- oracle committees
- oracle operator registry
- oracle query books
- oracle reward engines
- oracle market settlement logic
- oracle challenge courts

---

## 16. Summary

GTOS should not ship a built-in oracle business protocol.

Because GTOS and TOL are already **agent-native by design**, oracle participation should be modeled as **Agent work**, not as a new parallel actor system. TOL already reflects this by treating `agent` as a native identity type and by exposing `oracle`, `vote`, and `task` as agent-coordination primitives.

Therefore the right design is:

- **GTOS provides agent-native oracle infrastructure**
- **users deploy oracle protocols as contracts**
- **oracle workers are GTOS Agents**
- **bounded result formats are standardized**
- **proof verification is modular**
- **committee and settlement policy remain contract-defined**

That gives GTOS a clean path from:

- simple contract oracles today  
to
- authenticated-evidence contract oracles  
to
- verifiable AI oracle contracts

without forcing one oracle architecture on every application.
