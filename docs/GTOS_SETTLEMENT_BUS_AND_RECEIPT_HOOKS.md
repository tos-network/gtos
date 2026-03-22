# GTOS Settlement Bus And Receipt Hooks

**Status: V1.1 IMPLEMENTED (2026-03-22)**

Implemented in code today:

- runtime receipt hooks:
  `tos.receipt_open(...)`, `tos.receipt_success(...)`,
  `tos.receipt_failure(...)`, `tos.receipt_info(...)`
- runtime settlement hooks:
  `tos.settle(...)`, `tos.settle_refund(...)`,
  `tos.settle_escrow(...)`, `tos.settlement_info(...)`
- state-backed `RuntimeReceipt` and `SettlementEffect` records in `settlement/`
- `PublicSettlementAPI.GetRuntimeReceipt(...)` and
  `GetSettlementEffect(...)`
- client/runtime consumption layers:
  - Go `tosclient.GetRuntimeReceipt(...)` / `GetSettlementEffect(...)`
  - Go `gtosclient.GetRuntimeReceiptSurface(...)` /
    `GetSettlementEffectSurface(...)`
  - TypeScript `inspectRuntimeReceipt(...)` / `inspectSettlementEffect(...)`
  - OpenFox runtime/operator consumption via
    `openfox settlement runtime-receipt ...`,
    `openfox settlement runtime-effect ...`, and matching operator API
    endpoints
- sponsor-aware settlement joins through runtime receipt/effect state plus
  client/runtime inspection
- `ESCROW_RELEASE_UNO` settlement mode and confidential escrow-release
  normalization through the same settlement-bus lifecycle
- OpenFox local settlement records now bridge onto canonical runtime
  `receipt_ref` / `settlement_ref` values when those refs are available
- VM/runtime tests for:
  - public transfer + auto-finalized receipt
  - split-phase settle + `receipt_success`
  - rollback on missing/open receipt precondition failure
  - escrow release settlement
  - UNO settlement

Still open for later waves:

- deciding which flows should mirror runtime receipts into app-level
  `ReceiptBook` by default

This document defines the next GTOS-owned protocol/runtime wave after:

- registry-backed capability / delegation / verification / pay-policy state
- package publishing trust
- explicit UNO runtime contract
- escrow / release rollback semantics

What remains is a protocol-native settlement surface that makes value movement,
receipt generation, and proof anchoring behave as one coherent runtime system
instead of loosely coordinated contract calls.

---

## Purpose

GTOS already has:

- value transfer primitives
- escrow / release primitives
- receipt-oriented application contracts
- sponsor and settlement-oriented openlib flows

What it does not yet have is a canonical runtime bus for:

- moving value
- binding that movement to a receipt
- exposing stable proof / trace anchors
- preserving atomicity under nested and composed execution

This document defines that bus.

---

## Problem Statement

Today, settlement-shaped flows are assembled from multiple pieces:

- `tos.transfer(...)`
- `tos.uno_transfer(...)`
- `tos.escrow(...)`
- `tos.release(...)`
- contract-local `ReceiptBook.openReceipt(...)`
- contract-local `ReceiptBook.finalizeSuccess(...)`
- contract-local `ReceiptBook.finalizeFailure(...)`

That already works for first-wave openlib, but it leaves four structural gaps:

1. settlement is composed by convention, not by one protocol-native runtime path
2. receipt linkage depends on each coordinator or contract family doing the same thing
3. public-value and UNO-value paths do not yet share one canonical settlement model
4. agent runtimes cannot ask GTOS for one normalized "what value moved, under what receipt, with what proof anchor?" view

This is acceptable for a first openlib closure wave.
It is not strong enough for a production-grade agent economy.

---

## Scope

This document defines:

1. a protocol-native `settlement bus`
2. runtime receipt hooks
3. atomicity / rollback rules
4. proof / trace anchor rules
5. public-value and UNO-value rail unification
6. phased rollout

It does **not** redefine:

- Tolang syntax
- openlib business logic
- selective disclosure cryptography
- discovery schema

It defines GTOS/LVM runtime semantics only.

---

## Design Principles

1. **Settlement is one runtime concept**
   Public-value transfer, confidential transfer, escrow release, sponsor payout,
   and refund should all map onto one canonical execution model.

2. **Receipts are protocol objects, not optional side effects**
   A commercial flow should not rely on ad hoc event conventions to prove that
   settlement happened.

3. **Atomicity beats convenience**
   If receipt finalization fails, the value movement must not half-commit.
   If value movement fails, receipt state must not lie.

4. **Rails differ; settlement shape should not**
   Public TOS value and UNO confidential value have different payloads, but the
   settlement lifecycle should still expose one stable machine-readable shape.

5. **Contracts may specialize policy; GTOS owns canonical settlement effects**
   Application contracts can decide *whether* to settle. GTOS should define
   *how* settlement effects and receipt hooks behave once invoked.

---

## Core Runtime Surface

Suggested canonical host surface:

```text
tos.settle(mode, recipient, amount_or_ciphertext, receipt_ref, opts?)
tos.settle_escrow(mode, beneficiary, amount_or_ciphertext, receipt_ref, opts?)
tos.settle_refund(mode, refundee, amount_or_ciphertext, receipt_ref, opts?)
tos.receipt_open(receipt_ref, kind, opts?)
tos.receipt_success(receipt_ref, settlement_ref, proof_ref, opts?)
tos.receipt_failure(receipt_ref, failure_ref, proof_ref, opts?)
tos.receipt_info(receipt_ref)
tos.settlement_info(settlement_ref)
```

The final spellings can change, but the model should preserve:

- one canonical settlement entrypoint
- one canonical receipt finalization surface
- read APIs for runtime inspection

---

## Settlement Modes

The bus should support at least these modes:

1. `PUBLIC_TRANSFER`
   Plain TOS/native balance transfer.

2. `UNO_TRANSFER`
   Confidential ciphertext transfer to native encrypted balance.

3. `ESCROW_RELEASE_PUBLIC`
   Release from contract-local escrow ledger into public balance.

4. `ESCROW_RELEASE_UNO`
   Release from contract-local escrow ledger into UNO/confidential rail.

5. `REFUND_PUBLIC`
   Public-value refund path.

6. `REFUND_UNO`
   Confidential refund path.

The bus must expose the same machine-readable settlement result regardless of
which mode is used.

---

## Receipt Model

Settlement bus hooks should not replace application-level receipt contracts.
They should provide a protocol-grade receipt backbone that application receipts
can either use directly or mirror.

Minimum runtime receipt shape:

```text
RuntimeReceipt {
  receipt_ref: bytes32
  receipt_kind: uint16
  status: uint8              // open, success, failure
  mode: uint16               // public, uno, escrow-release, refund, sponsor...
  sender: address
  recipient: address
  sponsor: address?
  amount_ref: bytes32        // amount hash or ciphertext hash
  settlement_ref: bytes32
  proof_ref: bytes32
  policy_ref: bytes32
  artifact_ref: bytes32
  opened_at: uint64
  finalized_at: uint64
}
```

This runtime receipt can be:

- directly exposed through RPC
- joined into deployed metadata views
- mirrored into `ReceiptBook`
- used by OpenFox and other agent runtimes as the canonical chain-facing anchor

---

## Runtime Hook Semantics

### 1. `tos.receipt_open(...)`

Purpose:

- reserve a canonical receipt identity before value movement
- make the intended settlement visible to downstream runtime logic

Required semantics:

- duplicate open must fail closed
- open does not imply success
- open must be rollback-safe

### 2. `tos.receipt_success(...)`

Purpose:

- finalize the receipt after value movement or escrow release succeeds

Required semantics:

- terminal
- idempotence rules must be explicit
- if this fails, the enclosing settlement operation must revert

### 3. `tos.receipt_failure(...)`

Purpose:

- finalize a receipt on failure/cancellation/dispute loss/refund completion

Required semantics:

- terminal
- binds failure reason or failure reference
- must not leave the receipt in an ambiguous state

---

## Atomicity And Rollback

The bus must define one strict rule:

> A settlement effect and its receipt finalization belong to the same atomic
> execution boundary unless the caller explicitly chooses a split-phase model.

Default required behavior:

1. if value movement fails, receipt finalization does not persist
2. if receipt finalization fails, value movement does not persist
3. if nested execution reverts, both value and receipt effects revert
4. if `tos.multicall` reverts, both value and receipt effects revert

This applies to:

- `tos.transfer(...)`
- `tos.uno_transfer(...)`
- `tos.release(...)`
- any future `tos.settle(...)` surface

---

## Split-Phase Model

Some workflows intentionally separate:

- receipt open
- off-chain evidence / approval
- final settlement

For those cases, GTOS should allow:

1. `open`
2. `finalize success`
3. `finalize failure`

but it must still guarantee:

- success/failure finalization is terminal
- a receipt cannot be both successful and failed
- settlement references and proof references become immutable once finalized

---

## Public Rail vs UNO Rail

The public and confidential rails differ in what the payload means:

- public rail payload = exact visible amount
- UNO rail payload = ciphertext

But the settlement bus should normalize these fields:

```text
SettlementEffect {
  mode: uint16
  sender: address
  recipient: address
  visible_amount: uint256?
  ciphertext_hash: bytes32?
  receipt_ref: bytes32
  proof_ref: bytes32
  settlement_ref: bytes32
}
```

For `UNO_TRANSFER`, the runtime should:

- preserve fail-closed address validation
- preserve rollback on top-level revert and nested revert
- expose ciphertext hash or commitment hash as the settlement-side amount anchor
- expose optional disclosure/proof references where higher-level flows attach them

---

## Sponsor And Escrow Integration

The settlement bus must also cover sponsor-aware and escrow-aware flows.

Required cases:

1. sponsor pays gas / relay costs, user receives service outcome
2. escrow releases to provider after approval
3. dispute resolution refunds payer
4. slash splits across worker/poster/arbitrator or policy-defined sinks

Required runtime-visible fields:

- `payer`
- `sponsor`
- `beneficiary`
- `escrow_contract`
- `policy_ref`
- `receipt_ref`
- `proof_ref`

Without this, receipt semantics remain app-specific instead of protocol-grade.

---

## Proof And Trace Anchors

Every settlement effect should be able to attach:

- `receipt_ref`
- `proof_ref`
- `policy_ref`
- `artifact_ref`
- `binding_ref`

Not all must be non-empty on every path.
But the shape must be stable so agent runtimes can reason uniformly across:

- sponsor relay
- settlement
- dispute resolution
- confidential disclosure-aware flows

---

## RPC / Inspection Surface

Required RPCs or RPC-visible joins:

- `GetRuntimeReceipt(receipt_ref)`
- `GetSettlementEffect(settlement_ref)`
- deployed contract metadata joins latest runtime receipt/settlement refs when applicable
- future routing/discovery joins can reference receipt mode and settlement mode

Required LVM inspection:

- `tos.receipt_info(receipt_ref)`
- `tos.settlement_info(settlement_ref)`

These should be protocol-backed facts, not best-effort event scraping.

---

## Relation To Existing Contracts

This design does not obsolete:

- `ReceiptBook`
- `TaskSettlement`
- `ConfidentialEscrow`
- `SponsorPolicyRelay`

Instead, it gives them a stronger substrate.

Recommended migration model:

1. first support optional use of runtime receipt hooks under openlib contracts
2. then mirror runtime receipts into `ReceiptBook`
3. later decide which flows should rely on runtime receipt hooks directly and which should keep app-level receipts as the primary object

---

## Implementation Phases

### Phase 1: runtime receipt info surface

Deliverables:

- protocol receipt state model
- `tos.receipt_open/success/failure`
- `tos.receipt_info`
- rollback tests for receipt finalization failure

### Phase 2: public settlement bus

Deliverables:

- `tos.settle(...)` for public-value path
- receipt-bound atomic transfer
- sponsor-aware fields where available

### Phase 3: UNO settlement bus

Deliverables:

- `tos.settle(...)` or equivalent for UNO rail
- ciphertext hash / commitment anchor in settlement effect
- disclosure/proof anchor integration expectations

### Phase 4: escrow and refund unification

Deliverables:

- escrow release / refund through the same settlement bus
- slash distribution integration
- dispute resolution integration

### Phase 5: RPC and OpenFox-facing consumption

Deliverables:

- stable RPCs
- metadata joins
- routing/discovery references where appropriate

---

## Acceptance Criteria

- a settlement effect and receipt finalization are atomic by default
- runtime receipts are queryable as protocol-backed facts
- public and UNO rails share one normalized settlement shape
- nested-call and `tos.multicall` rollback semantics cover settlement + receipt together
- sponsor, escrow, refund, and slash paths expose stable trace anchors
- openlib settlement families can adopt the bus without losing existing business flexibility

---

## Related Documents

- `/home/tomi/gtos/docs/LVM_NATIVE_ECONOMIC_PRIMITIVES.md`
- `/home/tomi/gtos/docs/GTOS_PROTOCOL_REGISTRIES.md`
- `/home/tomi/gtos/docs/PACKAGE_PUBLISHING_REGISTRY.md`
- `/home/tomi/tolang/docs/PROTOCOL_ANNOTATION_BACKING.md`
- `/home/tomi/tolang/docs/AGENT_NATIVE_STDLIB_2046.md`
- `/home/tomi/tolang/docs/STDLIB_THREAT_MODEL_MATRIX.md`
