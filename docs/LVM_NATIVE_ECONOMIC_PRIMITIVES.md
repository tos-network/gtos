# LVM Native Economic Primitives

**Status: V1 PARTIALLY IMPLEMENTED (2026-03-22)**

Implemented in code today:

- native `tos.package_call` validation and rollback semantics
- state-backed `tos.hascapability(...)` and `tos.hasdelegation(...)`
- protocol-backed `tos.isverified(...)`
- protocol-backed `tos.canpay(...)`
- package / contract inspection over deployed TOL code and package metadata
- package inspection now joins published package identity, publisher status,
  and latest-channel package resolution through GTOS RPC

Still open for later waves:

- deeper `escrow/release` standardization
- fuller UNO rails normalization
- richer runtime-native settlement / receipt hooks

## Purpose

This document defines the GTOS / LVM work required to make core
agent-economic primitives native, dependable, and uniform.

The problem is not that Tolang lacks syntax.
The problem is that too many economic operations still depend on host-shaped
plumbing rather than stable VM-native semantics.

This document turns those ad hoc host surfaces into an implementation plan.

---

## Problem Statement

Today, meaningful stdlib execution depends on runtime conventions such as:

- `tos.package_call`
- `agentload`
- `escrow`
- `release`
- `uno.balance(...)`
- `uno.transfer(...)`

These are already usable, but they are not yet a fully normalized protocol/VM
surface.

That creates four risks:

1. semantic differences between test harnesses and on-chain runtime
2. inconsistent failure and rollback behavior across primitives
3. unclear gas and accounting expectations
4. hard-to-audit economic behavior for agent runtimes

---

## Scope

This document covers five native primitive families:

1. package-dispatched execution
2. capability and agent lookup
3. escrow / release lifecycle
4. UNO confidential rails primitives
5. runtime-native inspection and receipt hooks

It also defines:

- failure semantics
- rollback semantics
- gas/accounting principles
- implementation phases

---

## Non-goals

This document does not:

- redesign Tolang syntax
- replace contract-local logic with system primitives everywhere
- define cryptographic proof systems
- replace the registry design from `GTOS_PROTOCOL_REGISTRIES.md`

It is about runtime-native execution semantics.

---

## Design Principles

1. **Native semantics first**
   Primitive behavior must be defined by LVM/GTOS, not by per-host convention.

2. **Fail closed**
   Missing or invalid runtime support must revert, never silently degrade.

3. **Rollback must be explicit**
   Any primitive that changes balances or state must have a clearly defined
   rollback boundary.

4. **Accounting must be auditable**
   Gas, value movement, and status changes must be visible in receipts/metadata
   or at least derive cleanly from them.

5. **Tolang composes these primitives; it should not emulate them**
   The language should stop carrying emulation burden in tests and helper code.

---

## Primitive Set

### 1. Native `tos.package_call`

Current problem:

- package composition still feels host-dependent
- package dispatch is not yet clearly protocol-native in every environment

Required semantics:

- address identifies a deployed `.tor` package
- contract name identifies a contract present in that package manifest
- dispatch fails if package identity or contract mapping is invalid
- call path has the same revert-data and rollback semantics as normal calls

Required GTOS work:

- formalize deployed package identity in runtime
- keep `package_call` validation inside VM, not outside it
- expose package identity and contract mapping through RPC

### 2. Native capability / agent lookup

Current problem:

- capability and agent queries still lean too much on host conventions

Required semantics:

- `tos.capabilitybit(name)` must be registry-backed
- `tos.hascapability(agent, cap)` must fail closed on unresolved capability
- `agentload(addr, field)` should become a stable runtime-backed query surface,
  not a loose per-host shim

Required GTOS work:

- bind lookup to protocol registries
- define canonical field surface for `agentinfo`
- expose versioned query semantics

### 3. Native `escrow` / `release`

Current problem:

- many stdlib contracts use `escrow` / `release`, but the semantics are still
  relatively implicit

Required semantics:

- who holds escrowed value
- when value is considered reserved vs transferred
- how rollback affects reserved value
- how nested failures interact with escrow/release
- what receipts or traces must exist for value movement

Required GTOS work:

- define escrow ledger semantics in runtime/state terms
- define release failure behavior
- define interaction with `multicall`
- expose inspectable state where appropriate

### 4. Native UNO rails primitives

Current problem:

- `uno.balance` / `uno.transfer` are usable, but their runtime contract should
  be more explicit and more uniform

Required semantics:

- transfer failure conditions
- rollback behavior under nested/composed execution
- relation to selective disclosure and receipts
- gas/accounting surface

Required GTOS work:

- publish a stable runtime contract for UNO host functions
- align confidential transfer behavior with LVM revert model
- define receipt/proof anchor expectations for higher-level flows

### 5. Runtime-native inspection hooks

Current problem:

- agents increasingly need runtime facts, not only contract-local view methods

Required semantics:

- package identity inspection
- capability resolution status
- verifier/policy identity lookup
- escrow or settlement trace lookup where protocol-owned

Required GTOS work:

- extend metadata RPC and inspection RPC
- make runtime-backed inspection composable with contract metadata

---

## Failure Semantics

Every native primitive should explicitly specify:

- what counts as malformed input
- whether failure returns `(false, data)` or raises hard error
- whether failure reverts all state/value effects
- whether revert data is structured

Recommended defaults:

- malformed descriptor -> hard revert
- missing registry entry -> hard revert or fail-closed false, never permissive
- balance/state mutation failure -> revert
- nested primitive failure -> snapshot revert at the primitive boundary

---

## Gas and Accounting

Each primitive family should have a published gas/accounting model:

- lookup primitives
- package dispatch
- escrow reserve
- escrow release
- UNO transfer

At minimum, GTOS must define:

- whether gas is charged before or after lookup validation
- whether child gas caps apply to package-dispatched calls identically to
  normal calls
- whether escrow/release accounting is charged as runtime system work or
  contract work

---

## Suggested System Interfaces

Illustrative surface:

```text
tos.package_call(addr, contract_name, calldata)
tos.capabilitybit(name)
tos.hascapability(agent, cap)
tos.agentinfo(addr, field)
tos.escrow(reserver, amount, tag?)
tos.release(beneficiary, amount, tag?)
tos.uno_balance(addr)
tos.uno_transfer(addr, ciphertext)
```

The exact spellings can evolve, but the semantics should be stable.

---

## Threat Model

Primary risks:

1. package dispatch to unintended contracts
2. permissive fallback on unresolved capability names
3. inconsistent escrow/release behavior across hosts
4. confidential transfer state drifting from receipt/disclosure state
5. runtime inspection returning incomplete or stale identity data

Required mitigations:

- native validation
- fail-closed behavior
- explicit revert model
- registry-backed lookup
- RPC/runtime parity

---

## Implementation Phases

### Phase 1: package_call + capability lookup hardening — IMPLEMENTED (2026-03-22)

Why first:

- most central to packageized stdlib execution

Deliverables:

- ~~native package identity validation~~ — **DONE**: `tos.package_call` now
  computes `keccak256(deployedCode)`, queries `pkgregistry.ReadPackageByHash`,
  blocks revoked packages/publishers; 4 tests in `lvm_pkgreg_test.go`
- ~~registry-backed capability lookup~~ — **DONE**: `tos.hascapability` upgraded
  with `RegistryReader` interface; checks status + agent bit; 14 tests with
  mock registry in `lvm_registry_stubs_test.go`
- ~~updated metadata/RPC inspection~~ — **DONE**: registry RPCs are now
  state-backed, `TolGetLatestPackage` resolves latest active package by
  channel, and deployed contract metadata joins published package identity

### Phase 2: escrow / release native semantics

Why second:

- directly affects settlement, sponsor, and account flows

Deliverables:

- defined ledger semantics
- tests for rollback, nested failure, and balance movement

### Phase 3: UNO runtime contract

Why third:

- privacy family already exists and needs a more explicit runtime base

Deliverables:

- documented transfer/balance contract
- receipt/disclosure integration expectations

### Phase 4: native inspection expansion

Why fourth:

- agent runtimes and OpenFox benefit once primitives and registries are stable

---

## Acceptance Criteria

- `package_call` is fully VM-native and validated against deployed package identity
- capability lookup is registry-backed and fail-closed
- `escrow` / `release` semantics are explicitly documented and tested
- UNO primitives have stable failure/rollback semantics
- GTOS inspection/RPC exposes the runtime-backed facts agents need

---

## Related Documents

- `/home/tomi/tolang/docs/TOLANG_SHORTCOMINGS.md`
- `/home/tomi/gtos/docs/Atomic-Execution-v1.md`
- `/home/tomi/gtos/docs/SELECTIVE-DISCLOSURE.md`
- `/home/tomi/gtos/docs/Native-Scheduled-Tasks.md`
- `/home/tomi/gtos/docs/GTOS_PROTOCOL_REGISTRIES.md`
