# Package Publishing Registry

**Status: DESIGN READY FOR IMPLEMENTATION**

## Purpose

This document defines the protocol-grade package identity and publishing model
for Tolang packages on GTOS.

Today, package compilation and local resolution work. What is not yet fully
defined is the network-facing identity model:

- who is the publisher
- what package name resolves to on-chain
- how versions are represented
- how revocation and deprecation work

This document specifies that model.

---

## Problem Statement

Local filesystem resolution is sufficient for development, but not for an
agent economy.

An autonomous runtime needs to answer:

- is this package name canonical?
- who published this package?
- is the package version active, deprecated, or revoked?
- what contract set belongs to this package hash?
- what should discovery or deployment tools trust?

Without a protocol-grade package model:

- package identity remains toolchain-local
- agents cannot rely on stable publishing rules
- OpenFox/discovery cannot reason about publisher trust
- revocation is weak and fragmented

---

## Scope

This document defines:

1. package identity model
2. publisher identity model
3. version/channel model
4. protocol registry data model
5. RPC/query surface
6. phased rollout path

---

## Non-goals

This document does not:

- replace local source imports for development
- require all packages to be published on-chain before local testing
- define ABI/discovery content itself
- define compiler internals

It defines the network and protocol meaning of published packages.

---

## Design Principles

1. **Content-addressed, name-addressable**
   A package should have both a stable human name and a canonical content hash.

2. **Publisher identity is explicit**
   Agents should know who published a package, not only its hash.

3. **Version and channel semantics are first-class**
   `1.2.0`, `beta`, `stable`, and `revoked` should not be off-chain folklore.

4. **Local dev and protocol publishing must coexist**
   Tooling mode and network mode should share shape where possible.

5. **Discovery joins package identity**
   A service contract's discovery metadata should be able to point to a stable
   published package identity.

---

## Identity Model

Every published package should be identified by:

```text
PackageIdentity {
  package_name: string
  package_version: string
  package_hash: bytes32     // hash of canonical .tor
  publisher_id: bytes32
}
```

This yields two independent handles:

- name/version identity for humans and routing
- package hash for canonical content integrity

---

## Publisher Model

Minimum publisher record:

```text
PublisherRecord {
  publisher_id: bytes32
  controller: address
  metadata_ref: bytes32
  status: uint8            // active, suspended, revoked
}
```

Publisher responsibilities:

- claim namespace
- publish package versions
- deprecate/revoke versions
- rotate metadata

---

## Package Record

Minimum record:

```text
PackageRecord {
  package_name: string
  package_version: string
  package_hash: bytes32
  publisher_id: bytes32
  manifest_hash: bytes32
  channel: uint16          // dev, beta, stable, deprecated
  status: uint8            // active, deprecated, revoked
  contract_count: uint16
  discovery_ref: bytes32
  published_at: uint64
}
```

Optional derived indexes:

- latest stable by package name
- latest beta by package name
- packages by publisher

---

## Registry Operations

Required operations:

- register publisher
- publish package
- publish new version
- mark version deprecated
- revoke version
- resolve name + version -> package hash
- resolve package hash -> package record
- query latest stable/beta for a package name

---

## Channel Model

Suggested channels:

1. `DEV`
2. `BETA`
3. `STABLE`
4. `DEPRECATED`

Status is separate from channel:

- `active`
- `deprecated`
- `revoked`

Example:

- a package may be in `STABLE` channel but later move to `deprecated`
- a malicious or broken package may be `revoked`

---

## Resolution Rules

### Tooling mode

Used for local development.

- package import may resolve from local filesystem
- no on-chain publish required

### Protocol mode

Used for discovery, deployment, and agent runtime trust decisions.

- package name + version resolves through protocol registry
- package hash must match deployed or referenced package
- publisher status must be checked

Recommended rule:

- local compile may remain filesystem-based
- network-facing trust decisions must use protocol resolution

---

## GTOS Dependencies

This is a protocol feature only if GTOS chooses the network-grade path.

Two rollout options exist:

### Option A: toolchain-first

- Tolang exporter and local resolver only
- no GTOS registry yet
- lower implementation cost

### Option B: protocol-grade registry

- GTOS system package / sysactions / RPC
- stable on-chain package identity
- publisher trust becomes queryable by agents

Recommended path:

1. keep local toolchain mode working
2. design the registry now
3. implement GTOS protocol mode once OpenFox/discovery needs network-trust

---

## RPC Surface

Suggested RPC family:

- `tos_getPackage(name, version)`
- `tos_getPackageByHash(hash)`
- `tos_getPublisher(id)`
- `tos_getLatestPackage(name, channel)`

The deployed contract metadata RPC should be able to attach:

- package name
- version
- package hash
- publisher id/status

---

## Threat Model

Primary risks:

1. namespace squatting
2. publisher spoofing
3. stale or revoked package use
4. discovery pointing to unverifiable package names
5. mismatch between package hash and referenced metadata

Required mitigations:

- explicit publisher ownership
- signed or owner-authorized publishing
- revocation state
- package hash as canonical integrity key
- RPC/query support for runtime validation

---

## Implementation Phases

### Phase 1: finalize identity schema

Deliverables:

- canonical record shapes
- channel/status model
- exporter compatibility plan

### Phase 2: toolchain alignment

Deliverables:

- exporter emits protocol-shaped package identity fields
- local tooling can validate against the same schema

### Phase 3: GTOS registry implementation

Deliverables:

- system package or registry hub entry
- sysactions
- RPC
- discovery join

### Phase 4: runtime trust integration

Deliverables:

- OpenFox / discovery consumers prefer protocol resolution for trust decisions

---

## Acceptance Criteria

- package name/version/hash/publisher model is explicit
- package status and revocation are queryable
- protocol mode and tooling mode are clearly separated
- discovery and deployed metadata can attach stable package identity
- agents can validate published package trust without filesystem assumptions

---

## Related Documents

- `/home/tomi/tolang/docs/TOLANG_SHORTCOMINGS.md`
- `/home/tomi/tolang/docs/AGENT_ABI_SCHEMA.md`
- `/home/tomi/tolang/docs/DISCOVERY_TYPED_SCHEMA.md`
- `/home/tomi/gtos/docs/Agent-Discovery-v1.md`
