# GTOS API Overview

This document is a concise overview of public APIs. Detailed schemas are in `docs/RPC.md`.

## Principles

- `tos_setCode` is a dedicated API for code storage setup.
- Code storage uses account `Code/CodeHash` directly.
- One account can keep only one active code entry.
- Active code cannot be overwritten or deleted.
- Code can be set again only after TTL expiry clears active state.
- `ttl` is measured in blocks, not seconds.
- `tos_setCode` gas includes ttl retention surcharge (`ttl * 1`).
- Retention/snapshot operational contract is versioned in `docs/RETENTION_SNAPSHOT_SPEC.md` (`v1.0.0`).

## Signer Algorithms

- Current account/wallet signer support: `secp256k1`, `secp256r1`, `ed25519`, `bls12-381`.
- `tos_setSigner` accepted canonical `signerType` values: `secp256k1`, `secp256r1`, `ed25519`, `bls12-381`.
- Current tx signature verification format supports direct validation for: `secp256k1`, `secp256r1`, `ed25519`, `bls12-381`.
- `bls12-381` verification/signing backend uses `blst` (`supranational`) for signer-account path.
- `bls12-381` tx signature bytes use compressed G2 format (`96` bytes); pubkeys use compressed G1 format (`48` bytes).

## Transaction Envelope Policy

- Only `SignerTx` envelopes are accepted for new submissions.
- `SignerTx` is the active envelope and carries explicit `chainId`, `from`, and `signerType`.
- `V` is signature-only and does not carry signer metadata.

## Main Methods

- `tos_setSigner({...tx fields...})`
- `tos_estimateSetCodeGas(code, ttl)`
- `tos_setCode({...tx fields...})`
- `tos_putKV({...tx fields...})`
- `tos_getCode(address, block?)`
- `tos_getCodeMeta(address, block?)`
- `tos_getKV(from, namespace, key, block?)`
- `tos_getKVMeta(from, namespace, key, block?)`

## `tos_setCode` Execution Model

- `tos_setCode` does not use the system action address.
- The API builds and submits a special transaction with `to = nil`.
- In GTOS, `to = nil` is reserved for setCode payload only.
- Arbitrary contract deployment is not supported.
- `tos_sendTransaction` does not allow user-supplied `to = nil` for code setup.
- Clients must use `tos_setCode` so `ttl` is explicit in RPC params.
- The execution path writes:
  - account `Code/CodeHash`
  - `createdAt` and `expireAt` metadata (block heights)

## TTL Semantics

- At write block `B`, expiry block is `B + ttl`.
- Stored state keeps `expireAt` (absolute block height).
- Reads treat expired entries as inactive.
