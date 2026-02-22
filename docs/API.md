# GTOS API Overview

This document is a concise overview of public APIs. Detailed schemas are in `docs/RPC.md`.

## Principles

- `tos_setCode` is a dedicated API for code storage setup.
- Code storage uses account `Code/CodeHash` directly.
- One account can keep only one active code entry.
- Active code cannot be overwritten or deleted.
- Code can be set again only after TTL expiry clears active state.
- `ttl` is measured in blocks, not seconds.

## Main Methods

- `tos_setSigner({...tx fields...})`
- `tos_setCode({...tx fields...})`
- `tos_putKVTTL({...tx fields...})`
- `tos_getCode(address, block?)`
- `tos_getCodeMeta(address, block?)`
- `tos_getKV(namespace, key, block?)`
- `tos_getKVMeta(namespace, key, block?)`

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
