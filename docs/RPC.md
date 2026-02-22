# GTOS RPC Specification (Draft)

This document defines the public RPC surface aligned with GTOS roadmap.
It extends the existing GTOS/geth-style RPC model; it is not a separate RPC stack.

- DPoS consensus.
- Storage-first chain capabilities.
- TTL lifecycle for code storage and KV storage.
- Rolling history retention without archive nodes.

## 1. Design Rules

- Namespace: keep storage and account APIs under `tos_*`.
- Consensus-specific validator queries remain under `dpos_*`.
- Public RPC should prioritize deterministic state queries over VM-style simulation.
- History outside retention window must return explicit pruning errors.
- Code storage is immutable while active: no update and no delete RPC.
- KV storage is non-deletable but updatable via `tos_putKVTTL` overwrite.
- `ttl` unit is block count (not seconds/milliseconds).
- Expiry is computed by height: `expireBlock = currentBlock + ttl`.
- State persistence stores computed expiry height (`expireBlock`), not raw `ttl`.

## 2. Public Namespaces

- `tos`: chain profile, retention, account/signer, code TTL, KV TTL.
- `dpos`: validator set and epoch/snapshot queries.
- `net`, `web3`: networking and client metadata.

Not enabled for external public endpoints by default:

- `admin`, `debug`, `personal`, `miner`, `txpool`.

## 3. Method List

## 3.1 `tos_*`

Read methods:

- `tos_getChainProfile()`
- `tos_getRetentionPolicy()`
- `tos_getPruneWatermark()`
- `tos_getAccount(address, block?)`
- `tos_getSigner(address, block?)`
- `tos_getCode(address, block?)`
- `tos_getCodeMeta(address, block?)`
- `tos_getKV(namespace, key, block?)`
- `tos_getKVMeta(namespace, key, block?)`
- `tos_listKV(namespace, cursor?, limit?, block?)`

Write/tx-submission methods:

- `tos_setSigner({...tx fields...})`
- `tos_buildSetSignerTx({...tx fields...})`
- `tos_putCodeTTL({...tx fields...})`
- `tos_putKVTTL({...tx fields...})`

## 3.2 `dpos_*`

- `dpos_getSnapshot(number?)`
- `dpos_getValidators(number?)`
- `dpos_getValidator(address, number?)`
- `dpos_getEpochInfo(number?)`

## 3.3 Storage Mutability Rules

- Code storage:
  - `tos_putCodeTTL` writes account code with TTL metadata.
  - One account keeps one active code/codeHash entry.
  - Active account code is immutable: update and delete are not supported.
  - Only TTL expiry/system pruning clears account code.
- KV storage:
  - `tos_putKVTTL` is an upsert operation for `(namespace, key)`.
  - `tos_deleteKV` is not part of this API.
  - Reads only return active (non-expired) values.

## 3.4 TTL Semantics

- `ttl` is a block-count delta.
- At write block `B`, effective expiry is `expireBlock = B + ttl`.
- `ttl` itself is request input and validation data; persisted state keeps `expireBlock`.
- In RPC responses, `createdAt` and `expireAt` are block heights.

## 4. JSON Schema

The schema snippets below define `params[0]` and `result` shape. For methods without params, `params` is `[]`.

## 4.1 Common Types

```json
{
  "$id": "gtos.rpc.common",
  "definitions": {
    "hexQuantity": {
      "type": "string",
      "pattern": "^0x([1-9a-fA-F][0-9a-fA-F]*|0)$"
    },
    "hexData": {
      "type": "string",
      "pattern": "^0x([0-9a-fA-F]{2})*$"
    },
    "address": {
      "type": "string",
      "pattern": "^0x[0-9a-fA-F]{40}$"
    },
    "hash32": {
      "type": "string",
      "pattern": "^0x[0-9a-fA-F]{64}$"
    },
    "blockTag": {
      "oneOf": [
        {"type": "string", "enum": ["latest", "safe", "finalized"]},
        {"$ref": "#/definitions/hexQuantity"}
      ]
    }
  }
}
```

## 4.2 Chain/Retention

### `tos_getChainProfile`

Result schema:

```json
{
  "type": "object",
  "required": ["chainId", "networkId", "targetBlockIntervalMs", "retainBlocks", "snapshotInterval"],
  "properties": {
    "chainId": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "networkId": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "targetBlockIntervalMs": {"type": "integer", "minimum": 1},
    "retainBlocks": {"type": "integer", "minimum": 1},
    "snapshotInterval": {"type": "integer", "minimum": 1}
  }
}
```

### `tos_getRetentionPolicy`

Result schema:

```json
{
  "type": "object",
  "required": ["retainBlocks", "snapshotInterval", "headBlock", "oldestAvailableBlock"],
  "properties": {
    "retainBlocks": {"type": "integer", "minimum": 1},
    "snapshotInterval": {"type": "integer", "minimum": 1},
    "headBlock": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "oldestAvailableBlock": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"}
  }
}
```

### `tos_getPruneWatermark`

Result schema:

```json
{
  "type": "object",
  "required": ["headBlock", "oldestAvailableBlock", "retainBlocks"],
  "properties": {
    "headBlock": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "oldestAvailableBlock": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "retainBlocks": {"type": "integer", "minimum": 1}
  }
}
```

## 4.3 Account/Signer

### `tos_getAccount`

Params:

- `params[0]` address schema: `{"$ref":"gtos.rpc.common#/definitions/address"}`
- `params[1]` optional block/tag schema: `{"$ref":"gtos.rpc.common#/definitions/blockTag"}`

Result schema:

```json
{
  "type": "object",
  "required": ["address", "nonce", "balance", "signer", "blockNumber"],
  "properties": {
    "address": {"$ref": "gtos.rpc.common#/definitions/address"},
    "nonce": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "balance": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "signer": {
      "type": "object",
      "required": ["type", "value", "defaulted"],
      "properties": {
        "type": {"type": "string"},
        "value": {"type": "string"},
        "defaulted": {"type": "boolean"}
      }
    },
    "blockNumber": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"}
  }
}
```

### `tos_getSigner`

Params: same as `tos_getAccount`.

Result schema:

```json
{
  "type": "object",
  "required": ["address", "signer", "blockNumber"],
  "properties": {
    "address": {"$ref": "gtos.rpc.common#/definitions/address"},
    "signer": {
      "type": "object",
      "required": ["type", "value", "defaulted"],
      "properties": {
        "type": {"type": "string"},
        "value": {"type": "string"},
        "defaulted": {"type": "boolean"}
      }
    },
    "blockNumber": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"}
  }
}
```

### `tos_setSigner`

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["from", "signerType", "signerValue", "gasPrice"],
  "properties": {
    "from": {"$ref": "gtos.rpc.common#/definitions/address"},
    "signerType": {"type": "string"},
    "signerValue": {"type": "string"},
    "nonce": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "gas": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "gasPrice": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"}
  }
}
```

Result schema:

```json
{"$ref": "gtos.rpc.common#/definitions/hash32"}
```

### `tos_buildSetSignerTx`

Params schema (`params[0]`): same as `tos_setSigner`.

Result schema:

```json
{
  "type": "object",
  "required": ["tx", "raw"],
  "properties": {
    "tx": {"type": "object"},
    "raw": {"$ref": "gtos.rpc.common#/definitions/hexData"}
  }
}
```

## 4.4 Code Storage TTL

### `tos_putCodeTTL`

Behavior:

- Writes code to the `from` account with TTL metadata.
- If the account code is still active, replacement is rejected.
- Manual delete/update is not supported.
- Code payload is limited to `65536` bytes (`64KiB`).
- `ttl` is block count; expiry is computed as `expireBlock = currentBlock + ttl`.
- State persists `expireBlock` (reported by `expireAt`).

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["from", "code", "ttl", "gasPrice"],
  "properties": {
    "from": {"$ref": "gtos.rpc.common#/definitions/address"},
    "code": {"$ref": "gtos.rpc.common#/definitions/hexData"},
    "ttl": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "nonce": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "gas": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "gasPrice": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"}
  }
}
```

Result schema:

```json
{"$ref": "gtos.rpc.common#/definitions/hash32"}
```

### `tos_getCode`

Params:

- `params[0]` address schema: `{"$ref":"gtos.rpc.common#/definitions/address"}`
- `params[1]` optional block/tag schema: `{"$ref":"gtos.rpc.common#/definitions/blockTag"}`

Result schema:

```json
{"$ref": "gtos.rpc.common#/definitions/hexData"}
```

### `tos_getCodeMeta`

Params: same as `tos_getCode`.

Result schema:

```json
{
  "type": "object",
  "required": ["address", "codeHash", "createdAt", "expireAt", "expired"],
  "properties": {
    "address": {"$ref": "gtos.rpc.common#/definitions/address"},
    "codeHash": {"$ref": "gtos.rpc.common#/definitions/hash32"},
    "createdAt": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "expireAt": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "expired": {"type": "boolean"}
  }
}
```

## 4.5 KV Storage TTL

### `tos_putKVTTL`

Behavior:

- Upsert operation for `(namespace, key)`.
- Existing active entries are overwritten with new value/TTL metadata.
- Manual delete is not supported.
- `ttl` is block count; expiry is computed as `expireBlock = currentBlock + ttl`.
- State persists `expireBlock` (reported by `expireAt`).

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["from", "namespace", "key", "value", "ttl", "gasPrice"],
  "properties": {
    "from": {"$ref": "gtos.rpc.common#/definitions/address"},
    "namespace": {"type": "string", "minLength": 1},
    "key": {"$ref": "gtos.rpc.common#/definitions/hexData"},
    "value": {"$ref": "gtos.rpc.common#/definitions/hexData"},
    "ttl": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "nonce": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "gas": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "gasPrice": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"}
  }
}
```

Result schema:

```json
{"$ref": "gtos.rpc.common#/definitions/hash32"}
```

### `tos_getKV`

Params:

- `params[0]` namespace schema:
```json
{"type":"string","minLength":1}
```
- `params[1]` key schema: `{"$ref":"gtos.rpc.common#/definitions/hexData"}`
- `params[2]` optional block/tag schema: `{"$ref":"gtos.rpc.common#/definitions/blockTag"}`

Result schema:

```json
{
  "type": "object",
  "required": ["namespace", "key", "value"],
  "properties": {
    "namespace": {"type": "string"},
    "key": {"$ref": "gtos.rpc.common#/definitions/hexData"},
    "value": {"$ref": "gtos.rpc.common#/definitions/hexData"}
  }
}
```

### `tos_getKVMeta`

Params: same as `tos_getKV`.

Result schema:

```json
{
  "type": "object",
  "required": ["namespace", "key", "createdAt", "expireAt", "expired"],
  "properties": {
    "namespace": {"type": "string"},
    "key": {"$ref": "gtos.rpc.common#/definitions/hexData"},
    "createdAt": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "expireAt": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "expired": {"type": "boolean"}
  }
}
```

### `tos_listKV`

Params:

- `params[0]` namespace schema:
```json
{"type":"string","minLength":1}
```
- `params[1]` optional cursor schema:
```json
{"type":"string"}
```
- `params[2]` optional limit schema:
```json
{"type":"integer","minimum":1,"maximum":1000}
```
- `params[3]` optional block/tag schema: `{"$ref":"gtos.rpc.common#/definitions/blockTag"}`

Result schema:

```json
{
  "type": "object",
  "required": ["items", "nextCursor"],
  "properties": {
    "items": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["namespace", "key", "value"],
        "properties": {
          "namespace": {"type": "string"},
          "key": {"$ref": "gtos.rpc.common#/definitions/hexData"},
          "value": {"$ref": "gtos.rpc.common#/definitions/hexData"}
        }
      }
    },
    "nextCursor": {"type": ["string", "null"]}
  }
}
```

## 4.6 DPoS Queries

### `dpos_getSnapshot`

Params: optional block number/tag value.

Result: snapshot object with validator set and recents map.

### `dpos_getValidators`

Params: optional block number/tag value.

Result schema:

```json
{
  "type": "array",
  "items": {"$ref": "gtos.rpc.common#/definitions/address"}
}
```

### `dpos_getValidator`

Params:

- `params[0]` address schema: `{"$ref":"gtos.rpc.common#/definitions/address"}`
- `params[1]` optional block/tag schema: `{"$ref":"gtos.rpc.common#/definitions/blockTag"}`

Result schema:

```json
{
  "type": "object",
  "required": ["address", "active", "snapshotBlock", "snapshotHash"],
  "properties": {
    "address": {"$ref": "gtos.rpc.common#/definitions/address"},
    "active": {"type": "boolean"},
    "index": {"type": "integer", "minimum": 0},
    "snapshotBlock": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "snapshotHash": {"$ref": "gtos.rpc.common#/definitions/hash32"},
    "recentSignedBlocks": {
      "type": "array",
      "items": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"}
    }
  }
}
```

### `dpos_getEpochInfo`

Params: optional block number/tag value.

Result schema:

```json
{
  "type": "object",
  "required": [
    "blockNumber",
    "epochLength",
    "epochIndex",
    "epochStart",
    "nextEpochStart",
    "blocksUntilEpoch",
    "targetBlockPeriodS",
    "maxValidators",
    "validatorCount",
    "snapshotHash"
  ],
  "properties": {
    "blockNumber": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "epochLength": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "epochIndex": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "epochStart": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "nextEpochStart": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "blocksUntilEpoch": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "targetBlockPeriodS": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "maxValidators": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "validatorCount": {"$ref": "gtos.rpc.common#/definitions/hexQuantity"},
    "snapshotHash": {"$ref": "gtos.rpc.common#/definitions/hash32"}
  }
}
```

## 5. Error Codes

JSON-RPC standard:

- `-32700` parse error
- `-32600` invalid request
- `-32601` method not found
- `-32602` invalid params
- `-32603` internal error

GTOS application errors:

- `-38000` `not_supported` - method/feature intentionally unsupported on this chain profile.
- `-38001` `not_implemented` - method skeleton exists but execution path is not implemented yet.
- `-38002` `invalid_ttl` - TTL block-count is zero, overflowed, or violates policy.
- `-38003` `expired` - record exists but is expired at requested block context.
- `-38004` `not_found` - record is not found in active state.
- `-38005` `history_pruned` - requested block/tx is outside retention window.
- `-38006` `permission_denied` - caller is not allowed to perform the action.
- `-38007` `invalid_signer` - signer type/value invalid or verification setup mismatch.
- `-38008` `retention_unavailable` - method requires data not retained by non-archive policy.
- `-38009` `code_too_large` - code payload exceeds `MaxCodeSize` (`65536` bytes).

Error payload shape (`error.data`):

```json
{
  "type": "object",
  "properties": {
    "reason": {"type": "string"},
    "details": {"type": "object"},
    "retainBlocks": {"type": "integer"},
    "oldestAvailableBlock": {"type": "string"}
  }
}
```

## 6. Legacy -> Extended Mapping

| Legacy method | extended method | Notes |
|---|---|---|
| `tos_chainId` | `tos_getChainProfile` | `chainId` also available in profile output. |
| `tos_blockNumber` | `tos_getPruneWatermark` | `headBlock` included. |
| `tos_getBalance` + `tos_getTransactionCount` | `tos_getAccount` | Unified account read with signer view. |
| `tos_getCode` | `tos_getCode` (+ TTL semantics) | Keep legacy shape; add TTL-aware visibility semantics. |
| n/a | `tos_getCodeMeta` | New metadata endpoint for code TTL (`createdAt/expireAt/expired`). |
| `tos_getStorageAt` | `tos_getKV` | TTL KV read semantics. |
| `tos_sendTransaction` (data to system address) | `tos_setSigner` / `tos_putCodeTTL` / `tos_putKVTTL` | Explicit operation RPCs. |
| legacy delete-style storage actions | removed | this API forbids manual delete for both code and KV. |
| `tos_sendRawTransaction` | unchanged | Still valid for raw tx broadcast. |
| `tos_getTransactionByHash` | unchanged (+pruning error) | Must return `history_pruned` when out of retention. |
| `tos_getTransactionReceipt` | unchanged (+pruning error) | Must return `history_pruned` when out of retention. |
| `tos_call` | deprecated | No VM runtime execution target. |
| `tos_estimateGas` | deprecated | VM-style estimation should be removed for storage-first APIs. |
| `tos_createAccessList` | removed | Not applicable to no-VM execution path. |
| `tos_getProof` | removed | Not a required public API in current roadmap. |
| `tos_getUncle*` | removed | Not meaningful for current DPoS target. |

## 7. Rollout Stages

Stage A (skeleton in code):

- Add all `tos_*` extension method endpoints and typed request/response structs.
- Return deterministic `not_implemented` for methods lacking execution backend.
- Implement read-only profile/retention/account/signer methods first.

Stage B (execution wiring):

- Bind `tos_setSigner` to account signer state transition.
- Bind code/KV TTL writes and reads to finalized state model (`tos_getCode` and `tos_getCodeMeta` for code).
- Enforce code immutability and KV upsert/no-delete behavior in validation.
- Add deterministic prune/expire behavior and errors.

Stage C (deprecation enforcement):

- Gate or remove VM-era RPCs (`tos_call`, `tos_estimateGas`, etc.).
- Move clients to extension methods with compatibility window.
