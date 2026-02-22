# GTOS RPC v2 Specification (Draft)

This document defines the public RPC v2 surface aligned with GTOS roadmap:

- DPoS consensus.
- Storage-first chain capabilities.
- TTL lifecycle for code storage and KV storage.
- Rolling history retention without archive nodes.

## 1. Design Rules

- Namespace: keep storage and account APIs under `tos_*`.
- Consensus-specific validator queries remain under `dpos_*`.
- Public RPC should prioritize deterministic state queries over VM-style simulation.
- History outside retention window must return explicit pruning errors.

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
- `tos_getAccount({address, block?})`
- `tos_getSigner({address, block?})`
- `tos_getCodeObject({codeHash, block?})`
- `tos_getCodeObjectMeta({codeHash, block?})`
- `tos_getKV({namespace, key, block?})`
- `tos_getKVMeta({namespace, key, block?})`
- `tos_listKV({namespace, cursor?, limit?, block?})`

Write/tx-submission methods:

- `tos_setSigner({...tx fields...})`
- `tos_buildSetSignerTx({...tx fields...})`
- `tos_putCodeTTL({...tx fields...})`
- `tos_deleteCodeObject({...tx fields...})`
- `tos_putKVTTL({...tx fields...})`
- `tos_deleteKV({...tx fields...})`

## 3.2 `dpos_*`

- `dpos_getSnapshot(number?)`
- `dpos_getValidators(number?)`
- `dpos_getValidator({address, block?})`
- `dpos_getEpochInfo(block?)`

## 4. JSON Schema

The schema snippets below define `params[0]` and `result` shape. For methods without params, `params` is `[]`.

## 4.1 Common Types

```json
{
  "$id": "gtos.rpc.v2.common",
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
    "chainId": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "networkId": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
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
    "headBlock": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "oldestAvailableBlock": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"}
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
    "headBlock": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "oldestAvailableBlock": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "retainBlocks": {"type": "integer", "minimum": 1}
  }
}
```

## 4.3 Account/Signer

### `tos_getAccount`

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["address"],
  "properties": {
    "address": {"$ref": "gtos.rpc.v2.common#/definitions/address"},
    "block": {"$ref": "gtos.rpc.v2.common#/definitions/blockTag"}
  }
}
```

Result schema:

```json
{
  "type": "object",
  "required": ["address", "nonce", "balance", "signer", "blockNumber"],
  "properties": {
    "address": {"$ref": "gtos.rpc.v2.common#/definitions/address"},
    "nonce": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "balance": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "signer": {
      "type": "object",
      "required": ["type", "value", "defaulted"],
      "properties": {
        "type": {"type": "string"},
        "value": {"type": "string"},
        "defaulted": {"type": "boolean"}
      }
    },
    "blockNumber": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"}
  }
}
```

### `tos_getSigner`

Params schema (`params[0]`): same as `tos_getAccount`.

Result schema:

```json
{
  "type": "object",
  "required": ["address", "signer", "blockNumber"],
  "properties": {
    "address": {"$ref": "gtos.rpc.v2.common#/definitions/address"},
    "signer": {
      "type": "object",
      "required": ["type", "value", "defaulted"],
      "properties": {
        "type": {"type": "string"},
        "value": {"type": "string"},
        "defaulted": {"type": "boolean"}
      }
    },
    "blockNumber": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"}
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
    "from": {"$ref": "gtos.rpc.v2.common#/definitions/address"},
    "signerType": {"type": "string"},
    "signerValue": {"type": "string"},
    "nonce": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "gas": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "gasPrice": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"}
  }
}
```

Result schema:

```json
{"$ref": "gtos.rpc.v2.common#/definitions/hash32"}
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
    "raw": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"}
  }
}
```

## 4.4 Code Storage TTL

### `tos_putCodeTTL`

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["from", "code", "ttl", "gasPrice"],
  "properties": {
    "from": {"$ref": "gtos.rpc.v2.common#/definitions/address"},
    "code": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"},
    "ttl": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "nonce": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "gas": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "gasPrice": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"}
  }
}
```

Result schema:

```json
{"$ref": "gtos.rpc.v2.common#/definitions/hash32"}
```

### `tos_getCodeObject`

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["codeHash"],
  "properties": {
    "codeHash": {"$ref": "gtos.rpc.v2.common#/definitions/hash32"},
    "block": {"$ref": "gtos.rpc.v2.common#/definitions/blockTag"}
  }
}
```

Result schema:

```json
{
  "type": "object",
  "required": ["codeHash", "code", "createdAt", "expireAt", "expired"],
  "properties": {
    "codeHash": {"$ref": "gtos.rpc.v2.common#/definitions/hash32"},
    "code": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"},
    "createdAt": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "expireAt": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "expired": {"type": "boolean"}
  }
}
```

### `tos_getCodeObjectMeta`

Params schema (`params[0]`): same as `tos_getCodeObject`.

Result schema:

```json
{
  "type": "object",
  "required": ["codeHash", "createdAt", "expireAt", "expired"],
  "properties": {
    "codeHash": {"$ref": "gtos.rpc.v2.common#/definitions/hash32"},
    "createdAt": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "expireAt": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "expired": {"type": "boolean"}
  }
}
```

### `tos_deleteCodeObject`

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["from", "codeHash", "gasPrice"],
  "properties": {
    "from": {"$ref": "gtos.rpc.v2.common#/definitions/address"},
    "codeHash": {"$ref": "gtos.rpc.v2.common#/definitions/hash32"},
    "nonce": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "gas": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "gasPrice": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"}
  }
}
```

Result schema:

```json
{"$ref": "gtos.rpc.v2.common#/definitions/hash32"}
```

## 4.5 KV Storage TTL

### `tos_putKVTTL`

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["from", "namespace", "key", "value", "ttl", "gasPrice"],
  "properties": {
    "from": {"$ref": "gtos.rpc.v2.common#/definitions/address"},
    "namespace": {"type": "string", "minLength": 1},
    "key": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"},
    "value": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"},
    "ttl": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "nonce": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "gas": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "gasPrice": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"}
  }
}
```

Result schema:

```json
{"$ref": "gtos.rpc.v2.common#/definitions/hash32"}
```

### `tos_getKV`

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["namespace", "key"],
  "properties": {
    "namespace": {"type": "string", "minLength": 1},
    "key": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"},
    "block": {"$ref": "gtos.rpc.v2.common#/definitions/blockTag"}
  }
}
```

Result schema:

```json
{
  "type": "object",
  "required": ["namespace", "key", "value"],
  "properties": {
    "namespace": {"type": "string"},
    "key": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"},
    "value": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"}
  }
}
```

### `tos_getKVMeta`

Params schema (`params[0]`): same as `tos_getKV`.

Result schema:

```json
{
  "type": "object",
  "required": ["namespace", "key", "createdAt", "expireAt", "expired"],
  "properties": {
    "namespace": {"type": "string"},
    "key": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"},
    "createdAt": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "expireAt": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "expired": {"type": "boolean"}
  }
}
```

### `tos_deleteKV`

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["from", "namespace", "key", "gasPrice"],
  "properties": {
    "from": {"$ref": "gtos.rpc.v2.common#/definitions/address"},
    "namespace": {"type": "string", "minLength": 1},
    "key": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"},
    "nonce": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "gas": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"},
    "gasPrice": {"$ref": "gtos.rpc.v2.common#/definitions/hexQuantity"}
  }
}
```

Result schema:

```json
{"$ref": "gtos.rpc.v2.common#/definitions/hash32"}
```

### `tos_listKV`

Params schema (`params[0]`):

```json
{
  "type": "object",
  "required": ["namespace"],
  "properties": {
    "namespace": {"type": "string", "minLength": 1},
    "cursor": {"type": "string"},
    "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
    "block": {"$ref": "gtos.rpc.v2.common#/definitions/blockTag"}
  }
}
```

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
          "key": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"},
          "value": {"$ref": "gtos.rpc.v2.common#/definitions/hexData"}
        }
      }
    },
    "nextCursor": {"type": ["string", "null"]}
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

GTOS application errors (v2):

- `-38000` `not_supported` - method/feature intentionally unsupported on this chain profile.
- `-38001` `not_implemented` - method skeleton exists but execution path is not implemented yet.
- `-38002` `invalid_ttl` - TTL is zero, overflowed, or violates policy.
- `-38003` `expired` - record exists but is expired at requested block context.
- `-38004` `not_found` - record is not found in active state.
- `-38005` `history_pruned` - requested block/tx is outside retention window.
- `-38006` `permission_denied` - caller is not allowed to perform the action.
- `-38007` `invalid_signer` - signer type/value invalid or verification setup mismatch.
- `-38008` `retention_unavailable` - method requires data not retained by non-archive policy.

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

## 6. Legacy -> v2 Mapping

| Legacy method | v2 method | Notes |
|---|---|---|
| `tos_chainId` | `tos_getChainProfile` | `chainId` also available in profile output. |
| `tos_blockNumber` | `tos_getPruneWatermark` | `headBlock` included. |
| `tos_getBalance` + `tos_getTransactionCount` | `tos_getAccount` | Unified account read with signer view. |
| `tos_getCode` | `tos_getCodeObject` | Switch from contract-code semantics to code-object storage semantics. |
| `tos_getStorageAt` | `tos_getKV` | TTL KV read semantics. |
| `tos_sendTransaction` (data to system address) | `tos_setSigner` / `tos_putCodeTTL` / `tos_putKVTTL` | Explicit operation RPCs. |
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

- Add all `tos_*` v2 method endpoints and typed request/response structs.
- Return deterministic `not_implemented` for methods lacking execution backend.
- Implement read-only profile/retention/account/signer methods first.

Stage B (execution wiring):

- Bind `tos_setSigner` to account signer state transition.
- Bind code/KV TTL writes and reads to finalized state model.
- Add deterministic prune/expire behavior and errors.

Stage C (deprecation enforcement):

- Gate or remove VM-era RPCs (`tos_call`, `tos_estimateGas`, etc.).
- Move clients to v2 methods with compatibility window.
