# 100% Parallel Transaction Execution: Eliminating Global Shared State

## Goal

All transactions from different senders in a block execute in level 0 — true 100%
parallel execution with no artificial serialization.

---

## Current Bottleneck

### Root Cause: Global Expiry Index

SetCode and KV Put transactions, in addition to writing the sender's own state, append
an entry to a global expiry index stored at a fixed system address:

**SetCode** (`appendSetCodeExpiryIndex`):
```
SystemActionAddress.storage[countSlot(expireAt)]++
SystemActionAddress.storage[ownerSlot(expireAt, count)] = sender
```

**KV Put** (`appendKVExpiryIndex`):
```
KVRouterAddress.storage[countSlot(expireAt)]++
KVRouterAddress.storage[ownerSlot(expireAt, count)] = sender
```

This is a read-modify-write on a **shared counter**. Any two transactions with the same
`expireAt` (identical TTL) conflict on this slot and must be serialized.

### Impact on Parallelism

| Scenario | Current behavior | Ideal behavior |
|---|---|---|
| 10 SetCode txs, different senders, same TTL | 10 levels — fully serial | 1 level — fully parallel |
| 100 KV Put txs, different senders, same TTL | 100 levels — fully serial | 1 level — fully parallel |
| Mixed txs from different senders | Forced into multiple levels by expiry conflicts | All level 0 |

The actual data dependency for SetCode and KV Put is strictly the sender's own state
(balance, nonce, code, storage). The global expiry index exists solely to support
efficient block-end pruning — it is not a business logic requirement. It is an
**artificially introduced conflict**.

---

## Solution: Expiry Info Lives on the Sender Only

### Principle

The write set of SetCode and KV Put is strictly limited to the sender address.
`expireAt` is already stored in the sender's own storage slots — that is sufficient.

**SetCode write set (revised):**
```
sender.balance
sender.nonce
sender.code
sender.storage[SetCodeCreatedAtSlot]
sender.storage[SetCodeExpireAtSlot]
```

**KV Put write set (revised):**
```
sender.balance
sender.nonce
sender.storage[KV slots]
```

No writes to any global address.

### Pruning Alternatives

Removing the global expiry index requires adjusting `pruneExpiredCodeAt` and
`PruneExpiredAt`. Three options:

#### Option A: Lazy Expiry (Recommended)

No proactive pruning at block end. Expiry is checked inline in business logic.

**SetCode** — already mostly correct, one line to remove:

`applySetCode` (`core/state_transition.go`) already contains the inline expiry check:

```go
expireAt := stateWordToUint64(st.state.GetState(from, SetCodeExpireAtSlot))
code := st.state.GetCode(from)
if len(code) > 0 && (expireAt == 0 || currentBlock < expireAt) {
    return ErrCodeAlreadyActive
}
// reaching here: code is absent or expired — overwrite is allowed
st.state.SetCode(from, payload.Code)
st.state.SetState(from, SetCodeCreatedAtSlot, ...)
st.state.SetState(from, SetCodeExpireAtSlot, ...)
appendSetCodeExpiryIndex(...)   // ← remove this line
```

Remove the `appendSetCodeExpiryIndex` call. The inline check already handles expiry
correctly: expired code is silently overwritten on the sender's next SetCode
transaction. No external pruner needed.

**KV Put** — `Get`/`GetMeta` need a `currentBlock` parameter:

`kvstore.Put` (`kvstore/state.go`) already overwrites the record in-place; the only
change is removing the global index append:

```go
func Put(db vm.StateDB, owner, namespace, key, value, createdAt, expireAt) {
    // ... write value, meta slots to owner's storage ...
    appendExpiryIndex(db, owner, base, expireAt)   // ← remove this line
}
```

`kvstore.Get` / `GetMeta` currently return expired records as live. Add inline expiry
filtering by passing `currentBlock` and checking on read:

```go
// Before
func Get(db vm.StateDB, owner, namespace, key) ([]byte, RecordMeta, bool) {
    meta := GetMeta(db, owner, namespace, key)
    if !meta.Exists { return nil, meta, false }
    return readValue(...), meta, true   // returns expired data
}

// After
func Get(db vm.StateDB, owner, namespace, key []byte, currentBlock uint64) ([]byte, RecordMeta, bool) {
    meta := GetMeta(db, owner, namespace, key)
    if !meta.Exists || meta.ExpireAt <= currentBlock {
        return nil, RecordMeta{}, false   // expired → not found
    }
    return readValue(...), meta, true
}
```

The same `currentBlock` guard is applied in `GetMeta`. All call sites that read KV
records pass the current block number (already available in every execution context).

**Removing block-end pruning calls** (`core/state_processor.go`):

```go
// Remove these two calls from Process():
codePruned := pruneExpiredCodeAt(statedb, header.Number.Uint64())
kvPruned   := kvstore.PruneExpiredAt(statedb, header.Number.Uint64())
```

The functions themselves can be kept as no-ops or deleted; their metrics and log
statements are also removed.

Pros: zero global writes, zero parallel conflicts, minimal code change.
Cons: expired storage slots are not reclaimed until the sender's next transaction
(minor on-chain storage growth for inactive accounts).

#### Option B: Node-Local Index

Store the `(expireAt → []sender)` index in the node's local database (leveldb/pebble),
not in statedb.

- On-chain state contains only the sender's own slots — no shared global writes.
- The node maintains the local index during block import; pruning runs against it at
  block end.
- The index is not part of consensus and can be rebuilt from chain history.

Pros: retains proactive pruning, no on-chain storage growth.
Cons: requires additional local DB reads/writes; slightly more complex to implement.

#### Option C: Append-Only Unique Slot

Each transaction writes to a unique slot (e.g., `keccak256(sender ++ expireAt)`) on
the global address instead of a shared read-modify-write counter.

- No read-modify-write, no conflict.
- Pruning scans all slots on the global address.

Cons: unbounded storage growth on the global address; expensive pruning scan.
Not recommended.

---

## Scope of Changes (Option A)

| File | Change |
|---|---|
| `core/state_transition.go` | `applySetCode`: remove `appendSetCodeExpiryIndex` call |
| `core/setcode_prune.go` | Remove or stub `appendSetCodeExpiryIndex` and `pruneExpiredCodeAt` |
| `kvstore/state.go` | `Put`: remove `appendExpiryIndex` call; `Get`/`GetMeta`: add `currentBlock` param and inline expiry check; remove or stub `PruneExpiredAt` |
| `core/state_processor.go` | Remove `pruneExpiredCodeAt` and `kvstore.PruneExpiredAt` calls and their metrics |
| `core/parallel/analyze.go` | `AnalyzeTx`: SetCode and KV Put write sets contain sender only; remove expiry count slot tracking |

All other files in `core/parallel/` (`accessset.go`, `dag.go`, `executor.go`,
`writebuf.go`) require no changes.

---

## Expected Outcome

After these changes, SetCode, KV Put, Transfer, and non-validator System Actions from
different senders are all conflict-free and execute in level 0.

The only remaining true conflicts are:

| Conflict | Reason | Unavoidable |
|---|---|---|
| Multiple txs from the same sender | Nonce dependency | Yes |
| Multiple System Actions (VALIDATOR_REGISTER) | Shared write on ValidatorRegistryAddress | Yes — business logic requirement |

All other cross-sender transactions: **level 0, 100% parallel**.
