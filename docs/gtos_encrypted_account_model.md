# gtos Encrypted Account Model
## Replace Plaintext Balance with Native Encrypted Balance in StateAccount

## Status

**Document status:** design proposal
**Scope:** replace dual-account model (plaintext + encrypted) with a single encrypted account model
**Prerequisite:** none (independent of Gigagas L1, can be sequenced before or after)
**Impact:** hard fork — changes StateAccount RLP encoding and state root computation

---

# 1. Problem

gtos currently maintains a **dual-account model**:

```go
// Plaintext balance — in StateAccount (account trie)
type StateAccount struct {
    Nonce    uint64      // plaintext nonce
    Balance  *big.Int    // plaintext balance
    Root     common.Hash // storage trie root
    CodeHash []byte      // contract code hash
}

// Encrypted balance — in storage slots (separate from StateAccount)
var (
    CommitmentSlot = Keccak256("gtos.priv.commitment")  // [32]byte
    HandleSlot     = Keccak256("gtos.priv.handle")       // [32]byte
    VersionSlot    = Keccak256("gtos.priv.version")      // uint64
    NonceSlot      = Keccak256("gtos.priv.nonce")         // uint64
)
```

This means:

- Every account has **two balances**: a plaintext `Balance *big.Int` in the account trie, and an encrypted `Commitment + Handle` in storage slots
- Two nonces: a plaintext `Nonce uint64` in StateAccount, and a privacy `NonceSlot` in storage
- Two parallel state mutation paths for transfers
- Two sets of validation logic
- Two proving surfaces for Gigagas L1

---

# 2. Proposal

**Replace the dual model with a single encrypted account model.** Move encrypted balance fields into `StateAccount` and remove plaintext `Balance`.

### Current StateAccount

```go
type StateAccount struct {
    Nonce    uint64      // plaintext nonce
    Balance  *big.Int    // plaintext balance
    Root     common.Hash // storage trie root
    CodeHash []byte      // contract code hash
}
```

### Proposed StateAccount

```go
type StateAccount struct {
    Nonce      uint64      // reused as unified nonce (same type, minimal call-site changes)
    Root       common.Hash // storage trie root
    CodeHash   []byte      // contract code hash
    Commitment [32]byte    // encrypted balance commitment (Pedersen commitment)
    Handle     [32]byte    // encrypted balance handle (ElGamal component)
    Version    uint8       // encrypted balance version
}
```

### What changes

| Field | Before | After |
|-------|--------|-------|
| `Balance *big.Int` | Plaintext balance | **Removed** |
| `Nonce uint64` | Plaintext tx nonce | **Reused as unified nonce** (type unchanged) |
| `Commitment [32]byte` | In storage slot `CommitmentSlot` | **Promoted to StateAccount field** |
| `Handle [32]byte` | In storage slot `HandleSlot` | **Promoted to StateAccount field** |
| `Version uint8` | In storage slot `VersionSlot` | **Promoted to StateAccount field** |
| `Root common.Hash` | Storage trie root | **Unchanged** |
| `CodeHash []byte` | Contract code hash | **Unchanged** |

### What is eliminated

- `CommitmentSlot` storage slot — no longer needed
- `HandleSlot` storage slot — no longer needed
- `VersionSlot` storage slot — no longer needed
- `NonceSlot` storage slot — no longer needed (unified into `StateAccount.Nonce`)
- `core/priv/state.go` Get/Set via storage slots — replaced by direct StateAccount access
- Dual balance mutation paths — single encrypted path

---

# 3. Existing Infrastructure That Makes This Feasible

gtos already has all the cryptographic primitives needed:

| Operation | Existing implementation | Location |
|-----------|------------------------|----------|
| Encrypted addition | `AddCiphertexts(a, b)` | `core/priv/state.go` |
| Encrypted subtraction | `SubCiphertexts(a, b)` | `core/priv/state.go` |
| Add plaintext to encrypted | `AddScalarToCiphertext(ct, amount)` | `core/priv/state.go` |
| Zero ciphertext | `ZeroCiphertext()` | `core/priv/types.go` |
| Range proofs | `ProveAggregatedRangeProof()` | `crypto/priv/prove.go` |
| Commitment equality | `ProveCommitmentEquality()` | `crypto/priv/prove.go` |
| Batch verification | `BatchVerifier.Verify()` | `core/priv/batch_verify.go` |
| Client-side proof generation | Shield/PrivTransfer/Unshield proofs | `crypto/priv/` |

These are production code, not prototypes. The encrypted account model simply promotes these operations from "privacy-specific path" to "default path".

---

# 4. Detailed Design

## 4.1 StateDB Method Changes

### Balance operations

| Current method | Current behavior | New behavior |
|----------------|-----------------|-------------|
| `GetBalance(addr) *big.Int` | Return plaintext balance | **Return decrypted balance (or remove entirely)** |
| `SetBalance(addr, amount)` | Set plaintext `*big.Int` | **Remove — use `SetCommitment` instead** |
| `AddBalance(addr, amount)` | Plaintext addition | **`AddScalarToCiphertext(commitment, amount)`** |
| `SubBalance(addr, amount)` | Plaintext subtraction | **Remove — use encrypted subtraction with proof** |

### New methods

```go
// Direct commitment access
func (s *StateDB) GetCommitment(addr common.Address) [32]byte
func (s *StateDB) GetHandle(addr common.Address) [32]byte
func (s *StateDB) SetCommitment(addr common.Address, commitment [32]byte, handle [32]byte)

// Homomorphic operations
func (s *StateDB) AddScalarToBalance(addr common.Address, amount uint64) error
func (s *StateDB) AddEncryptedToBalance(addr common.Address, ct priv.Ciphertext) error
func (s *StateDB) SubEncryptedFromBalance(addr common.Address, ct priv.Ciphertext) error
```

### Nonce operations (minimal changes)

| Current method | Change |
|----------------|--------|
| `GetNonce(addr) uint64` | **No change** (type is the same) |
| `SetNonce(addr, nonce)` | **No change** (type is the same) |

The 95 call sites for nonce operations require **no type changes**. The semantic meaning shifts from "plaintext tx nonce" to "unified nonce", but the code is identical.

## 4.2 Gas Fee Handling

This is the most critical change. Current flow:

```go
// core/state_transition.go — current
st.state.SubBalance(payer, gasCost)        // deduct gas (plaintext)
st.state.AddBalance(coinbase, fee)         // pay validator (plaintext)
st.state.AddBalance(gasPayer, remaining)   // refund unused gas (plaintext)
```

### Proposed flow

```go
// core/state_transition.go — proposed
// Gas deduction: use homomorphic scalar subtraction
// The client's range proof guarantees balance >= gasCost
st.state.SubScalarFromBalance(payer, gasCost)

// Validator reward: use homomorphic scalar addition
// AddScalarToCiphertext already exists and works
st.state.AddScalarToBalance(coinbase, fee)

// Gas refund: use homomorphic scalar addition
st.state.AddScalarToBalance(gasPayer, remaining)
```

`AddScalarToCiphertext()` already exists in `core/priv/state.go` (line 139) and handles the Pedersen commitment arithmetic:

```
C' = C + amount * G    (commitment updated)
H' = H                 (handle unchanged for scalar addition)
```

For subtraction, the inverse operation:

```
C' = C - amount * G    (commitment updated)
H' = H                 (handle unchanged)
```

### Gas validation (can the sender afford gas?)

Current: `if st.state.GetBalance(payer).Cmp(gasCost) < 0 { reject }`

Proposed: **The client provides a range proof** as part of the transaction, proving:

```
balance - gasCost - transferAmount >= 0
```

This is the same pattern already used by `PrivTransferTx` — the sender proves they have enough balance without revealing the exact amount. The validator verifies the range proof instead of comparing plaintext values.

## 4.3 Block Reward Distribution

Current:

```go
// consensus/dpos/dpos.go
st.AddBalance(header.Coinbase, params.DPoSBlockReward)
```

Proposed:

```go
st.AddScalarToBalance(header.Coinbase, params.DPoSBlockReward)
```

`AddScalarToCiphertext()` adds a known plaintext amount to an encrypted balance. This is already implemented and used for fee refunds in `core/privacy_tx_prepare.go:75`.

## 4.4 Genesis Initialization

Current:

```go
// core/genesis.go
statedb.AddBalance(addr, account.Balance)
statedb.SetNonce(addr, account.Nonce)
```

Proposed:

```go
// Genesis accounts specify an initial encrypted balance
statedb.SetCommitment(addr, account.Commitment, account.Handle)
statedb.SetNonce(addr, account.Nonce)
```

Genesis config changes from:

```json
{
  "alloc": {
    "0x1234...": {
      "balance": "1000000000000000000"
    }
  }
}
```

To:

```json
{
  "alloc": {
    "0x1234...": {
      "commitment": "0xaabb...",
      "handle": "0xccdd...",
      "nonce": 0
    }
  }
}
```

The genesis tooling generates commitments from known initial balances using a deterministic randomness seed.

## 4.5 RPC Changes

| Current RPC | Change |
|-------------|--------|
| `eth_getBalance(addr)` → `*big.Int` | **Deprecated.** Returns `0` or error. |
| `tos_getPrivBalance(addr)` → commitment + handle | **Renamed to `tos_getBalance(addr)`** — returns encrypted balance |

New RPC:

```go
// Returns the encrypted balance (commitment + handle)
// Client decrypts locally using their private key
func (api *PublicBlockChainAPI) GetBalance(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*RPCEncryptedBalance, error)

type RPCEncryptedBalance struct {
    Commitment hexutil.Bytes `json:"commitment"`
    Handle     hexutil.Bytes `json:"handle"`
    Version    hexutil.Uint  `json:"version"`
    Nonce      hexutil.Uint64 `json:"nonce"`
}
```

## 4.6 RLP Encoding

Current:

```
RLP(Nonce uint64, Balance *big.Int, Root [32]byte, CodeHash []byte)
```

Proposed:

```
RLP(Nonce uint64, Root [32]byte, CodeHash []byte, Commitment [32]byte, Handle [32]byte, Version uint8)
```

**This changes the account hash → changes all state roots → requires a hard fork.**

## 4.7 Storage Slot Cleanup

After migration, the following storage slots are no longer used:

```go
// REMOVE from core/priv/state.go:
CommitmentSlot = Keccak256("gtos.priv.commitment")  // moved to StateAccount
HandleSlot     = Keccak256("gtos.priv.handle")       // moved to StateAccount
VersionSlot    = Keccak256("gtos.priv.version")      // moved to StateAccount
NonceSlot      = Keccak256("gtos.priv.nonce")         // unified with StateAccount.Nonce
```

`GetAccountState()` and `SetAccountState()` in `core/priv/state.go` are replaced by direct `StateAccount` field access.

---

# 5. Impact on Gigagas L1

## Benefits

| Benefit | Explanation |
|---------|-------------|
| **Single proving surface** | Only one balance model to prove (encrypted), not two (plaintext + encrypted) |
| **Client-side proofs already exist** | Every tx already carries range proofs — validators just verify, don't re-execute |
| **Simpler witness model** | Witness only captures commitment/handle changes, not `*big.Int` balance changes |
| **Simpler state diff** | Phase 2 `ProofBackedTransferStateDiff` has one field type, not two |
| **Aligns with "Proposer as ordering node"** | If every tx has a client-side proof, Proposer can skip execution validation |

## Interaction with Phase 1-4

| Phase | Impact |
|-------|--------|
| Phase 1 | Witness export simplified (one balance model) |
| Phase 2 | State diff materialization simplified (commitment fields only) |
| Phase 3 | Contract storage still uses storage slots (unaffected) |
| Phase 4 | Hot-path profiles are simpler (no plaintext/encrypted branching) |
| Phase 5 | No additional impact |

---

# 6. Migration Strategy

## Recommended sequencing

**Option A (recommended):** Do this BEFORE Gigagas L1 Phase 1.

- Reduces Phase 1 scope (only one balance model to handle)
- Single hard fork, then Phase 1 builds on clean foundation
- Avoids building Phase 1 infrastructure for two models and then migrating

**Option B:** Do this AFTER Gigagas L1 Phase 2.

- Phase 1-2 handle both models
- Then migrate to encrypted-only
- More total work but lower risk (Gigagas L1 is tested on existing model first)

## State migration

For existing networks:

1. At fork block, for each account:
   - If account has storage slot encrypted balance → promote to StateAccount fields
   - If account has only plaintext balance → encrypt with deterministic commitment (`AddScalarToCiphertext(ZeroCiphertext(), balance)`)
   - Delete old storage slots
2. Recompute state root with new StateAccount encoding
3. Continue from fork block with new model

---

# 7. Work Estimate

| Component | Call sites affected | Effort |
|-----------|-------------------|--------|
| `StateAccount` struct + RLP | 1 struct, 1 generated file | 1 week |
| `statedb.go` balance methods | ~50 internal methods | 2 weeks |
| `state_transition.go` gas/fee | 12 critical paths | 2 weeks |
| `state_object.go` | ~20 methods | 1 week |
| `consensus/dpos/dpos.go` reward | 1-2 call sites | 1 day |
| `genesis.go` initialization | 2-4 call sites | 2 days |
| `core/priv/state.go` cleanup | Delete slot-based access | 1 day |
| RPC (`internal/tosapi/`) | 15+ endpoints | 1 week |
| Tests | 37 test files | 2 weeks |
| Migration tooling | State migration script | 1 week |
| **Total** | | **~10 weeks, 2 engineers** |

Compared to "delete plaintext" (11-18 weeks), this is ~30% less work because:

- `Nonce` type is unchanged → 95 nonce call sites need minimal changes
- Existing homomorphic operations are reused (no new crypto code)
- `core/priv/state.go` is simplified (delete code, not write new code)

---

# 8. Risks

| Risk | Mitigation |
|------|-----------|
| **Hard fork required** | Coordinate network upgrade; testnet first |
| **State root changes** | All historical roots invalid; archival nodes need migration |
| **Performance: encrypted ops slower** | Homomorphic scalar add/sub is ~10 microseconds — negligible vs block time |
| **RPC compatibility** | Deprecation period for `eth_getBalance`; wallets/explorers must update |
| **Gas validation without plaintext** | Client range proofs already exist; same model as PrivTransferTx |

---

# 9. Files Affected

## New files

None — this is a restructuring, not new functionality.

## Modified files

| File | Change |
|------|--------|
| `core/types/state_account.go` | Replace `Balance *big.Int` with `Commitment`, `Handle`, `Version` |
| `core/types/gen_account_rlp.go` | Regenerate RLP encoding |
| `core/state/statedb.go` | Replace balance methods with commitment methods |
| `core/state/state_object.go` | Update account field access |
| `core/state_transition.go` | Gas fee handling via homomorphic operations |
| `core/priv/state.go` | Remove storage slot access (promote to StateAccount) |
| `consensus/dpos/dpos.go` | Block reward via `AddScalarToBalance` |
| `core/genesis.go` | Genesis with encrypted balances |
| `internal/tosapi/api.go` | RPC returns encrypted balance |
| 37 test files | Update balance assertions |

## Deleted code

| Location | What is removed |
|----------|----------------|
| `core/priv/state.go` | `CommitmentSlot`, `HandleSlot`, `VersionSlot`, `NonceSlot` constants |
| `core/priv/state.go` | `GetAccountState()`, `SetAccountState()` via storage slots |
| `core/state/statedb.go` | `GetBalance()`, `SetBalance()` plaintext methods |

---

# 10. Summary

The encrypted account model replaces two parallel balance systems with one:

```
Before:  StateAccount.Balance (*big.Int)  +  StorageSlot (Commitment, Handle)  =  two systems
After:   StateAccount.Commitment + Handle                                      =  one system
```

This is not adding encryption. gtos already has encryption. This is **removing the plaintext duplicate** and promoting the encrypted balance to the canonical position.

The result is:

- One balance per account (encrypted)
- One nonce per account (unified)
- One proving surface for Gigagas L1
- One state mutation path for all transfers
- Simpler code, simpler proofs, simpler state
