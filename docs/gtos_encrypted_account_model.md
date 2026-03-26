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

# 8. System Action and Transaction Type Impact

## 8.1 System action audit: 52 actions, only 10 need changes

gtos has 52 system action types across 19 handler modules. The vast majority are pure metadata operations that never touch plaintext balance.

### Actions that touch plaintext balance (10 actions — must migrate)

All 10 follow the same pattern: `SubBalance(from, amount)` + `AddBalance(registry, amount)` for deposits/stakes, or the reverse for withdrawals. The migration is uniform: replace with `SubScalarFromBalance` / `AddScalarToBalance`.

| Action | Handler | What it does | Migration |
|--------|---------|-------------|-----------|
| `VALIDATOR_REGISTER` | `validator/handler.go` | Lock validator stake | `SubBalance` → `SubScalarFromBalance` |
| `VALIDATOR_WITHDRAW` | `validator/handler.go` | Refund validator stake | `AddBalance` → `AddScalarToBalance` |
| `AGENT_REGISTER` | `agent/handler.go` | Lock agent stake | Same pattern |
| `AGENT_INCREASE_STAKE` | `agent/handler.go` | Add to agent stake | Same pattern |
| `AGENT_DECREASE_STAKE` | `agent/handler.go` | Refund agent stake | Same pattern |
| `TASK_SCHEDULE` | `task/handler.go` | Task deposit | Same pattern |
| `TASK_CANCEL` | `task/handler.go` | Refund task deposit | Same pattern |
| `LEASE_RENEW` | `lease/handler.go` | Lease deposit | Same pattern |
| `LEASE_CLOSE` | `lease/handler.go` | Refund lease deposit | Same pattern |
| `TNS_REGISTER` | `tns/handler.go` | Domain registration fee | Same pattern |

**Estimated effort:** ~1 week. All 10 actions use the same deposit/withdraw pattern.

### Actions that do NOT touch balance (42 actions — no changes needed)

These are pure metadata operations (write storage slots, update registries, set permissions):

- **Policy wallet** (11 actions): SetSpendCaps, SetAllowlist, SetTerminalPolicy, AuthorizeDelegate, RevokeDelegate, SetGuardian, InitiateRecovery, CancelRecovery, CompleteRecovery, Suspend, Unsuspend, SetAuditorKey
- **Package registry** (7 actions): RegisterPublisher, SetPublisherStatus, Publish, Deprecate, Revoke, DisputeNamespace, ResolveNamespace
- **Registry/Verifier/PayPolicy** (10 actions): RegisterCap, DeprecateCap, RevokeCap, GrantDelegation, RevokeDelegation, RegisterVerifier, DeactivateVerifier, AttestVerification, RevokeVerification, RegisterPayPolicy, DeactivatePayPolicy
- **Capability** (3 actions): Register, Grant, Revoke
- **Gateway** (3 actions): Register, Update, Deregister
- **Settlement** (3 actions): RegisterCallback, ExecuteCallback, FulfillAsync
- **KYC** (2 actions): Set, Suspend
- **Delegation** (2 actions): MarkUsed, Revoke
- **Group** (2 actions): Register, StateCommit
- **Reputation** (2 actions): AuthorizeScorer, RecordScore
- **Referral** (1 action): Bind
- **AccountSigner** (1 action): SetSigner
- **Validator maintenance** (2 actions): EnterMaintenance, ExitMaintenance

**No system actions need to be deleted.**

### Registry accounts that accumulate balance

These system contract addresses currently hold plaintext balance from deposits/stakes:

| Address | What it holds |
|---------|---------------|
| `ValidatorRegistryAddress` | Validator stakes |
| `AgentRegistryAddress` | Agent stakes |
| `LeaseRegistryAddress` | Lease deposits |
| `TNSRegistryAddress` | Registration fees |
| `TaskSchedulerAddress` | Task deposits |

After migration, these accounts hold **encrypted balance** (Commitment + Handle) instead of plaintext `*big.Int`. The homomorphic operations handle this transparently.

## 8.2 Transaction type changes

### ShieldTx and UnshieldTx become obsolete

With no plaintext balance, there is no need to bridge between plaintext and encrypted:

- `ShieldTx (0x02)`: converts plaintext → encrypted. **Delete** — no plaintext to shield from.
- `UnshieldTx (0x03)`: converts encrypted → plaintext. **Delete** — no plaintext to unshield to.

### Remaining transaction types

| Tx type | Status | Change |
|---------|--------|--------|
| `SignerTx (0x00)` | **Keep** | Gas fees use encrypted operations; value transfers use encrypted path |
| `PrivTransferTx (0x01)` | **Keep** | Already fully encrypted, no changes needed |
| `ShieldTx (0x02)` | **Delete** | No plaintext balance to shield from |
| `UnshieldTx (0x03)` | **Delete** | No plaintext balance to unshield to |

Transaction types reduce from 4 to 2:

```
Before:  SignerTx + PrivTransferTx + ShieldTx + UnshieldTx  (4 types)
After:   SignerTx + PrivTransferTx                          (2 types)
```

### SignerTx changes

`SignerTx` remains the general-purpose transaction type but its internal execution changes:

| Operation | Before | After |
|-----------|--------|-------|
| Gas deduction | `SubBalance(payer, gasCost)` | `SubScalarFromBalance(payer, gasCost)` |
| Value transfer | `Transfer(from, to, amount)` | Encrypted transfer with client-side proof |
| Fee to coinbase | `AddBalance(coinbase, fee)` | `AddScalarToBalance(coinbase, fee)` |
| Gas refund | `AddBalance(payer, remaining)` | `AddScalarToBalance(payer, remaining)` |

## 8.3 Impact on Gigagas L1 proving surface

With ShieldTx and UnshieldTx deleted, the Phase 1 proving target simplifies:

```
Before:  4 tx types to prove (native transfer, shield, priv transfer, unshield)
After:   2 tx types to prove (SignerTx encrypted transfer, PrivTransferTx)
```

This directly reduces the proof circuit complexity for Phase 1-2.

## 8.4 Additional work estimate for system actions and tx types

| Item | Effort |
|------|--------|
| Migrate 10 system actions (uniform pattern) | ~1 week |
| Delete ShieldTx + UnshieldTx (code + tests) | ~1 week |
| Modify SignerTx gas/transfer path | ~2 weeks (included in section 7 estimate) |
| 42 metadata-only actions | **0** |

---

# 9. Risks

| Risk | Mitigation |
|------|-----------|
| **Hard fork required** | Coordinate network upgrade; testnet first |
| **State root changes** | All historical roots invalid; archival nodes need migration |
| **Performance: encrypted ops slower** | Homomorphic scalar add/sub is ~10 microseconds — negligible vs block time |
| **RPC compatibility** | Deprecation period for `eth_getBalance`; wallets/explorers must update |
| **Gas validation without plaintext** | Client range proofs already exist; same model as PrivTransferTx |

---

# 10. Files Affected

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
| `core/types/transaction.go` | `ShieldTxType` (0x02), `UnshieldTxType` (0x03) constants |
| `core/privacy_tx_prepare.go` | Shield and unshield execution paths |
| Related test files | Shield/unshield test cases |

---

# 11. Summary

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
