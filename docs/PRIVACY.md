# PrivAccount Dual-Account System Implementation Plan

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                     GTOS Node                         │
│                                                        │
│   ┌──────────────┐          ┌───────────────┐         │
│   │   TxPool      │          │  PrivTxPool    │        │
│   │  (public tx)  │          │ (private tx)   │        │
│   │  SignerTxType  │          │ PrivTransferTx │        │
│   │  uses Nonce   │          │ uses PrivNonce  │        │
│   └──────┬───────┘          └───────┬────────┘        │
│          │                           │                  │
│          ▼                           ▼                  │
│   ┌───────────────────────────────────────────┐        │
│   │           Block Assembly                   │       │
│   │    public txs + private txs mixed          │       │
│   └──────────────────┬────────────────────────┘        │
│                      │                                  │
│                      ▼                                  │
│   ┌───────────────────────────────────────────┐        │
│   │          State Transition                  │       │
│   │  switch tx.Type() {                        │       │
│   │    case SignerTxType:       applyPublic()  │       │
│   │    case PrivTransferTxType: applyPriv()    │       │
│   │  }                                         │       │
│   └──────────────────┬────────────────────────┘        │
│                      │                                  │
│                      ▼                                  │
│   ┌───────────────────────────────────────────┐        │
│   │       StateDB (per address)                │       │
│   │                                            │       │
│   │  Account Trie:                             │       │
│   │    { Nonce, Balance, Root, CodeHash }      │       │
│   │                                            │       │
│   │  Storage Slots (same trie):                │       │
│   │    gtos.priv.commitment → 32B              │       │
│   │    gtos.priv.handle     → 32B              │       │
│   │    gtos.priv.version    → uint64           │       │
│   │    gtos.priv.nonce      → uint64           │       │
│   └───────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────┘
```

**Core Principles**:
- Full public/private isolation. PrivBalance is allocated only at genesis; afterwards only PrivTransfer (private-to-private) is supported
- Gas is paid from the public Balance
- Private transactions use a dedicated `PrivTransferTxType` transaction type, no longer routed via `To == PrivRouterAddress`
- Private transactions have a dedicated PrivTxPool, fully separate from the public TxPool

---

## Phase 1: PrivTransferTx Transaction Type + core/priv Package

### Goal
Add `PrivTransferTxType` transaction type, create `core/priv/` package to replace `core/uno/`, remove Shield/Unshield.

### 1a. New Transaction Type `PrivTransferTx`

**Modify** `core/types/transaction.go`:
```go
const (
    SignerTxType       = iota  // 0x00 — existing public transactions
    PrivTransferTxType         // 0x01 — private transfer
)
```

Add case in `decodeTyped()`:
```go
case PrivTransferTxType:
    var inner PrivTransferTx
    err := rlp.DecodeBytes(b[1:], &inner)
    return &inner, err
```

Relax type checks in `EncodeRLP()`/`MarshalBinary()` to support PrivTransferTxType.

**New file** `core/types/priv_transfer_tx.go`:
```go
package types

type PrivTransferTx struct {
    ChainID   *big.Int
    PrivNonce uint64             // independent nonce for private txs (validated against storage slot)
    Gas       uint64
    GasPrice  *big.Int           // gas paid from public Balance

    From      common.Address     // sender
    To        common.Address     // receiver

    // Privacy payload (direct fields, no Envelope wrapping)
    NewSenderCommitment     [32]byte
    NewSenderHandle         [32]byte
    ReceiverDeltaCommitment [32]byte
    ReceiverDeltaHandle     [32]byte
    ProofBundle             []byte   // 1032 bytes (CTValidity 160 + Balance 200 + Range 672)
    EncryptedMemo           []byte

    // Signature (ElGamal)
    SignerType string
    V *big.Int
    R *big.Int
    S *big.Int
}

// Implements TxData interface
func (tx *PrivTransferTx) txType() byte      { return PrivTransferTxType }
func (tx *PrivTransferTx) chainID() *big.Int  { return tx.ChainID }
func (tx *PrivTransferTx) gas() uint64        { return tx.Gas }
func (tx *PrivTransferTx) txPrice() *big.Int  { return tx.GasPrice }
func (tx *PrivTransferTx) value() *big.Int    { return common.Big0 }  // always 0
func (tx *PrivTransferTx) nonce() uint64      { return tx.PrivNonce }
func (tx *PrivTransferTx) to() *common.Address { return &tx.To }
func (tx *PrivTransferTx) data() []byte        { return nil }         // payload in dedicated fields
func (tx *PrivTransferTx) accessList() AccessList { return nil }
func (tx *PrivTransferTx) gasTipCap() *big.Int { return tx.GasPrice }
func (tx *PrivTransferTx) gasFeeCap() *big.Int { return tx.GasPrice }
func (tx *PrivTransferTx) copy() TxData { ... }
func (tx *PrivTransferTx) rawSignatureValues() (v, r, s *big.Int) { return tx.V, tx.R, tx.S }
func (tx *PrivTransferTx) setSignatureValues(chainID, v, r, s *big.Int) { ... }
```

**Advantages over PrivRouterAddress routing**:

| | `To == PrivRouterAddress` (old) | `PrivTransferTxType` (new) |
|---|---|---|
| **Pool routing** | Must decode Data to identify private txs | `tx.Type()` routes directly to PrivTxPool |
| **Field design** | Reuses SignerTx; To/Value/Data are redundant | Dedicated fields, no redundancy |
| **Nonce** | Reuses public Nonce or hacks storage slot | `PrivNonce` field carried directly |
| **RLP encoding** | Data nests "GTOSPRV1" + Envelope, double encoding | Single-layer RLP |
| **P2P broadcast** | Extra logic to distinguish which pool | Routes by TxType directly |

### 1b. New `core/priv/` Package (evolved from core/uno/)

**New file** `core/priv/types.go`:
```go
package priv

const CiphertextSize = 32

type Ciphertext struct {
    Commitment [CiphertextSize]byte
    Handle     [CiphertextSize]byte
}

type AccountState struct {
    Ciphertext Ciphertext
    Version    uint64
    Nonce      uint64  // independent nonce for private transactions
}
```

Note: `Envelope`, `ActionID`, `TransferPayload` types are no longer needed — payload is embedded directly in the `PrivTransferTx` struct. Only `Ciphertext` and `AccountState` are retained for state management.

**New file** `core/priv/state.go`:
```go
var (
    CommitmentSlot = crypto.Keccak256Hash([]byte("gtos.priv.commitment"))
    HandleSlot     = crypto.Keccak256Hash([]byte("gtos.priv.handle"))
    VersionSlot    = crypto.Keccak256Hash([]byte("gtos.priv.version"))
    NonceSlot      = crypto.Keccak256Hash([]byte("gtos.priv.nonce"))
)

func GetAccountState(db vm.StateDB, account common.Address) AccountState
func SetAccountState(db vm.StateDB, account common.Address, st AccountState)
func GetPrivNonce(db vm.StateDB, account common.Address) uint64
func IncrementPrivNonce(db vm.StateDB, account common.Address) uint64
func IncrementVersion(db vm.StateDB, account common.Address) (uint64, error)
```

**Migrated files** (trimmed from core/uno/ into core/priv/):

| Original core/uno/ file | → core/priv/ file | Changes |
|---|---|---|
| `state.go` | `state.go` | Rename slots to gtos.priv.*, add NonceSlot |
| `context.go` | `context.go` | Keep only BuildPrivTransferTranscriptContext |
| `verify.go` | `verify.go` | Keep only VerifyTransferProofBundle |
| `proofs.go` | `proofs.go` | Keep only Transfer proof decoding |
| `signer.go` | `signer.go` | RequireElgamalSigner unchanged |
| `errors.go` | `errors.go` | Unchanged |
| `prover.go` | `prover.go` | Keep only BuildTransferPayloadProof |

**Deleted files/code**:
- `core/uno/types.go`: Envelope, ShieldPayload, UnshieldPayload, ActionID constants
- `core/uno/codec.go`: entire file (Envelope encode/decode no longer needed, payload in tx fields)
- `core/uno/protocol_constants.go`: ProtocolPayloadPrefix "GTOSUNO1" no longer needed
- All Shield/Unshield related context, verify, prover functions
- **Delete entire `core/uno/` directory after migration**

### 1c. Update `params/tos_params.go`

```go
// Delete
PrivacyRouterAddress                    // routing address no longer needed
UNOBaseGas, UNOShieldGas, UNOTransferGas, UNOUnshieldGas
UNOMaxPayloadBytes, UNOMaxProofBytes

// Add
PrivTransferGas     uint64 = 650_000    // uniform gas
PrivMaxProofBytes          = 96 * 1024
```

### 1d. Update `core/state_transition.go`

```go
// TransitionDb() routing now based on tx.Type()
func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
    ...
    switch st.msg.Type() {
    case types.PrivTransferTxType:
        snap := st.state.Snapshot()
        vmerr = st.applyPrivTransfer()
        if vmerr != nil {
            st.state.RevertToSnapshot(snap)
        }
    default:
        // existing public transaction logic (LVM, plain transfers, etc.)
    }
    ...
}

// applyPrivTransfer() — reads directly from tx fields, no Envelope decoding
func (st *StateTransition) applyPrivTransfer() error {
    ptx := st.msg.inner.(*types.PrivTransferTx)

    // 1. Require sender has ElGamal signer
    senderPubkey, err := priv.RequireElgamalSigner(st.state, ptx.From)

    // 2. Charge gas: PrivTransferGas (deducted from public Balance)
    if !st.useGas(params.PrivTransferGas) { return ErrOutOfGas }

    // 3. Validate PrivNonce
    expectedNonce := priv.GetPrivNonce(st.state, ptx.From)
    if ptx.PrivNonce != expectedNonce { return ErrNonceTooHigh/Low }

    // 4. Get sender/receiver AccountState
    senderState := priv.GetAccountState(st.state, ptx.From)
    receiverPubkey, err := priv.RequireElgamalSigner(st.state, ptx.To)
    receiverState := priv.GetAccountState(st.state, ptx.To)

    // 5. Construct Ciphertext and verify proof bundle
    newSender := priv.Ciphertext{Commitment: ptx.NewSenderCommitment, Handle: ptx.NewSenderHandle}
    receiverDelta := priv.Ciphertext{Commitment: ptx.ReceiverDeltaCommitment, Handle: ptx.ReceiverDeltaHandle}
    // ... verify CT-Validity + Balance + Range proofs

    // 6. Update state
    senderState.Ciphertext = newSender
    senderState.Version++
    priv.SetAccountState(st.state, ptx.From, senderState)

    receiverState.Ciphertext = priv.AddCiphertexts(receiverState.Ciphertext, receiverDelta)
    receiverState.Version++
    priv.SetAccountState(st.state, ptx.To, receiverState)

    // 7. Increment PrivNonce
    priv.IncrementPrivNonce(st.state, ptx.From)

    return nil
}
```

**Delete**:
- Entire `applyUNO()` function
- `toAddr == params.PrivacyRouterAddress` branch in `TransitionDb()`

### 1e. Update `core/parallel/analyze.go`

```go
// Analyze by tx.Type(), no longer by To address
switch msg.Type() {
case types.PrivTransferTxType:
    ptx := msg.inner.(*types.PrivTransferTx)
    as.WriteAddrs[ptx.From] = struct{}{}
    as.ReadAddrs[ptx.From] = struct{}{}
    as.WriteAddrs[ptx.To] = struct{}{}
    as.ReadAddrs[ptx.To] = struct{}{}
default:
    // existing logic
}
```

---

## Phase 2: Genesis PrivBalance Allocation

### 2a. Update `core/genesis.go` — GenesisAccount

```go
type GenesisAccount struct {
    Code       []byte                      `json:"code,omitempty"`
    Storage    map[common.Hash]common.Hash `json:"storage,omitempty"`
    Balance    *big.Int                    `json:"balance" gencodec:"required"`
    Nonce      uint64                      `json:"nonce,omitempty"`
    PrivateKey []byte                      `json:"secretKey,omitempty"`

    SignerType  string `json:"signerType,omitempty"`
    SignerValue string `json:"signerValue,omitempty"`

    // Renamed UNO → Priv
    PrivCommitment []byte `json:"priv_commitment,omitempty"`
    PrivHandle     []byte `json:"priv_handle,omitempty"`
    PrivVersion    uint64 `json:"priv_version,omitempty"`
    PrivNonce      uint64 `json:"priv_nonce,omitempty"`
}
```

### 2b. Update `applyExtendedGenesisAccount()`

```go
hasPriv := len(account.PrivCommitment) > 0 || len(account.PrivHandle) > 0
if !hasPriv {
    return nil
}
if len(account.PrivCommitment) != priv.CiphertextSize ||
   len(account.PrivHandle) != priv.CiphertextSize {
    return fmt.Errorf("genesis alloc %s: priv_commitment/priv_handle must be %d bytes",
        addr.Hex(), priv.CiphertextSize)
}
if _, err := priv.RequireElgamalSigner(statedb, addr); err != nil {
    return fmt.Errorf("genesis alloc %s: priv account requires elgamal signer: %w", addr.Hex(), err)
}
var st priv.AccountState
copy(st.Ciphertext.Commitment[:], account.PrivCommitment)
copy(st.Ciphertext.Handle[:], account.PrivHandle)
st.Version = account.PrivVersion
st.Nonce = account.PrivNonce
priv.SetAccountState(statedb, addr, st)
```

### 2c. Rename `scripts/gen_genesis_uno_ct/` → `scripts/gen_genesis_priv_ct/`

Rename script and update output JSON field names to `priv_commitment`, `priv_handle`, etc.

### 2d. Regenerate `core/gen_genesis_account.go`

Run gencodec to generate new MarshalJSON/UnmarshalJSON.

---

## Phase 3: PrivTxPool — Dedicated Private Transaction Pool

### New file `core/priv_tx_pool.go`

```go
type PrivTxPool struct {
    config      PrivTxPoolConfig
    chainconfig *params.ChainConfig
    chain       blockChain
    signer      types.Signer
    mu          sync.RWMutex

    currentState  *state.StateDB
    pendingNonces *privTxNoncer     // uses PrivNonce

    pending map[common.Address]*txList
    queue   map[common.Address]*txList
    all     *txLookup
    priced  *txPricedList

    chainHeadCh  chan ChainHeadEvent      // shared chain head events
    chainHeadSub event.Subscription

    txFeed event.Feed                     // dedicated feed for miner subscription
    scope  event.SubscriptionScope
}
```

### New file `core/priv_tx_noncer.go`

```go
type privTxNoncer struct {
    fallback *state.StateDB
    nonces   map[common.Address]uint64
    lock     sync.Mutex
}

func (txn *privTxNoncer) get(addr common.Address) uint64 {
    txn.lock.Lock()
    defer txn.lock.Unlock()
    if _, ok := txn.nonces[addr]; !ok {
        // Read PrivNonce from storage slot, not account.Nonce
        txn.nonces[addr] = priv.GetPrivNonce(txn.fallback, addr)
    }
    return txn.nonces[addr]
}
```

### Transaction Validation

```go
func (pool *PrivTxPool) validateTx(tx *types.Transaction) error {
    // 1. tx.Type() must be PrivTransferTxType
    // 2. Sender must have ElGamal signer
    // 3. Public Balance >= gas cost (gas still paid from public balance)
    // 4. PrivNonce validation (read from storage slot)
    // 5. ProofBundle size validation (== 1032 bytes)
}
```

### Block Assembly Integration

Modify `miner/worker.go`:
```go
// Pull transactions from both pools, sort by gas price
func (w *worker) commitWork() {
    publicTxs := w.txPool.Pending()
    privTxs   := w.privTxPool.Pending()
    // Merge-sort and commit
}
```

### P2P Broadcast

Modify P2P layer to route by `tx.Type()`:
- `SignerTxType` → broadcast to TxPool subscribers
- `PrivTransferTxType` → broadcast to PrivTxPool subscribers

### Node Startup

Modify `cmd/gtos/` or `tos/backend.go`:
```go
privPool := core.NewPrivTxPool(privPoolConfig, chainConfig, eth.BlockChain())
```

---

## Phase 4: RPC Interface Update

### Modify `internal/tosapi/api.go`

**Delete**:
- `UnoShield()`, `UnoUnshield()` and their RPC types
- `RPCUNOShieldArgs`, `RPCUNOUnshieldArgs`

**Rename**:

| Old RPC | New RPC | Description |
|---------|---------|-------------|
| `tos_unoTransfer` | `priv_transfer` | Build and submit PrivTransferTx |
| `tos_getUNOCiphertext` | `priv_getBalance` | Query encrypted balance |
| `tos_unoDecryptBalance` | `priv_decryptBalance` | Client-side balance decryption |
| `personal_unoBalance` | `priv_personalBalance` | Decrypt using keystore |
| — | `priv_getNonce` | New: query on-chain PrivNonce |
| — | `priv_pendingNonce` | New: PrivTxPool virtual nonce |

**RPC Structures**:
```go
type RPCPrivTransferArgs struct {
    From                    common.Address
    To                      common.Address
    PrivNonce               *hexutil.Uint64  // private nonce
    Gas                     *hexutil.Uint64
    GasPrice                *hexutil.Big
    NewSenderCommitment     hexutil.Bytes
    NewSenderHandle         hexutil.Bytes
    ReceiverDeltaCommitment hexutil.Bytes
    ReceiverDeltaHandle     hexutil.Bytes
    ProofBundle             hexutil.Bytes
    EncryptedMemo           hexutil.Bytes
}

type RPCPrivBalanceResult struct {
    Address     common.Address
    Commitment  hexutil.Bytes
    Handle      hexutil.Bytes
    Version     hexutil.Uint64
    PrivNonce   hexutil.Uint64
    BlockNumber hexutil.Uint64
}
```

`priv_transfer` RPC builds a `PrivTransferTx`, signs it, and submits to `PrivTxPool`.

---

## Phase 5: CLI and Tooling Update

### Rename `cmd/toskey/uno_tx.go` → `cmd/toskey/priv_tx.go`

- Remove `shield`, `unshield` subcommands
- `transfer` → `priv-transfer`, builds `PrivTransferTx` instead of SignerTx + Envelope

### Rename `scripts/gen_genesis_uno_ct/` → `scripts/gen_genesis_priv_ct/`

---

## Phase 6: Test Update

### Deleted Tests
- Shield/Unshield test cases in `core/uno_state_transition_test.go`
- Shield/Unshield tests in `core/uno_reorg_test.go`

### Migrated Tests (core/uno/*_test.go → core/priv/*_test.go)

| Old file | New file | Changes |
|----------|----------|---------|
| `codec_test.go` | Deleted | Envelope encode/decode tests no longer needed |
| `context_test.go` | `context_test.go` | Keep only Transfer context tests |
| `state_test.go` | `state_test.go` | Add PrivNonce read/write tests |
| `verify_test.go` | `verify_test.go` | Keep only Transfer verify tests |
| `signer_test.go` | `signer_test.go` | Unchanged |

### New Tests
- `core/types/priv_transfer_tx_test.go` — PrivTransferTx RLP encode/decode, sign/verify
- `core/priv/state_test.go` — PrivNonce increments independently, does not affect public Nonce
- `core/priv_tx_pool_test.go` — PrivTxPool ordering by PrivNonce, gap handling, no conflict with TxPool
- `core/priv_state_transition_test.go` — End-to-end: genesis alloc → PrivTransferTx → verify balance change
- `core/priv_isolation_test.go` — Public/private isolation: PrivTransfer does not change Balance, public transfer does not change PrivBalance

---

## Phase 7: Crypto Layer Update

### `crypto/uno/` → `crypto/priv/`

| File | Changes |
|------|---------|
| `verify.go` | Rename package to priv, remove Shield/Unshield wrappers |
| `prove.go` | Remove Shield/Unshield proof generation |
| `elgamal.go` | Rename package to priv, code unchanged |
| `ecdlp.go` | Rename package to priv, code unchanged |
| `backend.go` | Rename package to priv |

### `crypto/ed25519/uno_proofs_*.go`

Low-level C bindings are **not renamed** (C function names do not affect the Go API). Go wrapper functions are re-exported through the `crypto/priv/` layer.

---

## File Change Summary

```
New (11+ files):
  core/types/priv_transfer_tx.go        — PrivTransferTx type + TxData interface impl
  core/priv/types.go                    — Ciphertext, AccountState
  core/priv/state.go                    — Storage slot read/write, PrivNonce
  core/priv/context.go                  — Merlin transcript context
  core/priv/verify.go                   — Proof verification
  core/priv/proofs.go                   — Proof decoding
  core/priv/signer.go                   — ElGamal signer validation
  core/priv/errors.go                   — Error definitions
  core/priv/prover.go                   — Proof generation (client-side)
  core/priv_tx_pool.go                  — Dedicated private transaction pool
  core/priv_tx_noncer.go                — PrivNonce management

Delete:
  core/uno/                             — entire directory
  core/uno/codec.go                     — Envelope encode/decode (no longer needed)
  core/uno/protocol_constants.go        — "GTOSUNO1" prefix (no longer needed)

Modify (~15 files):
  core/types/transaction.go             — Add PrivTransferTxType, extend encode/decode
  params/tos_params.go                  — Remove UNO constants, add Priv constants, remove PrivacyRouterAddress
  core/state_transition.go              — Route by tx.Type(), add applyPrivTransfer()
  core/parallel/analyze.go              — Analyze by tx.Type()
  core/genesis.go                       — Rename GenesisAccount fields
  core/gen_genesis_account.go           — Regenerate
  internal/tosapi/api.go                — Rename RPCs + remove Shield/Unshield
  cmd/toskey/uno_tx.go → priv_tx.go     — Rename CLI
  miner/worker.go                       — Integrate PrivTxPool
  tos/backend.go (or cmd/gtos/)         — Initialize PrivTxPool
  tos/handler.go (P2P)                  — Route broadcast by tx.Type()
  internal/unotracker/                  — Rename to privtracker/
```

---

## Implementation Sequence

```
Phase 1 (PrivTransferTx type + core/priv package + state_transition)  ← first, ensure compilation
    │
Phase 2 (Genesis update)                    ← ensure chain boots
    │
Phase 3 (PrivTxPool + P2P routing)          ← dedicated mempool
    │
Phase 4 (RPC)                               ← external interface
    │
Phase 5 (CLI tooling)
    │
Phase 6 (Tests)                             ← throughout all phases
    │
Phase 7 (Crypto layer cleanup)              ← last, lowest risk
```

---

## Verification Strategy

- **Phase 1**: `go build ./...` compiles with no UNO references remaining; PrivTransferTx RLP encode/decode is correct
- **Phase 2**: Genesis allocates PrivBalance, chain boots, `priv_getBalance` returns correct ciphertext
- **Phase 3**: PrivTxPool orders by PrivNonce, does not interfere with TxPool; P2P routes correctly by type
- **Phase 4**: End-to-end RPC: `priv_transfer` → block produced → `priv_getBalance` reflects balance change
- **Phase 6**: All public/private isolation tests pass
