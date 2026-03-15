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
- Fees are plaintext `uint64` values deducted from the encrypted balance via homomorphic subtraction (aligned with X protocol). No gas model, no public Balance needed for fee payment
- Private transactions use a dedicated `PrivTransferTxType` transaction type, no longer routed via `To == PrivRouterAddress`
- Private transactions have a dedicated PrivTxPool, fully separate from the public TxPool

**Signature Type Separation**:
- `PrivTransferTxType`: **ElGamal only**. From/To fields are ElGamal compressed public keys (32 bytes each). No `SignerType` field — the signature algorithm is implicit in the transaction type
- `SignerTxType` (public): **No longer supports ElGamal**. Only secp256k1, ed25519, schnorr, secp256r1, bls12-381

---

## Design Decisions: Pubkey-as-Address Model

### Reference: X Protocol Transaction Structure

The X protocol uses a clean pubkey-as-identity model for its confidential transactions:

```rust
// X Transaction
struct Transaction {
    source: CompressedPublicKey,       // 32B — sender IS their pubkey
    data: TransactionType,             // Transfers(Vec<TransferPayload>), Burn, ...
    fee: u64,
    nonce: Nonce,                      // u64
    source_commitments: Vec<SourceCommitment>,
    range_proof: RangeProof,
    signature: Signature,              // { s: Scalar, e: Scalar } = 64B
    ...
}

// X TransferPayload
struct TransferPayload {
    destination: CompressedPublicKey,   // 32B — receiver IS their pubkey
    commitment: CompressedCommitment,   // 32B
    sender_handle: CompressedHandle,    // 32B
    receiver_handle: CompressedHandle,  // 32B
    ct_validity_proof: CiphertextValidityProof,
    ...
}
```

### GTOS PrivTransferTx Adopts Same Model

| Aspect | X Protocol | GTOS PrivTransferTx |
|--------|------------|---------------------|
| **Sender identity** | `source: CompressedPublicKey` (32B) | `From: [32]byte` (ElGamal compressed pubkey) |
| **Receiver identity** | `destination: CompressedPublicKey` (32B) | `To: [32]byte` (ElGamal compressed pubkey) |
| **Address = pubkey** | Yes, address wraps pubkey directly | Yes, From/To ARE the pubkeys |
| **Signature** | `{ s: Scalar, e: Scalar }` (64B) | `{ S: [32]byte, E: [32]byte }` (64B) |
| **SignerType field** | None (implicit) | None (implicit in tx type) |
| **Signer lookup** | Not needed — pubkey in tx | Not needed — pubkey in tx |
| **Multi-transfer** | `Vec<TransferPayload>` per tx | Single transfer per tx |
| **Ciphertext** | commitment + sender_handle + receiver_handle (3x32B) | commitment + sender_handle + receiver_handle (3x32B) |
| **Proofs** | Per-transfer CiphertextValidityProof + per-asset CommitmentEqProof + aggregated RangeProof | CiphertextValidityProof + CommitmentEqProof + RangeProof (separated) |
| **Nonce** | `nonce: u64` | `PrivNonce: uint64` |
| **Fees** | `fee: u64` + `fee_limit: u64` (plaintext, from encrypted balance) | `Fee: uint64` + `FeeLimit: uint64` (plaintext, from encrypted balance) |

**Key benefits of pubkey-as-address**:
- Signature verification uses From field directly — zero storage IO
- Proof verification uses From/To as ElGamal pubkeys directly — zero storage IO
- No need for signer metadata storage slots for priv accounts
- No `RequireElgamalSigner()` lookup at transaction execution time

---

## Phase 1: PrivTransferTx Transaction Type + core/priv Package

### Goal
Add `PrivTransferTxType` transaction type with ElGamal-only pubkey-as-address model, create `core/priv/` package to replace `core/uno/`, remove Shield/Unshield. Remove ElGamal support from `SignerTxType`.

### 1a. New Transaction Type `PrivTransferTx`

**Modify** `core/types/transaction.go`:
```go
const (
    SignerTxType       = iota  // 0x00 — existing public transactions (no ElGamal)
    PrivTransferTxType         // 0x01 — private transfer (ElGamal only)
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

// PrivTransferTx is a confidential transfer between two ElGamal accounts.
// From and To are compressed ElGamal public keys (Ristretto255), NOT hashed addresses.
// The signature is always ElGamal Ristretto-Schnorr (s, e) — no SignerType field needed.
//
// Fee model aligned with X protocol:
//   - Fee and FeeLimit are plaintext uint64 values (publicly visible)
//   - Deducted from encrypted balance via homomorphic subtraction
//   - FeeLimit is locked at build time; excess refunded after execution
//   - No gas model, no public Balance needed
//
// Ciphertext and proof structure aligned with X protocol:
//   - Transfer ciphertext: 1 shared commitment + 2 handles (sender/receiver) = 3x32B
//   - Source commitment: sender's new balance commitment = 32B
//   - Proofs separated: CiphertextValidityProof + CommitmentEqProof + RangeProof
type PrivTransferTx struct {
    ChainID   *big.Int
    PrivNonce uint64           // independent nonce for private txs
    Fee       uint64           // plaintext fee paid to validators (publicly visible)
    FeeLimit  uint64           // max fee sender is willing to pay (locked at build time)

    From      [32]byte         // sender ElGamal compressed public key = identity
    To        [32]byte         // receiver ElGamal compressed public key = identity

    // Transfer ciphertext (3 fields, aligned with X protocol)
    // Single Pedersen commitment shared by sender and receiver,
    // with separate decrypt handles per party.
    Commitment     [32]byte   // Pedersen commitment to transfer amount: C = amount*G + r*H
    SenderHandle   [32]byte   // decrypt handle under sender's key:   sender_pubkey * r
    ReceiverHandle [32]byte   // decrypt handle under receiver's key: receiver_pubkey * r

    // Source commitment: sender's new balance after transfer
    SourceCommitment [32]byte // commitment to sender's post-transfer balance

    // Proofs (separated, aligned with X protocol)
    CtValidityProof   []byte  // CiphertextValidityProof (~160B): proves ciphertext is valid for receiver
    CommitmentEqProof []byte  // CommitmentEqProof (~192B): proves source commitment equals new balance
    RangeProof        []byte  // Aggregated Bulletproof (~672B): proves all amounts in [0, 2^64)

    EncryptedMemo     []byte  // optional encrypted metadata

    // ElGamal Ristretto-Schnorr signature (fixed, no SignerType field)
    S [32]byte               // Schnorr s scalar
    E [32]byte               // Schnorr e scalar
}

// Implements TxData interface
func (tx *PrivTransferTx) txType() byte        { return PrivTransferTxType }
func (tx *PrivTransferTx) chainID() *big.Int    { return tx.ChainID }
func (tx *PrivTransferTx) gas() uint64          { return 0 }            // no gas model
func (tx *PrivTransferTx) txPrice() *big.Int    { return common.Big0 }  // fee via Fee/FeeLimit fields
func (tx *PrivTransferTx) value() *big.Int      { return common.Big0 }  // always 0
func (tx *PrivTransferTx) nonce() uint64        { return tx.PrivNonce }
func (tx *PrivTransferTx) to() *common.Address  { /* derive address from To pubkey */ }
func (tx *PrivTransferTx) data() []byte         { return nil }
func (tx *PrivTransferTx) accessList() AccessList { return nil }
func (tx *PrivTransferTx) gasTipCap() *big.Int  { return common.Big0 }
func (tx *PrivTransferTx) gasFeeCap() *big.Int  { return common.Big0 }
func (tx *PrivTransferTx) copy() TxData         { ... }

// Signature methods — convert between [32]byte scalars and *big.Int for TxData interface
func (tx *PrivTransferTx) rawSignatureValues() (v, r, s *big.Int) {
    return new(big.Int), new(big.Int).SetBytes(tx.S[:]), new(big.Int).SetBytes(tx.E[:])
}
func (tx *PrivTransferTx) setSignatureValues(chainID, v, r, s *big.Int) { ... }

// PrivTransferTx-specific helpers
func (tx *PrivTransferTx) FromPubkey() [32]byte { return tx.From }
func (tx *PrivTransferTx) ToPubkey() [32]byte   { return tx.To }

// FromAddress derives the common.Address for state trie access.
// This is Keccak256(From) — used for priv storage slot lookup (PrivNonce, encrypted balance).
func (tx *PrivTransferTx) FromAddress() common.Address {
    return common.BytesToAddress(crypto.Keccak256(tx.From[:]))
}

// ToAddress derives the common.Address for the receiver.
func (tx *PrivTransferTx) ToAddress() common.Address {
    return common.BytesToAddress(crypto.Keccak256(tx.To[:]))
}

// SenderCiphertext constructs the sender-side ciphertext from the shared commitment.
// sender_ct = (Commitment, SenderHandle)
func (tx *PrivTransferTx) SenderCiphertext() priv.Ciphertext {
    return priv.Ciphertext{Commitment: tx.Commitment, Handle: tx.SenderHandle}
}

// ReceiverCiphertext constructs the receiver-side ciphertext from the shared commitment.
// receiver_ct = (Commitment, ReceiverHandle)
func (tx *PrivTransferTx) ReceiverCiphertext() priv.Ciphertext {
    return priv.Ciphertext{Commitment: tx.Commitment, Handle: tx.ReceiverHandle}
}
```

**Signature verification** — no storage lookup needed:
```go
// Verify signature directly from the From pubkey in the transaction
func VerifyPrivTransferSignature(tx *PrivTransferTx, txHash common.Hash) bool {
    // tx.From is the compressed Ristretto pubkey
    // tx.S, tx.E are the Schnorr signature scalars
    // Verify: H * s + From * (-e) == R, then check e == hash(From, msg, R)
    return elgamalSchnorrVerify(tx.From[:], txHash[:], tx.S[:], tx.E[:])
}
```

### 1b. Remove ElGamal from SignerTxType

**Modify** `accountsigner/crypto.go`:
- Remove `SignerTypeElgamal` from `NormalizeSigner()` — return error for elgamal type
- Remove `case SignerTypeElgamal` from `AddressFromSigner()`
- Remove `case SignerTypeElgamal` from `VerifySignature()`
- Keep ElGamal crypto primitives in `crypto/priv/` for use by PrivTransferTx

**Modify** `core/state_transition.go`:
- In public tx validation, reject transactions with ElGamal signer type

### 1c. New `core/priv/` Package (evolved from core/uno/)

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

Note: `Envelope`, `ActionID`, `TransferPayload` types are no longer needed — payload is embedded directly in the `PrivTransferTx` struct. Only `Ciphertext` and `AccountState` are retained for state management. `RequireElgamalSigner()` is no longer needed — the pubkey is directly in the transaction.

**New file** `core/priv/state.go`:
```go
var (
    CommitmentSlot = crypto.Keccak256Hash([]byte("gtos.priv.commitment"))
    HandleSlot     = crypto.Keccak256Hash([]byte("gtos.priv.handle"))
    VersionSlot    = crypto.Keccak256Hash([]byte("gtos.priv.version"))
    NonceSlot      = crypto.Keccak256Hash([]byte("gtos.priv.nonce"))
)

// State functions take common.Address (derived from pubkey) for storage slot access.
func GetAccountState(db vm.StateDB, account common.Address) AccountState
func SetAccountState(db vm.StateDB, account common.Address, st AccountState)
func GetPrivNonce(db vm.StateDB, account common.Address) uint64
func IncrementPrivNonce(db vm.StateDB, account common.Address) uint64
func IncrementVersion(db vm.StateDB, account common.Address) (uint64, error)
```

**New file** `core/priv/signature.go`:
```go
// ElGamal Ristretto-Schnorr signature verification.
// No storage lookup needed — pubkey comes directly from the transaction.
func VerifySchnorrSignature(pubkey [32]byte, message []byte, s, e [32]byte) bool
func SignSchnorr(privkey [32]byte, message []byte) (s, e [32]byte, err error)
```

**Migrated files** (trimmed from core/uno/ into core/priv/):

| Original core/uno/ file | → core/priv/ file | Changes |
|---|---|---|
| `state.go` | `state.go` | Rename slots to gtos.priv.*, add NonceSlot |
| `context.go` | `context.go` | Keep only BuildPrivTransferTranscriptContext; bind Fee/FeeLimit to transcript |
| `verify.go` | `verify.go` | Separate verifiers: VerifyCiphertextValidityProof, VerifyCommitmentEqProof, VerifyRangeProof |
| `proofs.go` | `proofs.go` | Separate proof decoding for each proof type |
| `errors.go` | `errors.go` | Unchanged |
| `prover.go` | `prover.go` | Keep only BuildTransferPayloadProof |

**Deleted files/code**:
- `core/uno/types.go`: Envelope, ShieldPayload, UnshieldPayload, ActionID constants
- `core/uno/codec.go`: entire file (Envelope encode/decode no longer needed)
- `core/uno/protocol_constants.go`: ProtocolPayloadPrefix "GTOSUNO1" no longer needed
- `core/uno/signer.go`: RequireElgamalSigner no longer needed (pubkey in tx)
- All Shield/Unshield related context, verify, prover functions
- **Delete entire `core/uno/` directory after migration**

### 1d. Update `params/tos_params.go`

```go
// Delete
PrivacyRouterAddress                    // routing address no longer needed
UNOBaseGas, UNOShieldGas, UNOTransferGas, UNOUnshieldGas
UNOMaxPayloadBytes, UNOMaxProofBytes

// Add
PrivBaseFee         uint64 = 10_000     // base fee per private transfer (in TOS smallest unit)
PrivMaxProofBytes          = 96 * 1024
```

### 1e. Update `core/state_transition.go`

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

// applyPrivTransfer() — reads directly from tx fields, no Envelope decoding, no signer lookup
//
// Fee model (aligned with X protocol):
//   - Fee and FeeLimit are plaintext uint64 values
//   - At tx build time, sender locks FeeLimit into the SourceCommitment:
//       new_balance = old_balance - fee_limit - transfer_amount
//   - At execution time, validator computes required_fee and determines refund:
//       refund = fee_limit - actual_fee_paid
//   - Refund is added back to sender's encrypted balance via homomorphic addition
//   - No public Balance is touched — fees come entirely from encrypted balance
func (st *StateTransition) applyPrivTransfer() error {
    ptx := st.msg.inner.(*types.PrivTransferTx)

    // 1. Derive addresses from pubkeys (for state trie access)
    fromAddr := ptx.FromAddress()  // Keccak256(From pubkey)
    toAddr := ptx.ToAddress()      // Keccak256(To pubkey)

    // 2. Verify ElGamal Schnorr signature using From pubkey directly
    //    (already done in tx validation, but double-check here)

    // 3. Validate and compute fee
    requiredFee := priv.EstimateRequiredFee(ptx)
    if requiredFee > ptx.FeeLimit {
        return ErrInsufficientFee
    }
    var feePaid, refund uint64
    if requiredFee > ptx.Fee {
        // Fee field too low, but FeeLimit covers it
        feePaid = requiredFee
        refund = ptx.FeeLimit - requiredFee
    } else {
        feePaid = ptx.Fee
        refund = ptx.FeeLimit - ptx.Fee
    }

    // 4. Validate PrivNonce
    expectedNonce := priv.GetPrivNonce(st.state, fromAddr)
    if ptx.PrivNonce != expectedNonce { return ErrNonceMismatch }

    // 5. Get sender/receiver AccountState
    senderState := priv.GetAccountState(st.state, fromAddr)
    receiverState := priv.GetAccountState(st.state, toAddr)

    // 6. Verify proofs using ptx.From/To directly as ElGamal pubkeys — zero IO
    //
    // The sender built SourceCommitment with fee_limit already deducted:
    //   source_new_balance = old_balance - fee_limit - transfer_amount
    //   SourceCommitment = Pedersen(source_new_balance, opening)
    //
    // The verifier reconstructs the encrypted output:
    //   output_ct = Scalar(fee_limit) + sender_ct
    //   new_sender_balance_ct = old_sender_ct - output_ct
    //
    // Proof verification (3 separate proofs, aligned with X protocol):
    //   a) CiphertextValidityProof: proves commitment & handles are valid
    //   b) CommitmentEqProof: proves SourceCommitment matches new_sender_balance_ct
    //   c) RangeProof: aggregated Bulletproof proving all amounts in [0, 2^64)

    senderCt := ptx.SenderCiphertext()
    receiverCt := ptx.ReceiverCiphertext()

    if err := priv.VerifyCiphertextValidityProof(
        ptx.Commitment, ptx.SenderHandle, ptx.ReceiverHandle,
        ptx.From, ptx.To, ptx.CtValidityProof); err != nil {
        return err
    }

    // output = fee_limit (as scalar) + sender_ct (transfer ciphertext)
    // new_sender_balance_ct = old_sender_ct - output
    outputCt := priv.AddScalarToCiphertext(senderCt, ptx.FeeLimit)
    newSenderBalanceCt := priv.SubCiphertexts(senderState.Ciphertext, outputCt)

    if err := priv.VerifyCommitmentEqProof(
        ptx.From, newSenderBalanceCt, ptx.SourceCommitment,
        ptx.CommitmentEqProof); err != nil {
        return err
    }

    if err := priv.VerifyRangeProof(
        ptx.SourceCommitment, ptx.Commitment,
        ptx.RangeProof); err != nil {
        return err
    }

    // 7. Update sender state
    //    Start from SourceCommitment (which has fee_limit already deducted)
    senderState.Ciphertext = priv.Ciphertext{
        Commitment: ptx.SourceCommitment,
        Handle:     newSenderBalanceCt.Handle,
    }

    //    Refund excess fee back to sender's encrypted balance
    if refund > 0 {
        senderState.Ciphertext = priv.AddScalarToCiphertext(senderState.Ciphertext, refund)
    }

    senderState.Version++
    priv.SetAccountState(st.state, fromAddr, senderState)

    // 8. Update receiver state: add transfer ciphertext to existing balance
    receiverState.Ciphertext = priv.AddCiphertexts(receiverState.Ciphertext, receiverCt)
    receiverState.Version++
    priv.SetAccountState(st.state, toAddr, receiverState)

    // 9. Increment PrivNonce
    priv.IncrementPrivNonce(st.state, fromAddr)

    // 10. Record fee paid (for block reward distribution)
    st.addPrivFee(feePaid)

    return nil
}
```

**Delete**:
- Entire `applyUNO()` function
- `toAddr == params.PrivacyRouterAddress` branch in `TransitionDb()`

### 1f. Update `core/parallel/analyze.go`

```go
// Analyze by tx.Type(), no longer by To address
switch msg.Type() {
case types.PrivTransferTxType:
    ptx := msg.inner.(*types.PrivTransferTx)
    fromAddr := ptx.FromAddress()
    toAddr := ptx.ToAddress()
    as.WriteAddrs[fromAddr] = struct{}{}
    as.ReadAddrs[fromAddr] = struct{}{}
    as.WriteAddrs[toAddr] = struct{}{}
    as.ReadAddrs[toAddr] = struct{}{}
default:
    // existing logic
}
```

### 1g. Remove ElGamal from `accountsigner/`

**Modify** `accountsigner/crypto.go`:
```go
// Remove from supported signer types for public transactions:
// - Delete SignerTypeElgamal constant (or mark as deprecated/rejected)
// - NormalizeSigner(): return ErrUnknownSignerType for "elgamal"
// - AddressFromSigner(): remove case SignerTypeElgamal
// - VerifySignature(): remove case SignerTypeElgamal

// Keep ElGamal crypto primitives — they move to crypto/priv/ package
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

Note: For priv accounts in genesis, the address key in GenesisAlloc IS the Keccak256 of the ElGamal pubkey. The pubkey itself is implied by the signer metadata (SignerType="elgamal", SignerValue=hex pubkey). At genesis time the signer slot is still written so that the address↔pubkey mapping is discoverable.

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
// Verify the address matches the ElGamal pubkey (address = Keccak256(pubkey))
if account.SignerType != "elgamal" {
    return fmt.Errorf("genesis alloc %s: priv account requires elgamal signer", addr.Hex())
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
    mu          sync.RWMutex

    currentState  *state.StateDB
    pendingNonces *privTxNoncer     // uses PrivNonce

    pending map[common.Address]*txList   // keyed by FromAddress(), ordered by PrivNonce
    queue   map[common.Address]*txList
    all     *txLookup
    priced  *txFeeList                   // sorted by Fee (not gas price)

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
    // 2. Verify ElGamal Schnorr signature using From pubkey (zero IO)
    // 3. Fee >= PrivBaseFee and FeeLimit >= Fee
    // 4. PrivNonce validation (read from storage slot at FromAddress())
    // 5. Validate From/To are valid Ristretto255 compressed points
    // 6. Proof size validation: CtValidityProof (~160B), CommitmentEqProof (~192B), RangeProof (~672B)
}
```

### Block Assembly Integration

Modify `miner/worker.go`:
```go
// Pull transactions from both pools
func (w *worker) commitWork() {
    publicTxs := w.txPool.Pending()       // sorted by gas price
    privTxs   := w.privTxPool.Pending()   // sorted by fee
    // Commit public txs first, then priv txs (or interleave by priority)
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
| `tos_getUNOCiphertext` | `priv_getBalance` | Query encrypted balance by pubkey |
| `tos_unoDecryptBalance` | `priv_decryptBalance` | Client-side balance decryption |
| `personal_unoBalance` | `priv_personalBalance` | Decrypt using keystore |
| — | `priv_getNonce` | New: query on-chain PrivNonce by pubkey |
| — | `priv_pendingNonce` | New: PrivTxPool virtual nonce |

**RPC Structures**:
```go
type RPCPrivTransferArgs struct {
    From                hexutil.Bytes    // 32-byte ElGamal pubkey
    To                  hexutil.Bytes    // 32-byte ElGamal pubkey
    PrivNonce           *hexutil.Uint64
    Fee                 *hexutil.Uint64  // plaintext fee
    FeeLimit            *hexutil.Uint64  // max fee willing to pay
    Commitment          hexutil.Bytes    // 32B: shared Pedersen commitment
    SenderHandle        hexutil.Bytes    // 32B: decrypt handle for sender
    ReceiverHandle      hexutil.Bytes    // 32B: decrypt handle for receiver
    SourceCommitment    hexutil.Bytes    // 32B: sender's new balance commitment
    CtValidityProof     hexutil.Bytes    // ~160B
    CommitmentEqProof   hexutil.Bytes    // ~192B
    RangeProof          hexutil.Bytes    // ~672B
    EncryptedMemo       hexutil.Bytes
    // Signature provided separately or signed server-side
}

type RPCPrivBalanceResult struct {
    Pubkey      hexutil.Bytes    // 32-byte ElGamal pubkey
    Commitment  hexutil.Bytes
    Handle      hexutil.Bytes
    Version     hexutil.Uint64
    PrivNonce   hexutil.Uint64
    BlockNumber hexutil.Uint64
}
```

`priv_transfer` RPC builds a `PrivTransferTx`, signs with ElGamal Schnorr, and submits to `PrivTxPool`.

---

## Phase 5: CLI and Tooling Update

### Rename `cmd/toskey/uno_tx.go` → `cmd/toskey/priv_tx.go`

- Remove `shield`, `unshield` subcommands
- `transfer` → `priv-transfer`, builds `PrivTransferTx` with ElGamal pubkeys as From/To

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
| `signer_test.go` | Deleted | No more signer lookup for priv txs |

### New Tests
- `core/types/priv_transfer_tx_test.go` — PrivTransferTx RLP encode/decode, ElGamal Schnorr sign/verify
- `core/priv/signature_test.go` — Schnorr signature round-trip, invalid pubkey rejection
- `core/priv/state_test.go` — PrivNonce increments independently, does not affect public Nonce
- `core/priv_tx_pool_test.go` — PrivTxPool ordering by PrivNonce, gap handling, no conflict with TxPool
- `core/priv_state_transition_test.go` — End-to-end: genesis alloc → PrivTransferTx → verify balance change
- `core/priv_isolation_test.go` — Public/private isolation: PrivTransfer does not change Balance, public transfer does not change PrivBalance
- `accountsigner/crypto_test.go` — Verify ElGamal signer type is rejected for SignerTxType

---

## Phase 7: Crypto Layer Update

### `crypto/uno/` → `crypto/priv/`

| File | Changes |
|------|---------|
| `verify.go` | Rename package to priv, remove Shield/Unshield wrappers |
| `prove.go` | Remove Shield/Unshield proof generation |
| `elgamal.go` | Rename package to priv, absorb ElGamal primitives from accountsigner |
| `ecdlp.go` | Rename package to priv, code unchanged |
| `backend.go` | Rename package to priv |

### New `crypto/priv/schnorr.go`

ElGamal Ristretto-Schnorr sign/verify extracted from `accountsigner/crypto.go` into dedicated file.

### `crypto/ed25519/uno_proofs_*.go`

Low-level C bindings are **not renamed** (C function names do not affect the Go API). Go wrapper functions are re-exported through the `crypto/priv/` layer.

### `accountsigner/crypto.go`

Remove ElGamal signing/verification code (moved to `crypto/priv/`). Remove `SignerTypeElgamal` from all switch statements.

---

## File Change Summary

```
New (12+ files):
  core/types/priv_transfer_tx.go        — PrivTransferTx type + TxData interface impl
  core/priv/types.go                    — Ciphertext, AccountState
  core/priv/state.go                    — Storage slot read/write, PrivNonce
  core/priv/signature.go                — ElGamal Ristretto-Schnorr sign/verify
  core/priv/context.go                  — Merlin transcript context (binds fee/fee_limit to proofs)
  core/priv/fee.go                      — EstimateRequiredFee, fee validation, refund logic
  core/priv/verify.go                   — VerifyCiphertextValidityProof, VerifyCommitmentEqProof, VerifyRangeProof
  core/priv/proofs.go                   — Proof size constants and decoding for each proof type
  core/priv/errors.go                   — Error definitions
  core/priv/prover.go                   — Proof generation (client-side)
  crypto/priv/schnorr.go                — Schnorr primitives (from accountsigner)
  core/priv_tx_pool.go                  — Dedicated private transaction pool
  core/priv_tx_noncer.go                — PrivNonce management

Delete:
  core/uno/                             — entire directory

Modify (~15 files):
  core/types/transaction.go             — Add PrivTransferTxType, extend encode/decode
  params/tos_params.go                  — Remove UNO constants, add Priv constants, remove PrivacyRouterAddress
  core/state_transition.go              — Route by tx.Type(), add applyPrivTransfer()
  core/parallel/analyze.go              — Analyze by tx.Type()
  core/genesis.go                       — Rename GenesisAccount fields
  core/gen_genesis_account.go           — Regenerate
  accountsigner/crypto.go              — Remove ElGamal support from public tx signing
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

- **Phase 1**: `go build ./...` compiles with no UNO references remaining; PrivTransferTx RLP encode/decode is correct; 3-field ciphertext round-trip works; separated proofs verify correctly; fee deduction from encrypted balance with refund works; ElGamal Schnorr signature round-trip works; ElGamal rejected in SignerTxType
- **Phase 2**: Genesis allocates PrivBalance, chain boots, `priv_getBalance` returns correct ciphertext
- **Phase 3**: PrivTxPool orders by PrivNonce, does not interfere with TxPool; P2P routes correctly by type
- **Phase 4**: End-to-end RPC: `priv_transfer` → block produced → `priv_getBalance` reflects balance change
- **Phase 6**: All public/private isolation tests pass
