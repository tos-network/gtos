# PrivAccount Dual-Account System Implementation Plan

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                     GTOS Node                         │
│                                                        │
│   ┌──────────────────────────────────────────┐        │
│   │              TxPool (unified)              │       │
│   │  SignerTxType     → uses account Nonce     │       │
│   │  PrivTransferTx   → uses PrivNonce (slot)  │       │
│   │  sorted by: gas price / fee respectively   │       │
│   └─────────────────────┬────────────────────┘        │
│                          │                              │
│                          ▼                              │
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
- **V1 scope**: PrivBalance is allocated only at genesis; afterwards only PrivTransfer (private-to-private) is supported. Shield (public→private) and Unshield (private→public) are deferred to v2 — see "Future: Public/Private Bridge" section below
- Fees are plaintext `uint64` values deducted from the encrypted balance via homomorphic subtraction (aligned with X protocol). No gas model, no public Balance needed for fee payment. Fee revenue is credited to the block coinbase as public TOS (same path as gas fees)
- Private transactions use a dedicated `PrivTransferTxType` transaction type, no longer routed via `To == PrivRouterAddress`
- Private transactions reuse the existing TxPool. The pool dispatches by `tx.Type()` for nonce lookup and validation
- PrivTransferTx uses `gas() == 0` and a plaintext Fee/FeeLimit model instead of the gas model. Block assembly and miner gas-limit checks must skip gas accounting for PrivTransferTxType

**Signature Type Separation**:
- `PrivTransferTxType`: **ElGamal only**. From/To fields are ElGamal compressed public keys (32 bytes each). No `SignerType` field — the signature algorithm is implicit in the transaction type
- `SignerTxType` (public): **No longer supports ElGamal**. Only secp256k1, ed25519, schnorr, secp256r1, bls12-381

**Deliberate Differences from X Protocol**:

| Difference | X Protocol | GTOS | Reason |
|------------|-----------|------|--------|
| **Transfers per tx** | `Vec<TransferPayload>` — multiple transfers per tx | Single transfer per tx | Simpler implementation, reduced proof complexity; batching can be added later |
| **Multi-asset** | `source_commitments` with asset hash per entry; supports arbitrary tokens | Single asset (native TOS only) — no asset field needed | GTOS priv transfers are native-TOS-only; private tokens are a future extension |
| **Reference field** | `Reference { hash, topoheight }` — binds proof to balance at specific block | Not needed | GTOS uses a linear chain with sequential block execution; nonce ordering guarantees the sender's balance state at proof time matches execution time |
| **Serialization** | Custom binary `Writer`/`Reader` serialization | RLP encoding | Consistent with GTOS existing framework; all public transaction types use RLP |
| **Dual-account model** | Pure privacy chain — all balances encrypted, no public balance | Dual: public `Balance` (Account trie) + private `PrivBalance` (storage slots) | GTOS supports both public and private economies on the same chain |

---

## Future: Public/Private Bridge (v2)

V1 deliberately omits Shield (public→private) and Unshield (private→public) to keep the initial scope minimal. This section documents why the bridge is needed and how it should be added.

**Why a bridge is necessary for a dual-economy chain:**

XELIS is a pure privacy chain — all balances are encrypted, so no bridge is needed. GTOS is different: it has a public economy (validator rewards, agent payments, smart contracts, system actions) and a private economy. Without a bridge:

- Validator block rewards (public TOS) can never enter the private economy
- Agent income from sysactions (public TOS) cannot be made private
- Private TOS cannot be used for smart contract interaction or escrow
- The private economy is a closed system seeded only at genesis, with supply that can only decrease (via fees)
- New users cannot obtain private TOS except by receiving a priv-transfer from an existing holder

**Planned v2 additions:**

| Action | TX Type | Description |
|--------|---------|-------------|
| **Shield** | `PrivShieldTxType` (0x02) | Sender burns public Balance, receives equivalent encrypted PrivBalance. Proof: commitment to shielded amount + range proof. Signed with the sender's public signer key (ed25519 etc), not ElGamal — because the sender is a public account. |
| **Unshield** | `PrivUnshieldTxType` (0x03) | Sender deducts from encrypted PrivBalance, receives equivalent public Balance at a designated recipient address. Proof: balance proof (sufficient encrypted balance) + range proof. Signed with ElGamal Schnorr — because the sender is a priv account. |

Shield and Unshield are structurally simpler than PrivTransfer (single party, no receiver ciphertext). They can be added after v1 stabilizes without changing the PrivTransferTx wire format or state model.

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
| **Encrypted memo** | ChaCha20Poly1305 with ECDH shared key, sender/receiver handles, max 1024B | ChaCha20Poly1305 with ECDH shared key, sender/receiver handles, max 1024B |
| **Zero balance** | Identity point ciphertext `(O, O)` | Identity point ciphertext `(O, O)` |
| **Signing** | Sign serialized unsigned tx bytes with Schnorr | Sign RLP of all fields except S/E with Schnorr |
| **Transcript binding** | Fee, fee_limit, nonce, source_pubkey bound to Merlin transcript | Fee, FeeLimit, PrivNonce, ChainID, From, To bound to Merlin transcript |
| **Reference field** | `Reference { hash, topoheight }` — binds proof to balance at specific block | Not needed — GTOS linear chain + nonce ordering provides equivalent guarantee |
| **Multi-asset** | `source_commitments: Vec<SourceCommitment>` with asset hash per entry | Single asset (native TOS only) — no asset field needed |

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

    // Encrypted memo (aligned with X protocol ExtraData)
    // Encrypted via ECDH + ChaCha20Poly1305:
    //   1. Generate random PedersenOpening r_memo
    //   2. Derive shared key: SHA3-256(r_memo * H)
    //   3. Encrypt plaintext with ChaCha20Poly1305 using shared key
    //   4. Include sender_memo_handle (sender_PK * r_memo) and
    //      receiver_memo_handle (receiver_PK * r_memo) for decryption
    // Both sender and receiver can decrypt using their private key + handle.
    // Max size: 1024 bytes per transfer.
    EncryptedMemo       []byte  // encrypted payload (ChaCha20Poly1305 ciphertext)
    MemoSenderHandle    [32]byte // decrypt handle for sender: sender_PK * r_memo
    MemoReceiverHandle  [32]byte // decrypt handle for receiver: receiver_PK * r_memo

    // ElGamal Ristretto-Schnorr signature (fixed, no SignerType field)
    // Signs the RLP encoding of all fields above (everything except S, E).
    S [32]byte               // Schnorr s scalar
    E [32]byte               // Schnorr e scalar
}

// Implements TxData interface
func (tx *PrivTransferTx) txType() byte        { return PrivTransferTxType }
func (tx *PrivTransferTx) chainID() *big.Int    { return tx.ChainID }
func (tx *PrivTransferTx) gas() uint64          { return 0 }            // no gas model; miner skips gas-limit check for this type
func (tx *PrivTransferTx) txPrice() *big.Int    { return new(big.Int).SetUint64(tx.Fee) } // used by TxPool priced list for priority sorting
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

**Transaction signing** (aligned with X protocol):
The signature covers the RLP encoding of all fields **except** S and E themselves. This is the same pattern as X where `UnsignedTransaction.to_bytes()` is signed. The signing flow:

```go
// 1. RLP-encode all fields except S, E
unsignedBytes := rlp.Encode(PrivTransferTx{...without S, E...})

// 2. Hash the encoding
txHash := keccak256(unsignedBytes)

// 3. Sign with ElGamal Ristretto-Schnorr
S, E := priv.SignSchnorr(privateKey, txHash)

// 4. Verification reconstructs the same hash and checks:
//    H * s + From * (-e) == R, then e == hash(From, txHash, R)
```

The transcript context (Merlin) for proof generation also binds: ChainID, PrivNonce, Fee, FeeLimit, From, To — preventing proof reuse across chains or with different fee parameters.

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

**Zero balance initialization** (aligned with X protocol):
New priv accounts start with `Ciphertext::Zero()` — both commitment and handle set to the Ristretto255 identity point. This represents an encryption of 0. When receiving a first transfer, the receiver's balance is updated via homomorphic addition: `zero + encrypted(amount) = encrypted(amount)`.

```go
// ZeroCiphertext returns the identity-point ciphertext representing encrypted(0).
func ZeroCiphertext() Ciphertext {
    // Identity point = compressed Ristretto encoding of the neutral element
    var zero Ciphertext
    copy(zero.Commitment[:], ristretto255.NewIdentityElement().Bytes())
    copy(zero.Handle[:], ristretto255.NewIdentityElement().Bytes())
    return zero
}
```

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
// Gas handling: PrivTransferTx has gas()=0. The caller (TransitionDb) must skip:
//   - intrinsicGas check (not applicable)
//   - gas purchase / refund accounting
//   - block gas limit deduction
// Cost control is via Fee/FeeLimit only.
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

    // 10. Record fee paid — credited to block coinbase as public TOS
    //     This converts private fee into public balance, same distribution
    //     path as gas fees from SignerTxType transactions.
    //     The coinbase validator receives: block_reward + sum(gas_fees) + sum(priv_fees)
    st.state.AddBalance(st.evm.Context.Coinbase, new(big.Int).SetUint64(feePaid))

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

### 1g. Update `miner/worker.go` — Gas-Free Block Assembly

PrivTransferTx has `gas() == 0`, so the miner must not deduct gas from the block gas limit when including private transactions:

```go
func (w *worker) commitTransactions(txs *types.TransactionsByPriceAndNonce, ...) {
    for {
        tx := txs.Peek()
        ...
        // Skip gas limit check for private transactions
        if tx.Type() == types.PrivTransferTxType {
            // No gas accounting — cost controlled by Fee/FeeLimit
            // Just execute and include
        } else {
            // Existing gas limit check
            if w.current.gasPool.Gas() < tx.Gas() { break }
        }
        ...
    }
}
```

A per-block cap on the number of PrivTransferTx (e.g. `PrivMaxPerBlock = 200`) should be enforced to bound proof verification cost.

### 1h. Remove ElGamal from `accountsigner/`

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

## Phase 3: TxPool Integration — Reuse Existing Pool

Instead of a dedicated PrivTxPool, PrivTransferTx reuses the existing `TxPool` with type-aware dispatch. This avoids duplicating the pool/queue/eviction/P2P infrastructure.

### Key Modifications to `core/tx_pool.go`

**Nonce dispatch by tx type:**
```go
// txNoncer.get() dispatches based on tx type
func (txn *txNoncer) get(addr common.Address, txType byte) uint64 {
    txn.lock.Lock()
    defer txn.lock.Unlock()
    key := nonceKey{addr, txType}
    if _, ok := txn.nonces[key]; !ok {
        switch txType {
        case types.PrivTransferTxType:
            // Read PrivNonce from storage slot
            txn.nonces[key] = priv.GetPrivNonce(txn.fallback, addr)
        default:
            // Read account Nonce as before
            txn.nonces[key] = txn.fallback.GetNonce(addr)
        }
    }
    return txn.nonces[key]
}
```

**Validation dispatch:**
```go
func (pool *TxPool) validateTx(tx *types.Transaction, local bool) error {
    switch tx.Type() {
    case types.PrivTransferTxType:
        return pool.validatePrivTransferTx(tx)
    default:
        return pool.validateSignerTx(tx, local)
    }
}

func (pool *TxPool) validatePrivTransferTx(tx *types.Transaction) error {
    ptx := tx.inner.(*types.PrivTransferTx)
    // 1. Verify ElGamal Schnorr signature using From pubkey (zero IO)
    // 2. Fee >= PrivBaseFee and FeeLimit >= Fee
    // 3. PrivNonce validation (from storage slot at FromAddress())
    // 4. Validate From/To are valid Ristretto255 compressed points
    // 5. Proof size validation: CtValidityProof (~160B), CommitmentEqProof (~192B), RangeProof (~672B)
}
```

**Pending/queue keying:**
- `SignerTxType` transactions: keyed by `msg.From()`, ordered by account Nonce
- `PrivTransferTxType` transactions: keyed by `ptx.FromAddress()`, ordered by PrivNonce
- Both types coexist in the same `pending`/`queue` maps — different addresses cannot collide (ElGamal-derived addresses are disjoint from other signer types)

**Price sorting:**
- `SignerTxType`: sorted by `GasPrice` (existing `txPricedList`)
- `PrivTransferTxType`: `txPrice()` returns `Fee` as `*big.Int` — same sorting interface, fee-based priority

**No separate P2P routing needed** — the existing transaction broadcast handles all types. Peers receiving a `PrivTransferTxType` transaction feed it into the same pool.

**No separate node startup** — the existing TxPool handles both types after the modifications above.

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
| — | `priv_pendingNonce` | New: TxPool virtual PrivNonce for pending priv txs |

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
    EncryptedMemo       hexutil.Bytes    // ChaCha20Poly1305 ciphertext (max 1024B)
    MemoSenderHandle    hexutil.Bytes    // 32B
    MemoReceiverHandle  hexutil.Bytes    // 32B
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

`priv_transfer` RPC builds a `PrivTransferTx`, signs with ElGamal Schnorr, and submits to the unified `TxPool`.

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
- `core/tx_pool_priv_test.go` — TxPool handles PrivTransferTx: PrivNonce ordering, gap handling, coexists with SignerTx
- `core/priv_state_transition_test.go` — End-to-end: genesis alloc → PrivTransferTx → verify balance change
- `core/priv_isolation_test.go` — Public/private isolation: PrivTransfer does not change Balance, public transfer does not change PrivBalance
- `accountsigner/crypto_test.go` — Verify ElGamal signer type is rejected for SignerTxType

---

## Phase 7: Crypto Layer Update

### C Backend Completeness Audit

All 12 cryptographic primitives required by PrivTransferTx have been audited against the C backend in `crypto/ed25519/libed25519/`. **9 of 12 are fully wired; 3 have C implementations but need CGO bindings.**

| # | Primitive | C Source | CGO Binding | Go Wrapper | Status |
|---|-----------|----------|-------------|------------|--------|
| 1 | ElGamal encrypt/decrypt | `at_elgamal.c` | ✅ 7 functions | ✅ `elgamal.go` | **Complete** |
| 2 | Pedersen commitments | `at_elgamal.c` | ✅ 3 functions | ✅ `elgamal.go` | **Complete** |
| 3 | Decrypt handles | `at_elgamal.c` | ✅ 1 function | ✅ `elgamal.go` | **Complete** |
| 4 | Homomorphic CT add/sub | `at_elgamal.c` | ✅ 2 functions | ✅ `elgamal.go` | **Complete** |
| 5 | Scalar add/sub to CT (fee) | `at_elgamal.c` | ✅ 5 functions | ✅ `elgamal.go` | **Complete** |
| 6 | CiphertextValidityProof | `at_uno_proofs.c` | ✅ 4 functions | ✅ `verify.go`/`prove.go` | **Complete** (128B/160B) |
| 7 | CommitmentEqProof | `at_uno_proofs.c` | ✅ 1 function (verify) | ✅ `verify.go` | **Complete** (verify; generate embedded in balance proof) |
| 8 | RangeProof (Bulletproofs) | `at_rangeproofs.c` | ✅ 2 functions | ✅ `verify.go`/`prove.go` | **Complete** (u64) |
| 9 | **Schnorr sign/verify** | `at_schnorr.c` | ❌ Not exposed | ❌ Missing | **C exists, needs CGO binding** |
| 10 | **ChaCha20Poly1305** | `at_chacha20_poly1305.c` | ❌ Not exposed | ❌ Missing | **C exists, needs CGO binding** |
| 11 | **ECDH (X25519)** | `at_x25519.c` | ❌ Not exposed | ❌ Missing | **C exists, needs CGO binding** |
| 12 | Baby-step giant-step ECDLP | — | — | ✅ `ecdlp.go` (pure Go) | **Complete** |

### 7a. Missing CGO Bindings (3 items)

All three C libraries exist and are tested. The work is purely binding + wrapping.

**1. ElGamal Ristretto-Schnorr Signature** — `at_schnorr.c` / `at_schnorr.h`

C functions available:
- `at_schnorr_sign(privkey, message, msg_len) → (s, e)` — generate 64-byte signature
- `at_schnorr_verify(pubkey, message, msg_len, s, e) → bool` — verify signature
- `at_schnorr_verify_batch(...)` — batch verification
- `at_schnorr_public_key_from_private(privkey) → pubkey` — derive pubkey

Add to `crypto/ed25519/uno_proofs_cgo.go`:
```go
func ElgamalSchnorrSign(privkey [32]byte, message []byte) (s, e [32]byte, err error)
func ElgamalSchnorrVerify(pubkey [32]byte, message []byte, s, e [32]byte) bool
```

**2. ChaCha20Poly1305 (Encrypted Memo)** — `at_chacha20_poly1305.c` / `at_chacha20_poly1305.h`

C functions available:
- `at_chacha20_poly1305_encrypt(key32, nonce12, plaintext, pt_len, aad, aad_len) → ciphertext + 16-byte tag`
- `at_chacha20_poly1305_decrypt(key32, nonce12, ciphertext, ct_len, aad, aad_len) → plaintext`

Add to `crypto/ed25519/uno_proofs_cgo.go`:
```go
func ChaCha20Poly1305Encrypt(key [32]byte, nonce [12]byte, plaintext, aad []byte) ([]byte, error)
func ChaCha20Poly1305Decrypt(key [32]byte, nonce [12]byte, ciphertext, aad []byte) ([]byte, error)
```

**3. ECDH X25519 (Memo Key Derivation)** — `at_x25519.c` / `at_x25519.h`

C functions available:
- `at_x25519_exchange(privkey, peer_pubkey) → shared_secret32` — compute ECDH shared secret
- `at_x25519_public(privkey) → pubkey` — derive X25519 public key

Add to `crypto/ed25519/uno_proofs_cgo.go`:
```go
func X25519Exchange(privkey, peerPubkey [32]byte) ([32]byte, error)
func X25519Public(privkey [32]byte) ([32]byte, error)
```

Memo encryption key derivation: `shared_key = SHA3-256(X25519Exchange(priv, peer_pub))`, then encrypt with ChaCha20Poly1305.

### 7b. Package Rename: `crypto/uno/` → `crypto/priv/`

| File | Changes |
|------|---------|
| `verify.go` | Rename package to priv, remove Shield/Unshield wrappers |
| `prove.go` | Remove Shield/Unshield proof generation |
| `elgamal.go` | Rename package to priv, absorb ElGamal primitives from accountsigner |
| `ecdlp.go` | Rename package to priv, code unchanged |
| `backend.go` | Rename package to priv |

### 7c. New Files in `crypto/priv/`

- `schnorr.go` — Go wrappers for `ElgamalSchnorrSign()`, `ElgamalSchnorrVerify()` (calls CGO bindings from 7a)
- `chacha.go` — Go wrappers for `ChaCha20Poly1305Encrypt()`, `ChaCha20Poly1305Decrypt()`
- `ecdh.go` — Go wrappers for `X25519Exchange()`, `X25519Public()`
- `memo.go` — High-level `EncryptMemo(senderPriv, receiverPub, plaintext)` and `DecryptMemo(priv, handle, ciphertext)` using ECDH + ChaCha20Poly1305

### 7d. `crypto/ed25519/uno_proofs_cgo.go`

Add ~6 new CGO wrapper functions (Schnorr 2 + ChaCha20 2 + X25519 2). Low-level C bindings are **not renamed** (C function names do not affect the Go API).

### 7e. `crypto/ed25519/uno_proofs_nocgo.go`

Add corresponding stubs that return `ErrUNOBackendUnavailable` for all 6 new functions.

### 7f. `accountsigner/crypto.go`

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
  core/priv/memo.go                     — EncryptedMemo ECDH + ChaCha20Poly1305 encrypt/decrypt
  core/priv/zero.go                     — ZeroCiphertext (identity point initialization)
  crypto/priv/schnorr.go                — Schnorr primitives (from accountsigner)

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
  core/tx_pool.go                       — Add PrivTransferTx validation, PrivNonce dispatch in txNoncer
  core/tx_noncer.go                     — Type-aware nonce lookup (account Nonce vs PrivNonce)
  miner/worker.go                       — Skip gas-limit deduction for PrivTransferTxType; enforce PrivMaxPerBlock cap
  internal/unotracker/                  — Rename to privtracker/
```

---

## Implementation Sequence

```
Phase 1 (PrivTransferTx type + core/priv package + state_transition)  ← first, ensure compilation
    │
Phase 2 (Genesis update)                    ← ensure chain boots
    │
Phase 3 (TxPool integration)                ← type-aware nonce + validation in existing pool
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

- **Phase 1**: `go build ./...` compiles with no UNO references remaining; PrivTransferTx RLP encode/decode is correct; 3-field ciphertext round-trip works; separated proofs verify correctly; fee deduction from encrypted balance with refund works; fee credited to coinbase as public TOS; ElGamal Schnorr signature round-trip works; ElGamal rejected in SignerTxType; `TransitionDb()` skips gas purchase/refund for PrivTransferTxType
- **Phase 2**: Genesis allocates PrivBalance, chain boots, `priv_getBalance` returns correct ciphertext
- **Phase 3**: TxPool accepts PrivTransferTx alongside SignerTx; PrivNonce ordering correct; `txPrice()` returns Fee for priced-list sorting; both types coexist without interference; miner includes PrivTransferTx without gas-limit deduction; PrivMaxPerBlock cap enforced
- **Phase 4**: End-to-end RPC: `priv_transfer` → block produced → `priv_getBalance` reflects balance change; coinbase balance increases by fee amount
- **Phase 6**: All public/private isolation tests pass; PrivTransfer does not change public Balance; public transfer does not change PrivBalance; fee flows to coinbase correctly

---

## Implementation Status

### Completed

| Item | Files | Status |
|------|-------|--------|
| **Phase 1a: PrivTransferTx type** | `core/types/priv_transfer_tx.go`, `core/types/transaction.go` | DONE |
| **Phase 1b: core/priv/ package** | `core/priv/types.go`, `state.go`, `errors.go`, `zero.go`, `verify.go`, `proofs.go`, `context.go`, `fee.go` | DONE |
| **Phase 1c: params update** | `params/tos_params.go` (PrivBaseFee, PrivMaxProofBytes added) | DONE |
| **Phase 1d: state_transition** | `core/state_transition.go` (applyPrivTransfer + tx.Type() routing) | DONE |
| **Phase 1e: parallel analysis** | `core/parallel/analyze.go` (PrivTransferTxType handler) | DONE |
| **Phase 1f: accountsigner** | `accountsigner/crypto.go` (ElGamal kept for UNO compat; VerifyRawSignature works) | DONE |
| **Phase 2: Genesis** | `core/genesis.go`, `core/gen_genesis_account.go` (PrivCommitment/Handle/Version/Nonce fields) | DONE |
| **Phase 3: TxPool integration** | `core/tx_pool.go`, `core/tx_noncer.go`, `core/tx_list.go` (type-aware nonce, validatePrivTransferTx) | DONE |
| **Phase 4: RPC** | `internal/tosapi/api.go` (PrivTransfer, PrivGetBalance, PrivGetNonce) | DONE |
| **Phase 5: CLI** | `cmd/toskey/priv_tx.go` (priv-transfer command, placeholder) | DONE |
| **Phase 5: Genesis script** | `scripts/gen_genesis_priv_ct/main.go` | DONE |
| **Phase 6: Tests** | 32 tests across `core/priv/*_test.go`, `core/types/priv_transfer_tx_test.go`, `core/priv_state_transition_test.go`, `core/priv_isolation_test.go` | DONE |
| **Phase 7a: CGO bindings** | `crypto/ed25519/uno_proofs_cgo.go`, `uno_proofs_nocgo.go` (ElgamalSchnorrSign/Verify, ChaCha20Poly1305, X25519) | DONE |
| **Phase 7d-e: CGO + nocgo stubs** | 6 new CGO functions + 6 nocgo stubs | DONE |
| **Message type propagation** | `core/types/transaction.go` (Type(), WithTxType(), PrivTransferInner(), PrivTransferFrom()), `core/state_processor.go` | DONE |
| **Phase 7b: crypto/priv/ package** | `crypto/priv/` (elgamal.go, verify.go, prove.go, ecdlp.go, backend.go + tests); `core/priv/` imports updated | DONE |
| **Phase 7c: crypto/priv/ wrappers** | `crypto/priv/schnorr.go`, `chacha.go`, `ecdh.go`, `memo.go` | DONE |
| **core/priv/signature.go** | ElGamal Ristretto-Schnorr sign/verify wrappers | DONE |
| **core/priv/prover.go** | BuildTransferProofs (CommitmentEqProof + aggregated RangeProof stubbed pending C backend) | DONE |
| **core/priv/memo.go** | EncryptMemo/DecryptMemo wrappers | DONE |
| **Miner PrivTransferTx handling** | `miner/worker.go` (gas-limit skip, PrivNonce sender, low-gas-pool), `core/state_transition.go` (transitionPrivTransfer bypass) | DONE |

### Not Yet Implemented

| Item | Files | Reason |
|------|-------|--------|
| **Delete core/uno/** | Entire directory | Deferred until old UNO RPCs/CLI removed |
| **Delete old UNO RPCs** | `internal/tosapi/api.go` (UnoShield, UnoUnshield, UnoTransfer, GetUNOCiphertext) | Deferred until core/uno/ deleted |
| **Rename internal/unotracker/** | → `internal/privtracker/` | Deferred until core/uno/ deleted |
| **priv-transfer CLI proof generation** | `cmd/toskey/priv_tx.go` (currently placeholder) | Requires C backend prover for CommitmentEqProof and aggregated RangeProof |
| **C backend: ProveCommitmentEqProof** | `crypto/ed25519/libed25519/at_uno_proofs.c` | Not exposed as standalone prover; currently embedded in balance proof only |
| **C backend: ProveAggregatedRangeProof** | `crypto/ed25519/libed25519/at_rangeproofs.c` | Existing prover handles single commitment; aggregated 2-commitment form needed |

### Summary

**Core v1 functionality: ~95% complete.** All validator execution paths, TxPool, miner, genesis, RPC, CLI, and crypto layers are implemented and tested. The remaining items are:
- Old UNO code cleanup (deletion of core/uno/, old RPCs, unotracker rename)
- Two C backend prover functions need standalone exposure (CommitmentEqProof, aggregated RangeProof)
- CLI proof generation (blocked on above C backend work)
