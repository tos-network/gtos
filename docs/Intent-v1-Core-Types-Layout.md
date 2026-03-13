# Intent v1 Core Types Layout

Status: draft  
Audience: `gtos` protocol and `core/types` implementers

## 1. Goal

This document turns the higher-level Intent v1 design into a concrete
`gtos/core/types` layout.

The design target is:

- keep one native transaction family
- add a first-class off-chain `IntentEnvelope`
- settle fills through `SignerTx`
- carry `IntentAuth` inside `SignerTx`
- keep sponsor authorization in the existing native sponsor fields

This is intentionally RLP-first because the current transaction and receipt
model in `gtos` is already RLP-typed.

## 2. Design Decisions

### 2.1 One Transaction Family

Intent v1 does **not** introduce `IntentTxType`.

Fills remain `SignerTxType` transactions.

### 2.2 Off-Chain Intent, On-Chain Fill

The intent itself is not inserted into the transaction trie.

Instead:

- `IntentEnvelope` is signed, propagated, and stored in the `intentpool`
- `SignerTx.Intent` references the chosen intent at fill time

### 2.3 Sponsor Auth Is Not Duplicated

`SignerTx` already has native sponsor authorization fields.

So `IntentAuth` must **not** carry a second sponsor signature block.
Intent validation checks the top-level transaction sponsor fields against the
referenced intent's sponsor requirements.

### 2.4 Receipt Encoding Stays Stable

Consensus receipt encoding should remain the ordinary typed receipt encoding for
`SignerTxType`.

Intent-specific outcome data should be indexed as a separate stored object such
as `IntentReceipt`, not by changing the consensus receipt body in v1.

## 3. Proposed File Split

The minimal file split in `core/types/` should be:

- `intent.go`
  - canonical core structs
- `intent_signing.go`
  - hash and signature helpers
- `intent_marshalling.go`
  - JSON encoding for RPC use
- `intent_receipt.go`
  - protocol-indexed intent outcome object

The existing files that will need corresponding changes are:

- `transaction.go`
- `signer_tx.go`
- `transaction_signing.go`
- `transaction_marshalling.go`
- `receipt.go`

## 4. New Constants

Intent v1 should use explicit numeric enums in `core/types`.

```go
const (
    IntentVersion1 uint8 = 1
)

const (
    ExecutionIntentKind uint8 = 1
)

const (
    IntentFillModeSingle  uint8 = 1
    IntentFillModePartial uint8 = 2
)

const (
    IntentCompetitionPrivateRFQ uint8 = 1
    IntentCompetitionOpen       uint8 = 2
)

const (
    IntentSponsorForbidden uint8 = 0
    IntentSponsorOptional  uint8 = 1
    IntentSponsorRequired  uint8 = 2
)

const (
    intentBodyHashPrefix    byte = 0x49 // "I"
    intentEnvelopeSigPrefix byte = 0x4a // "J"
    intentCancelSigPrefix   byte = 0x4b // "K"
)
```

These are not transaction type bytes.
They are domain-separation prefixes for intent hashing and signing.

## 5. Off-Chain Intent Types

The off-chain types should live in `core/types/intent.go`.

```go
type ExecutionIntent struct {
    Version         uint8
    Kind            uint8
    ChainID         *big.Int
    Principal       common.Address
    Requester       common.Address
    Nonce           *big.Int
    CancelDomain    common.Hash
    IssuedAtMs      uint64
    ExpiresAtMs     uint64
    FillMode        uint8
    CompetitionMode uint8

    Target      IntentTarget
    Constraints IntentConstraints
    Settlement  IntentSettlement

    Payload      []byte
    MetadataHash common.Hash
}

type IntentTarget struct {
    Contract       common.Address
    SurfaceID      string
    SurfaceVersion string
    EntryPoint     string
}

type IntentConstraints struct {
    MaxInputAmount       *big.Int
    MinOutputAmount      *big.Int
    MaxTotalFeeWei       *big.Int
    MaxSlippageBps       uint32
    MaxGasUsed           uint64
    AllowPartialFill     bool
    AllowedMutableParams []string
    RequiredCapabilities []string
}

type IntentSettlement struct {
    Beneficiary common.Address
    RefundTo    common.Address
    SponsorMode uint8
    Sponsor     common.Address
}

type IntentEnvelope struct {
    Intent     ExecutionIntent
    SignerType string
    V          *big.Int
    R          *big.Int
    S          *big.Int
}

type IntentCancel struct {
    Version      uint8
    ChainID      *big.Int
    Principal    common.Address
    CancelDomain common.Hash
    Nonce        *big.Int
    IntentHash   common.Hash
    IssuedAtMs   uint64
    SignerType   string
    V            *big.Int
    R            *big.Int
    S            *big.Int
}
```

### 5.1 Why `V/R/S` Instead of `Signature []byte`

`gtos/core/types` already stores transaction signatures in split scalar form to
support multiple signer types with one verification path.

Intent v1 should reuse the same internal representation.

RPC layers can still expose a convenience `signature` field later if needed,
but the core in-memory model should stay aligned with the transaction model.

## 6. On-Chain Fill Block

`IntentAuth` is the intent reference block embedded into `SignerTx`.

```go
type IntentAuth struct {
    IntentHash      common.Hash
    Principal       common.Address
    Solver          common.Address
    FillNonce       uint64
    FillAmount      *big.Int
    FillFractionBps uint32
    MaxSolverFeeWei *big.Int
}
```

### 6.1 What Is Intentionally Not Inside `IntentAuth`

`IntentAuth` should not include:

- sponsor signatures
- observed post-state hashes
- arbitrary solver quote metadata

Reasons:

- sponsor auth already exists at the top level of `SignerTx`
- post-state values are not reliably known before execution
- quote metadata belongs in `OpenFox` persistence, not consensus types

## 7. `SignerTx` Extension

The minimal v1 change is to extend the existing `SignerTx` rather than create a
new transaction family.

```go
type SignerTx struct {
    ChainID    *big.Int
    Nonce      uint64
    Gas        uint64
    To         *common.Address `rlp:"nil"`
    Value      *big.Int
    Data       []byte
    AccessList AccessList

    From       common.Address
    SignerType string

    Sponsor           common.Address
    SponsorSignerType string
    SponsorNonce      uint64
    SponsorExpiry     uint64
    SponsorPolicyHash common.Hash

    Intent *IntentAuth `rlp:"nil"`

    V *big.Int
    R *big.Int
    S *big.Int

    SponsorV *big.Int
    SponsorR *big.Int
    SponsorS *big.Int
}
```

### 7.1 Why `Intent` Comes After Sponsor Policy Fields

This ordering keeps the existing sender and sponsor sections grouped together,
and places the intent reference block immediately before the signature scalars.

### 7.2 Compatibility Note

Adding `Intent *IntentAuth` changes the RLP field layout of `SignerTx`.

Intent v1 should treat this as an intentional pre-launch envelope change rather
than attempt fragile compatibility tricks.

## 8. Exact RLP Field Order

The canonical `SignerTx` RLP field order for v1 should be:

1. `ChainID`
2. `Nonce`
3. `Gas`
4. `To`
5. `Value`
6. `Data`
7. `AccessList`
8. `From`
9. `SignerType`
10. `Sponsor`
11. `SponsorSignerType`
12. `SponsorNonce`
13. `SponsorExpiry`
14. `SponsorPolicyHash`
15. `Intent`
16. `V`
17. `R`
18. `S`
19. `SponsorV`
20. `SponsorR`
21. `SponsorS`

The canonical `ExecutionIntent` RLP field order should be:

1. `Version`
2. `Kind`
3. `ChainID`
4. `Principal`
5. `Requester`
6. `Nonce`
7. `CancelDomain`
8. `IssuedAtMs`
9. `ExpiresAtMs`
10. `FillMode`
11. `CompetitionMode`
12. `Target`
13. `Constraints`
14. `Settlement`
15. `Payload`
16. `MetadataHash`

The canonical `IntentTarget` RLP field order should be:

1. `Contract`
2. `SurfaceID`
3. `SurfaceVersion`
4. `EntryPoint`

The canonical `IntentConstraints` RLP field order should be:

1. `MaxInputAmount`
2. `MinOutputAmount`
3. `MaxTotalFeeWei`
4. `MaxSlippageBps`
5. `MaxGasUsed`
6. `AllowPartialFill`
7. `AllowedMutableParams`
8. `RequiredCapabilities`

The canonical `IntentSettlement` RLP field order should be:

1. `Beneficiary`
2. `RefundTo`
3. `SponsorMode`
4. `Sponsor`

The canonical `IntentAuth` RLP field order should be:

1. `IntentHash`
2. `Principal`
3. `Solver`
4. `FillNonce`
5. `FillAmount`
6. `FillFractionBps`
7. `MaxSolverFeeWei`

## 9. Hashing Rules

Intent v1 should use three distinct hashes.

### 9.1 Intent Identity Hash

This identifies the semantic intent.

```go
func IntentHash(intent *ExecutionIntent) common.Hash {
    return prefixedRlpHash(intentBodyHashPrefix, intent)
}
```

This hash excludes signer metadata and signatures.

### 9.2 Intent Signature Hash

This is the hash actually signed by the principal.

```go
func IntentSignHash(intent *ExecutionIntent, signerType string) common.Hash {
    return prefixedRlpHash(intentEnvelopeSigPrefix, []interface{}{
        IntentHash(intent),
        signerType,
    })
}
```

This keeps signer-type domain separation explicit without making signer type part
of the semantic intent identity.

### 9.3 Intent Cancellation Signature Hash

```go
func IntentCancelSignHash(cancel *IntentCancel) common.Hash {
    return prefixedRlpHash(intentCancelSigPrefix, []interface{}{
        cancel.Version,
        cancel.ChainID,
        cancel.Principal,
        cancel.CancelDomain,
        cancel.Nonce,
        cancel.IntentHash,
        cancel.IssuedAtMs,
        cancel.SignerType,
    })
}
```

## 10. Transaction Signing Hash Changes

The native transaction signing hash must include `Intent` when present, just as
it already includes sponsor authorization fields when present.

The v1 rule should be:

- no sponsor, no intent:
  - preserve the current sender hash shape
- sponsor only:
  - preserve the current sponsor-aware hash shape
- intent only:
  - append `Intent` after sponsor policy fields
- sponsor and intent:
  - append `Intent` after sponsor policy fields

Concretely, the fully populated sponsor-plus-intent branch is:

```go
prefixedRlpHash(tx.Type(), []interface{}{
    chainID,
    nonce,
    gas,
    to,
    value,
    data,
    accessList,
    from,
    signerType,
    sponsor,
    sponsorSignerType,
    sponsorNonce,
    sponsorExpiry,
    sponsorPolicyHash,
    intent,
})
```

Signatures are still excluded from the signing payload.

## 11. JSON Marshalling Shape

`transaction_marshalling.go` should add one optional field:

```go
Intent *IntentAuth `json:"intent,omitempty"`
```

`IntentEnvelope` and `IntentCancel` should also get dedicated JSON helpers in
`intent_marshalling.go`.

Suggested JSON field names:

- `intent`
- `intentHash`
- `fillNonce`
- `fillAmount`
- `fillFractionBps`
- `maxSolverFeeWei`

## 12. Intent Receipt Type

Do not overload `Receipt` consensus encoding in v1.

Instead define a separate stored/indexed type:

```go
type IntentReceipt struct {
    IntentHash        common.Hash
    Status            uint8
    Principal         common.Address
    Solver            common.Address
    Sponsor           common.Address
    FillTxHash        common.Hash
    FilledAmount      *big.Int
    TotalFilledAmount *big.Int
    BlockNumber       *big.Int
    ReasonCode        string
}
```

This object can be returned by:

- `tos_getIntent`
- `tos_intentStatus`

without altering the consensus receipt encoding already used in blocks.

## 13. Minimal Validation Hooks

With the types above, `gtos` can perform the minimum required checks:

1. load `IntentEnvelope` by `IntentHash`
2. verify the intent signature
3. verify the intent is open and not expired
4. verify the top-level transaction sponsor fields match the intent sponsor mode
5. verify the fill does not exceed remaining capacity
6. verify solver-selected parameters stay within the referenced `intent_surface`
7. record an `IntentReceipt`

## 14. Recommended First Implementation Order

Inside `gtos`, the first implementation order should be:

1. add `intent.go` with the off-chain structs
2. add `IntentHash`, `IntentSignHash`, and `IntentCancelSignHash`
3. add JSON marshalling helpers
4. extend `SignerTx` with `Intent *IntentAuth`
5. extend transaction hash/signing helpers
6. add the protocol-indexed `IntentReceipt`

That is the smallest coherent `core/types` foundation for Intent v1.
