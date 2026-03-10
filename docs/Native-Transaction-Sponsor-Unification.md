# Native Transaction Sponsor Unification

## Status

Implemented.

This document defines the implemented one-step replacement of the current split
between ordinary native transactions and sponsored native transactions across:

- `gtos`
- `tosdk`
- `openfox`

This plan assumes there are no external users to preserve compatibility for.
The refactor is intentionally **not** designed around backward compatibility
with `SponsoredSignerTxType`.

## 1. Problem

The current design has two separate transaction families:

- ordinary native execution
- sponsored native execution

In practice this creates avoidable duplication across:

- transaction types
- RLP encoding and decoding
- signing and hashing helpers
- SDK transaction models
- RPC request/response surfaces
- txpool validation
- state transition rules
- OpenFox signer/paymaster composition

The protocol does need two distinct authorizations:

- execution authorization
- sponsor authorization

But it does **not** need two separate transaction families.

## 2. Design Goal

Replace the split model with a **single native transaction envelope** where
sponsor funding is represented as an optional authorization block.

The end state should be:

- one native transaction model
- one SDK transaction type
- one RPC transaction shape
- one txpool path
- one state transition path
- one OpenFox execution path

The presence or absence of sponsor funding should be a property of the native
transaction, not a second top-level transaction type.

## 3. Design Principles

1. There is only one native transaction family.
2. Sponsor funding is optional metadata plus a second authorization.
3. Execution and sponsor still require separate verification.
4. Both authorizations sign the same canonical unsigned transaction object.
5. Sender and sponsor roles stay distinct:
   - sender authorizes execution
   - sponsor authorizes gas funding
6. `tx.value` remains sender-owned value transfer by default.
7. Sponsor funding covers execution cost, not arbitrary transfer subsidy.
8. No compatibility layer is required for the old sponsored transaction type.

## 4. Final Transaction Model

The final target model is a single native transaction with an optional sponsor
section.

```go
type NativeTx struct {
    ChainID    *big.Int
    Nonce      uint64
    Gas        uint64
    To         *common.Address
    Value      *big.Int
    Data       []byte

    From       common.Address
    SignerType string

    Sponsor    *SponsorAuth

    V *big.Int
    R *big.Int
    S *big.Int
}

type SponsorAuth struct {
    Address      common.Address
    SignerType   string
    Nonce        uint64
    Expiry       uint64
    PolicyHash   common.Hash

    V *big.Int
    R *big.Int
    S *big.Int
}
```

Semantics:

- `Sponsor == nil`
  - sender pays gas
- `Sponsor != nil`
  - sponsor pays gas
  - sender still owns `Value`

## 5. Canonical Hashing and Signing

The system should use **one canonical unsigned transaction object**.

That canonical object includes:

- chain ID
- sender nonce
- gas
- to
- value
- data
- sender address
- sender signer type
- optional sponsor section:
  - sponsor address
  - sponsor signer type
  - sponsor nonce
  - sponsor expiry
  - sponsor policy hash

It does **not** include either signature.

### 5.1 Execution Signing

The execution signer signs the canonical unsigned transaction object.

Verification uses:

- `From`
- `SignerType`
- execution signature `(V, R, S)`

### 5.2 Sponsor Signing

The sponsor signs the **same canonical unsigned transaction object**.

Verification uses:

- `Sponsor.Address`
- `Sponsor.SignerType`
- sponsor signature `(Sponsor.V, Sponsor.R, Sponsor.S)`

### 5.3 Key Consequence

There are still two verifications, but only one signable payload and one
transaction envelope.

This removes the protocol split without collapsing the two authorization roles
into one.

## 6. GTOS Refactor

## 6.1 Transaction Types

Remove the split:

- remove `SponsoredSignerTxType`
- remove `SponsoredSignerTx`

Keep a single native transaction type, renamed to `NativeTxType` if the codebase
is ready for the rename. If naming churn is temporarily undesirable inside the
implementation, a single legacy struct name may be kept internally, but the
protocol model must still be unified into one type.

The protocol target is:

- one typed native transaction envelope
- optional sponsor auth inside it

## 6.2 `core/types/transaction.go`

Replace the current dual decode path with one decode path:

- decode one native transaction struct
- validate sender signer fields
- if sponsor block exists:
  - validate sponsor signer fields
  - require sponsor address
  - require sponsor expiry

## 6.3 `transaction_signing.go`

Refactor hashing so:

- there is one transaction signing hash
- sponsor presence only changes the hashed payload contents
- there is no branch by transaction family

Expected public behavior:

- `tx.HasSponsor()`
- `tx.SponsorAddress()`
- `tx.SponsorNonce()`
- `tx.SponsorExpiry()`
- `tx.SponsorPolicyHash()`
- `tx.SponsorSignerType()`

## 6.4 Tx Pool

The tx pool should no longer branch on two transaction types.

Instead:

- all native transactions go through one validation path
- if `tx.HasSponsor()`:
  - resolve sponsor identity
  - verify sponsor signature
  - check sponsor balance for gas
  - check sponsor nonce
  - check sponsor expiry
- otherwise:
  - ordinary sender-pays checks apply

Replacement semantics remain one native transaction family.

## 6.5 State Transition

State transition should use:

- `msg.From()` for sender semantics
- `msg.HasSponsor()` for gas funding semantics

The unified rules should be:

- sender nonce always applies to execution authority
- sponsor nonce applies only when sponsor exists
- gas payer is sponsor when sponsor exists, otherwise sender
- `Value` transfer remains charged against sender balance, not sponsor balance

This preserves the current security boundary while removing the transaction-type
split.

## 6.6 RPC Surface

RPC should expose one transaction shape.

JSON transaction objects should include optional sponsor fields:

- `sponsor`
- `sponsorSignerType`
- `sponsorNonce`
- `sponsorExpiry`
- `sponsorPolicyHash`
- sponsor signature values

But RPC methods should not expose a separate sponsored transaction family.

## 7. TOSDK Refactor

`tosdk` should collapse:

- `TransactionSerializableNative`
- `TransactionSerializableSponsored`

into one:

```ts
export type TransactionSerializable = {
  chainId: number | bigint
  nonce: number | bigint
  gas: number | bigint
  to?: Address | null
  value: number | bigint
  data?: Hex
  from: Address
  signerType: string
  sponsor?: {
    address: Address
    signerType: string
    nonce: number | bigint
    expiry: number | bigint
    policyHash: Hex
  }
}
```

### 7.1 Remove Split SDK APIs

Remove the dedicated sponsored transaction path:

- `TransactionSerializableSponsored`
- `SponsoredTransactionSignatureBundle`
- `serializeTransactionSponsored`
- `signSponsoredExecution`
- `signSponsoredTransaction`
- `sendSponsoredTransaction`

Replace them with one path:

- `signAuthorization(...)`
- `assembleTransaction(...)`
- `signTransaction(...)`
- `serializeTransaction(...)`
- `sendTransaction(...)`

with optional sponsor support.

### 7.2 New SDK Helpers

The unified SDK should expose:

- `signAuthorization`
  - execution or sponsor signature over the same canonical unsigned transaction
- `assembleTransaction`
  - emits a final signed native envelope from an execution signature and an
    optional sponsor signature
- `signTransaction`
  - convenience helper for sender-pays transactions or sponsor-aware
    transactions when a sponsor signature is supplied
- `serializeTransaction`
  - emits one native transaction envelope
- `sendTransaction`
  - accepts optional sponsor signature parameters

That keeps one mainline transaction UX while still making the dual-signature
boundary explicit.

## 8. OpenFox Refactor

OpenFox should stop treating sponsored execution as a second execution family.

### 8.1 Signer-Provider

Signer-provider remains the source of execution authorization.

Its output should be:

- execution signature
- sender-side receipt data

It should not need a separate transaction family.

### 8.2 Paymaster-Provider

Paymaster-provider remains the source of sponsor authorization.

Its output should be:

- sponsor authorization
- sponsor signature
- sponsorship receipt

It should bind into the same transaction envelope used by the normal execution
path.

### 8.3 Combined Flows

OpenFox should support these compositions through one transaction model:

- local wallet only
- local wallet + paymaster-provider
- signer-provider only
- signer-provider + paymaster-provider
- combined signer-provider + paymaster-provider

The runtime should choose which authorizations are needed, not which top-level
transaction family to construct.

## 9. One-Step Cutover

This refactor is intentionally one-step.

Do not implement:

- backward compatibility with `SponsoredSignerTxType`
- dual serialization forever
- conversion shims
- transitional RPC aliases

Instead:

1. replace the chain transaction type
2. replace the SDK transaction model
3. replace the OpenFox signer/paymaster integration
4. update tests
5. delete the old sponsored family completely

## 10. Implementation Order

Recommended order:

1. `gtos`
   - unify transaction struct
   - unify hashing and signature verification
   - unify txpool/state transition
   - update RPC shape
2. `tosdk`
   - collapse transaction types
   - collapse serialization/signing APIs
   - update wallet/public client paths
3. `openfox`
   - refactor signer-provider and paymaster-provider around unified
     transaction construction
   - remove sponsored-only code paths
   - keep requester/operator UX stable

## 11. Acceptance Criteria

The refactor is complete when all of the following are true:

1. `gtos` has exactly one native transaction family for ordinary and sponsored
   execution.
2. sponsor funding is represented by an optional sponsor authorization block.
3. `tosdk` exposes one mainline transaction model and one mainline send path.
4. `openfox` signer-provider and paymaster-provider compose on top of the same
   transaction envelope.
5. ordinary sender-pays execution still works.
6. sponsored execution still works.
7. sender value transfer remains sender-owned by default.
8. sponsor gas funding remains bounded by sponsor policy.
9. there is no runtime branch that depends on a second sponsored transaction
   family.

## 12. Non-Goals

This refactor does not attempt to:

- turn sponsor funding into arbitrary transfer subsidy
- introduce ERC-4337 compatibility
- copy Solana’s account-meta model exactly
- collapse sender and sponsor into one authority

The goal is narrower:

**one native transaction family, optional sponsor authorization, two
authorizations, one protocol path**
