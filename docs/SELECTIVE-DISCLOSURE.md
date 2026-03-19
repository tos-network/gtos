# Selective Disclosure for UNO Confidential Balances

**Status**: Implemented (all three phases complete)
**Last updated**: 2026-03-19

---

## Motivation

Privacy is not anonymity. A production confidential asset system must allow
account holders to selectively reveal encrypted balance information to
authorized parties without surrendering spending authority. Three distinct
disclosure scenarios drive the design:

| Scenario | Recipient | What is revealed | Frequency |
|----------|-----------|------------------|-----------|
| Third-party verification | Lender, arbitrator, DAO, exchange | Amount or threshold proof | Per-ciphertext, on demand |
| Audit inspection | External auditor | Balance at a point in time, or a set of transactions | Periodic, batch |
| Regulatory compliance | Regulator / compliance officer | All transactions for an account | Continuous, mandatory |

**Note:** Direct transaction recipients (the person you send to) can already
decrypt the amount using their own private key — no disclosure mechanism is
needed for that case. The three layers below address scenarios where the
verifier is NOT the transaction recipient.

Each scenario has different trust assumptions, latency requirements, and
cryptographic cost profiles. A single mechanism cannot serve all three
efficiently, so the system provides three complementary layers.

---

## Background: UNO Cryptographic Primitives

UNO encrypted balances use **Twisted ElGamal on Ristretto255**:

```
Key generation:
    sk  ← random non-zero scalar
    PK  = sk⁻¹ · H          (H = Pedersen generator)

Encryption (amount, randomness r):
    C   = amount · G + r · H      (commitment)
    D   = r · PK                   (handle)

Decryption:
    M   = C − sk · D
        = amount·G + r·H − sk·r·(sk⁻¹·H)
        = amount·G                  (plaintext point)
    amount = ECDLP(M, G)           (baby-step giant-step)
```

**Critical constraint**: the same scalar `sk` serves as both the ElGamal
decryption key and the Schnorr signing key. Sharing `sk` grants full
spending authority. All disclosure mechanisms must therefore avoid revealing
`sk`.

---

## Note: Direct Transfer Recipients Can Already Decrypt

In a standard PrivTransfer, the receiver **already has decryption ability**
because the ciphertext handle is encrypted under the receiver's public key:

```
D = r · PK_receiver
Receiver decrypts:  amount·G = C − sk_receiver · D
```

This means the most common "counterparty disclosure" scenario — the receiver
verifying the amount they received — requires **no additional mechanism**.
The receiver simply decrypts with their own key.

The three disclosure layers below address scenarios where the verifier is
**not** the transaction recipient:

| Scenario | Why receiver decryption is insufficient |
|----------|---------------------------------------|
| Prove balance to a lender | Lender is not the recipient of any transfer |
| Third-party arbitration | Arbitrator is neither sender nor receiver |
| Prove solvency to an exchange | Exchange cannot decrypt your on-chain balance |
| Prove deposit amount to a DAO | Contract cannot hold a private key to decrypt |
| Regulatory threshold check | Regulator needs proof without being a party |

---

## Layer 1: DisclosureProof — Third-Party Amount Verification

### Purpose

A user proves to a **third party** (not the transaction recipient) that a
specific ciphertext encrypts a claimed plaintext amount, without revealing
the private key or the encryption randomness.

This is needed when the verifier cannot decrypt the ciphertext themselves —
they are not the recipient, not the sender, and do not hold any key related
to the encrypted balance.

### When Is This Needed?

| Scenario | Who proves | To whom | Why DisclosureProof is needed |
|----------|-----------|---------|------------------------------|
| Balance proof | Account holder | Lender / exchange | Prove "my encrypted balance ≥ X" — the verifier cannot decrypt the balance |
| Third-party verification | Sender | Arbitrator / guarantor | A party outside the transaction needs to confirm the amount |
| Contract interaction proof | User | Contract / DAO | Prove the encrypted amount deposited into a contract meets a condition |
| Solvency proof | Institution | Regulator / auditor | Prove balance ≥ threshold without disclosing the exact amount |
| Pre-trade credit check | Buyer | Seller / escrow | Prove sufficient funds before entering a confidential trade |

### Variants

**Exact amount proof** — "This ciphertext encrypts exactly 500 UNO."

**Range proof** — "My encrypted balance is at least 1000 UNO." (Does not
reveal the exact amount; uses Bulletproofs range proof on the difference
`balance − threshold`.)

### Construction (Exact Amount)

Given public information `(C, D, PK)` and claimed amount `a`, the prover
(who knows randomness `r`) executes a Sigma protocol:

```
Prover:
    1. Sample random k₁, k₂
    2. Compute  A₁ = k₁·G + k₂·H
                A₂ = k₂·PK
    3. Challenge e = Merlin("disclosure-proof", C, D, PK, a, A₁, A₂)
    4. Respond   z₁ = k₁ + e·a     (mod L)
                 z₂ = k₂ + e·r     (mod L)

Verifier:
    Check  z₁·G + z₂·H  ==  A₁ + e·C
    Check  z₂·PK         ==  A₂ + e·D
```

### Construction (Range / Threshold Proof)

To prove `balance ≥ threshold` without revealing the exact amount:

```
Prover:
    1. Compute diff_ct = balance_ct − Encrypt(threshold, r')
       (homomorphic subtraction: result encrypts balance − threshold)
    2. Generate a Bulletproofs range proof that diff_ct encrypts
       a value in [0, 2^64)

Verifier:
    Verify the range proof against diff_ct's commitment component.
    If valid, balance ≥ threshold (the difference is non-negative).
```

### Properties

| Property | Value |
|----------|-------|
| Exact proof size | 128 bytes (A₁ 32B + A₂ 32B + z₁ 32B + z₂ 32B) |
| Range proof size | 672 bytes (single 64-bit Bulletproofs) |
| Reveals (exact) | Plaintext amount `a` |
| Reveals (range) | Only that `balance ≥ threshold` |
| Does NOT reveal | Private key `sk`, randomness `r` |
| Verification | Off-chain, no state change |
| Transcript binding | Merlin with chain ID, block number, account address |
| Selective | Per-ciphertext — user chooses which to disclose |

### Real-World Scenarios

**Scenario 1: DeFi Collateral Verification**

Alice wants to borrow from a confidential lending protocol. The protocol
requires proof that her encrypted UNO balance exceeds the collateral
threshold (e.g., 10,000 UNO) but should not learn her exact balance.

- Alice generates a **range proof**: `balance ≥ 10,000 UNO` (672 bytes).
- The lending contract verifies the proof on-chain via `tos.ciphertext.verify_eq`
  or off-chain via the protocol's verification service.
- Alice's exact balance remains hidden. The protocol only learns: "sufficient."

**Scenario 2: Dispute Arbitration**

Bob pays Carol 500 UNO for goods via PrivTransfer. Carol claims she received
less. A third-party arbitrator is appointed.

- Carol can decrypt the received amount (she is the recipient, `D = r·PK_carol`).
  She shows: "I received 500 UNO."
- Bob generates an **exact disclosure proof** (128 bytes) proving the
  ciphertext he sent encrypts exactly 500 UNO.
- The arbitrator verifies both proofs independently without either party
  revealing their private keys.
- Neither the arbitrator nor any observer learns Bob's remaining balance.

**Scenario 3: Exchange Withdrawal Gate**

An exchange requires users to prove their on-chain encrypted balance exceeds
the withdrawal amount before initiating an off-chain withdrawal process.

- User generates a **range proof**: `balance ≥ withdrawal_amount`.
- Exchange verifies off-chain. No on-chain transaction is needed for the proof.
- The user's full balance is never disclosed to the exchange.

**Scenario 4: DAO Governance Threshold**

A DAO requires members to hold ≥ 1,000 encrypted governance tokens to vote.

- Voter generates a **range proof**: `token_balance ≥ 1,000`.
- The DAO governance contract verifies the proof before accepting the vote.
- Individual token holdings remain private; only the threshold check is disclosed.

**Scenario 5: Insurance Claim**

An insurance contract needs to verify that a claimed loss (encrypted) does
not exceed the policy limit (also encrypted).

- Claimant generates a **range proof**: `policy_limit − claim_amount ≥ 0`.
- Insurer verifies without learning the exact claim amount or remaining limit.
- If disputed, the claimant can generate an **exact proof** for the arbitrator.

---

## Layer 2: DecryptionToken — Audit Inspection

### Purpose

A user generates a per-ciphertext token that allows an auditor to decrypt
the encrypted amount without learning the private key. The token is a
single elliptic-curve point (32 bytes) per ciphertext.

### When Is This Needed?

| Scenario | Who generates tokens | To whom | Why DecryptionToken is needed |
|----------|---------------------|---------|-------------------------------|
| Annual audit | Company treasury | External auditor | Auditor must verify actual amounts across many transactions; range proofs alone are insufficient |
| Tax reporting | Individual user | Tax preparer / authority | Exact amounts of all Shield/Unshield crossings needed for capital gains calculation |
| Dispute evidence | Litigating party | Court / legal counsel | Selective disclosure of only the transactions relevant to the dispute |
| Fund verification | Fund manager | Independent verifier / investors | Verify total holdings match reported NAV without revealing trading positions |
| Forensic investigation | Account holder (voluntary) | Investigator | Cooperating party provides tokens for a specific time window to assist investigation |

### Construction

```
User (holds sk):
    token = sk · D                  (scalar multiplication, one operation)

User sends to auditor:
    (C, token)                      — or a batch [(C₁, token₁), ..., (Cₙ, tokenₙ)]

Auditor recovers plaintext:
    M = C − token
      = (amount·G + r·H) − sk·(r·PK)
      = (amount·G + r·H) − sk·r·(sk⁻¹·H)
      = amount·G
    amount = ECDLP(M, G)
```

### Security Argument

The auditor observes `(D, token) = (D, sk·D)`. Recovering `sk` from this
pair requires computing the discrete logarithm of `token` with respect to
base `D` on Ristretto255, which is computationally infeasible under the
elliptic-curve discrete logarithm assumption.

### Properties

| Property | Value |
|----------|-------|
| Token size | 32 bytes per ciphertext |
| Reveals | Plaintext amount for the specific ciphertext |
| Does NOT reveal | Private key `sk`, randomness `r` |
| Verification | Off-chain, auditor runs BSGS to recover amount |
| Batch-friendly | User generates N tokens for N ciphertexts in a single pass |
| Revocable | Tokens are per-ciphertext; user controls which ciphertexts are disclosed |

### Real-World Scenarios

**Scenario 1: Annual Financial Audit**

A company holds its treasury in encrypted UNO. At fiscal year-end, an
external auditor needs to verify all quarterly balance snapshots and
material transactions.

- The company's treasury agent generates DecryptionTokens for:
  - 4 quarterly balance ciphertexts (balance at each quarter-end)
  - N material transactions above the audit threshold
- Tokens are exported as a batch file: `[(C₁, token₁), ..., (Cₙ, tokenₙ)]`.
- The auditor decrypts each token, recovers plaintext amounts via BSGS, and
  verifies the treasury reconciliation.
- The auditor requests a **DLEQ proof** for each token to confirm the tokens
  were computed honestly (same `sk` that owns the account).
- The company's private key never leaves its custody.

**Scenario 2: Tax Reporting**

An individual uses Shield/Unshield to move funds between public and private
balances. Tax authority requires disclosure of all public-private boundary
crossings for the tax year.

- User generates DecryptionTokens for all Shield and Unshield transactions
  in the reporting period (these are identifiable on-chain by tx type).
- Tax preparer decrypts the amounts and computes capital gains/losses.
- Non-boundary transactions (private-to-private PrivTransfers) are not
  disclosed unless specifically requested.

**Scenario 3: Dispute Evidence Package**

In a commercial dispute, one party must demonstrate a pattern of payments to
the other over a six-month period.

- The disclosing party generates tokens only for the transactions relevant
  to the dispute (e.g., 12 monthly payments to the counterparty's address).
- The legal team verifies each amount using the tokens.
- Unrelated transactions (payments to other counterparties, personal
  transfers) are not disclosed — the token mechanism is per-ciphertext.
- If the opposing party contests authenticity, the discloser provides DLEQ
  proofs binding the tokens to their on-chain public key.

**Scenario 4: Institutional Fund Verification**

A fund manager operates an encrypted treasury on behalf of investors.
Investors periodically request verification that the fund holds at least
their proportional share.

- Fund manager generates a DecryptionToken for the current balance ciphertext.
- An independent verifier decrypts and confirms: `total_balance ≥ sum(investor_shares)`.
- Individual investor allocations can be verified separately using
  per-investor sub-account tokens.
- The fund's exact balance and trading positions remain undisclosed to
  any single investor.

### Proof of Correct Token (Optional)

An auditor may require proof that the token was computed honestly (i.e.,
`token = sk · D` for the same `sk` that owns the account). This is a
DLEQ (discrete-log equality) proof:

```
Prove:  log_H(PK⁻¹) == log_D(token)
        i.e., PK = sk⁻¹·H  and  token = sk·D  use the same sk

Sigma protocol:
    1. Sample random k
    2. A₁ = k · H,  A₂ = k · D
    3. e  = Merlin("dleq-token", PK, D, token, A₁, A₂)
    4. z  = k + e · sk
    Verify: z·H == A₁ + e·(PK⁻¹),  z·D == A₂ + e·token

Proof size: 96 bytes (A₁ 32B + A₂ 32B + z 32B)
```

---

## Layer 3: AuditorKey — Regulatory Compliance

### Purpose

A policy wallet mandates that all UNO transactions for a regulated account
include a secondary encryption under a designated auditor's public key. The
auditor can independently decrypt every transaction without any cooperation
from the account holder.

### When Is This Needed?

| Scenario | Who sets the key | Auditor | Why AuditorKey is needed |
|----------|-----------------|---------|--------------------------|
| Banking regulation | Bank compliance officer (guardian) | Banking regulator | Real-time visibility into all customer transactions; user cooperation not feasible at scale |
| Custodial agent monitoring | Enterprise security team (guardian) | Internal security | AI agents operate autonomously; monitoring must not depend on agent cooperation |
| Court-ordered disclosure | Court-appointed guardian | Court auditor | Legal mandate; account holder may be uncooperative or unavailable |
| AML/CTF compliance | Automated policy rule | AML authority | Threshold-triggered; accounts above transaction volume limits must be transparent |
| Multi-jurisdictional regulation | Guardian per jurisdiction | Multiple regulators | Each jurisdiction independently decrypts; no single regulator has exclusive access |

### On-Chain State

```
PolicyWallet storage (per account):
    AuditorPubKey   [32]byte    // auditor's ElGamal public key, or zero if unset
```

When `AuditorPubKey` is set (non-zero), the consensus layer enforces that
every Shield, PrivTransfer, and Unshield transaction from this account
includes an additional `AuditHandle` field.

### Transaction Extension

```
Current ciphertext:
    C = amount·G + r·H       (commitment — unchanged)
    D = r · PK_sender         (handle for sender)

Additional field when AuditorPubKey is set:
    D_audit = r · PK_audit    (handle for auditor, same randomness r)

Auditor decrypts:
    amount·G = C − sk_audit · D_audit
```

Using the same randomness `r` for both handles is safe: the auditor learns
the plaintext amount but not `r` (recovering `r` from `D_audit = r·PK_audit`
requires solving DLP on `PK_audit`), and cannot derive the sender's private
key.

### Enforcement

| Component | Behavior |
|-----------|----------|
| **PolicyWallet** | `SetAuditorKey(address, auditorPubKey)` — only callable by wallet owner or guardian |
| **State transition** | If `AuditorPubKey != 0` for sender, reject UNO tx without valid `AuditHandle` |
| **TxPool** | Pre-validate `AuditHandle` presence before admission |
| **Proof binding** | Extend Merlin transcript context with `AuditHandle` to prevent substitution |

### Key Rotation

When the auditor key is rotated:

1. Guardian calls `SetAuditorKey(account, newAuditorPubKey)`.
2. All subsequent transactions use `newAuditorPubKey` for `D_audit`.
3. Historical transactions remain decryptable by the old auditor key.
4. No re-encryption of existing balances is needed (the balance ciphertext
   `(C, D)` is unchanged; only new transaction handles change).

### Properties

| Property | Value |
|----------|-------|
| Additional tx size | 32 bytes (`AuditHandle`) |
| Reveals to auditor | Every transaction amount for the regulated account |
| Does NOT reveal | Private key `sk`, encryption randomness `r` |
| User cooperation | Not required — enforced by consensus |
| Auditor key management | On-chain, rotatable by guardian |
| Retroactive disclosure | Only for transactions after `AuditorPubKey` was set |

### Real-World Scenarios

**Scenario 1: Licensed Financial Institution**

A bank operates on TOS with encrypted customer accounts. The banking
regulator requires real-time transaction visibility for all customer
accounts under its jurisdiction.

- The bank's guardian (compliance officer) calls
  `SetAuditorKey(customerAddr, regulatorPubKey)` for each regulated account.
- From that point forward, every Shield, PrivTransfer, and Unshield
  transaction from these accounts automatically includes `D_audit`.
- The regulator runs a monitoring node that decrypts all `D_audit` handles
  using `sk_audit`, building a real-time transaction ledger.
- Customers cannot circumvent disclosure — it is enforced at the consensus
  layer. Transactions without a valid `AuditHandle` are rejected.
- The regulator can decrypt amounts but cannot spend funds (no access to
  customer `sk`).

**Scenario 2: Custodial Agent Wallet**

An enterprise deploys AI agents that manage encrypted treasury operations.
The enterprise's security team needs to monitor all agent transactions
without holding spending keys.

- The enterprise guardian sets `AuditorPubKey` to the security team's key.
- Every automated agent transaction (e.g., paying service providers,
  settling bounties, funding sub-agents) includes an `AuditHandle`.
- The security team's monitoring system decrypts all transactions in real
  time, flagging anomalies (unusually large transfers, unexpected recipients,
  rapid sequential transfers).
- If an agent is compromised, the security team can detect the breach from
  the audit stream and trigger guardian suspension — without needing the
  agent's cooperation.

**Scenario 3: Court-Ordered Disclosure**

A court issues a disclosure order requiring visibility into a specific
account's encrypted transactions for a defined period.

- The account's guardian (or a court-appointed guardian) calls
  `SetAuditorKey(targetAddr, courtAuditorPubKey)`.
- All future transactions become decryptable by the court-appointed auditor.
- Historical transactions before the order are NOT retroactively disclosed
  (the mechanism is forward-only).
- When the order expires, the guardian calls `SetAuditorKey(targetAddr, 0x0)`
  to remove the auditor key. Subsequent transactions are private again.
- Transactions during the disclosure window remain permanently decryptable
  by the court's key (the `D_audit` values are recorded on-chain).

**Scenario 4: Anti-Money-Laundering (AML) Compliance**

A jurisdiction requires all accounts above a certain balance or transaction
volume to have continuous regulatory visibility.

- Policy wallet rules automatically set `AuditorPubKey` when an account
  crosses the AML threshold (e.g., total Shield volume > 100,000 UNO in
  a rolling 30-day window).
- The AML authority's key is pre-registered as a system parameter.
- Accounts below the threshold operate with full privacy.
- If an account later falls below the threshold, the guardian can remove
  the auditor key, restoring full privacy for future transactions.

**Scenario 5: Multi-Regulator Jurisdiction**

An account operates across jurisdictions that each require independent
audit access.

- The policy wallet supports multiple auditor keys (extension: `AuditorPubKeys`
  as a list, each transaction includes one `D_audit` per registered key).
- Each regulator decrypts independently using their own key.
- No single regulator can impersonate another or access the account holder's
  spending authority.
- Key rotation for one regulator does not affect the others.

---

## Comparison of Layers

| | DisclosureProof | DecryptionToken | AuditorKey |
|---|---|---|---|
| **Disclosed to** | Third party (lender, arbitrator, DAO) | Auditor | Regulator |
| **Granularity** | Per-ciphertext | Per-ciphertext (batchable) | All transactions (automatic) |
| **User cooperation** | Required (user generates proof) | Required (user generates tokens) | Not required (consensus-enforced) |
| **On-chain state** | None | None | AuditorPubKey in policy wallet |
| **Tx size overhead** | None (off-chain proof) | None (off-chain token) | +32 bytes per tx |
| **Reveals amount** | Yes | Yes | Yes |
| **Reveals private key** | No | No | No |
| **Retroactive** | Yes (user has `r`) | Yes (user has `sk`) | No (only future txs) |
| **Proof of honesty** | Inherent (ZK proof) | Optional DLEQ proof | Inherent (consensus-verified) |

---

## Implementation Plan

### Phase 1: DisclosureProof (off-chain, no consensus changes)

**Scope**: Pure cryptography + CLI tooling.

- [x] `crypto/ed25519/priv_nocgo_disclosure.go` — DLEQ proof (`ProvePrivDisclosureExact` / `VerifyPrivDisclosureExact`)
- [x] `crypto/priv/disclosure.go` — high-level wrappers (`ProveDisclosureExact` / `VerifyDisclosureExact`)
- [x] `core/priv/disclosure.go` — chain-layer `DisclosureClaim` type, `BuildDisclosureContext`, `ProveDisclosure`, `VerifyDisclosure`
- [x] Merlin transcript label `"disclosure-exact"` with chain context binding (chainID, pubkey, ciphertext, blockNumber)
- [x] `cmd/toskey/priv_disclosure.go` — CLI `priv-disclose` command to generate disclosure proofs
- [x] RPC: `PrivProveDisclosure` / `PrivVerifyDisclosure` in `internal/tosapi/api.go`
- [x] Tests: `crypto/priv/disclosure_test.go` (5 tests), `core/priv/disclosure_test.go` (1 test)
- [x] SDK: `tosdk/src/types/disclosure.ts` — `DisclosureProofParams`, `DisclosureProofResult`, `VerifyDisclosureParams`
- [x] SDK functions: `client.privProveDisclosure()` / `client.privVerifyDisclosure()` in `tosdk/src/clients/createPublicClient.ts`

### Phase 2: DecryptionToken (off-chain, no consensus changes)

**Scope**: Scalar multiplication + optional DLEQ proof + CLI/RPC.

- [x] `crypto/ed25519/priv_nocgo_point_ops.go` — `ScalarMultPoint`, `PointSubtract` primitives
- [x] `crypto/priv/decryption_token.go` — `GenerateDecryptionToken(sk, D)` and `DecryptWithToken(token, C)`
- [x] `core/priv/decryption_token.go` — `DecryptionToken` struct, `BuildDecryptionToken` (with DLEQ proof), `VerifyDecryptionToken`, `DecryptTokenAmount`
- [x] DLEQ proof of honest token generation reuses Phase 1 disclosure-exact construction
- [x] `cmd/toskey/priv_token.go` — CLI `priv-generate-token` and `priv-decrypt-token` commands
- [x] RPC: `PrivGenerateDecryptionToken`, `PrivVerifyDecryptionToken`, `PrivDecryptWithToken` in `internal/tosapi/api.go`
- [x] Tests: `crypto/priv/decryption_token_test.go` (3 tests), `core/priv/decryption_token_test.go` (2 tests)
- [x] Batch API: `BuildDecryptionTokenBatch` in `core/priv/decryption_token.go`
- [x] SDK: `tosdk/src/types/disclosure.ts` — `DecryptionToken`, `DecryptionTokenParams`, `TokenDecryptResult`
- [x] SDK functions: `client.privGenerateDecryptionToken()` / `client.privVerifyDecryptionToken()` / `client.privDecryptWithToken()` in `tosdk/src/clients/createPublicClient.ts`

### Phase 3: AuditorKey (consensus change)

**Scope**: On-chain state + tx validation + policy wallet integration.

- [x] `policywallet/state.go` — `ReadAuditorKey(db, addr)` / `WriteAuditorKey(db, addr, pubkey)`
- [x] `policywallet/handler.go` — `POLICY_SET_AUDITOR_KEY` system action handler
- [x] `policywallet/types.go` — `SetAuditorKeyPayload`
- [x] `sysaction/types.go` — `ActionPolicySetAuditorKey` constant
- [x] Transaction types: `AuditorHandle [32]byte` + `AuditorDLEQProof []byte` added to PrivTransferTx, ShieldTx, UnshieldTx (with `copy()` and `SigningHash()` updates)
- [x] `crypto/ed25519/priv_nocgo_disclosure.go` — `ProveAuditorHandleDLEQ` / `VerifyAuditorHandleDLEQ` (same-randomness DLEQ)
- [x] `crypto/priv/disclosure.go` — auditor DLEQ wrappers
- [x] `core/priv/verify.go` — `VerifyAuditorHandleDLEQ`
- [x] `core/priv/batch_verify.go` — `AddAuditorHandleDLEQ`
- [x] `core/priv/prover.go` — `BuildAuditorHandle(opening, auditorPub, receiverPub, receiverHandle, ctx)`
- [x] `core/privacy_tx_prepare.go` — validate AuditorHandle presence + DLEQ proof when AuditorKey is set (all 3 tx types)
- [x] `core/tx_pool_privacy_verify.go` — `AuditorDLEQProof` shape validation (0 or 96 bytes)
- [x] `core/priv/context.go` — context version bumped to 2 when AuditorHandle is non-zero; all three builders extended
- [x] RPC: `PrivDecryptWithAuditorKey` in `internal/tosapi/api.go` — auditor-side decryption by tx hash
- [x] SDK: `tosdk/src/types/disclosure.ts` — `AuditorDecryptParams`, `AuditorDecryptResult`
- [x] SDK function: `client.privDecryptWithAuditorKey()` in `tosdk/src/clients/createPublicClient.ts`

---

## Security Considerations

### What is NOT disclosed

None of the three layers reveal the account holder's private key (`sk`).
The spending authority remains exclusively with the key holder. An auditor
who receives decryption tokens or audit handles can observe amounts but
cannot forge transactions, transfer funds, or impersonate the account.

### Collusion resistance

- **Layer 1**: Even if all counterparties pool their DisclosureProofs, they
  cannot decrypt ciphertexts for which no proof was generated.
- **Layer 2**: DecryptionTokens are bound to specific ciphertexts. An
  auditor with tokens for transactions A and B cannot derive a token for
  transaction C.
- **Layer 3**: The auditor key holder can decrypt all transactions after
  activation. This is intentional — regulatory access is unconditional.
  Key rotation limits the blast radius of a compromised auditor key.

### Forward secrecy

DecryptionTokens and AuditHandles do not provide forward secrecy. If a
user's private key is later compromised, all historical ciphertexts become
decryptable. This is inherent to the ElGamal encryption scheme and is
consistent with the threat model (the private key is the root of trust).

### Quantum considerations

Ristretto255 is not quantum-resistant. A future quantum computer capable of
solving ECDLP would break all three layers simultaneously (by recovering
`sk` from `PK`). Post-quantum migration would require replacing the
underlying group, which is out of scope for this design.
