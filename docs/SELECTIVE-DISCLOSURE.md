# Selective Disclosure for UNO Confidential Balances

**Status**: Design — not yet implemented
**Last updated**: 2026-03-19

---

## Motivation

Privacy is not anonymity. A production confidential asset system must allow
account holders to selectively reveal encrypted balance information to
authorized parties without surrendering spending authority. Three distinct
disclosure scenarios drive the design:

| Scenario | Recipient | What is revealed | Frequency |
|----------|-----------|------------------|-----------|
| Counterparty verification | Trading partner | Amount in a specific transaction | Per-transaction, on demand |
| Audit inspection | External auditor | Balance at a point in time, or a set of transactions | Periodic, batch |
| Regulatory compliance | Regulator / compliance officer | All transactions for an account | Continuous, mandatory |

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

## Layer 1: DisclosureProof — Counterparty Verification

### Purpose

A user proves to a counterparty that a specific ciphertext encrypts a
claimed plaintext amount, without revealing the private key or the
encryption randomness.

### Construction

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

### Properties

| Property | Value |
|----------|-------|
| Proof size | 128 bytes (A₁ 32B + A₂ 32B + z₁ 32B + z₂ 32B) |
| Reveals | Plaintext amount `a` |
| Does NOT reveal | Private key `sk`, randomness `r` |
| Verification | Off-chain, no state change |
| Transcript binding | Merlin with chain ID, block number, account address |
| Selective | Per-ciphertext — user chooses which transactions to disclose |

### Use Cases

- Counterparty confirms received transfer amount before releasing goods.
- Confidential token contract verifies a deposit amount for KYC threshold.
- User voluntarily proves solvency to a lender.

---

## Layer 2: DecryptionToken — Audit Inspection

### Purpose

A user generates a per-ciphertext token that allows an auditor to decrypt
the encrypted amount without learning the private key. The token is a
single elliptic-curve point (32 bytes) per ciphertext.

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

### Use Cases

- Annual audit: user exports tokens for all balance snapshots in the fiscal year.
- Dispute resolution: user discloses specific transactions relevant to the dispute.
- Tax reporting: user provides tokens for all Shield/Unshield events (public-private boundary crossings).

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

### Use Cases

- Regulated financial institution: all confidential transactions auditable by compliance officer.
- Custodial agent wallet: operator can verify all transactions without holding spending keys.
- Legal hold: court order mandates disclosure; guardian sets auditor key; no user cooperation needed.

---

## Comparison of Layers

| | DisclosureProof | DecryptionToken | AuditorKey |
|---|---|---|---|
| **Disclosed to** | Counterparty | Auditor | Regulator |
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

- [ ] `crypto/priv/disclosure.go` — `GenerateDisclosureProof(sk, amount, r, C, D, PK, context)` and `VerifyDisclosureProof(proof, amount, C, D, PK, context)`
- [ ] Merlin transcript label `"disclosure-proof"` with chain context binding
- [ ] `cmd/toskey/priv-disclose.go` — CLI command to generate/verify disclosure proofs
- [ ] RPC: `priv_generateDisclosureProof(address, txHash)` — returns proof + amount
- [ ] SDK: `generateDisclosureProof()` / `verifyDisclosureProof()` in tosdk

### Phase 2: DecryptionToken (off-chain, no consensus changes)

**Scope**: Scalar multiplication + optional DLEQ proof + CLI/RPC.

- [ ] `crypto/priv/token.go` — `GenerateDecryptionToken(sk, D)` and `VerifyDecryptionTokenDLEQ(proof, PK, D, token)`
- [ ] Batch API: `GenerateDecryptionTokenBatch(sk, handles []D)` — returns `[]token`
- [ ] `cmd/toskey/priv-audit-token.go` — CLI for token generation and batch export
- [ ] RPC: `priv_generateDecryptionTokens(address, fromBlock, toBlock)` — returns tokens for all UNO txs in range
- [ ] SDK: `generateDecryptionTokens()` / `decryptWithToken()` in tosdk

### Phase 3: AuditorKey (consensus change)

**Scope**: On-chain state + tx validation + policy wallet integration.

- [ ] `policywallet/state.go` — `ReadAuditorKey(db, addr)` / `WriteAuditorKey(db, addr, pubkey)`
- [ ] `policywallet/handler.go` — `SET_AUDITOR_KEY` system action
- [ ] Transaction types: add optional `AuditHandle [32]byte` field to PrivTransferTx, ShieldTx, UnshieldTx
- [ ] `core/state_transition.go` — validate `AuditHandle` when `AuditorPubKey` is set; reject tx if missing
- [ ] `core/priv/context.go` — extend Merlin transcript with `AuditHandle`
- [ ] TxPool: pre-validate `AuditHandle` presence
- [ ] RPC: `priv_decryptWithAuditorKey(auditorPrivKey, txHash)` — auditor-side decryption
- [ ] `core/parallel/analyze.go` — ensure AuditorKey txs are serialized correctly

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
