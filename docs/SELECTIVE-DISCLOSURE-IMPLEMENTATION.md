# Selective Disclosure Implementation Plan

## Context

The UNO confidential balance system has complete privacy infrastructure (Shield/Transfer/Unshield, 22+ LVM ciphertext ops, payable(uno) contracts), but lacks **selective disclosure** — the ability for account holders to prove properties about their encrypted balances to third parties (lenders, auditors, regulators) without revealing their private key.

Design doc: `docs/SELECTIVE-DISCLOSURE.md`. This plan implements the three layers described there.

## Approach: Three Phases, Off-chain First

```
Phase 1: DisclosureProof   — pure crypto, no consensus change, ~500 lines
    ↓ (establishes DLEQ primitive)
Phase 2: DecryptionToken   — pure crypto, reuses Phase 1 DLEQ, ~340 lines
    ↓
Phase 3: AuditorKey        — consensus change (hard fork), ~400 lines
```

Phases 1-2 are off-chain only (CLI + RPC + SDK). Phase 3 modifies tx types and state transition.

---

## Phase 1: DisclosureProof

**Core primitive**: DLEQ (discrete-log equality) Sigma protocol. Proves `sk` is the same scalar in `sk·D = C - amount·G` (decryption) and `sk·PK = H` (key ownership). This is the foundation reused by Phase 2 and Phase 3.

### New files

| File | Lines | Purpose |
|------|-------|---------|
| `crypto/ed25519/priv_nocgo_disclosure.go` | ~120 | Pure-Go DLEQ proof: Merlin transcript, prove/verify |
| `crypto/priv/disclosure.go` | ~60 | High-level wrappers: `ProveDisclosureExact`, `VerifyDisclosureExact` |
| `core/priv/disclosure.go` | ~100 | Chain-layer: context builder, `DisclosureClaim` type, range variant |
| `cmd/toskey/priv_disclosure.go` | ~80 | CLI: `priv-disclose` command |
| `crypto/priv/disclosure_test.go` | ~80 | Round-trip, wrong amount, wrong key, cross-chain replay |
| `core/priv/disclosure_test.go` | ~60 | Context binding, range proof |

### Modified files

| File | Change |
|------|--------|
| `internal/tosapi/api.go` | Add `PrivProveDisclosure`, `PrivVerifyDisclosure` RPC methods (~40 lines) |
| `cmd/toskey/main.go` | Register `commandPrivDisclose` |
| `tosdk/src/types/disclosure.ts` (new) | TypeScript types for disclosure params/results (~30 lines) |

### Key function signatures

```go
// crypto/priv/disclosure.go
func ProveDisclosureExact(privkey, pubkey [32]byte, ct64 []byte, amount uint64, ctx []byte) (proof96 []byte, err error)
func VerifyDisclosureExact(pubkey [32]byte, ct64 []byte, amount uint64, proof96 []byte, ctx []byte) error

// core/priv/disclosure.go
func BuildDisclosureContext(chainID *big.Int, pubkey [32]byte, ct Ciphertext, amount uint64, blockNum uint64) []byte
func ProveDisclosure(privkey, pubkey [32]byte, ct Ciphertext, amount uint64, chainID *big.Int, blockNum uint64) ([]byte, error)
func VerifyDisclosure(claim DisclosureClaim, chainID *big.Int) error
```

### DLEQ proof construction (96 bytes: R₁[32] + R₂[32] + z[32])

```
Transcript: Merlin("disclosure-exact")
  append("chain-ctx", context)
  append("pubkey", PK)
  append("commitment", C)
  append("handle", D)
  append("amount", amount_le8)

Prover:
  target = C - amount·G          (the point that should equal sk·D)
  pk_inv = sk · PK               (should equal H)
  k ← random scalar
  R₁ = k · D
  R₂ = k · PK
  c = transcript.challenge_scalar("c")
  z = k + c·sk

Verifier:
  target = C - amount·G
  Check: z·D  == R₁ + c·target
  Check: z·PK == R₂ + c·H
```

---

## Phase 2: DecryptionToken

**Core primitive**: `token = sk · D` (32 bytes). Auditor decrypts via `amount·G = C - token`. DLEQ proof (from Phase 1) proves token honesty.

### New files

| File | Lines | Purpose |
|------|-------|---------|
| `crypto/priv/decryption_token.go` | ~50 | `GenerateDecryptionToken`, `DecryptWithToken` |
| `core/priv/decryption_token.go` | ~100 | `DecryptionToken` struct, build/verify/decrypt with ECDLP |
| `cmd/toskey/priv_token.go` | ~90 | CLI: `priv-generate-token`, `priv-decrypt-token` |
| `crypto/priv/decryption_token_test.go` | ~60 | Generate/verify round-trip, decrypt correctness |
| `core/priv/decryption_token_test.go` | ~50 | Batch generation, ECDLP recovery |

### Modified files

| File | Change |
|------|--------|
| `internal/tosapi/api.go` | Add `PrivGenerateDecryptionToken`, `PrivDecryptWithToken`, `PrivVerifyDecryptionToken` (~50 lines) |
| `cmd/toskey/main.go` | Register token commands |
| `tosdk/src/types/disclosure.ts` | Add `DecryptionToken` type (~20 lines) |

### Key function signatures

```go
// crypto/priv/decryption_token.go
func GenerateDecryptionToken(privkey32 []byte, handle32 []byte) (token32 []byte, err error)
func DecryptWithToken(token32, commitment32 []byte) (amountPoint32 []byte, err error)

// core/priv/decryption_token.go
type DecryptionToken struct {
    Pubkey      [32]byte
    Ciphertext  Ciphertext
    Token       [32]byte
    DLEQProof   [96]byte     // reuses Phase 1 DLEQ
    BlockNumber uint64
}
func BuildDecryptionToken(privkey, pubkey [32]byte, ct Ciphertext, chainID *big.Int, blockNum uint64) (*DecryptionToken, error)
func VerifyDecryptionToken(dt *DecryptionToken, chainID *big.Int) error
func DecryptTokenAmount(dt *DecryptionToken) (uint64, error) // uses ECDLP BSGS table
```

---

## Phase 3: AuditorKey (Consensus Change)

**Core primitive**: Policy wallet stores `AuditorPubKey` per account. Priv txs must include `AuditorHandle = r · PK_audit` (32B) + DLEQ proof (96B) proving same `r` as the main handle. Auditor decrypts independently.

### New/modified files

| File | Change | Lines |
|------|--------|-------|
| `policywallet/state.go` | Add `ReadAuditorKey`/`WriteAuditorKey` | ~20 |
| `policywallet/handler.go` | Add `POLICY_SET_AUDITOR_KEY` action handler | ~30 |
| `core/types/priv_transfer_tx.go` | Add `AuditorHandle [32]byte`, `AuditorDLEQProof []byte` fields; update `copy()`, `SigningHash()` | ~15 |
| `core/types/shield_tx.go` | Same: add `AuditorHandle`, `AuditorDLEQProof` | ~10 |
| `core/types/unshield_tx.go` | Same: add `AuditorHandle`, `AuditorDLEQProof` | ~10 |
| `core/priv/context.go` | Extend transcript contexts with AuditorHandle when non-zero | ~15 |
| `core/privacy_tx_prepare.go` | Validate AuditorHandle presence + DLEQ proof when AuditorKey set | ~40 |
| `core/priv/verify.go` | Add `VerifyAuditorHandleDLEQ` | ~30 |
| `core/priv/batch_verify.go` | Add `AddAuditorHandleDLEQ` | ~15 |
| `core/priv/prover.go` | Extend proof builders with optional `auditorPubkey` param | ~30 |
| `core/tx_pool_privacy_verify.go` | Validate AuditorHandle at txpool admission | ~20 |
| `internal/tosapi/api.go` | Add `auditorHandle`/`auditorDLEQProof` to RPC args | ~20 |

### DLEQ for same-randomness proof

Proves `log_{PK_audit}(D_audit) == log_{PK_receiver}(D_receiver)` (both equal `r`):

```
Transcript: Merlin("auditor-handle-dleq")
  append("chain-ctx", context)
  append("pk-audit", PK_audit)
  append("pk-receiver", PK_receiver)
  append("d-audit", D_audit)
  append("d-receiver", D_receiver)

Prover:
  k ← random scalar
  R₁ = k · PK_audit
  R₂ = k · PK_receiver
  c = challenge_scalar("c")
  z = k + c·r

Verifier:
  Check: z·PK_audit    == R₁ + c·D_audit
  Check: z·PK_receiver == R₂ + c·D_receiver
```

### Hard fork considerations

- New fields in tx types change RLP encoding → requires activation block
- Pre-activation: `AuditorHandle` and `AuditorDLEQProof` must be zero/empty
- `core/priv/context.go`: increment context version to 2 when AuditorHandle present

---

## Verification Plan

### Phase 1
```bash
go test -v ./crypto/priv/... -run TestDisclosure
go test -v ./core/priv/... -run TestDisclosure
go test -short -p 96 -timeout 600s ./...   # full suite, no regression
```

### Phase 2
```bash
go test -v ./crypto/priv/... -run TestDecryptionToken
go test -v ./core/priv/... -run TestDecryptionToken
go test -short -p 96 -timeout 600s ./...
```

### Phase 3
```bash
go test -v ./policywallet/... -run TestAuditor
go test -v ./core/... -run TestAuditor
go test -v ./core/... -run TestPriv   # existing priv tests still pass
go test -short -p 96 -timeout 600s ./...
```

### Cross-phase
- Verify Phase 1 DLEQ proof is reused correctly in Phase 2 (token honesty) and Phase 3 (same-r proof)
- Verify backward compatibility: txs without AuditorHandle still accepted when AuditorKey not set

---

## Total scope

| Phase | New files | Modified files | ~Lines |
|-------|-----------|----------------|--------|
| Phase 1 | 6 | 3 | ~500 |
| Phase 2 | 5 | 3 | ~340 |
| Phase 3 | 0 | 12 | ~400 |
| **Total** | **11** | **18** | **~1240** |
