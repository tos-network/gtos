# Privacy as a First-Class Property — Gap Assessment

Status: **HISTORICAL — superseded by [PRIVACY-ROADMAP.md](PRIVACY-ROADMAP.md)**

> **Update 2026-03-16**: This assessment was written on 2026-03-15 when progress
> was ~30-35%. Since then, Phases 0-5 of the privacy roadmap have been completed
> (~80%). The "Critical Blocker" (C backend) is resolved — both CGO and pure-Go
> backends are fully functional. Phase 5 (contract ciphertext ops) added the
> `uno` type with 22 LVM operations, all with real ZK verification (Sigma
> protocols + Bulletproofs range proofs). See PRIVACY-ROADMAP.md for current status.

This document evaluates how far the GTOS network has progressed toward
its stated goal of "privacy as a first-class property, not an afterthought."

---

## What Is Implemented

### 1. Encrypted Balances (Priv Protocol) — Complete

| Component | Status | Detail |
|-----------|--------|--------|
| Twisted ElGamal over Ristretto255 | Done | 64-byte ciphertext pair per account (Commitment + Handle) |
| Homomorphic arithmetic | Done | Add / subtract / scalar-multiply on ciphertexts without decryption |
| Account state storage | Done | Slots: `gtos.priv.ctCommitment`, `gtos.priv.ctHandle`, `gtos.priv.version` |
| Three privacy operations | Done | Shield (public→private), Transfer (private→private), Unshield (private→public) |
| EncryptedMemo field | Done | Optional encrypted memo attached to Priv transactions |

### 2. Zero-Knowledge Proof Architecture — Interface Complete

| Proof Type | Size | Purpose |
|-----------|------|---------|
| Shield Proof | 96 bytes | Proves encrypted balance equals claimed amount |
| CT Validity Proof | 160 bytes | Proves ciphertext encryption is valid for both parties |
| Balance Proof | 200 bytes | Proves sender has sufficient encrypted balance |
| Range Proof | 672 bytes | Proves amount fits 64-bit range |
| **Total per transfer** | **1,032 bytes** | All proofs bundled together |

All six verification functions are defined with `...WithContext()` variants
for replay hardening.

### 3. Replay Protection — Complete

All proofs are bound via Merlin transcript context:
- Chain ID, sender address, receiver address, sender nonce, action type
- 83+ byte context header constructed in `core/priv/context.go`
- Cross-chain protection with `MaxUint64` clamping

### 4. Cryptographic Primitives — Complete

- Ristretto255: RFC 9496 compliant, constant-time scalar multiplication
- Edwards25519: fiat-crypto backend with assembly acceleration
- Pedersen commitments: unconditionally hiding, computationally binding
- ElGamal: semantic security under DDH

---

## ~~Critical Blocker~~ ✅ RESOLVED

### ~~Proof Verification Not Functional~~

> **Resolved**: Phase 0 (commit `415d63c`) added pure-Go implementations for
> all 43 cryptographic functions. Both CGO and pure-Go backends are fully
> functional. `PrivBackendEnabled()` returns `true` on all builds.

~~All proof verification dispatches to the C backend (`ed25519c`) via FFI.
Without CGO compilation, every verification call returns
`ErrPrivBackendUnavailable`.~~

---

## Privacy Gaps

### 1. Transaction Graph Privacy — NOT ADDRESSED (Severity: High)

| Aspect | Status | Issue |
|--------|--------|-------|
| Sender anonymity | Private | Encrypted in state; revealed only at unshield |
| Receiver anonymity | **Public** | Receiver address visible on-chain even in private transfers |
| Amount privacy | Private | ZK-proven; revealed only at unshield |
| Linkage detection | **Trivial** | Shield→Transfer→Unshield sequences fully traceable |

Missing mechanisms:
- No stealth addresses for receivers
- No decoy / mixin transactions to obscure true recipients
- No unified address model with optional transparency
- Unshield explicitly reveals `{To, Amount}` at exit

### 2. Agent / Identity Privacy — NOT ADDRESSED (Severity: High)

The Agent Registry is fully transparent:
- Stake amount, registration status, suspension flag, metadata URI,
  capability bits, reputation score, and rating count are all public
- Agent count is a monotonically increasing counter
- Agent Discovery broadcasts capabilities, connection modes, and node IDs
  via ENR records

Missing mechanisms:
- No ZK proofs for agent identity
- No anonymous agent creation
- No stealth addresses for agents
- No threshold / m-of-n identity schemes

### 3. Network-Layer Privacy — NOT ADDRESSED (Severity: Medium-High)

Standard libp2p P2P stack without privacy enhancements:
- IP addresses visible in DHT
- Peer discovery reveals node IDs and connectivity patterns
- No Tor, VPN, or onion routing integration
- No encrypted peer-to-peer message channels beyond transport TLS

### 4. Metadata Privacy — NOT ADDRESSED (Severity: Medium)

| Metadata | Visibility | Notes |
|----------|------------|-------|
| Transaction size | Observable | Proof sizes are deterministic per action type |
| Block timing | Observable | 360ms target, fully public |
| Action type | Inferable | Gas cost differs: Shield ≠ Transfer ≠ Unshield |
| Gas patterns | Observable | Constant per action type, leaks operation identity |
| Account version | Observable | Increments per operation, reveals activity frequency |
| EncryptedMemo | Optional | Not mandatory, not validated as actually encrypted |

### 5. Contract / Call Privacy — ~~NOT ADDRESSED~~ ✅ PARTIALLY ADDRESSED (Phase 5 complete)

> **Update 2026-03-16**: Phase 5 added the `uno` encrypted type to TOL with
> 22 `tos.ciphertext.*` LVM operations (homomorphic add/sub/mul/div/rem,
> comparisons, min/max/select, verification). All with real ZK proofs.
> Contracts can now store and manipulate encrypted values (confidential tokens,
> private voting). Encrypted logs/events and confidential general-purpose
> compute remain out of scope.

- ~~LVM contract calls are on-chain visible~~
- ~~No private contract state~~
- No encrypted logs or events
- No confidential compute for contract execution

---

## Overall Verdict

```
Vision                                     Current Reality
────────────────────────────────────────────────────────────────
"Privacy as a first-class property"        Private payment layer (partial)
Privacy extends to intent, routing,        Covers balance encryption only
  metadata, and coordination patterns
────────────────────────────────────────────────────────────────
```

**Estimated progress at time of writing: ~30-35% toward the stated goal.** *(Now ~80% — see PRIVACY-ROADMAP.md)*

Priv is solid foundational infrastructure — the cryptographic primitives
(Ristretto255, Twisted ElGamal, Pedersen) are well-chosen and the proof
architecture is structurally complete. But "encrypted balances" alone does
not constitute "privacy as a first-class property."

---

## Recommended Roadmap

### Short Term — Reach ~50%

- **Integrate C backend for proof verification.** Without this, Priv is
  architecturally present but operationally inert on-chain.

### Medium Term — Reach ~70%

- **Stealth addresses** for receivers to break transaction graph linkability.
- **Uniform transaction sizing** to eliminate gas-based action type inference.
- **Optional privacy mode** for Agent Registry (ZK-proven stake and
  capabilities without revealing identity).

### Long Term — Reach ~90%+

- **Network-layer privacy** (Tor integration or mixnet relay).
- **Metadata obfuscation** (dummy transactions, uniform timing).
- **Confidential contract state** for LVM execution.
- **Mandatory privacy** as the default mode, not opt-in.
