# Privacy Roadmap: Gap Analysis & Path to First-Class Privacy

**Last updated**: 2026-03-15
**Current progress**: ~40-45% toward "Privacy as a first-class property"

---

## Current State

GTOS has a working confidential transfer pipeline (Level 1) with real cryptographic primitives that work on **all builds** (CGO and pure-Go). The privacy surface is narrow: only transfer amounts are hidden, and the private economy is sealed — no public-to-private or private-to-public flow exists at the consensus level.

### What Works

| Capability | Status | Notes |
|---|---|---|
| PrivTransfer consensus path | Full 10-step pipeline | Fee → Nonce → Schnorr → Context → 3 ZK proofs → State update |
| Schnorr signature verification | Wired into consensus | Authenticates sender via ElGamal Ristretto-Schnorr |
| Chain-bound proof context | 235-byte Merlin transcript | Binds proofs to chainID, nonce, fee, addresses, ciphertexts |
| ZK proof verification | CTValidity + CommitmentEq + RangeProof | CGO + pure-Go — both backends fully functional |
| ZK proof generation | Shield + CTValidity + Balance + RangeProof | CGO + pure-Go — prove→verify round-trips pass |
| Homomorphic ciphertext arithmetic | Add / Sub / AddScalar | Pure-Go + CGO |
| Encrypted balance state storage | 4 slots per account | commitment, handle, version, nonce in StateDB |
| RPC endpoints | privTransfer / privGetBalance / privGetNonce | Functional |
| TxPool handling | Size, chainID, nonce, fee validation | Correct nonce source dispatch for PrivTransferTx |
| EncryptedMemo | ECDH + ChaCha20-Poly1305 | Per-tx nonce from txHash; integrity-protected by Schnorr signature |
| Genesis seeding | Full support | Helper script generates encrypted balances for genesis accounts |
| Miner/Worker | PrivTransferTx gas bypass | Correct zero-gas handling in block assembly |

### Exists but Not Usable

| Capability | Issue |
|---|---|
| Shield/Unshield crypto | Proof primitives exist in `crypto/priv` but **no consensus execution path** (no `applyPrivShield`/`applyPrivUnshield`) |
| EncryptedMemo consumption | Memo is carried in tx and covered by Schnorr signature, but **execution path does not read or validate it** |
| TxPool FeeLimit check | Fee vs FeeLimit validation is marked TODO |

### Entirely Missing

| Dimension | What's Missing |
|---|---|
| Transaction graph privacy | No stealth addresses, no decoy/mixin outputs, no ring signatures — sender/receiver fully linkable |
| Network-layer privacy | No Dandelion++, no Tor, no mixnet — standard gossip broadcast, transaction origin IP is traceable |
| Contract privacy | LVM executes publicly, no encrypted storage, no FHE/MPC |
| Key management CLI | Only `priv-transfer` exists — no keygen, balance, shield, unshield subcommands |
| Shield/Unshield consensus | No public→private or private→public flow — private economy is sealed inside genesis seeds |
| RPC access control | commitment/handle/version readable by anyone — account activity frequency is observable |

---

## Privacy Capability Layers

```
┌─────────────────────────────────────────────┐
│  Level 5: Contract privacy (FHE/MPC)        │  MISSING
├─────────────────────────────────────────────┤
│  Level 4: Network privacy (Dandelion++/Tor) │  MISSING
├─────────────────────────────────────────────┤
│  Level 3: Graph privacy (stealth/decoy)     │  MISSING
├─────────────────────────────────────────────┤
│  Level 2: Liquidity (Shield/Unshield)       │  Crypto exists, consensus path missing
├─────────────────────────────────────────────┤
│  Level 1: Amount privacy (CT transfer)      │  DONE (CGO + pure-Go)
├─────────────────────────────────────────────┤
│  Level 0: Infrastructure (state/genesis/RPC)│  DONE
└─────────────────────────────────────────────┘
```

---

## Critical Gaps (Priority Order)

### ~~P0: Default build produces non-functional privacy~~ ✅ DONE

Resolved in commit `415d63c`. All 43 cryptographic functions now have pure-Go implementations using `crypto/ristretto255` and `golang.org/x/crypto`. `PrivBackendEnabled()` returns `true` on all builds. Prove→verify round-trips, context-binding mutation tests, and determinism tests all pass under `CGO_ENABLED=0`.

### P1: No Shield/Unshield consensus path

**Problem**: The private economy is sealed. Users cannot move TOS from public balance to encrypted balance (Shield) or back (Unshield). The only way to have encrypted balance is through genesis seeding.

**What exists**: `VerifyShieldProof` / `ProveShieldProof` in the crypto layer. No `applyPrivShield()` or `applyPrivUnshield()` in `state_transition.go`. No `PrivShieldTxType` or `PrivUnshieldTxType` in the type system.

**Required work**:
- Define `PrivShieldTxType` and `PrivUnshieldTxType` transaction types
- Implement `applyPrivShield()`: deduct public balance, add to encrypted balance, verify proof
- Implement `applyPrivUnshield()`: deduct encrypted balance, add to public balance, verify proof
- Add gas constants (`PrivShieldGas`, `PrivUnshieldGas`)
- Wire into TxPool validation
- Add CLI subcommands (`priv-shield`, `priv-unshield`)
- Add RPC endpoints

**Impact**: Without this, privacy is a demo feature, not a production capability.

### P2: Zero transaction graph privacy

**Problem**: `PrivTransferTx.From` and `PrivTransferTx.To` are 32-byte ElGamal public keys. The derived addresses (`Keccak256(pubkey)[:20]`) are deterministic and fully linkable across transactions. Anyone observing the chain can:
- Link all transactions from the same sender
- Link all transactions to the same receiver
- Build a complete transaction graph
- Track account activity via the version counter

Only the transfer *amount* is hidden. The *who-pays-whom* relationship is fully public.

**Required work** (Phase 2 in PRIVACY-FIRST-CLASS-ADD.md):
- DKSAP (Dual-Key Stealth Address Protocol) for receiver unlinkability
- Stealth meta-address storage slots
- `DeriveStealthAddress()` / `ScanStealthPayment()` implementation
- Ephemeral pubkey in transaction
- Scanner RPC endpoint

**Impact**: Amount privacy without graph privacy provides limited real-world protection.

---

## Secondary Gaps

### S1: Network-layer privacy

Transactions are broadcast via standard gossip. The first node to propagate a transaction reveals the sender's IP. Dandelion++ (stem-then-fluff routing) would break the link between transaction origin and network identity.

**Required**: Dandelion++ implementation in `p2p/` layer, intercept PrivTransferTx broadcast for stem phase.

### S2: Key management CLI

Only `toskey priv-transfer` exists. Users need:
- `toskey priv-keygen` — generate ElGamal keypair
- `toskey priv-balance` — decrypt and display encrypted balance from on-chain ciphertext
- `toskey priv-shield` — build and submit Shield transaction
- `toskey priv-unshield` — build and submit Unshield transaction

### S3: TxPool pre-validation gaps

- Fee vs FeeLimit check is TODO
- No proof shape/size pre-validation at pool admission (malformed proofs consume consensus resources)
- No Schnorr signature pre-check at pool level (invalid signatures consume consensus resources)

### S4: EncryptedMemo not consumed

The memo field is integrity-protected (included in Schnorr signing hash) but the execution path does not validate or index it. Consider whether memos should be:
- Validated for size/format during consensus
- Indexed for recipient retrieval via RPC
- Or remain purely opaque (current behavior — simplest)

### S5: Contract privacy

The LVM executes all contracts with fully public state. No encrypted storage, no confidential computation. This is a long-term gap that would require FHE, MPC, or TEE integration.

---

## Suggested Execution Order

| Phase | Work | Unlocks |
|---|---|---|
| ~~**Phase 0**~~ | ~~Resolve CGO dependency (P0)~~ | ✅ **DONE** — Privacy works on default builds |
| **Phase 1** | Shield/Unshield consensus paths (P1) | Public ↔ private flow, usable economy |
| **Phase 1b** | Key management CLI (S2) | End-user tooling |
| **Phase 1c** | TxPool hardening (S3) | DoS resistance |
| **Phase 2** | Stealth addresses (P2) | Receiver unlinkability |
| **Phase 3** | Dandelion++ (S1) | Network-layer privacy |
| **Phase 4** | Decoy outputs | Sender unlinkability |
| **Phase 5** | Contract privacy (S5) | Full-stack privacy |

**Phase 0 is complete.** Completing Phase 1 brings privacy from "functional crypto" (~40%) to "minimally viable" (~55%).
Completing Phases 1-2 reaches "meaningfully private" (~70%).
Phases 3-5 are required for "first-class property" status.
