# Privacy Roadmap: Gap Analysis & Path to First-Class Privacy

**Last updated**: 2026-03-15
**Current progress**: ~55% toward "Privacy as a first-class property"

---

## Current State

GTOS has a working confidential transfer pipeline (Level 1) and a complete Shield/Unshield consensus path (Level 2). The privacy surface covers amount hiding for transfers and bidirectional public↔private fund flow. Transaction graph privacy (sender/receiver linkability) remains the primary gap.

### What Works

| Capability | Status | Notes |
|---|---|---|
| PrivTransfer consensus path | Full 10-step pipeline | Fee → Nonce → Schnorr → Context → 3 ZK proofs → State update |
| Shield consensus path (0x02) | Full 11-step pipeline | Public balance → encrypted balance deposit with ShieldProof + RangeProof |
| Unshield consensus path (0x03) | Full 12-step pipeline | Encrypted balance → public balance withdrawal with CommitmentEqProof + RangeProof |
| Schnorr signature verification | Wired into consensus | Authenticates sender via ElGamal Ristretto-Schnorr (all 3 tx types) |
| Chain-bound proof context | Merlin transcripts | Transfer 259B, Shield 131B, Unshield 163B — binds proofs to chain state |
| ZK proof verification | CTValidity + CommitmentEq + RangeProof + Shield | CGO + pure-Go — both backends fully functional |
| ZK proof generation | Shield + Unshield + CTValidity + Balance + RangeProof | CGO + pure-Go — prove→verify round-trips pass |
| Homomorphic ciphertext arithmetic | Add / Sub / AddScalar | Pure-Go + CGO |
| Encrypted balance state storage | 4 slots per account | commitment, handle, version, nonce in StateDB |
| RPC endpoints | privTransfer / privShield / privUnshield / privGetBalance / privGetNonce | Functional |
| TxPool handling | Size, chainID, nonce, fee validation | Correct nonce source dispatch for all 3 priv tx types |
| EncryptedMemo | ECDH + ChaCha20-Poly1305 | Per-tx nonce from txHash; integrity-protected by Schnorr signature |
| Genesis seeding | Full support | Helper script generates encrypted balances for genesis accounts |
| Miner/Worker | All priv tx types gas bypass | Correct zero-gas handling in block assembly for PrivTransfer/Shield/Unshield |
| CLI tooling | priv-transfer / priv-shield / priv-unshield | Proof generation and transaction construction |

### Exists but Not Usable

| Capability | Issue |
|---|---|
| EncryptedMemo consumption | Memo is carried in tx and covered by Schnorr signature, but **execution path does not read or validate it** |
| TxPool FeeLimit check | Fee vs FeeLimit validation is marked TODO |

### Entirely Missing

| Dimension | What's Missing |
|---|---|
| Transaction graph privacy | No stealth addresses, no decoy/mixin outputs, no ring signatures — sender/receiver fully linkable |
| Network-layer privacy | No Dandelion++, no Tor, no mixnet — standard gossip broadcast, transaction origin IP is traceable |
| Contract privacy | LVM executes publicly, no encrypted storage, no FHE/MPC |
| Key management CLI | No keygen or balance-decrypt subcommands (shield/unshield now exist) |
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
│  Level 2: Liquidity (Shield/Unshield)       │  DONE (consensus + RPC + CLI)
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

### ~~P1: No Shield/Unshield consensus path~~ ✅ DONE

Resolved in Privacy Phase 1 implementation. Full details:

- **Transaction types**: `ShieldTxType=0x02` and `UnshieldTxType=0x03` defined with complete TxData interface, RLP encoding, and SigningHash
- **Consensus execution**: `applyShield()` (11 steps) and `applyUnshield()` (12 steps) in `state_transition.go`, bypassing gas pipeline like PrivTransfer
- **Shield flow**: Deducts Amount+Fee from public balance → verifies ShieldProof + RangeProof → adds (Commitment, Handle) to encrypted balance homomorphically
- **Unshield flow**: Computes zeroedCt via ciphertext subtraction → verifies CommitmentEqProof + RangeProof → updates encrypted balance → credits Amount to public balance (before fee deduction)
- **Proof context**: 131-byte Shield context (actionTag=0x11), 163-byte Unshield context (actionTag=0x12), bound to chain/nonce/fee/amount/address
- **Shared PrivNonce**: All 3 tx types (Transfer, Shield, Unshield) share the same PrivNonce counter per account
- **TxPool**: `validateShieldTx()` / `validateUnshieldTx()` with proper nonce resolution for all priv types
- **Miner/Worker**: `isPrivTransfer` check covers all 3 types; `txSenderHint` uses unified `PrivTxFrom()`
- **RPC**: `PrivShield()` / `PrivUnshield()` endpoints with `RPCShieldArgs` / `RPCUnshieldArgs`
- **CLI**: `priv-shield` / `priv-unshield` commands in `toskey` for client-side proof generation
- **Prover**: `BuildShieldProofs()` / `BuildUnshieldProofs()` in `core/priv/prover.go`
- **Fee**: Fixed 10,000 minimum for both Shield and Unshield (same as PrivTransfer)

### P2: Zero transaction graph privacy

**Problem**: `PrivTransferTx.From` and `PrivTransferTx.To` are 32-byte ElGamal public keys. The derived addresses (`Keccak256(pubkey)`) are deterministic and fully linkable across transactions. Anyone observing the chain can:
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

`toskey` now has `priv-transfer`, `priv-shield`, and `priv-unshield`. Users still need:
- `toskey priv-keygen` — generate ElGamal keypair
- `toskey priv-balance` — decrypt and display encrypted balance from on-chain ciphertext

### S3: TxPool pre-validation gaps

- Fee vs FeeLimit check is TODO (PrivTransfer only; Shield/Unshield have no FeeLimit field)
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
| ~~**Phase 1**~~ | ~~Shield/Unshield consensus paths (P1)~~ | ✅ **DONE** — Public ↔ private flow, usable economy |
| **Phase 1b** | Key management CLI (S2) | End-user tooling |
| **Phase 1c** | TxPool hardening (S3) | DoS resistance |
| **Phase 2** | Stealth addresses (P2) | Receiver unlinkability |
| **Phase 3** | Dandelion++ (S1) | Network-layer privacy |
| **Phase 4** | Decoy outputs | Sender unlinkability |
| **Phase 5** | Contract privacy (S5) | Full-stack privacy |

**Phases 0-1 are complete.** Privacy has advanced from "functional crypto" (~40%) to "minimally viable" (~55%).
Completing Phase 2 reaches "meaningfully private" (~70%).
Phases 3-5 are required for "first-class property" status.
