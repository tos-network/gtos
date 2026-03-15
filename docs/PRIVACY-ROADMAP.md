# Privacy Roadmap: Gap Analysis & Path to First-Class Privacy

**Last updated**: 2026-03-15
**Current progress**: ~58% toward "Privacy as a first-class property"

---

## Current State

GTOS has a working confidential transfer pipeline (Level 1) and a complete Shield/Unshield consensus path (Level 2). The privacy surface covers amount hiding for transfers and bidirectional public↔private fund flow. Transaction graph privacy (sender/receiver linkability) remains the primary gap.

### What Works

| Capability | Status | Notes |
|---|---|---|
| PrivTransfer consensus path | Full 10-step pipeline | Fee → Nonce → Schnorr → Context → 3 ZK proofs → State update |
| Shield consensus path (0x02) | Full 11-step pipeline | Public balance → encrypted balance deposit with ShieldProof + RangeProof; supports third-party recipient |
| Unshield consensus path (0x03) | Full 12-step pipeline | Encrypted balance → public balance withdrawal with CommitmentEqProof + RangeProof; supports third-party recipient |
| Schnorr signature verification | Wired into consensus | Authenticates sender via ElGamal Ristretto-Schnorr (all 3 tx types) |
| Chain-bound proof context | Merlin transcripts | Transfer 259B, Shield 131B, Unshield 163B — binds proofs to chain state |
| ZK proof verification | CTValidity + CommitmentEq + RangeProof + Shield | CGO + pure-Go — both backends fully functional |
| ZK proof generation | Shield + Unshield + CTValidity + CommitmentEq + Balance + RangeProof | CGO + pure-Go — prove→verify round-trips pass |
| Homomorphic ciphertext arithmetic | Add / Sub / AddScalar | Pure-Go + CGO |
| Encrypted balance state storage | 4 slots per account | commitment, handle, version, nonce in StateDB |
| RPC endpoints | privTransfer / privShield / privUnshield / privGetBalance / privGetNonce | Functional |
| TxPool handling | Size, chainID, nonce, fee, funds validation | Correct priv nonce source dispatch; PrivTransfer FeeLimit enforced; Shield/Unshield public-balance coverage enforced |
| Fee model | Gas units × TxPriceWei | PrivBaseFee = 42,000 gas (2× plain transfer); `FeeToWei()` converts to Wei on-chain |
| EncryptedMemo | ECDH + ChaCha20-Poly1305 | Per-tx nonce from txHash; integrity-protected by Schnorr signature |
| Genesis seeding | Full support | Helper script generates encrypted balances for genesis accounts |
| Miner/Worker | All priv tx types gas bypass | Correct zero-gas handling in block assembly for PrivTransfer/Shield/Unshield |
| CLI tooling | priv-transfer / priv-shield / priv-unshield | Proof generation and transaction construction |

### Exists but Not Usable

| Capability | Issue |
|---|---|
| EncryptedMemo consumption | Memo is carried in tx and covered by Schnorr signature, but **execution path does not read or validate it** |

### Entirely Missing

| Dimension | What's Missing |
|---|---|
| Transaction graph privacy | No stealth addresses, no decoy/mixin outputs, no ring signatures — sender/receiver fully linkable |
| P2P encryption | No encrypted peer-to-peer communication — transaction payloads visible to network observers |
| Network-layer anonymity | No Dandelion++, no Tor, no mixnet — standard gossip broadcast, transaction origin IP is traceable |
| Contract privacy | LVM executes publicly, no encrypted storage, no homomorphic operations in contracts |
| Key management CLI | No keygen or balance-decrypt subcommands (shield/unshield now exist) |
| RPC access control | commitment/handle/version readable by anyone — account activity frequency is observable |

---

## Privacy Capability Layers

```
┌─────────────────────────────────────────────┐
│  Level 5: Contract privacy (FHE/MPC)        │  MISSING
├─────────────────────────────────────────────┤
│  Level 4: Network privacy (encrypt+anon)    │  MISSING
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

## Completed Work

### ~~P0: Default build produces non-functional privacy~~ ✅ DONE

Resolved in commit `415d63c`. All 43 cryptographic functions now have pure-Go implementations using `crypto/ristretto255` and `golang.org/x/crypto`. `PrivBackendEnabled()` returns `true` on all builds. Prove→verify round-trips, context-binding mutation tests, and determinism tests all pass under `CGO_ENABLED=0`.

### ~~P1: No Shield/Unshield consensus path~~ ✅ DONE

Resolved in commit `f358af8`. Full details:

- **Transaction types**: `ShieldTxType=0x02` and `UnshieldTxType=0x03` defined with complete TxData interface, RLP encoding, and SigningHash
- **Third-party support**: Shield `Recipient` field (ElGamal pubkey) and Unshield `Recipient` field (address) allow deposits/withdrawals to any account
- **Consensus execution**: `applyShield()` (11 steps) and `applyUnshield()` (12 steps) in `state_transition.go`, bypassing gas pipeline like PrivTransfer
- **Shield flow**: Deducts `Amount + FeeToWei(Fee)` from sender → verifies ShieldProof under Recipient's key + RangeProof → adds ciphertext to recipient's encrypted balance
- **Unshield flow**: Computes `zeroedCt` via ciphertext subtraction → verifies CommitmentEqProof + RangeProof → updates sender's encrypted balance → credits `Amount` to recipient's public balance, deducts `FeeToWei(Fee)` from recipient
- **Proof context**: 131-byte Shield context (actionTag=0x11), 163-byte Unshield context (actionTag=0x12), bound to chain/nonce/fee/amount/address
- **Shared PrivNonce**: All 3 tx types (Transfer, Shield, Unshield) share the same PrivNonce counter per account
- **Fee**: PrivBaseFee = 42,000 gas (2× plain transfer); fee fields are gas units, charged on-chain via `FeeToWei()`

---

## Remaining Work

### Phase 1b: Key management CLI (~60%)

**Goal**: End users can generate keys and check encrypted balances from the command line.

**Effort**: 1–2 days

**Tasks**:
- [ ] `toskey priv-keygen` — generate ElGamal keypair, output pubkey + privkey (optionally encrypted with passphrase)
- [ ] `toskey priv-balance` — take privkey + on-chain ciphertext (via `--rpc` or `--ct` flag), decrypt via ECDLP baby-step-giant-step, display plaintext balance
- [ ] `toskey priv-history` (optional) — scan PrivNonce range and decrypt each version's balance

### Phase 1c: TxPool pre-validation hardening (~62%)

**Goal**: Reject obviously invalid priv transactions at pool admission before they consume consensus resources.

**Effort**: 1–2 days

**Tasks**:
- [ ] Proof shape/size pre-validation — reject transactions with wrong proof sizes at `validatePrivTransferTx` / `validateShieldTx` / `validateUnshieldTx` (check `len(CtValidityProof)==160`, `len(ShieldProof)==96`, etc.)
- [ ] Schnorr signature pre-check — verify `VerifySchnorrSignature(pubkey, sigHash, S, E)` at pool admission (currently only checked during consensus execution)
- [ ] ShieldProof/RangeProof pre-verification (optional, expensive) — only if DoS proves to be a real concern

### Phase 2: Stealth addresses — receiver unlinkability (~72%)

**Goal**: Each PrivTransfer generates a one-time recipient address. Observers cannot link multiple payments to the same recipient. This is the single highest-impact privacy improvement remaining.

**Effort**: 2–4 weeks

**What it protects against**: An observer sees `From → StealthAddr1`, `From → StealthAddr2` and cannot determine that both payments went to the same person.

**Protocol**: DKSAP (Dual-Key Stealth Address Protocol)
- Each recipient publishes a **stealth meta-address** (spend pubkey + view pubkey)
- Sender derives a one-time stealth address per transaction using an ephemeral keypair
- Recipient scans the chain using their view private key to detect payments

**Tasks**:
- [ ] **Crypto layer** (`crypto/priv/stealth.go`):
  - `GenerateStealthMetaAddress(spendPriv, viewPriv) → (spendPub, viewPub)`
  - `DeriveStealthAddress(metaAddr, ephemeralPriv) → (stealthPub, ephemeralPub)`
  - `ScanStealthPayment(viewPriv, ephemeralPub, stealthPub) → bool`
  - `RecoverStealthPrivKey(spendPriv, viewPriv, ephemeralPub) → stealthPriv`
- [ ] **Transaction changes** (`core/types/priv_transfer_tx.go`):
  - Add `EphemeralPubkey [32]byte` field to PrivTransferTx
  - `To` becomes the one-time stealth address (not the long-lived pubkey)
  - Update SigningHash to cover EphemeralPubkey
  - Update transcript context to include EphemeralPubkey
- [ ] **State changes** (`core/priv/state.go`):
  - Stealth meta-address storage slots per account (spendPub + viewPub)
  - RPC to register/query stealth meta-addresses
- [ ] **Consensus changes** (`core/state_transition.go`):
  - `applyPrivTransfer()` validates that `To` is a properly derived stealth address (optional — can be enforced client-side only)
- [ ] **Scanner** (`internal/privtracker/` or new package):
  - Background scanner: iterate new blocks, try `ScanStealthPayment` for each known view key
  - RPC endpoint: `privScanPayments(viewKey, fromBlock, toBlock) → []Payment`
- [ ] **CLI**:
  - `toskey priv-stealth-keygen` — generate stealth meta-address
  - `toskey priv-stealth-scan` — scan chain for incoming payments
  - Update `priv-transfer` to accept stealth meta-address and auto-derive one-time address
- [ ] **Tests**: Unit tests for crypto primitives, integration test for full send→scan→recover flow

### Phase 3: Network-layer privacy (~80%)

**Goal**: Break the link between transaction origin and network identity. An observer monitoring the P2P network cannot determine which node originated a transaction.

**Effort**: 1–2 weeks

**Sub-goals**:

#### Phase 3a: P2P encryption
- [ ] Encrypt all peer-to-peer communication using ChaCha20-Poly1305 with x25519 Diffie-Hellman key exchange
- [ ] Key rotation after fixed data threshold (e.g. 1GB)
- [ ] Separate encryption keys per direction

#### Phase 3b: Dandelion++ transaction relay
- [ ] **Stem phase**: When a node creates or first receives a priv transaction, forward it to exactly one random peer (the "stem")
- [ ] **Fluff phase**: After a random number of stem hops (Poisson-distributed, λ≈4), switch to standard gossip broadcast
- [ ] **Fail-safe timer**: If a stemmed transaction doesn't appear in a block within timeout, fluff it
- [ ] Intercept only `PrivTransferTx`, `ShieldTx`, `UnshieldTx` for stem phase; regular transactions use standard gossip
- [ ] **Files**: `p2p/dandelion.go` — stem routing table, phase tracking, timeout management

### Phase 4: Decoy outputs — sender unlinkability (~90%)

**Goal**: Observers cannot determine which account is the true sender of a transaction. Combined with Phase 2 (stealth addresses), this makes both sender and receiver unlinkable.

**Effort**: 3–6 weeks

**What it protects against**: Without decoys, the `From` field directly identifies the sender. With decoys, `From` is hidden among a set of plausible senders.

**Approach options** (choose one):

#### Option A: Ring signatures (Monero-style)
- Each transaction includes the true sender plus N decoy signers (ring size = N+1)
- Verifier can confirm "one of these N+1 accounts signed" but not which one
- Requires: Linkable ring signatures over Ristretto255, key images to prevent double-spend
- **Tasks**:
  - [ ] Ring signature crypto (`crypto/priv/ring.go`): `RingSign()`, `RingVerify()`, `KeyImage()`
  - [ ] Key image set in state (prevents double-spend without revealing sender)
  - [ ] Decoy selection algorithm (recent outputs, age distribution matching)
  - [ ] PrivTransferTx: replace `From [32]byte` with `Ring [][32]byte` + `KeyImage [32]byte`
  - [ ] Update consensus verification to ring-verify instead of Schnorr-verify

#### Option B: Spend authorization proofs (lighter)
- Sender proves "I own one of these N accounts" via a ZK membership proof
- Lighter than full ring signatures but provides same unlinkability
- **Tasks**:
  - [ ] ZK membership proof (`crypto/priv/membership.go`)
  - [ ] Nullifier/key-image mechanism
  - [ ] Decoy selection and ring construction

**Shared tasks** (either option):
- [ ] Decoy selection RPC: `privGetDecoys(count, excludeAddr) → []Pubkey`
- [ ] Update TxPool validation for ring/membership proofs
- [ ] Update transcript context to cover ring members
- [ ] Integration tests: send with decoys → verify → confirm no sender leakage

### Phase 5: Contract privacy (~100%)

**Goal**: Smart contract state and computation are confidential. Observers cannot read contract storage or infer contract logic from execution traces.

**Effort**: Months to years (research frontier)

**Staged approach**:

#### Phase 5a: Homomorphic operations in contracts (near-term)
- [ ] Expose `Ciphertext` as an opaque type in LVM contract language
- [ ] Support homomorphic operations: `ct_add(a, b)`, `ct_add_scalar(ct, n)`, `ct_sub(a, b)`
- [ ] Contracts can store and manipulate encrypted values without decrypting
- [ ] Use case: confidential token balances managed by a contract

#### Phase 5b: Encrypted contract storage (medium-term)
- [ ] Contract storage slots optionally encrypted under contract-specific keys
- [ ] Read-access requires decryption proof or authorized viewkey
- [ ] Encrypted event logs for private contract notifications

#### Phase 5c: Confidential computation (long-term, research)
- [ ] FHE integration for arbitrary encrypted computation
- [ ] Or MPC-based execution across validator committee
- [ ] Or TEE (Trusted Execution Environment) based contract execution
- [ ] This is an active research area with no production-ready solution

---

## Execution Order and Milestones

| Phase | Work | Effort | Unlocks | Cumulative |
|---|---|---|---|---|
| ~~**Phase 0**~~ | ~~CGO dependency~~ | ✅ DONE | Privacy works on default builds | ~40% |
| ~~**Phase 1**~~ | ~~Shield/Unshield~~ | ✅ DONE | Public ↔ private flow | ~58% |
| **Phase 1b** | Key management CLI | 1–2 days | End-user tooling | ~60% |
| **Phase 1c** | TxPool hardening | 1–2 days | DoS resistance | ~62% |
| **Phase 2** | Stealth addresses | 2–4 weeks | **Receiver unlinkability** | **~72%** |
| **Phase 3** | P2P encrypt + Dandelion++ | 1–2 weeks | Network privacy | ~80% |
| **Phase 4** | Decoy outputs / ring sig | 3–6 weeks | **Sender unlinkability** | **~90%** |
| **Phase 5a** | Contract ciphertext ops | 2–4 weeks | Confidential tokens | ~93% |
| **Phase 5b** | Encrypted storage | 4–8 weeks | Private contract state | ~96% |
| **Phase 5c** | FHE/MPC/TEE | Months–years | Full-stack privacy | 100% |

### Privacy milestones

| Milestone | Phases required | What it means |
|---|---|---|
| **Minimally viable** | 0 + 1 | ← **We are here** (~58%). Amounts hidden, funds flow freely, but transaction graph fully exposed |
| **Meaningfully private** | + 2 | (~72%). Receiver unlinkable — chain analysis can no longer trivially map payment recipients |
| **Strongly private** | + 2 + 3 + 4 | (~90%). Both sender and receiver unlinkable, network layer anonymized |
| **First-class property** | + 2 + 3 + 4 + 5 | (100%). Full-stack privacy including confidential smart contracts |

**Next priority: Phase 1b + 1c (quick wins), then Phase 2 (stealth addresses) as the highest-impact single improvement.**
