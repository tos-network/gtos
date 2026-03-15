# Privacy Roadmap: Gap Analysis & Path to First-Class Privacy

**Last updated**: 2026-03-15
**Current progress**: ~62% toward practical privacy target (~85%)

---

## Current State

GTOS has a working confidential transfer pipeline (Level 1) and a complete Shield/Unshield consensus path (Level 2). The privacy surface covers amount hiding for transfers and bidirectional public↔private fund flow. Network-layer privacy (P2P encryption + Dandelion++) and contract-level homomorphic operations are the remaining practical targets. Transaction graph privacy (sender/receiver unlinkability) has been deprioritized — stealth addresses and ring signatures are UTXO-model concepts incompatible with GTOS's account model.

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
| TxPool handling | Size, chainID, nonce, fee, funds, proof-shape, signature validation | Correct priv nonce source dispatch; PrivTransfer FeeLimit enforced; Shield/Unshield public-balance coverage enforced; malformed proofs and bad Schnorr signatures rejected at pool admission |
| Fee model | Gas units × TxPriceWei | PrivBaseFee = 42,000 gas (2× plain transfer); `FeeToWei()` converts to Wei on-chain |
| EncryptedMemo | ECDH + ChaCha20-Poly1305 | Per-tx nonce from txHash; integrity-protected by Schnorr signature |
| Genesis seeding | Full support | Helper script generates encrypted balances for genesis accounts |
| Miner/Worker | All priv tx types gas bypass | Correct zero-gas handling in block assembly for PrivTransfer/Shield/Unshield |
| CLI tooling | priv-keygen / priv-balance / priv-transfer / priv-shield / priv-unshield | Key generation, ciphertext decryption, proof generation, and transaction construction |

### Exists but Not Usable

| Capability | Issue |
|---|---|
| EncryptedMemo consumption | Memo is carried in tx and covered by Schnorr signature, but **execution path does not read or validate it** |

### Entirely Missing

| Dimension | What's Missing |
|---|---|
| P2P encryption | No encrypted peer-to-peer communication — transaction payloads visible to network observers |
| Network-layer anonymity | No Dandelion++, no Tor, no mixnet — standard gossip broadcast, transaction origin IP is traceable |
| Contract privacy | LVM executes publicly, no homomorphic operations in contracts |
| RPC access control | commitment/handle/version readable by anyone — account activity frequency is observable |

---

## Privacy Capability Layers

```
┌─────────────────────────────────────────────┐
│  Level 4: Contract HE ops (ciphertext arith)│  PLANNED
├─────────────────────────────────────────────┤
│  Level 3: Network privacy (encrypt+anon)    │  MISSING
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

### Phase 1b: Key management CLI (~60%) ✅ Mostly done

**Goal**: End users can generate keys and check encrypted balances from the command line.

**Effort**: 1–2 days

**Tasks**:
- [x] `toskey priv-keygen` — generate ElGamal keypair, output pubkey + privkey (optionally encrypted with passphrase)
- [x] `toskey priv-balance` — take privkey + on-chain ciphertext (via `--rpc` or `--ct` flag), decrypt via ECDLP baby-step-giant-step, display plaintext balance
- [ ] `toskey priv-history` (optional) — scan PrivNonce range and decrypt each version's balance

### Phase 1c: TxPool pre-validation hardening (~62%) ✅ Mostly done

**Goal**: Reject obviously invalid priv transactions at pool admission before they consume consensus resources.

**Effort**: 1–2 days

**Tasks**:
- [x] Proof shape/size pre-validation — reject transactions with wrong proof sizes at `validatePrivTransferTx` / `validateShieldTx` / `validateUnshieldTx` (check `len(CtValidityProof)==160`, `len(ShieldProof)==96`, etc.)
- [x] Schnorr signature pre-check — verify `VerifySchnorrSignature(pubkey, sigHash, S, E)` at pool admission (currently only checked during consensus execution)
- [ ] ShieldProof/RangeProof pre-verification (optional, expensive) — only if DoS proves to be a real concern

### ~~Phase 2: Stealth addresses~~ ABANDONED

Stealth addresses (DKSAP) are incompatible with the account model. Each one-time address creates a new state entry (commitment/handle/version/nonce slots), causing unbounded state growth. Stealth addresses are a UTXO-model concept (Monero) and do not map cleanly to account-based chains. XELIS (our reference implementation) also does not implement stealth addresses for the same reason. Receiver unlinkability on an account model remains an open research problem.

### Phase 3: Network-layer privacy

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

### ~~Phase 4: Decoy outputs / ring signatures~~ ABANDONED

Ring signatures and decoy outputs are fundamentally incompatible with the account model. In an account model, the validator must know the real sender to debit their encrypted balance — this breaks the ring's purpose. These are UTXO-model concepts (Monero) where each "output" is independently spendable. XELIS (our reference implementation) does not implement sender unlinkability for the same reason. Sender unlinkability on an account model would require a fundamentally different approach (e.g., ZK-SNARK membership proofs + nullifiers, similar to Tornado Cash), which is out of scope.

### Phase 5: Contract homomorphic operations

**Goal**: Contracts can store and manipulate encrypted values without decrypting them, enabling confidential token balances and private voting.

**Effort**: 2–4 weeks

**Tasks**:
- [ ] Expose `Ciphertext` as an opaque type in LVM contract language
- [ ] Support homomorphic operations: `ct_add(a, b)`, `ct_add_scalar(ct, n)`, `ct_sub(a, b)`
- [ ] Contracts can store and manipulate encrypted values without decrypting
- [ ] Use case: confidential token balances managed by a contract

#### ~~Phase 5b: Encrypted contract storage~~ ABANDONED
#### ~~Phase 5c: Confidential computation (FHE/MPC/TEE)~~ ABANDONED

Encrypted storage and confidential computation (FHE/MPC/TEE) are active research areas with no production-ready solution. Homomorphic operations on Twisted ElGamal ciphertexts (Phase 5a above) provide practical contract privacy for the near term. FHE/MPC/TEE may be revisited if the research landscape matures.

---

## Execution Order and Milestones

| Phase | Work | Effort | Unlocks | Cumulative |
|---|---|---|---|---|
| ~~**Phase 0**~~ | ~~CGO dependency~~ | ✅ DONE | Privacy works on default builds | ~40% |
| ~~**Phase 1**~~ | ~~Shield/Unshield~~ | ✅ DONE | Public ↔ private flow | ~58% |
| ~~**Phase 1b**~~ | ~~Key management CLI~~ | ✅ DONE | End-user tooling | ~60% |
| ~~**Phase 1c**~~ | ~~TxPool hardening~~ | ✅ DONE | DoS resistance | ~62% |
| ~~**Phase 2**~~ | ~~Stealth addresses~~ | ABANDONED | Incompatible with account model | — |
| **Phase 3** | P2P encrypt + Dandelion++ | 1–2 weeks | Network privacy | ~75% |
| ~~**Phase 4**~~ | ~~Decoy outputs / ring sig~~ | ABANDONED | Incompatible with account model | — |
| **Phase 5** | Contract ciphertext ops | 2–4 weeks | Confidential tokens | ~85% |
| ~~**Phase 5b**~~ | ~~Encrypted storage~~ | ABANDONED | No production-ready solution | — |
| ~~**Phase 5c**~~ | ~~FHE/MPC/TEE~~ | ABANDONED | No production-ready solution | — |

### Abandoned phases and rationale

| Phase | Reason |
|---|---|
| **Phase 2: Stealth addresses** | DKSAP creates unbounded state growth (new slots per one-time address). This is a UTXO-model concept; XELIS also does not implement it. |
| **Phase 4: Ring signatures / decoys** | Account model requires validator to know the real sender for balance debit — breaks ring anonymity. XELIS also does not implement sender unlinkability. |
| **Phase 5b-c: Encrypted storage / FHE / MPC / TEE** | Active research frontier with no production-ready solution. May revisit if landscape matures. |

### Privacy milestones

| Milestone | Phases required | What it means |
|---|---|---|
| **Minimally viable** | 0 + 1 + 1b + 1c | ← **We are here** (~62%). Amounts hidden, funds flow freely, key/decrypt tooling exists, malformed priv txs are filtered early |
| **Network-hardened** | + 3 | (~75%). P2P encrypted, transaction origin IP anonymized via Dandelion++ |
| **Contract-ready** | + 3 + 5 | (~85%). Contracts can manipulate encrypted values (confidential tokens, private voting) |

**Next priority: Phase 3 (P2P encryption + Dandelion++) as the highest-impact improvement — low implementation cost, high practical privacy gain.**
