# Privacy Roadmap: Gap Analysis & Path to First-Class Privacy

**Last updated**: 2026-03-16
**Current progress**: ~80% — practical privacy target reached

---

## Current State

GTOS has a working confidential transfer pipeline (Level 1) and a complete Shield/Unshield consensus path (Level 2). The privacy surface covers amount hiding for transfers and bidirectional public↔private fund flow. Contract-level homomorphic operations are the remaining practical target. Transaction graph privacy (sender/receiver unlinkability) has been deprioritized — stealth addresses and ring signatures are UTXO-model concepts incompatible with GTOS's account model. Network-layer anonymity (Dandelion++) is not needed — GTOS uses DPoS with a small set of known validators; users submit transactions via JSON-RPC, not P2P gossip.

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
| Homomorphic ciphertext arithmetic | Add / Sub / AddScalar / MulScalar / DivScalar | Pure-Go + CGO |
| Contract ciphertext ops (`tos.ciphertext.*`) | 22 LVM functions (9 Tier-1 native + 9 Tier-2 proof-bundle + 2 accessor + 2 verify) | ProofBundle mechanism for non-homomorphic ops; verify_transfer/verify_eq use real crypto |
| TOL `uno` encrypted type | First-class type with method syntax | `a.add(b)`, `uno.zero()`, two-slot storage, ABI encode/decode |
| Encrypted balance state storage | 4 slots per account | commitment, handle, version, nonce in StateDB |
| RPC endpoints | privTransfer / privShield / privUnshield / privGetBalance / privGetNonce | Functional |
| TxPool handling | Real proof admission + batch verification | Pool admission now does real privacy proof verification, batch sigma/range verification, and pool-local private-state replay; malformed proofs and bad Schnorr signatures are rejected before admission |
| Execution-path batch verification | Shared prepared-proof flow | Blocks containing privacy txs reuse the same prepared verification model and batch-verify consecutive privacy runs before apply |
| Fee model | UNO base units | UNOBaseFee = 1 (0.01 UNO = 10^16 Wei); `UNOFeeToWei()` converts to Wei on-chain |
| EncryptedMemo | ECDH + ChaCha20-Poly1305 | Per-tx nonce from txHash; integrity-protected by Schnorr signature |
| Genesis seeding | Full support | Helper script generates encrypted balances for genesis accounts |
| Miner/Worker | All priv tx types gas bypass | Correct zero-gas handling in block assembly for PrivTransfer/Shield/Unshield |
| CLI tooling | priv-keygen / priv-balance / priv-transfer / priv-shield / priv-unshield | Key generation, ciphertext decryption, proof generation, and transaction construction |

### Exists but Not Usable

| Capability | Issue |
|---|---|
| EncryptedMemo consumption | Memo is carried in tx and covered by Schnorr signature, but **execution path does not read or validate it** |

### Remaining Gaps

| Dimension | What's Missing |
|---|---|
| Tier-2 ZK proof verification | mul/div/rem/lt/gt/eq/min/max/select proofs are InputHash-bound but not cryptographically verified (Sigma protocols TODO) |
| RPC access control | commitment/handle/version readable by anyone — account activity frequency is observable |

---

## Privacy Capability Layers

```
┌─────────────────────────────────────────────┐
│  Level 3: Contract HE ops (ciphertext arith)│  DONE (22 ops, Tier-2 ZK stubs)
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
- **Shield flow**: Deducts `(UnoAmount + UnoFee) × UNOUnit` Wei from sender → verifies ShieldProof under Recipient's key + RangeProof → adds ciphertext to recipient's encrypted balance
- **Unshield flow**: Computes `zeroedCt` via ciphertext subtraction → verifies CommitmentEqProof + RangeProof → updates sender's encrypted balance → credits `UnoAmount × UNOUnit` Wei to recipient's public balance, deducts `UnoFee × UNOUnit` Wei from recipient
- **Proof context**: 131-byte Shield context (actionTag=0x11), 163-byte Unshield context (actionTag=0x12), bound to chain/nonce/fee/amount/address
- **Shared PrivNonce**: All 3 tx types (Transfer, Shield, Unshield) share the same PrivNonce counter per account
- **Fee**: UNOBaseFee = 1 UNO base unit (0.01 UNO = 10^16 Wei); fee fields are UNO base units, charged on-chain via `UNOFeeToWei()`

---

## Remaining Work

### ~~Phase 1b: Key management CLI~~ ✅ DONE

**Goal**: End users can generate keys and check encrypted balances from the command line.

**Tasks**:
- [x] `toskey priv-keygen` — generate ElGamal keypair, output pubkey + privkey (optionally encrypted with passphrase)
- [x] `toskey priv-balance` — take privkey + on-chain ciphertext (via `--rpc` or `--ct` flag), decrypt via ECDLP baby-step-giant-step, display plaintext balance as X.XX UNO

### ~~Phase 1c: TxPool pre-validation hardening~~ ✅ DONE

**Goal**: Reject obviously invalid priv transactions at pool admission before they consume consensus resources.

**Tasks**:
- [x] Proof shape/size pre-validation — reject transactions with wrong proof sizes at `validatePrivTransferTx` / `validateShieldTx` / `validateUnshieldTx` (check `len(CtValidityProof)==160`, `len(ShieldProof)==96`, etc.)
- [x] Schnorr signature pre-check — verify `VerifySchnorrSignature(pubkey, sigHash, S, E)` at pool admission (currently only checked during consensus execution)
- [x] Real privacy proof pre-verification at pool admission — txpool now verifies actual shield/transfer/unshield proofs before admission instead of stopping at shape-only checks
- [x] Pool-level sigma/range batch verification — pure-Go and native `ed25519c` backends both batch-verify privacy proofs for txpool admission
- [x] Pool-local private-state replay — dependent private txs are replayed on virtual private state before verification

### ~~Phase 1d: UNO unit system~~ ✅ DONE

**Goal**: Replace Wei-denominated privacy balances with UNO base units (2 decimal places) to make BSGS discrete-log decryption feasible.

**Tasks**:
- [x] `params.UNOUnit = 1e16` (1 UNO base unit = 0.01 TOS = 10^16 Wei), `params.UNOBaseFee = 1`
- [x] Replace gas-based fee model (`PrivBaseFee × TxPriceWei`) with direct UNO base unit fees
- [x] `UNOFeeToWei()` / `WeiToUNO()` / `WeiToUNORemainder()` conversion functions
- [x] Shield/Unshield convert UNO↔Wei at public balance boundary; PrivTransfer ciphertext arithmetic in UNO base units
- [x] Rename tx fields for unit clarity: `Fee→UnoFee`, `Amount→UnoAmount`, `FeeLimit→UnoFeeLimit`
- [x] BSGS precomputed table (L1=26, ~350 MB) — decrypts full 5B TOS supply in ~62ms
- [x] `toskey priv-balance` displays balance as `X.XX UNO`

### ~~Phase 1e: Sigma/range batch-verification alignment~~ ✅ DONE

**Goal**: Align GTOS privacy verification with the practical `~/x` model for real sigma/range batch verification, without taking on `ZKP cache`.

**Tasks**:
- [x] Pure-Go sigma batch verifier
- [x] Pure-Go range batch verifier
- [x] Native `ed25519c` sigma batch verifier
- [x] Native `ed25519c` range batch verifier
- [x] Shared prepare / pre-verify architecture between txpool and execution
- [x] Execution-path batch verification beyond txpool
- [x] Transfer range-proof representation aligned to aggregated multi-commitment form
- [x] Batch vs sequential equivalence tests and focused benchmarks

See `docs/PRIVACY-BATCH-VERIFY-TRACKER.md` for the detailed completion tracker. The only intentional verifier-model difference left against `~/x` is the out-of-scope `ZKP cache`.

### ~~Phase 2: Stealth addresses~~ ABANDONED

Stealth addresses (DKSAP) are incompatible with the account model. Each one-time address creates a new state entry (commitment/handle/version/nonce slots), causing unbounded state growth. Stealth addresses are a UTXO-model concept (Monero) and do not map cleanly to account-based chains. Other account-model privacy chains also does not implement stealth addresses for the same reason. Receiver unlinkability on an account model remains an open research problem.

### ~~Phase 3: Dandelion++~~ ABANDONED

Dandelion++ anonymizes transaction origin IP by routing through random stem hops before gossip broadcast. This is designed for open P2P networks (Bitcoin, Ethereum) with thousands of anonymous nodes. GTOS uses DPoS with a small set of known validators — users submit transactions via JSON-RPC to validators, not via P2P gossip. P2P payload encryption is already provided by RLPx (AES-256-CTR + ECIES handshake). Dandelion++ adds complexity without meaningful privacy benefit in this topology.

### ~~Phase 4: Decoy outputs / ring signatures~~ ABANDONED

Ring signatures and decoy outputs are fundamentally incompatible with the account model. In an account model, the validator must know the real sender to debit their encrypted balance — this breaks the ring's purpose. These are UTXO-model concepts (Monero) where each "output" is independently spendable. Other account-model privacy chains does not implement sender unlinkability for the same reason. Sender unlinkability on an account model would require a fundamentally different approach (e.g., ZK-SNARK membership proofs + nullifiers, similar to Tornado Cash), which is out of scope.

### ~~Phase 5: Contract homomorphic operations~~ ✅ DONE

**Goal**: Contracts can store and manipulate encrypted values without decrypting them, enabling confidential token balances and private voting.

**Tasks**:
- [x] `uno` first-class encrypted type in TOL compiler (lexer, parser, sema, IR lowering, ABI encode/decode)
- [x] `tos.ciphertext` LVM sub-table with 22 Go-native functions
- [x] Tier 1 (9 native homomorphic): `add`, `sub`, `add_scalar`, `sub_scalar`, `mul_scalar`, `div_scalar`, `zero`, `encrypt`, `from_parts`
- [x] Tier 2 (9 proof-bundle verified): `mul`, `div`, `rem`, `lt`, `gt`, `eq`, `min`, `max`, `select` — InputHash enforced, ZK proof verification stubbed (TODO: Sigma protocol)
- [x] Accessors: `commitment`, `handle`
- [x] Verification (real crypto): `verify_transfer` (VerifyCTValidityProof), `verify_eq` (VerifyCommitmentEqProof)
- [x] ProofBundle binary format (`PBND` magic) appended to calldata; Execute() strips before ABI decoding
- [x] TOL method desugaring: `a.add(b)` → `tos.ciphertext.add(a, b)`, `uno.zero()` → `tos.ciphertext.zero()`
- [x] Two-slot storage for `uno` (commitment + handle), `mapping(agent => uno)` supported
- [x] Operator restrictions: `==`/`!=` allowed (desugared to `eq`), arithmetic/comparison operators rejected
- [x] Sample contract `ConfidentialToken.tol` compiles end-to-end
- [x] 19 gtos tests + 12 tolang tests passing

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
| ~~**Phase 1d**~~ | ~~UNO unit system~~ | ✅ DONE | Feasible BSGS decryption | ~68% |
| ~~**Phase 1e**~~ | ~~Batch-verification alignment~~ | ✅ DONE | Real sigma/range batch verification in Go and native C; txpool + execution-path parity | ~72% |
| ~~**Phase 2**~~ | ~~Stealth addresses~~ | ABANDONED | Incompatible with account model | — |
| ~~**Phase 3**~~ | ~~Dandelion++~~ | ABANDONED | Not needed in DPoS topology | — |
| ~~**Phase 4**~~ | ~~Decoy outputs / ring sig~~ | ABANDONED | Incompatible with account model | — |
| ~~**Phase 5**~~ | ~~Contract ciphertext ops~~ | ✅ DONE | Confidential tokens | ~80% |
| ~~**Phase 5b**~~ | ~~Encrypted storage~~ | ABANDONED | No production-ready solution | — |
| ~~**Phase 5c**~~ | ~~FHE/MPC/TEE~~ | ABANDONED | No production-ready solution | — |

### Abandoned phases and rationale

| Phase | Reason |
|---|---|
| **Phase 2: Stealth addresses** | DKSAP creates unbounded state growth (new slots per one-time address). This is a UTXO-model concept; other account-model privacy chains also do not implement it. |
| **Phase 3: Dandelion++** | Designed for open P2P networks with anonymous nodes. GTOS uses DPoS — users submit via JSON-RPC to known validators, not P2P gossip. RLPx already encrypts peer traffic. |
| **Phase 4: Ring signatures / decoys** | Account model requires validator to know the real sender for balance debit — breaks ring anonymity. other account-model privacy chains also do not implement sender unlinkability. |
| **Phase 5b-c: Encrypted storage / FHE / MPC / TEE** | Active research frontier with no production-ready solution. May revisit if landscape matures. |

### Privacy milestones

| Milestone | Phases required | What it means |
|---|---|---|
| **Minimally viable** | 0 + 1 + 1b + 1c + 1d + 1e | (~72%). Amounts hidden, funds flow freely, UNO unit system with feasible BSGS decryption, key/decrypt tooling exists, privacy txs are batch-verified in txpool and execution |
| **Contract-ready** | + 5 | ← **We are here** (~80%). Contracts can manipulate encrypted values via `uno` type (confidential tokens, private voting). Tier-2 ZK proof verification is stubbed — InputHash binding prevents result substitution, but proofs are not cryptographically verified yet. |

**All planned privacy phases are complete.** Remaining hardening:
- Tier-2 ZK proof verification (Sigma protocols for mul/div/rem, sub+range for lt/gt, sub+zero-check for eq)
- RPC access control for encrypted balance slots
