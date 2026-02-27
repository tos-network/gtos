# GTOS UNO Privacy Balance Design (XELIS-Convergent)
> Design v0.2 (account model + homomorphic encrypted balance)

## 0. Positioning

### Primary target
- Make GTOS UNO implementation approach close to `~/xelis-blockchain`:
  - account-based encrypted balances
  - transcript-bound proof verification
  - deterministic nonce/version based replay protection
  - wallet-side decrypt/sync workflow

### Explicitly not required
- Byte-level compatibility with XELIS wire/protocol.
- Matching every transaction type and VM feature.

### MVP boundaries (current track)
- Native asset only.
- Public gas, private transfer amount.
- Three UNO actions:
  - `UNO_SHIELD` (public -> private)
  - `UNO_TRANSFER` (private -> private)
  - `UNO_UNSHIELD` (private -> public)

---

## 1. GTOS Native Routing

- Fixed router:
  - `params.PrivacyRouterAddress = 0x...0004`
- Envelope remains signer tx:
  - `to = PrivacyRouterAddress`
  - `tx.Data = UNO payload`
- Execution branch:
  - `if to == params.PrivacyRouterAddress { applyUNO(msg) }`

UNO is implemented as native state transition logic, not EVM contract execution.

---

## 2. Cryptography and Proof Model

### Baseline cryptography
- Group: `Ristretto255`
- Key type: account signer with canonical `signerType = elgamal`
- Ciphertext: commitment + handle tuple (`C`, `D`) suitable for homomorphic updates

### Proof classes used
- `CiphertextValidityProof`
- `CommitmentEqProof`
- `RangeProof`

### Required transcript binding (must converge)
Every verified proof bundle must bind:
- `chainId`
- `actionTag`
- `from`
- `to` (if action has receiver)
- sender nonce
- old/new ciphertext commitments and handles
- native asset tag

This is the critical replay-hardening axis to align with the XELIS verification style.

---

## 3. State Model

Per account UNO state in StateDB slots:
- `uno_ct_commitment` (32 bytes compressed)
- `uno_ct_handle` (32 bytes compressed)
- `uno_version` (uint64 monotonic)

Signer key source:
- not duplicated in UNO slots
- loaded from GTOS signer state
- UNO actions require `signerType == elgamal`

Core invariants:
- UNO mutation only after proof verification.
- `UNO_TRANSFER` requires sender and receiver both have `elgamal` signer.
- `uno_version` increments on each successful UNO mutation.

---

## 4. Payload Envelope and Actions

Binary envelope:
- Prefix: `GTOSUNO1`
- Fields:
  - `action` (`u8`)
  - `body` (`bytes`)

Action IDs:
- `0x02 = UNO_SHIELD`
- `0x03 = UNO_TRANSFER`
- `0x04 = UNO_UNSHIELD`

### UNO_SHIELD
- Input: public amount + proof bundle.
- Effect: subtract public balance, add encrypted value to sender UNO state.

### UNO_TRANSFER
- Input: receiver address, sender new ciphertext, receiver ciphertext delta, proof bundle.
- Effect:
  - sender `uno := newSenderCiphertext`
  - receiver `uno := receiver_old + receiverDelta`

### UNO_UNSHIELD
- Input: destination address, public amount, sender new ciphertext, proof bundle.
- Effect: decrease sender UNO encrypted balance, increase destination public balance.

---

## 5. Verification Flow (Consensus Path)

For every UNO tx:
1. Standard checks (nonce, gas, signature, sender).
2. Strict payload decode and size bounds.
3. Load signer metadata and require canonical `elgamal`.
4. Load current UNO ciphertext state.
5. Build canonical transcript context.
6. Verify action proof bundle.
7. Apply deterministic state updates.
8. Increment `uno_version` for touched account(s).

Rule:
- Any verification failure must produce zero state mutation.

---

## 6. Replay/Double-Spend Model

UNO follows account model protections:
- GTOS nonce ordering
- transcript-bound context
- ciphertext transition checks tied to sender state

No note/nullifier set is used in this design.

---

## 7. Genesis Initialization

To pre-allocate UNO balances:
1. Configure account signer metadata (`signerType = elgamal`, `signerValue = pubkey`).
2. Generate initial ciphertext for target private amount.
3. Set:
  - `uno_ct_commitment`
  - `uno_ct_handle`
  - `uno_version = 0`

Recipient visibility:
- Wallet fetches on-chain UNO ciphertext and decrypts using local private key corresponding to signer public key.

---

## 8. Parallel Execution Rule

Current deterministic safety rule:
- Serialize all UNO actions in parallel analyzer using shared conflict marker (`PrivacyRouterAddress`).

Future optimization can relax this only after parity and soak evidence.

---

## 9. Convergence Gap vs XELIS (Current)

`DONE`:
- UNO router and core package scaffolding.
- Genesis UNO fields and signer bootstrap checks.
- UNO RPC actions and basic validation.
- Baseline proof verification entrypoints wired.

`IN PROGRESS`:
- Full transcript binding with complete chain context.
- Transfer/unshield semantics hardening to XELIS-like strictness.
- Txpool/execution rejection parity completion.
- Wallet decrypt/sync lifecycle integration.

`PENDING`:
- Differential test vectors against Rust/C references.
- Reorg and replay stress matrix for UNO paths.

---

## 10. Roadmap (Implementation Style Close to XELIS)

### Phase A: Deterministic Verification Core
- Finish transcript binding and replay-hardening matrix.
- Finish transfer/unshield strict semantics.
- Add strict error taxonomy from C bridge to consensus errors.

### Phase B: Cross-Path Equivalence
- Ensure txpool precheck and block execution yield same accept/reject result.
- Strengthen serial/parallel parity tests with UNO-heavy mixed blocks.

### Phase C: Wallet Lifecycle
- Implement wallet decrypt/update flow with nonce/version tracking.
- Add recovery/reorg-safe local cache update rules.

### Phase D: Differential and Security Gates
- Run vector differential checks against reference implementations.
- Complete malformed-proof, gas-griefing, and divergence audits.

### Phase E: Network Rollout
- Local -> devnet soak -> public testnet trial -> mainnet gate.

---

## 11. Status Snapshot (2026-02-27)

- Direction is confirmed: converge toward XELIS-style account privacy architecture.
- GTOS UNO has entered executable MVP stage but is not yet XELIS-equivalent.
- The blocking items are transcript completeness, parity matrix, wallet integration, and differential validation.
