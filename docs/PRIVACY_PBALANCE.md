# GTOS PBalance (Homomorphic Encrypted Account Balance)
> Design v0.1 (XELIS-style account model, GTOS-native execution)

## 0. Scope

### Goals
- Keep existing public ledger unchanged:
  - `Account.balance` remains plaintext and fully functional.
  - Public transfers and existing GTOS tx routes continue to work.
- Add a second ledger field: `pbalance` (encrypted balance).
- Reuse account signer metadata for privacy public keys:
  - private-balance accounts must use canonical `signerType = elgamal` (Ristretto255-backed).
  - no separate per-account privacy key registry in MVP.
- Support private value transfer in account model (no note/nullifier set):
  - `shield`: public -> private
  - `pbalanceTransfer`: private -> private
  - `unshield`: private -> public
- Use homomorphic ciphertext updates and zero-knowledge proofs for correctness.
- Keep gas public in MVP (paid from public balance).

### Non-goals (MVP)
- Fully private fee market.
- Cross-chain privacy.
- Private smart contract execution semantics.
- Multi-asset support (MVP uses native TOS only).

---

## 1. GTOS-Native Routing

GTOS does not rely on EVM contract execution for user calldata paths. PBalance is implemented as native execution branches.

- Add fixed router address:
  - `params.PrivacyRouterAddress = 0x...0004`
- Keep tx envelope unchanged:
  - `SignerTxType`
  - `to = PrivacyRouterAddress`
  - `tx.Data = PBalance payload`
- Add branch in `core/state_transition.go`:
  - `if to == params.PrivacyRouterAddress { vmerr = st.applyPBalance(msg) }`

Action set:
- `PBALANCE_SHIELD`
- `PBALANCE_TRANSFER`
- `PBALANCE_UNSHIELD`

Signer setup is done via existing account-signer flows (for example `ACCOUNT_SET_SIGNER`), not a pbalance-specific action.

---

## 2. Cryptography Stack

MVP defaults:
- Group: `Ristretto255`.
- Ciphertext form: Twisted ElGamal-compatible tuple `(C, D)`:
  - `C` is Pedersen-style commitment component.
  - `D` is decrypt handle component.
- Proofs:
  - `CommitmentEqProof` (sender balance transition correctness)
  - `CiphertextValidityProof` (receiver ciphertext well-formed for destination key)
  - `RangeProof` (amount bounds)
- Hash/transcript domain separation required for all proofs.

This follows account-balance privacy instead of note/nullifier privacy.

---

## 3. State Model

## 3.1 Per-account PBalance State
Stored under owner account address in StateDB slots.

Required fields (native asset only in MVP):
- `pbalance_ct_commitment` (32 bytes compressed)
- `pbalance_ct_handle` (32 bytes compressed)
- `pbalance_version` (uint64, monotonic)

Key source (not in pbalance slots):
- Read from GTOS account signer state.
- Canonical signer type must be `elgamal` for private-balance actions.
- `elgamal` signer public key is used as the ciphertext destination/source key.

Recommended slot namespace prefix:
- `gtos.pbalance.<field>`

## 3.2 Invariants
For each account:
- Any pbalance mutation requires signer metadata to exist and `signerType == elgamal`.
- `PBALANCE_TRANSFER` requires both sender and receiver to have `signerType == elgamal`.
- `pbalance_version` increments whenever `pbalance` mutates.
- Ciphertext values are only mutated through verified PBalance actions.

---

## 4. Transaction Payloads

Use binary envelope (`RLP` + fixed prefix), not JSON.

## 4.1 Envelope
- Prefix: `GTOSPBL1`
- Fields:
  - `action` (u8)
  - `body` (bytes)

Action IDs:
- `0x01 = reserved` (unused in this design revision)
- `0x02 = PBALANCE_SHIELD`
- `0x03 = PBALANCE_TRANSFER`
- `0x04 = PBALANCE_UNSHIELD`

## 4.2 PBALANCE_SHIELD
Body:
- `amount` (u64)
- `newSenderCiphertext` (`C,D`)
- `proofBundle`

Rules:
- sender `signerType == elgamal`
- `amount > 0`
- deduct `amount` from public balance (or require equivalent value path)
- credit encrypted value into sender `pbalance`
- proof verifies transition from old sender ciphertext -> new sender ciphertext

## 4.3 PBALANCE_TRANSFER
Body:
- `to` (address)
- `amount` (private witness, not required public in final form)
- `newSenderCiphertext` (`C,D`)
- `receiverCiphertextDelta` (`C,D`)
- `proofBundle`
- optional `encryptedMemo`

Rules:
- sender and receiver account signer type must both be `elgamal`
- sender/receiver ElGamal pubkeys are loaded from account signer state
- verify proofs and update:
  - sender `pbalance := newSenderCiphertext`
  - receiver `pbalance := receiver_old + receiverCiphertextDelta`

## 4.4 PBALANCE_UNSHIELD
Body:
- `to` (address)
- `amount` (public in MVP)
- `newSenderCiphertext` (`C,D`)
- `proofBundle`

Rules:
- sender `signerType == elgamal`
- verify sender encrypted balance decrease is valid
- credit `to` public balance by `amount`

---

## 5. Consensus Verification Flow

For all PBalance actions:
1. Standard GTOS pre-checks (nonce, gas, signature, sender).
2. Decode payload with strict size checks.
3. Load sender account signer metadata and require `signerType == elgamal`.
4. For transfer, load receiver account signer metadata and require `signerType == elgamal`.
5. Load sender/receiver pbalance state.
6. Build canonical proof transcript context.
7. Verify `proofBundle`.
8. Apply deterministic state updates.
9. Increment `pbalance_version` for modified accounts.

`proofBundle` must bind at least:
- `chainId`
- `actionTag`
- `from`
- `to` (if applicable)
- sender nonce
- old/new ciphertext commitments used in transition
- `assetId` (fixed native asset constant in MVP)

This prevents cross-chain/cross-action replay.

---

## 6. Double-spend / Replay Model

No nullifier set is used.

Protection basis:
- account nonce ordering (existing GTOS model)
- each tx consumes exactly one nonce
- sender ciphertext transition must match proof under that nonce-bound transcript

Result:
- conflicting private spends from same sender nonce cannot both pass on canonical chain.

---

## 7. Genesis Initialization (Your Main Use Case)

If chain wants to pre-allocate private balances at genesis:

1. Define recipients and their ElGamal (Ristretto255-backed) public keys.
2. For each recipient, set account signer metadata:
   - `signerType = elgamal`
   - `signerValue = compressed ElGamal pubkey`
3. For each recipient, compute initial ciphertext representing allocated amount.
4. Write into genesis state for each account:
   - `pbalance_ct_commitment = ...`
   - `pbalance_ct_handle = ...`
   - `pbalance_version = 0`
5. If funds should originate from protocol reserve, mirror total accounting rule in genesis spec.

How A/B know they received private funds:
- wallet reads account `pbalance` ciphertext from chain
- wallet uses the private key corresponding to its `elgamal` account signer pubkey
- the same keypair is used for account signer identity and private-balance decryption
- wallet displays plaintext private balance

No note scanning/nullifier indexing is required for this model.

---

## 8. Gas Model

Gas remains public and deterministic.

Suggested constants:
- `PBalanceBaseGas`
- `PBalanceShieldGas`
- `PBalanceTransferGas`
- `PBalanceUnshieldGas`
- `PBalanceProofVerifyBaseGas`
- `PBalanceProofVerifyPerInputGas`

MVP recommendation:
- fixed upper bounds on payload bytes and proof bytes
- reject oversize payloads before heavy verification

---

## 9. Parallel Execution Safety

GTOS parallel executor must avoid nondeterministic races.

MVP-safe policy:
- serialize all PBalance txs against each other.

Implementation hint in `core/parallel/analyze.go`:
- For `to == PrivacyRouterAddress`, add shared conflict marker:
  - `WriteAddrs[PrivacyRouterAddress] = {}`

Later optimization:
- allow parallelism for disjoint sender/receiver pairs after parity proofs and soak tests.

---

## 10. GTOS Implementation Plan

### Step 1: Params
- `params/tos_params.go`
  - add `PrivacyRouterAddress`
  - add gas and limit constants for PBalance

### Step 2: Core PBalance package
Create `core/pbalance/`:
- `codec.go` (payload encode/decode)
- `state.go` (slot derivation and read/write)
- `proofs.go` (proof structures and transcript encoding)
- `verify.go` (verification entrypoint)
- `errors.go`

### Step 3: State transition integration
- `core/state_transition.go`
  - add `applyPBalance`
  - add per-action handlers

### Step 4: Parallel conflict integration
- `core/parallel/analyze.go`
  - MVP serialization rule for all PBalance txs

### Step 5: RPC and tooling
- `internal/tosapi/api.go`
  - `tos_pbalanceShield`
  - `tos_pbalanceTransfer`
  - `tos_pbalanceUnshield`
  - `tos_getPBalanceCiphertext`
- wallet-side SDK/CLI:
  - decrypt ciphertext to plaintext balance locally

### Step 6: Tests
- Unit tests:
  - payload codec, slot layout, transcript domain separation
- Core tests:
  - shield/transfer/unshield state transitions
  - replay/nonce conflict rejection
  - invalid proof rejection
- Parallel parity tests:
  - serial vs parallel state root equivalence
- Integration tests:
  - 3-node DPoS testnet private transfer flow
  - genesis pre-allocation to A/B decryptable by wallets

---

## 11. Security Checklist

- Enforce strict payload/proof size limits before proof verification.
- Reject zero or malformed ciphertext elements.
- Reject pbalance actions if account signer type is not canonical `elgamal`.
- For transfers, reject if receiver signer is missing or non-`elgamal`.
- Bind nonce + chainId + action in proof transcript.
- No partial writes on verification failure.
- Track deterministic ordering in state updates.
- Audit cryptography implementation and transcript canonicalization.
- Document key-loss behavior (lost private key means unrecoverable private balance access).

---

## 12. MVP Defaults

- asset set: native TOS only
- public gas, private amount semantics
- private-balance eligible accounts: signer type `elgamal` only
- serialized PBalance execution path
- one receiver per transfer tx
- fixed-size proof bundle per action class

---

## 13. Future Phases

- Multi-asset encrypted balances (`pbalance[asset]`).
- Receiver-stealth routing to reduce sender->receiver linkage.
- Relayer model for UX.
- Partial parallelism for disjoint account sets.
- Optional migration from compressed ciphertext slots to dedicated StateDB namespace.
