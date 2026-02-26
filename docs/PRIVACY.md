# GTOS UNO Privacy Pool (Zcash-Style Notes)
> Design v0.3 (MVP-first, GTOS-native)

## 0. Scope

### Goals
- Keep GTOS public ledger unchanged:
  - Public balances remain `Account.balance`.
  - Public transfer rules remain unchanged.
- Add a separate private pool using Zcash-style notes:
  - `shield` (public -> private)
  - `privateTransfer` (private -> private)
  - `unshield` (private -> public)
- Prevent double spend via nullifiers.
- Verify zero-knowledge proofs inside consensus execution.
- Keep gas payment public in MVP (`Hybrid UNO`): gas is paid in public TOS.

### Non-goals (MVP)
- Fully private gas/fee market.
- Private smart-contract DeFi.
- Network-layer anonymity.
- Multi-asset notes.

---

## 1. GTOS-Native Architecture (No EVM Contract Path)

GTOS currently does not execute EVM contracts for user calldata paths. UNO must be implemented as a native transaction execution branch, not as a Solidity system contract.

### 1.1 Routing Model
- Add fixed router address in protocol params:
  - `PrivacyRouterAddress = 0x...0004` (example)
- Keep transaction envelope unchanged:
  - still `SignerTxType`
  - `to = PrivacyRouterAddress`
  - `tx.Data = UNO payload`

### 1.2 Execution Entry
- In `core/state_transition.go`, add:
  - `if to == params.PrivacyRouterAddress { vmerr = st.applyUNO(msg) }`
- `applyUNO` dispatches by UNO action:
  - `SHIELD`
  - `PRIVATE_TRANSFER`
  - `UNSHIELD`

### 1.3 State Ownership
MVP stores UNO consensus state under a dedicated state owner account (the router address):
- owner: `params.PrivacyRouterAddress`
- keyspace prefix: `gtos.uno.*`

This avoids adding a brand-new database namespace in first release.

---

## 2. Private State Model

### 2.1 Note Commitment Tree
- Append-only Merkle tree of commitments.
- Suggested MVP height: `H=32`.
- Store:
  - `nextLeafIndex`
  - incremental tree frontier/internal nodes (implementation-defined)
  - `currentRoot`

### 2.2 Roots Ring Buffer
- Keep recent accepted roots for spend proofs.
- `ROOT_RING_SIZE = 1000` (≈ 6 minutes at 360 ms/block).
  - At 256 the validity window was only ~92 seconds — too tight for Groth16 proof generation
    on slow devices (mobile: 30–60 s) plus network propagation delay.
  - 1000 blocks gives ~360 seconds; wallets must generate and broadcast within this window.
- Store:
  - `roots[0..N-1]`
  - `rootsHead`

### 2.3 Nullifier Set
- One-way spent tags from circuit.
- On-chain rule: nullifier can appear only once.
- Store:
  - `spentNullifier[nf] = 1`

### 2.4 Optional Ciphertext Log
- Store or emit encrypted note payloads for wallet scanning.
- Consensus does not require ciphertext semantic correctness in MVP.

---

## 3. Payloads

Use a deterministic binary codec (recommended: RLP envelope with prefix), not JSON.

### 3.1 Envelope
- Prefix: `GTOSUNO1`
- Fields:
  - `action` (u8)
  - `body` (bytes)

Actions:
- `0x01 = SHIELD`
- `0x02 = PRIVATE_TRANSFER`
- `0x03 = UNSHIELD`

### 3.2 Shield Body
- `amount` (u64/u128)
- `newCommitments[]` (bytes32[], MVP exactly 1)
- `proof` (bytes) — output proof that `CM = Poseidon(amount ‖ rho ‖ r)` for the stated `amount`
- `ciphertexts[]` (bytes[], optional; consensus does not enforce 1:1 with commitments — wallet
  should provide one ciphertext per commitment for recoverability, but only total size is checked)

### 3.3 PrivateTransfer Body
- `root` (bytes32)
- `nullifiers[]` (bytes32[], MVP max 1)
- `newCommitments[]` (bytes32[], MVP max 2)
- `ciphertexts[]` (bytes[]; consensus only checks total size ≤ UNO_MAX_CIPHERTEXT_TOTAL_BYTES)
- `proof` (bytes)

Note: `publicInputs` is NOT a payload field. Consensus derives canonical public inputs from
the transaction fields (chainId, routerAddr, actionTag, root, nullifiers, newCommitments) and
calls `verifier.Verify(proof, derivedInputs)`. Accepting user-supplied public inputs would
make domain separation illusory.

### 3.4 Unshield Body
- Same as PrivateTransfer plus:
- `to` (common.Address)
- `amount` (u64/u128, public in MVP)

---

## 4. Consensus Rules Per Action

## 4.1 SHIELD
Checks:
1. `amount > 0`
2. `msg.Value == amount` (mandatory; deduction must be exact)
3. payload limits (commitment count = 1 in MVP, ciphertext total size)
4. Verifier returns success for SHIELD proof with public inputs `[chainId, routerAddr, amount, CM]`

State updates:
1. Deduct from sender public balance through normal GTOS value flow.
2. Add shielded pool reserve (escrow) on `PrivacyRouterAddress` public balance.
3. Append commitment(s), update root and ring buffer.
4. Emit/store ciphertext metadata.

## 4.2 PRIVATE_TRANSFER
Checks (all must pass before any state mutation):
1. `root` exists in roots ring buffer.
2. All nullifiers within the transaction are pairwise distinct.
3. Every nullifier is currently unspent (checked against nullifier set).
4. Payload size limits pass.
5. Verifier returns success for canonical public inputs (derived by consensus from tx fields).

State updates (strict order, only after all checks pass):
1. Mark all nullifiers as spent.
2. Append new commitments.
3. Update root/ring.
4. Emit/store ciphertext metadata.

## 4.3 UNSHIELD
Checks:
1. Same checks as `PRIVATE_TRANSFER`.
2. `to != zero address`.
3. `amount > 0`.
4. Escrow balance of `PrivacyRouterAddress` is sufficient.

State updates:
1. Mark nullifiers spent.
2. Append change commitments (if any).
3. Update root/ring.
4. Subtract `amount` from `PrivacyRouterAddress` public balance.
5. Add `amount` to `to` public balance.

---

## 5. Proof / Domain Separation Requirements

### 5.1 Public Inputs — Derived by Consensus, Not User-Supplied

Consensus code derives canonical public inputs from the transaction fields and passes them
to the verifier. The `proof` bytes are the only verifier-related field in the payload.

For `SHIELD`:
```
publicInputs = [chainId, PrivacyRouterAddress, actionTag=SHIELD, assetId, amount, CM]
```

For `PRIVATE_TRANSFER` and `UNSHIELD`:
```
publicInputs = [chainId, PrivacyRouterAddress, actionTag, assetId,
                root, nullifiers[], newCommitments[]
                (, to, publicAmount) for UNSHIELD]
```

This prevents an attacker from submitting a proof for different public inputs than what
the transaction actually executes (cross-chain and cross-method replay are also prevented).

### 5.2 Value Balance Equation (Circuit Constraint)

The circuit MUST enforce the value balance equation as a hard constraint:

```
Σ(input note amounts) == Σ(output note amounts) + publicUnshieldAmount
```

- `PRIVATE_TRANSFER`: `publicUnshieldAmount = 0`
- `UNSHIELD`: `publicUnshieldAmount = amount` (public input)

Without this constraint, a prover could spend a note of value V, create a change note of
value V, and also unshield V — tripling the value. This equation is enforced inside the
ZK circuit; consensus cannot verify it independently.

---

## 6. Parallel Execution Safety (GTOS-Specific)

MVP must avoid nondeterministic conflicts with parallel executor.

### 6.1 MVP Policy
Force all UNO txs to serialize relative to each other.

Implementation hint in `core/parallel/analyze.go`:
- For `to == PrivacyRouterAddress`, add shared write conflict marker:
  - `WriteAddrs[PrivacyRouterAddress] = {}`

This guarantees UNO operations do not execute in parallel with other UNO operations.

### 6.2 Future Optimization
Later, split conflict domains (e.g., per-nullifier slot/per-batch bucket) only after full parity tests.

---

## 7. Gas and Limits

GTOS uses fixed public gas pricing. UNO does not change this in MVP.

Add protocol constants (examples):
- `UNOBaseGas`
- `UNOShieldGas`
- `UNONullifierGas` (per nullifier)
- `UNOCommitmentGas` (per commitment)
- `UNOVerifyBaseGas`
- `UNOVerifyPerInputGas`

Hard limits (MVP examples):
- `UNO_MAX_IN = 1`
- `UNO_MAX_OUT = 2`
- `UNO_MAX_PROOF_BYTES = 512`
  - Groth16 BN254 proof sizes by serialization format:
    - arkworks uncompressed: 3×G1(96B) + G2(192B) = 288 bytes
    - bellman / snarkjs uncompressed: A(64B) + B(128B) + C(64B) = 256 bytes
  - Implementation must commit to one format; `UNO_MAX_PROOF_BYTES` includes a safety margin.
  - Chosen format must be documented in `core/uno/verify.go`.
- `UNO_MAX_CIPHERTEXT_BYTES = 1024` each
- `UNO_MAX_CIPHERTEXT_TOTAL_BYTES = 4096`

Any limit violation must fail deterministically.

---

## 8. Crypto Choices (MVP Defaults)

- Proof system: `Groth16 BN254`
- Circuit hash: `Poseidon` (for commitments/tree)
- Nullifier derivation: circuit-defined PRF (field-native)
- Note ciphertext encryption: wallet-layer (X25519 + AEAD recommended)

Consensus verifies proof validity and state transitions only; ciphertext decryptability is wallet concern in MVP.

---

## 9. GTOS Code Integration Plan

### Step 1: Params
- `params/tos_params.go`
  - add `PrivacyRouterAddress`
  - add UNO gas/limit constants

### Step 2: Core UNO Package
Create `core/uno/`:
- `codec.go` (payload encode/decode)
- `state.go` (slot derivation, read/write helpers)
- `tree.go` (incremental root update)
- `verify.go` (verifier interface + size checks)
- `errors.go`

### Step 3: State Transition
- `core/state_transition.go`
  - add router branch
  - implement `applyUNO`, `applyUNOShield`, `applyUNOTransfer`, `applyUNOUnshield`

### Step 4: Parallel Access Set
- `core/parallel/analyze.go`
  - mark UNO tx as conflicting with all UNO txs (MVP serialization)

### Step 5: RPC/API
- `internal/tosapi/api.go`
  - `tos_shield`
  - `tos_privateTransfer`
  - `tos_unshield`
  - gas estimate helpers

### Step 6: Tests
- Unit:
  - codec roundtrip
  - root ring membership
  - nullifier replay reject
  - domain separation mismatch reject
- Core:
  - shield/unshield escrow conservation
  - apply order determinism
- Parallel:
  - serial/parallel parity with mixed blocks
- Integration:
  - 3-node DPoS testnet with repeated UNO traffic

---

## 10. Security Checklist

- SHIELD commitment validity verified by ZK proof before insertion into tree.
- Intra-tx nullifier pairwise distinctness checked before any state mutation.
- All nullifiers confirmed unspent (against set) before any state mutation.
- Root must be from bounded accepted ring (validity window = ROOT_RING_SIZE × periodMs).
- Public inputs derived by consensus from tx fields; never accepted from payload.
- Circuit enforces value balance: Σin == Σout + publicUnshieldAmount.
- No partial state updates on failure (all checks pass → then all state writes).
- Escrow conservation invariant: `escrow_balance(PrivacyRouterAddress) = Σshield_amounts − Σunshield_amounts`.
- Strict byte limits to prevent proof/ciphertext DoS.
- Proof serialization format fixed and documented in `core/uno/verify.go`.
- Wallet key loss model documented (private notes unrecoverable without keys).

---

## 11. MVP Parameter Set (Recommended)

- `H = 32`
- `ROOT_RING_SIZE = 1000` (~6 min validity window at 360 ms/block)
- `MAX_IN = 1`
- `MAX_OUT = 2`
- single asset: native TOS only
- public unshield amount (Hybrid UNO)
- UNO transactions serialized against each other

---

## 12. Future Phases

- Phase 2:
  - `MAX_IN=2`, `MAX_OUT=2`
  - batch proof verification optimizations
- Phase 3:
  - move UNO state from router-owned storage slots to dedicated StateDB namespace
- Phase 4:
  - relayer/paymaster model
  - optional multi-asset notes

