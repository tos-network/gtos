# Dual-Ledger Privacy Transfers for gtos
> Design v0.1 (MVP-first, audit-friendly)

## 0. Goals / Non-goals

### Goals
- Keep **public plaintext balance** (Ethereum-like `Account.balance`) fully functional and unchanged.
- Add an **independent private ledger** (“private balance”) that supports:
  - Private-to-private transfers: A → B → C without revealing sender/receiver linkage or amounts on-chain (amounts are hidden inside notes).
  - Double-spend protection via nullifiers.
  - Efficient verification via zk proof verification **precompile**.
- Provide explicit, controlled bridges:
  - **Shield**: public balance → private notes
  - **Unshield**: private notes → public balance
- Ensure **two ledgers are logically separated**:
  - Public value-transfer uses `Account.balance`
  - Private value-transfer uses note commitments/nullifiers
  - No implicit auto-conversion

### Non-goals (MVP)
- Fully hidden gas fees (gas will be paid from public balance like normal EVM tx).
- Private smart-contract DeFi semantics inside the private ledger.
- Full anonymity against global network-level attackers (timing, mempool, etc.).
- Cross-chain privacy or stealth address support (optional later).

---

## 1. High-level Architecture

We introduce a **Shielded Pool System** alongside the existing EVM/account model.

### Public Ledger (existing)
- `stateObject.balance` continues to exist and behaves as Ethereum.
- Normal transfers, contract calls with `value`, EIP-1559 gas mechanics remain unchanged.
- Public ledger state transitions remain identical to upstream geth.

### Private Ledger (new)
A separate state machine maintained in consensus:
- **Commitment Merkle Tree** (append-only)
- **Nullifier set** (spent set)
- **Roots ring buffer** (to allow proofs referencing recent roots)
- (Optional) Encrypted note payload log (ciphertexts) for wallet scanning

### Controlled Bridges
- **Shield**: deduct public balance, mint private note(s).
- **Unshield**: consume private note(s), credit public balance.

Private-to-private transfers never touch public balances (except gas fees for the EVM transaction executing the call).

---

## 2. Data Model (Private Ledger)

### 2.1 Note
A note represents spendable private value, similar to Zcash Sapling-style UTXO.

Fields (conceptual):
- `value`: UInt (hidden in zk circuit)
- `assetId`: optional (MVP: single asset = native coin)
- `owner`: recipient public key / diversified address (hidden)
- `rho/rseed`: randomness for nullifier/commitment derivation
- `memo`: optional encrypted data

### 2.2 Commitment
Commitment binds to a note without revealing its contents:
- `cm = Commit(note, rcm)` (Pedersen or Poseidon-based depending on circuit)

On-chain we store:
- leaf `cm` in an append-only Merkle tree.

### 2.3 Nullifier
Nullifier is a public tag to prevent double-spend:
- `nf = PRF_nf(sk, note)` (derived from spending key + note randomness)

On-chain we store:
- `spent[nf] = true`

### 2.4 Merkle Tree
- Height: `H` (e.g. 20~32)
- Append-only insertion
- Maintain:
  - `currentRoot`
  - `rootsRing[0..N-1]` (e.g. N=100 or 256)
  - internal nodes for incremental update (implementation choice)

---

## 3. Interfaces: System Contract + Precompiles (Recommended MVP)

### 3.1 System Contract: `ShieldedPool`
A pre-deployed contract at fixed address:
- e.g. `0x0000000000000000000000000000000000001001`

Responsibilities:
- Public <-> private bridging logic (shield/unshield)
- Private ledger updates (append commitments, mark nullifiers)
- Root ring buffer maintenance
- Emit events for wallets (commitments, ciphertexts, roots)
- Call verifier precompile for zk proof verification

### 3.2 Precompile: `ZKVerifier`
A new precompile address:
- e.g. `0x000000000000000000000000000000000000000A`

Responsibilities:
- Verify zk-SNARK proofs (MVP: Groth16 on BN254)
- Enforce input size limits and gas accounting
- Return success/failure

---

## 4. Transaction Flows

### 4.1 Shield (Public → Private)
User wants to convert public balance into a private note.

**Call**
- `shield(uint256 amount, bytes32 commitment, bytes ciphertext) payable?`

**Rules**
- `amount` is public (MVP). The minted private note value equals `amount`.
- Contract deducts `amount` from the user’s public balance:
  - Implemented via requiring `msg.value == amount` OR via ERC20-like transfer (for native coin simplest is `msg.value`).
- Append `commitment` into the tree.
- Emit ciphertext for recipient scanning.

**Outputs**
- New Merkle root
- Commitment event
- Ciphertext event

**Notes**
- If you want `shield` without revealing amount, that is a different (harder) design; MVP keeps amount public at shield/unshield edges.

### 4.2 Private Transfer (Private → Private)
A spends one or more notes and creates new notes for B (and change back to A), staying fully in private ledger.

**Call**
- `privateTransfer(bytes proof, bytes32 root, bytes32[] nullifiers, bytes32[] newCommitments, bytes[] ciphertexts)`

**Proof statement (circuit)**
- There exist input notes owned by spender such that:
  - Each input note commitment is a member of Merkle tree with root `root`.
  - Each nullifier is correctly derived from the input note and spender key.
  - Value is conserved: `sum(inputs) = sum(outputs) + fee_private(optional)`
  - Each output commitment matches its output note.
- Public inputs: `root`, `nullifiers`, `newCommitments`, (optional) `fee_private`.

**On-chain checks**
1. `root` is in roots ring buffer.
2. Each `nullifier` is not yet spent.
3. Call verifier precompile to validate `proof`.
4. Mark nullifiers as spent.
5. Append all `newCommitments`.
6. Emit ciphertexts.

**Result**
- A → B → C can be repeated indefinitely inside private ledger.

### 4.3 Unshield (Private → Public)
A consumes private notes and credits a public address’ `Account.balance`.

**Call**
- `unshield(bytes proof, bytes32 root, bytes32[] nullifiers, bytes32[] newCommitments, bytes[] ciphertexts, address to, uint256 amount)`

(Optionally newCommitments includes change note.)

**Proof statement**
- Like private transfer, but one output is “public withdrawal”:
  - `sum(inputs) = sum(privateOutputs) + amount + fee_private(optional)`
- Public inputs include `to` and `amount` (MVP: both public).

**On-chain**
- Same verify/spend/append process.
- Then credit `to` with `amount` (native coin transfer from pool escrow or minting logic if protocol-defined).
- Emit events.

---

## 5. Gas & Fee Model

### MVP rule
- Gas fees for calling the system contract are paid **from public balance** exactly like any EVM tx.
- Private ledger does not pay gas (no private fee market needed).

### Optional later
- Relayer model: user submits proof off-chain, relayer pays gas, relayer is compensated in private notes.
- Private fee in-circuit as a public input, minted to miner as a private note (complex; not MVP).

---

## 6. State Storage Design

### 6.1 Where to store private ledger state
Option A (MVP): store in EVM contract storage
- `spent[nullifier] => bool`
- tree nodes / roots ring buffer in storage

Pros:
- Minimal client changes; easiest to ship and test.
Cons:
- Potentially heavy storage/gas. Need careful tree design.

Option B (Recommended for performance later): store in client-side state (consensus-level)
- Extend StateDB with a new namespace/table:
  - `shielded_roots`
  - `shielded_tree_nodes`
  - `shielded_nullifiers`

Pros:
- Much cheaper per tx and more scalable.
Cons:
- Requires deeper geth modifications; more audit surface.

### MVP recommendation
- Start with **Option A** for correctness and iteration speed.
- Plan migration to Option B once circuits and rules stabilize.

---

## 7. Anti-DoS / Limits

Because proofs and ciphertexts are large:
- Enforce maximum calldata size for private methods:
  - e.g. `maxProofBytes`, `maxCiphertextBytes`, `maxNotesPerTx`
- Enforce maximum number of inputs/outputs per proof:
  - e.g. `MAX_IN = 2`, `MAX_OUT = 2` for MVP (1 recipient + 1 change)
- Enforce verifier precompile input constraints.
- Implement strict gas schedule for verifier:
  - base + per-pairing cost + per-public-input cost (fixed for Groth16)

---

## 8. Cryptography & Circuit Choices (MVP Defaults)

### zk system
- Groth16 over BN254 (alt_bn128), due to mature tooling and compact proof size.

### Hashes
- Commitment and Merkle hashes should match circuit-friendly hash:
  - Poseidon (preferred) or Pedersen (common)
- Merkle tree uses same hash in-circuit and on-chain.

### Encryption for ciphertexts
- Encrypt output note data for recipients to scan:
  - ECIES over secp256k1 OR X25519 + AEAD (depending on wallet stack)
- On-chain does not validate ciphertext correctness (MVP), only stores/logs it.

---

## 9. Wallet Requirements (Off-chain)

Wallet must:
- Maintain keys:
  - spending key (for creating nullifiers/proofs)
  - viewing key (for scanning and decrypting ciphertexts)
- Scan chain events:
  - commitments/ciphertexts
  - roots updates
- Track unspent notes and build proofs:
  - note selection (inputs)
  - create outputs: recipient note + change note
- Submit EVM tx calling `privateTransfer` and `unshield`

---

## 10. geth/gtos Implementation Plan (Concrete Steps)

### Step 1: Add verifier precompile
- Add precompile address mapping.
- Implement Groth16 verify function:
  - Input encoding: `vkId || proof || publicInputs`
  - Output: `0x01` for success, empty/revert for failure.
- Add strict gas schedule & size checks.

### Step 2: Deploy system contract at genesis
- Embed `ShieldedPool` bytecode into genesis alloc for fixed address.
- Optionally add chain config flag to enable/disable private ledger.

### Step 3: Implement ShieldedPool contract
- Storage layout:
  - `rootsRing[]`
  - `currentRoot`
  - `spentNullifier[nf]`
  - Merkle tree incremental state
- Functions:
  - `shield`
  - `privateTransfer`
  - `unshield`
  - getters: `isSpent(nf)`, `getRoot(i)`, `getCurrentRoot()`
- Events:
  - `CommitmentInserted(index, commitment, newRoot)`
  - `NullifierSpent(nullifier)`
  - `Ciphertext(index, bytes ciphertext)` (or batched)
  - `ShieldedTxMeta(root, nullifiers, newCommitments)` (optional)

### Step 4: Protocol safety checks
- Enforce max inputs/outputs.
- Enforce ring buffer root membership.
- Reentrancy protection where needed.
- Ensure unshield uses escrowed funds:
  - `shield` deposits native coin into contract
  - `unshield` pays out from contract balance

### Step 5: Tooling
- Provide reference circuits and prover CLI.
- Provide test vectors:
  - deterministic keys/notes
  - sample proofs
- Provide an indexer script for scanning events.

---

## 11. Security Considerations

- **Double-spend**: nullifier must be unique and derived correctly in-circuit.
- **Root validity**: only accept roots from a bounded ring buffer.
- **Front-running / timing leaks**: private transfer hides on-chain amounts/links but mempool timing and off-chain metadata can leak.
- **Key management**: spending key compromise drains private notes irreversibly.
- **Circuit bugs**: catastrophic; require audits and test vectors.
- **Verifier correctness**: must be constant-time and robust against malformed inputs.
- **Storage growth**: commitment insertions grow tree; plan pruning or periodic checkpoints (future).

---

## 12. Upgrade Path

### v0.2
- Increase max notes per tx (e.g. 2-in/2-out).
- Add multi-asset notes (`assetId`) if needed.
- Add relayer / paymaster patterns.

### v0.3
- Move private ledger storage from contract storage to client-level StateDB namespace (performance).
- Add RPC endpoints for efficient scanning.
- Add optional compliance features (viewing keys, selective disclosure).

---

## 13. Open Parameters (MVP Defaults)

- Tree height `H`: 20 (≈1,048,576 leaves) or 32 for long-term.
- Roots ring size `N`: 100 or 256.
- Max inputs/outputs: 1-in/2-out (recipient + change) for MVP, or 2/2.
- zk system: Groth16 BN254.
- Hash: Poseidon.
- Ciphertext size cap: e.g. 512 bytes per output.

---

## Appendix A: Public Input Encoding (Example)
For Groth16 verification, public inputs could be serialized as:
- `root (32)`
- `nullifier[0..MAX_IN-1] (32 each)`
- `newCommitment[0..MAX_OUT-1] (32 each)`
- `withdrawTo (20) + withdrawAmount (32)` for unshield
All converted into field elements as required by BN254 verifier conventions.

---

## Appendix B: Minimal ABI Sketch
```solidity
interface IShieldedPool {
  function shield(bytes32 commitment, bytes calldata ciphertext) external payable;

  function privateTransfer(
    bytes calldata proof,
    bytes32 root,
    bytes32[] calldata nullifiers,
    bytes32[] calldata newCommitments,
    bytes[] calldata ciphertexts
  ) external;

  function unshield(
    bytes calldata proof,
    bytes32 root,
    bytes32[] calldata nullifiers,
    bytes32[] calldata newCommitments,
    bytes[] calldata ciphertexts,
    address to,
    uint256 amount
  ) external;

  function isSpent(bytes32 nullifier) external view returns (bool);
  function getCurrentRoot() external view returns (bytes32);
  function getRoot(uint256 i) external view returns (bytes32);
}
