# Why Dual Public/Private Accounts

GTOS implements a dual-account model: every address can hold a public `Balance` (cleartext) or a private `PrivBalance` (ElGamal encrypted), but never both on the same address. Public transfers use `SignerTxType`; private transfers use `PrivTransferTxType`. This document explains why.

## 1. Performance Tiering

| | Public Transfer | Private Transfer |
|---|---|---|
| Verification cost | ~21,000 gas equivalent | CiphertextValidityProof + CommitmentEqProof + RangeProof (~1,024 bytes of proofs) |
| Verification time | Sub-millisecond | 10-50x more expensive (EC multi-scalar multiplication, Bulletproof verification) |
| Transaction size | ~110 bytes | ~500+ bytes (ciphertexts + proofs + handles) |

Scenarios that do not require privacy — staking, gas payments, contract interactions, governance voting — should not bear the cost of ZK proof generation and verification. The dual model lets users pay only for what they need.

## 2. Smart Contract Compatibility

Public accounts can interact with the LVM (DeFi, NFT, governance, oracles, etc.). Private accounts are limited to confidential transfers only.

General-purpose computation on encrypted state remains an unsolved problem at scale. The leading approaches — Fully Homomorphic Encryption (FHE) and Multi-Party Computation (MPC) — are orders of magnitude too slow for on-chain execution today. By keeping public accounts fully functional for contract interaction, GTOS avoids blocking its entire smart contract ecosystem on cryptographic breakthroughs.

When practical encrypted computation becomes available, it can be layered on top of the existing private account infrastructure without redesigning the public contract model.

## 3. Regulatory Flexibility

Some use cases require full transparency:
- Treasury and foundation accounts
- Public grant disbursements
- On-chain governance proposals and voting
- Compliance-required audit trails

Other use cases demand privacy:
- Personal transactions
- Payroll
- Commercial settlements
- Avoiding front-running

A single-mode chain forces all participants into one regime. The dual model lets each participant choose the appropriate level of transparency for their context.

## 4. Progressive Adoption

Users start with the familiar public account model (same UX as Ethereum-style chains). When privacy is needed, they generate an ElGamal keypair and receive private balance at genesis or via future bridge mechanisms.

This avoids forcing all users to manage ZK-compatible key material, understand encrypted balances, or run client-side proof generation just to use the chain. Privacy is opt-in, not mandatory overhead.

## 5. State Bloat Control

| | Public Account | Private Account |
|---|---|---|
| Balance storage | `Balance` field in `StateAccount` (~32 bytes) | `Commitment` + `Handle` in storage slots (64 bytes) |
| Additional state | None | `Version` + `PrivNonce` (16 bytes) |

If the entire chain were forced into encrypted balances, every account in the state trie would carry at least 80 bytes of ciphertext state — doubling the storage footprint for accounts that gain no benefit from privacy. The dual model keeps public accounts lean.

## 6. Fee Model Separation

Public transactions use the standard gas model (`Gas * GasPrice`) — well-understood, battle-tested, compatible with existing tooling (wallets, explorers, gas estimators).

Private transactions use a plaintext `Fee`/`FeeLimit` model deducted from the encrypted balance via homomorphic subtraction. This is necessary because private accounts have no public `Balance` to pay gas from.

Keeping these fee models separate avoids contorting either one to fit the other.

## Summary

The dual-account model is not a compromise — it is a deliberate design that provides:

- **Efficiency**: pay for privacy only when you need it
- **Functionality**: full smart contract support on public accounts
- **Flexibility**: transparency and privacy coexist on the same chain
- **Simplicity**: progressive adoption without mandatory complexity
- **Scalability**: controlled state growth

Not every transaction needs privacy. But when privacy is needed, it must be cryptographically strong. The dual model delivers both.
