# GTOS UNO Implementation TODO

This checklist turns [PRIVACY_UNO.md](./PRIVACY_UNO.md) into an executable engineering plan.
Reference implementations:
- Rust reference: `~/xelis-blockchain` (`transaction/verify`, `api`, `account/versioned balance`).
- C reference: `~/avatar` (`src/uno/*`, `include/at/crypto/*`).

Status legend:
- `[ ]` not started
- `[/]` in progress
- `[x]` done

---

## 0. Baseline and Freeze

- [ ] Freeze UNO MVP scope (native asset only, public gas, 3 actions: `UNO_SHIELD/UNO_TRANSFER/UNO_UNSHIELD`).
- [ ] Freeze canonical transcript labels and domains (must match C/Rust references where intended).
- [ ] Freeze wire prefix and action IDs (`GTOSUNO1`, `0x02/0x03/0x04`).
- [ ] Write constants doc block in code (single source of truth).

DoD:
- A single constants source exists and all modules import from it.

---

## 1. Crypto Adapter Layer (Go <-> C)

Target: expose stable Go APIs over existing `libed25519` UNO C primitives.

- [x] Create `crypto/uno/` package.
- [x] Add cgo wrappers for ElGamal ciphertext operations:
  - [x] `Encrypt` (adapter wired)
  - [x] `Add/Sub ciphertext` (C wrapper + Go adapter wired)
  - [x] `Add/Sub amount` (C wrapper + Go adapter wired)
  - [x] `Compress/Decompress` (normalize roundtrip wrapper wired)
- [x] Add wrappers for proof parsing/verification:
  - [x] `CiphertextValidityProof` (verify wrapper wired)
  - [x] `CommitmentEqProof` (verify wrapper wired)
  - [x] `RangeProof verify` (adapter wired; consensus integration pending)
- [x] Add transcript helper wrappers required by proof verification.
- [/] Define strict Go error mapping for all C return codes.

Reference:
- `~/avatar/src/uno/at_uno_balance.c`
- `~/avatar/src/uno/at_uno_exec.c`
- `~/avatar/include/at/crypto/at_elgamal.h`
- `~/avatar/include/at/crypto/at_uno_proofs.h`
- `~/avatar/include/at/crypto/at_rangeproofs.h`

DoD:
- `go test ./crypto/uno/...` passes with deterministic vectors.

---

## 2. UNO State Model in GTOS

- [x] Implement UNO slot keys in `core/uno/state.go`:
  - [x] `uno_ct_commitment`
  - [x] `uno_ct_handle`
  - [x] `uno_version`
- [x] Implement read/write helpers with strict length validation.
- [x] Implement zero/default state semantics.
- [x] Ensure account signer lookup is used as key source (`signerType == elgamal`).

DoD:
- Unit tests prove roundtrip encoding and state mutation correctness.

---

## 3. Payload Codec

- [x] Implement binary envelope codec in `core/uno/codec.go`:
  - [x] Parse/encode `GTOSUNO1` prefix
  - [x] Parse action and body
  - [x] Strict bounds checks for all fields
- [x] Implement action payload structs:
  - [x] `UNO_SHIELD`
  - [x] `UNO_TRANSFER`
  - [x] `UNO_UNSHIELD`
- [x] Reject non-canonical payloads (duplicate forms, invalid lengths).

DoD:
- Fuzz and golden tests cover malformed payload rejection and canonical decode.

---

## 4. Consensus Path Integration

- [x] Add `PrivacyRouterAddress` and UNO gas constants to params.
- [x] Route in `core/state_transition.go`:
  - [x] `to == PrivacyRouterAddress` -> `applyUNO`
- [/] Implement `applyUNO` action handlers:
  - [x] `applyUNOShield` (proof verify path + state mutation baseline)
  - [/] `applyUNOTransfer` (proof verify + deterministic state mutation; transcript binding/range strategy still pending)
  - [/] `applyUNOUnshield` (proof verify + deterministic state mutation; transcript binding still pending)
- [x] Enforce signer constraints:
  - [x] sender signer type must be `elgamal`
  - [x] transfer receiver signer type must be `elgamal`
- [ ] Bind proof transcript to chain context:
  - [ ] `chainId`, `actionTag`, `from`, `to`, `nonce`, commitments, asset id.
- [x] Ensure no partial state writes on any verification failure.

DoD:
- Block import path fully verifies UNO txs deterministically.

---

## 5. TxPool and Precheck Alignment

- [x] Add txpool precheck path for UNO payload parse and basic constraints.
- [/] Mirror consensus-critical checks in txpool (no consensus divergence; transcript/proof semantics still execution-only).
- [x] Add max payload/proof size guards before heavy crypto.

DoD:
- Same tx accepted/rejected consistently by txpool and block execution.

---

## 6. Parallel Executor Safety

- [x] In `core/parallel/analyze.go`, serialize UNO txs via shared conflict marker.
- [/] Add parity tests: serial vs parallel same receipts/logs/state root (batch-vs-per-tx parity with UNO added).

DoD:
- No state-root mismatch between serial and parallel execution for mixed blocks.

---

## 7. Genesis and Chain Config Support

- [x] Add genesis loader support for UNO initial state:
  - [x] `uno_ct_commitment`
  - [x] `uno_ct_handle`
  - [x] `uno_version`
- [x] Validate preallocated UNO accounts must have `elgamal` signer metadata.
- [x] Add genesis validation errors with actionable messages.
- [x] Add optional genesis signer shortcut fields (`signerType`, `signerValue`) for UNO bootstrap.

DoD:
- Devnet/testnet genesis can preallocate UNO balances and boot successfully (integration pending).

---

## 8. RPC and Tooling

- [x] Add RPC methods:
  - [x] `tos_unoShield`
  - [x] `tos_unoTransfer`
  - [x] `tos_unoUnshield`
  - [x] `tos_getUNOCiphertext`
- [x] Add request/response schema validation.
- [ ] Provide wallet-side decrypt workflow (local only).

DoD:
- End-to-end CLI/RPC flow works on local 3-node network.

---

## 9. Testing Matrix

### 9.1 Unit
- [x] Codec tests (valid/invalid/canonical).
- [x] UNO state slot tests.
- [ ] Crypto wrapper tests (vector-based).
- [ ] Transcript domain-separation tests.

### 9.2 Core
- [/] `UNO_SHIELD` state transition tests.
- [/] `UNO_TRANSFER` state transition tests.
- [/] `UNO_UNSHIELD` state transition tests.
- [ ] Nonce/replay rejection tests.
- [x] Invalid proof rejection tests.

### 9.3 Integration
- [ ] 3-node local DPoS UNO transfer scenario.
- [ ] Genesis preallocation: A/B decryptability check.
- [ ] Reorg/re-import determinism test for UNO blocks.

### 9.4 Fuzz / Robustness
- [ ] Payload decoder fuzzing.
- [ ] Proof blob parser fuzzing.
- [ ] Differential check against Rust/C reference vectors.

DoD:
- New test suites are green in CI and deterministic under repeated runs.

---

## 10. Security Review Gates

- [ ] Consensus divergence audit (txpool vs execution vs import).
- [ ] Transcript binding audit (replay/cross-action/cross-chain).
- [ ] Malformed proof and malformed curve point handling audit.
- [ ] Gas griefing audit (large proofs / expensive verify path).
- [ ] Overflow/underflow and bounds audit on amount/version counters.
- [ ] Key-loss and signer-rotation behavior documented.

DoD:
- Security checklist signed off before enabling UNO on shared networks.

---

## 11. Rollout Plan

- [ ] Phase A: compile-time off by default, local testnet only.
- [ ] Phase B: devnet enabled with soak + fault injection.
- [ ] Phase C: public testnet trial with monitoring.
- [ ] Phase D: mainnet decision gate (performance + security + operability).

Exit criteria for each phase:
- No consensus split.
- No nondeterministic test failures.
- Stable resource usage under load.

---

## 12. Task Ownership Board (fill-in)

- [ ] Crypto wrappers owner:
- [ ] Core state transition owner:
- [ ] RPC/tooling owner:
- [ ] Test/integration owner:
- [ ] Security review owner:
