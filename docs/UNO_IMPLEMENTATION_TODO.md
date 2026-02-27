# GTOS UNO Implementation TODO (XELIS-Convergent Track)

This checklist turns [PRIVACY_UNO.md](./PRIVACY_UNO.md) into an execution plan with one explicit target:

- **Target:** GTOS UNO implementation approach should be close to `~/xelis-blockchain` account-balance privacy architecture.
- **Non-target:** byte-level protocol compatibility or identical wire format.

Reference implementations:
- Rust reference: `~/xelis-blockchain` (`xelis_common/src/transaction/{builder,verify}`, wallet sync/build flow).
- C reference: `~/avatar` (`src/uno/*`, `include/at/crypto/*`).

Status legend:
- `[ ]` not started
- `[/]` in progress
- `[x]` done

---

## 0. Alignment Baseline and Freeze

- [x] Freeze canonical transcript labels/domains for GTOS UNO v1 (`core/uno/protocol_constants.go`, `docs/UNO_PROTOCOL_FREEZE.md`).
- [x] Freeze action wire IDs and field ordering for UNO payloads (golden wire vectors in `core/uno/protocol_constants_test.go` + `FrozenPayloadFieldOrder`).
- [x] Freeze GTOS/XELIS semantic mapping table (same meaning, different wire allowed) in `docs/UNO_PROTOCOL_FREEZE.md`.
- [x] Add one source-of-truth constants block for all transcript tags and separators (`core/uno/protocol_constants.go`).

DoD:
- All proof builders/verifiers import a single constants source.

---

## 1. Crypto Adapter Layer (Go <-> C)

Target: stable Go API over imported C primitives with deterministic error mapping.

- [x] Create `crypto/uno/` package.
- [x] Ciphertext operations wired (`Encrypt`, add/sub ct, add/sub amount/scalar, zero ct, opening/keypair helpers, normalize/compress paths).
- [x] Proof verification wrappers wired (`CiphertextValidity`, `CommitmentEq`, `RangeProof` verify).
- [x] Strict Go error mapping for every C return code.
- [x] Deterministic vector tests against known Rust/C vectors (C-side fixed vectors landed; Rust/XELIS differential ciphertext-op vectors landed in `crypto/uno/testdata/xelis_vectors.json` + `TestXelisDifferentialCiphertextOpsVectors`; proof-vector self-consistency + context-binding differential landed in `crypto/uno/proof_differential_cgo_test.go` + `core/uno/proof_context_mutation_cgo_test.go`).

DoD:
- `go test ./crypto/uno/...` passes with reproducible vectors and explicit error-class assertions.

---

## 2. State Model and Versioning

Target: XELIS-style versioned account-balance semantics (adapted to GTOS state model).

- [x] UNO state fields exist (`uno_ct_commitment`, `uno_ct_handle`, `uno_version`).
- [x] Strict length/type validation in read/write helpers.
- [x] Enforce signer source key (`signerType == elgamal`) for UNO accounts.
- [x] Define and enforce `uno_version` monotonic transitions in all mutation paths (overflow guard pre-write in all 3 actions; `TestUNOVersionOverflowRejectedInExecution` covers shield/transfer-sender/transfer-receiver/unshield with no-mutation assertion).
- [x] Add reorg/re-import tests for version consistency (`TestUNOReorgReimportVersionConsistency` covers reorg away/back and re-import invariants for `uno_version`/nonce).

DoD:
- Version monotonicity and deterministic re-execution are proven by tests.

---

## 3. Transaction Semantics Convergence (Core)

Target: converge to XELIS-style transaction verification flow:
transcript-bound proofs + source balance transition correctness + range constraints.

- [x] UNO router path and action dispatch are live.
- [x] `UNO_TRANSFER` self-transfer guard added (txpool + execution); state-write semantics verified.
- [x] `UNO_UNSHIELD` full transition semantics: gas charge, version-overflow guard, SubCiphertexts delta, transcript-bound proof verify, ciphertext+version state write, public AddBalance — all implemented and tested (proof-failure/no-state-write + version-overflow/no-state-write).
- [x] Bind proofs to full chain context transcript:
  - [x] `chainId`
  - [x] `actionTag`
  - [x] `from`
  - [x] `to` (if applicable)
  - [x] sender nonce
  - [x] old/new commitments and handles
  - [x] native asset constant
- [x] Ensure replay-hardening matrix is complete (cross-chain/cross-action tests + tx-context field-diff matrix in `core/uno/context_test.go` for shield/transfer/unshield).

DoD:
- Block import path performs deterministic, context-bound verification for all three UNO actions.

---

## 4. TxPool vs Execution Equivalence

Target: no acceptance divergence between txpool precheck and execution path.

- [x] UNO payload decode and signer checks in txpool are present.
- [x] Payload/proof shape and size guards are present.
- [x] Consensus-critical semantic checks mirrored: sender/receiver version overflow (all 3 actions) and combined gas+shield-amount balance guard for Shield.
- [x] Explicit parity tests: invalid-envelope/unsupported-action, empty-UNO-payload, nonce-too-low, low-gas, nonzero-value, shield insufficient-balance, shield/transfer/unshield oversized-proof-bundle, sender signer missing/type-mismatch, shield/transfer(sender+receiver)/unshield sender version-overflow, transfer receiver missing-signer, transfer receiver signer-type-mismatch, shield-zero-amount, transfer/unshield-zero-receiver, transfer-self-transfer, unshield-zero-amount, shield/transfer/unshield malformed-ciphertext decode, shield/transfer/unshield empty-proof-bundle, and shield/transfer/unshield invalid-proof-shape.

DoD:
- Same tx is accepted/rejected for the same reason by both paths.

---

## 5. Parallel/Determinism Guarantees

Target: preserve deterministic state root/receipts/log ordering with UNO enabled.

- [x] UNO conflict marker in parallel analyzer is present (serialized UNO lane).
- [x] Serial/parallel parity coverage with UNO (mixed-block + randomized stress parity tests) is in place.
- [x] Add mixed-block parity tests: plain transfer + system action + UNO actions.
- [x] Add stress parity test with repeated randomized UNO action batches.

DoD:
- No serial/parallel divergence under repeated randomized runs.

---

## 6. Wallet/Tooling Convergence

Target: move toward XELIS-like wallet flow for encrypted balance lifecycle.

- [x] RPC actions live: `tos_unoShield`, `tos_unoTransfer`, `tos_unoUnshield`, `tos_getUNOCiphertext`.
- [x] Amount unit fixed: 1 UNO = 1 TOS (wei conversion only at public-balance boundary; ECDLP range is now feasible).
- [x] `tos_unoDecryptBalance` RPC: reads ciphertext from state, decrypts with private key, solves ECDLP with BSGS (`crypto/uno/ecdlp.go`).
- [x] `personal_unoBalance` RPC: decrypts balance using local keystore + password (no raw private key over RPC wire).
- [x] `toskey uno-balance` CLI: local keyfile decrypt + `tos_getUNOCiphertext` + ECDLP in-process; private key never leaves the machine.
- [x] Nonce/version-aware local state update and rollback handling (`toskey uno-balance --track-state`, `--track-accept-reorg`; tracker tests in `internal/unotracker/state_test.go`).
- [x] Proof builder/prover path landed:
  - [x] `crypto/uno` prover wrappers (`ProveShieldProof*`, `ProveCTValidityProof*`, `ProveBalanceProof*`).
  - [x] `core/uno` action builders (`BuildShieldPayloadProof`, `BuildTransferPayloadProof`, `BuildUnshieldPayloadProof`) that bind transcript context and emit payload-ready proof bundles.
- [x] End-to-end user flow: genesis preallocation -> transfer -> unshield -> balance reconciliation (validated on local 3-node DPoS with `toskey uno-shield|uno-transfer|uno-unshield`; evidence under `/data/gtos/uno_e2e/run_20260227_101711_v2`).

DoD:
- Local wallet tooling can track/decrypt UNO state reliably across new blocks and reorgs.

---

## 7. Tests and Differential Validation

### 7.1 Unit
- [x] Payload codec tests.
- [x] UNO state slot tests.
- [x] Transcript domain-separation tests (context serialization/layout + field-diff matrices + protocol-freeze constants/wire golden tests landed; prover/verifier differential: context-binding for all 3 proof types verified in `crypto/uno/proof_differential_cgo_test.go`; payload-level header+tail mutation rejection for all 3 actions verified in `core/uno/proof_context_mutation_cgo_test.go`).
- [x] Crypto vector tests (fixed C vectors done; Rust/XELIS ciphertext-op differential done; proof-context binding differential done — cross-implementation byte-level proof parity deferred: GTOS C uses `balance-proof` domain separator vs xelis Rust `balance_proof`, incompatible wire formats).

### 7.2 Core
- [x] Shield/transfer/unshield transition tests: proof-failure/no-state-write (all 3) + version-overflow/no-state-write (all 3 actions, sender+receiver for transfer) + nonce-replay rejection + reorg/re-import consistency. Success-path CGO coverage includes `TestUNOLifecycleReorgAndReimportDeterminism` and `TestUNOGenesisPreallocReorgLifecycle`.
- [x] Nonce/replay rejection matrix: execution-path same-action and cross-action same-nonce replay for all 3 actions; txpool/execution nonce-too-low parity for Shield, Transfer (with receiver elgamal signer precondition), and Unshield.
- [x] Invalid proof rejection baseline exists.

### 7.3 Integration
- [/] 3-node local DPoS UNO scenario (stable repeated run). Prover/builder plumbing and builder->CLI->RPC wiring are in place and e2e path is validated (`shield -> transfer -> unshield`, all receipts `0x1`) with artifacts under `/data/gtos/uno_e2e/run_20260227_101711_v2`; repeat-run harness `scripts/uno_e2e_soak.sh` is landed (auto-fund + receipt gating, smoke artifact: `/data/gtos/uno_e2e/run_20260227_104612_soak1`), remaining work is long-duration repeated stability evidence.
- [x] Genesis preallocation decryptability checks for recipients. Reorg-drill lifecycle coverage is now in `TestUNOGenesisPreallocReorgLifecycle` (decrypt at genesis prealloc, post-unshield residual, reorg-away rollback, reorg-back recovery) and `TestUNOLifecycleReorgAndReimportDeterminism`.
- [x] Reorg/re-import determinism for UNO blocks (`TestUNOReorgReimportVersionConsistency`).

### 7.4 Fuzz / Robustness
- [x] Payload decoder fuzzing.
- [x] Proof blob parser fuzzing.
- [x] Cross-implementation differential checks: XELIS ciphertext-op differential vectors done; proof-context binding differential (context mutation rejection for all 3 proof types at crypto/uno and core/uno levels) done. Byte-level cross-implementation proof parity blocked by domain separator mismatch (`balance-proof` vs `balance_proof`) — documented.

DoD:
- New suites are deterministic and green in CI.

---

## 8. Security Review Gates

- [x] Consensus divergence audit (txpool vs execution vs import) completed; evidence tracked in `docs/UNO_SECURITY_GATES.md`.
- [x] Transcript binding audit (replay/cross-action/cross-chain) completed; evidence tracked in `docs/UNO_SECURITY_GATES.md`.
- [x] Malformed point/proof handling audit completed; evidence tracked in `docs/UNO_SECURITY_GATES.md`.
- [x] Gas griefing audit for expensive verify paths (benchmark baseline + threshold-enforced runner + SLO doc landed: `core/uno_gas_griefing_bench_test.go`, `scripts/uno_gas_griefing_audit.sh`, `docs/UNO_GAS_GRIEFING_SLO.md`).
- [x] Counter bounds audit (`amount`, `uno_version`, nonce coupling) completed; evidence tracked in `docs/UNO_SECURITY_GATES.md`.
- [x] Signer rotation and key-loss behavior documented in `docs/UNO_SECURITY_GATES.md`.

DoD:
- Security checklist signed off before enabling UNO on shared networks.
