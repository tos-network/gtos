# GTOS UNO Security Gates (Evidence Log)

This file records gate-by-gate evidence for UNO rollout readiness.

Execution helper:
- `scripts/uno_security_gate.sh`

## Gate 1: Consensus divergence audit (txpool vs execution vs import)

Status: `DONE`

Evidence:
- TxPool vs execution parity matrix in `core/tx_pool_test.go`:
  - invalid envelope / unsupported action
  - empty payload
  - low gas / nonce too low / nonzero value
  - shield insufficient-balance
  - sender/receiver signer mismatch/missing
  - version-overflow guards (all 3 actions; transfer sender+receiver)
  - malformed ciphertext / invalid proof shape / empty proof / oversized proof
  - transfer self-transfer / zero amount / zero receiver
- Import/reorg determinism:
  - `TestUNOReorgReimportVersionConsistency` in `core/uno_reorg_test.go`
  - serial/parallel parity tests in `core/execute_transactions_parity_test.go`

Notes:
- Oversized UNO payload is intercepted by txpool global tx-size cap (`ErrOversizedData`) before UNO-level decode; this is expected and explicitly tested.

## Gate 2: Transcript binding audit (replay / cross-action / cross-chain)

Status: `DONE`

Evidence:
- Canonical transcript constants frozen:
  - `core/uno/protocol_constants.go`
  - `core/uno/protocol_constants_test.go`
- Context layout and field-diff tests:
  - `core/uno/context_test.go`
  - covers chain id/action/from/to/nonce and transition ciphertext fields for shield/transfer/unshield
- Replay behavior:
  - same-action and cross-action nonce replay rejection in `core/uno_state_transition_test.go`

## Gate 3: Malformed point/proof handling audit

Status: `DONE`

Evidence:
- Reject malformed ciphertext lengths and malformed proof shapes:
  - `core/tx_pool_test.go`
  - `core/uno/verify_test.go`
- Fuzz coverage for decoder/proof parsers:
  - `core/uno/fuzz_test.go`
- Proof failure no-state-write checks:
  - `core/uno_state_transition_test.go`

## Gate 4: Gas griefing audit for expensive verify paths

Status: `IN PROGRESS`

Current evidence:
- Bench baselines for shield reject paths:
  - `BenchmarkUNOShieldInvalidProofShape`
  - `BenchmarkUNOShieldInvalidProofVerifyPath`
  - file: `core/uno_gas_griefing_bench_test.go`
- Runner:
  - `scripts/uno_gas_griefing_audit.sh`

Remaining work:
- Define explicit SLO/thresholds for max verify cost under adversarial mixes.
- Extend from single-tx microbench to sustained block-level UNO load profiles.

## Gate 5: Counter bounds audit (`amount`, `uno_version`, nonce coupling)

Status: `DONE`

Evidence:
- `amount` bounds:
  - zero amount reject (shield/unshield)
  - insufficient-balance guard including gas+amount
- `uno_version` bounds:
  - overflow guards in execution+txpool
  - no-state-write assertions on overflow
- nonce coupling:
  - same-action and cross-action replay reject (`ErrNonceTooLow`)
  - reorg/re-import invariants preserve deterministic nonce/version progression

## Gate 6: Signer rotation and key-loss behavior documented

Status: `DONE`

Operational workflow:
- UNO accounts must keep `signerType == elgamal` to submit UNO transactions.
- Rotation is executed via `ACCOUNT_SET_SIGNER` system action (on-chain metadata update).
- Safe rotation procedure:
  1. Quiesce outgoing UNO txs for the account.
  2. Wait until all pending txs from the account are finalized.
  3. Submit `ACCOUNT_SET_SIGNER` to the new ElGamal public key.
  4. Verify signer metadata via state/RPC before resuming UNO tx submission.

Behavioral guarantees:
- If signer type is rotated away from ElGamal, UNO txpool/execution reject with signer mismatch/not-configured errors.
- Existing UNO ciphertext state (`commitment`, `handle`, `version`) is not mutated by signer metadata updates alone.
- Version overflow and malformed-proof/ciphertext checks remain unchanged across rotations.

Key-loss behavior:
- Loss of ElGamal private key prevents proving/decrypting for that account; encrypted balance is operationally frozen.
- Current protocol has no trustless key-recovery primitive for UNO ciphertext ownership transfer.
- Recommended operational control:
  - keep encrypted backups / HSM custody for active UNO keys
  - pre-rotation drills on dev/test environments
  - alerting on unexpected `ACCOUNT_SET_SIGNER` events

Evidence pointers:
- signer mismatch/not-configured parity tests in `core/tx_pool_test.go`
- replay/reorg/version invariants in `core/uno_state_transition_test.go` and `core/uno_reorg_test.go`
