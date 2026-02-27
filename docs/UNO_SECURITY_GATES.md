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

Status: `PENDING`

Pending work:
- Add profiling/bench evidence under adversarial proof-bundle mixes.
- Define max verify budget targets and failure thresholds for devnet soak.

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

Status: `PENDING`

Pending work:
- Document operational workflow for `ACCOUNT_SET_SIGNER` with UNO accounts.
- Define recovery and monitoring playbook for signer loss/rotation.
