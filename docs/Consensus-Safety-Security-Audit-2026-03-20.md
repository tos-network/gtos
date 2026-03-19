# GTOS Security / Consensus Safety Audit

Date: 2026-03-20

Scope:
- Security
- Deterministic execution
- Consensus safety
- Parallel transaction execution
- Privacy / confidential transfer logic
- State transition / receipts / gas / miner / validator parity

Note:
- This review was code-path driven inside this repository.
- I could not perform a direct upstream diff against `~/geth`, because that baseline was not present in the workspace.

# 1. Executive Summary

This client is not safe for production in its current form.

The main problem is not raw goroutine timing. The parallel executor is mostly deterministic in the narrow implementation sense: it builds fixed execution levels, runs each level concurrently, and merges results in transaction-index order. The real problem is that the scheduler's dependency model is incomplete, so it can produce results that do not match the intended serial semantics for consensus-critical blocks.

I found:
- 3 critical consensus-safety bugs in the parallel scheduler and access-set analysis
- 1 critical privacy accounting bug that can under-collateralize shield / unshield settlement
- 2 medium-severity txpool / sponsorship issues with operational and liveness impact

Positive findings:
- Pre-block sender resolution is handled carefully in `core/state_processor.go`.
- Scheduled tasks are executed in both validator and miner paths before user transactions.
- Any block containing privacy transactions is forced onto the serial execution path.
- Parallel merge, receipt construction, and log indexing are done in tx order.
- Validator ordering is explicitly canonicalized.

Verification performed:
- `go test -p 96 ./core/... ./miner/... ./consensus/... -count=1 -timeout 300s`
- `go test -race ./core/parallel -count=1`

Both passed, but they do not cover the critical cases described below.

# 2. Architecture Understanding

## Most likely consensus-critical directories / files

- `core/blockchain.go`
- `core/block_validator.go`
- `core/state_processor.go`
- `core/state_transition.go`
- `core/parallel/`
- `core/state/`
- `core/types/`
- `core/tx_pool.go`
- `core/tx_noncer.go`
- `miner/worker.go`
- `validator/`
- `consensus/dpos/`
- `consensus/slashindicator/`
- `task/`
- `lease/`
- `agent/`
- `tns/`
- `capability/`
- `delegation/`
- `group/`
- `referral/`
- `reputation/`
- `kyc/`
- `accountsigner/`
- `core/privacy_tx_prepare.go`
- `core/execute_transactions_privacy.go`
- `core/priv/`
- `crypto/ed25519/`

## Block execution path

Block import runs through:
- `core/blockchain.go`: `bc.processor.Process(block, statedb)`
- `core/state_processor.go`: `Process`
- `core/state_transition.go`: per-message execution
- `core/block_validator.go`: bloom / receipt root / state root validation

High-level flow in `core/state_processor.go`:
1. Resolve all tx messages from the pre-block state.
2. Execute scheduled tasks for the current block.
3. Execute transactions through `ExecuteTransactions`.
4. Shift receipt cumulative gas by scheduled-task gas.
5. Finalize consensus-engine side effects.
6. Validate finalized state if the engine implements extra invariants.

## Miner / validator parity

The miner path mirrors validator execution:
- `miner/worker.go` runs `RunScheduledTasks(...)` before user txs
- `miner/worker.go` executes selected txs via `core.ExecuteTransactions(...)`

This is a good design decision and avoids an obvious miner / verifier state-root split.

## Parallel transaction execution model

Parallel execution works as follows:
1. `core/parallel/analyze.go` computes a static access set per tx.
2. `core/parallel/dag.go` assigns execution levels.
3. `core/parallel/executor.go` gives each tx a private `StateDB.Copy()` snapshot wrapped by `WriteBufStateDB`.
4. Each tx in a level executes concurrently.
5. Results are merged back in deterministic tx-index order.
6. Receipts are built strictly in tx order.

Important conclusion:
- The model is deterministic as implemented.
- It is not safe, because determinism here depends on `AnalyzeTx(...)` being complete.
- That assumption is false in several consensus-critical cases.

## Privacy transfer / shield / unshield model

Privacy tx handling is separate from the parallel path:
- `core/state_processor.go`: any privacy tx in a block forces serial execution
- `core/privacy_tx_prepare.go`: prepares public/private state and proof inputs
- `core/execute_transactions_privacy.go`: batch verifies proofs, then applies state

This serialization choice is conservative and good.

However, the public-side amount conversion uses `uint64` multiplication and overflows at realistic values, which is a critical accounting flaw.

# 3. Determinism / Consensus Safety Findings

## Finding 1

- Severity: Critical
- Title: System-action access sets are incomplete and unsafely parallelized
- Why it matters:
  `core/parallel/analyze.go` treats all system actions as if they only conflict through `ValidatorRegistryAddress`, except for a special case for `LEASE_DEPLOY`. Real handlers touch many other consensus-visible registries and balances.
- Exact code location:
  - `core/parallel/analyze.go`
  - `agent/handler.go`
  - `task/handler.go`
  - `lease/handler.go`
  - `core/vm/lvm.go`
  - `core/state_transition.go`
- Root cause:
  The scheduler uses a single coarse sentinel for all system actions, but custom native actions and LVM builtins read / write additional registry accounts and contract metadata that are not modeled.
- Divergence scenario:
  Example 1:
  - `tx0`: plain transfer to `AgentRegistryAddress`
  - `tx1`: `AGENT_DECREASE_STAKE`
  Serial execution can succeed if `tx0` tops up the registry balance first.
  Parallel execution runs `tx1` on the stale parent snapshot, sees insufficient registry balance, and fails / reverts.

  Example 2:
  - `tx0`: `LEASE_CLOSE` or `LEASE_RENEW`
  - `tx1`: LVM call to the lease contract
  `core/state_transition.go` checks lease callability against lease metadata. If the metadata changes in `tx0`, the LVM call outcome can differ from the stale parallel snapshot.

  Example 3:
  - `tx0`: task system action (`TASK_SCHEDULE` / `TASK_CANCEL`)
  - `tx1`: LVM builtin call such as `tos.schedule`, `tos.canceltask`, or `tos.taskinfo`
  These read / write `TaskSchedulerAddress`, but the scheduler does not model that dependency.
- Can cause consensus divergence:
  Yes, against the intended serial semantics and against any corrected / serial implementation.
- Can cause fund loss or privacy failure:
  Indirectly yes, because stake / deposit / lease balances and native registries can be settled incorrectly.
- Fix recommendation:
  Immediate mitigation: disable parallel execution for all system actions.

  Proper fix: make `AnalyzeTx(...)` action-aware and model exact read / write sets per action family, including registry balances, per-account slots, task scheduler storage, lease metadata, and any LVM builtin state they interact with.

## Finding 2

- Severity: Critical
- Title: Slash-indicator txs omit validator-registry dependency
- Why it matters:
  Slash-evidence execution reads validator status from the validator registry, but the scheduler only serializes slash txs against other slash txs.
- Exact code location:
  - `core/parallel/analyze.go`
  - `consensus/slashindicator/slash_indicator.go`
  - `validator/state.go`
  - `validator/handler.go`
- Root cause:
  `AnalyzeTx(...)` only marks `CheckpointSlashIndicatorAddress` as touched for evidence submissions.
- Divergence scenario:
  - `tx0`: validator withdraw / maintenance status change
  - `tx1`: slash evidence submission against the same validator

  Serial execution can reject the evidence after the validator becomes inactive.
  Parallel execution can accept the evidence from the stale parent snapshot.
- Can cause consensus divergence:
  Yes.
- Can cause fund loss or privacy failure:
  It can corrupt slash / validator-state semantics; direct privacy impact no.
- Fix recommendation:
  Add `ValidatorRegistryAddress` and, ideally, the exact validator-status slot to the slash tx access set. Safe fallback: serialize slash-indicator txs with validator-related system actions.

## Finding 3

- Severity: Critical
- Title: Sponsored transactions omit sponsor state from parallel dependency analysis
- Why it matters:
  Sponsored execution reads and writes sponsor balance and sponsor nonce, but the scheduler only models sender-side writes.
- Exact code location:
  - `core/parallel/analyze.go`
  - `core/state_transition.go`
  - `core/sponsor_state.go`
  - `core/parallel/executor.go`
- Root cause:
  The sponsor address and `SponsorRegistryAddress` nonce slot are not included in access-set analysis. The special coinbase fallback only checks `msg.From() == coinbase`, not `msg.Sponsor() == coinbase`.
- Divergence scenario:
  - Sponsor `S` has current sponsor nonce `0`
  - `tx0`: sender `A`, sponsor `S`, sponsor nonce `0`
  - `tx1`: sender `B`, sponsor `S`, sponsor nonce `1`

  Serial execution in block order is valid.
  Parallel execution runs both against sponsor nonce `0`; `tx1` fails `preCheck`, so a block valid under serial semantics is rejected.
- Can cause consensus divergence:
  Yes.
- Can cause fund loss or privacy failure:
  Fund-loss risk is indirect; primary impact is valid block rejection / sponsorship semantics breakage.
- Fix recommendation:
  Add sponsor address and sponsor-nonce storage dependency to `AnalyzeTx(...)`, and extend the coinbase fallback to sponsored gas payers.

# 4. Security Findings

## Finding 4

- Severity: Critical
- Title: Privacy UNO-to-Wei conversion overflows and can under-collateralize shield / unshield
- Why it matters:
  `UNOFeeToWei(...)` multiplies by `UNOUnit` using `uint64`. With `UNOUnit = 1e16`, overflow happens once the UNO-base-unit amount exceeds about `1844`, i.e. about `18.44 TOS`.
- Exact code location:
  - `params/tos_params.go`
  - `core/priv/fee.go`
  - `core/privacy_tx_prepare.go`
  - `docs/PRIVACY-ROADMAP.md`
- Root cause:
  Both the conversion and the `UnoAmount + UnoFee` addition are done in `uint64`.
- Attack / failure scenario:
  A shield tx with a realistic amount, e.g. `100 TOS`, overflows the public debit calculation.
  The public balance deduction wraps low, while the proof and ciphertext still represent the full intended private amount.

  Result: under-collateralized private minting or incorrect unshield settlement.
- Can cause consensus divergence:
  Not by itself; it is deterministic.
- Can cause fund loss or privacy failure:
  Yes, directly.
- Fix recommendation:
  Replace all public-side UNO/Wei arithmetic with `big.Int`, reject overflow before conversion, and add boundary tests around the wrap point.

## Finding 5

- Severity: Medium
- Title: Txpool cannot pipeline valid sponsored tx sequences across different senders
- Why it matters:
  The txpool validates sponsor nonce only against current chain state and does not maintain virtual sponsor nonces for pending txs.
- Exact code location:
  - `core/tx_pool.go`
  - `core/tx_noncer.go`
- Root cause:
  Pending nonce tracking is keyed by sender address, not sponsor address.
- Attack / failure scenario:
  Sponsor `S` authorizes:
  - Alice with sponsor nonce `0`
  - Bob with sponsor nonce `1`

  Alice's tx can enter the pool.
  Bob's tx is rejected until Alice's tx is mined, even though the sequence is valid as a block.
- Can cause consensus divergence:
  No direct consensus split.
- Can cause fund loss or privacy failure:
  No direct fund-loss bug, but it is a sponsorship liveness / censorship problem.
- Fix recommendation:
  Add a virtual sponsor-nonce tracker to the pool and integrate it into validation, promotion, and selection logic.

## Finding 6

- Severity: Medium
- Title: Sponsor-expiry checks use inconsistent time units between txpool and consensus
- Why it matters:
  The txpool uses wall-clock seconds, while consensus execution compares against block timestamps in milliseconds.
- Exact code location:
  - `core/tx_pool.go`
  - `core/state_transition.go`
  - `core/vm_context.go`
  - `consensus/dpos/dpos.go`
- Root cause:
  One code path uses `time.Now().Unix()`, the other uses `header.Time` / `UnixMilli()` semantics.
- Attack / failure scenario:
  The pool can accept already-expired sponsored txs or reject still-valid ones. Miners can waste work or build bad candidate blocks around those txs.
- Can cause consensus divergence:
  Not directly; execution itself is deterministic.
- Can cause fund loss or privacy failure:
  No direct fund-loss issue.
- Fix recommendation:
  Standardize sponsor-expiry units across txpool, signing, and execution, and add explicit unit tests.

# 5. Areas Requiring Manual Verification

- `tos/state_accessor.go` does not replay block-start scheduled tasks inside `stateAtTransaction(...)`, so trace / replay state at a tx index can disagree with true consensus state.
- Privacy batch verification has separate `cgo` and `nocgo` backends in `crypto/ed25519/`. I did not find differential tests proving identical acceptance behavior across build variants.
- The `nocgo` batch verifier uses random batch weights. That does not immediately break determinism because execution falls back to single-proof verification on batch failure, but backend parity should still be verified explicitly.
- Privacy transcript context truncates `chainID` to `uint64`. That is probably acceptable on the current chain, but it is not future-proof.
- Equal-fee tx ordering uses local first-seen time. That is miner-local nondeterminism, not a consensus split by itself, but it does mean different miners can construct different valid blocks from the same mempool.
- DPoS future-block admission depends on local wall clock. That is a liveness sensitivity and should be operationally monitored with clock discipline.

# 6. Final Risk Assessment

- Can this code safely run as a blockchain client?
  No, not in its current form.

- Main fork risks:
  - system-action dependency under-modeling in the parallel scheduler
  - slash-indicator dependency under-modeling
  - sponsored-tx dependency under-modeling
  - possible heterogeneous-build privacy-verifier drift if `cgo` and `nocgo` backends are not proven equivalent

- Main security risks:
  - privacy shield / unshield public-settlement overflow
  - sponsor-feature liveness failure in txpool
  - sponsor-expiry unit mismatch

- Must-fix items before production:
  - disable or heavily serialize parallel execution for system actions, slash txs, and sponsored txs until exact access-set modeling exists
  - fix privacy UNO-to-Wei arithmetic with overflow-safe `big.Int` accounting
  - add txpool support for virtual sponsor nonces
  - unify sponsor-expiry units
  - add explicit parity tests for serial vs parallel execution on all custom native actions
  - add differential tests for privacy proof verification across build backends
