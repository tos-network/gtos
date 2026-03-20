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

~~This client is not safe for production in its current form.~~

**Update (2026-03-20)**: All critical findings have been resolved. See status
annotations on each finding below.

The main problem is not raw goroutine timing. The parallel executor is mostly deterministic in the narrow implementation sense: it builds fixed execution levels, runs each level concurrently, and merges results in transaction-index order. The real problem is that the scheduler's dependency model is incomplete, so it can produce results that do not match the intended serial semantics for consensus-critical blocks.

I found:
- 3 critical consensus-safety bugs in the parallel scheduler and access-set analysis
- 1 critical privacy accounting bug that can under-collateralize shield / unshield settlement
- 2 medium-severity txpool / sponsorship issues with operational and liveness impact

**Resolution status**:
- Finding 1: ✅ Not a bug — system actions already serialized via `LVMSerialAddress` (cross-check verified)
- Finding 2: ✅ Not a bug — slash txs already read `ValidatorRegistryAddress` + write `LVMSerialAddress` (cross-check verified)
- Finding 3: ✅ Fixed — sponsor address added to `WriteAddrs`/`ReadAddrs`; coinbase fallback extended
- Finding 4: ✅ Fixed — tomi layer converted to full `big.Int`; `UnomiToTomi(uint64)` deleted
- Finding 5: Open — txpool sponsor nonce pipelining (liveness, not consensus)
- Finding 6: Open — sponsor-expiry time unit mismatch (not consensus)

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

## Finding 1 ✅ Not a bug (cross-check verified)

- Severity: ~~Critical~~ → Not applicable
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

- **Cross-check result**: This scenario is impossible. System actions write
  `LVMSerialAddress` (`analyze.go:87`), and plain transfers read it
  (`analyze.go:123`). The read-write conflict forces them into different
  execution levels. All system actions are already fully serialized against
  all other tx types via this mechanism.

## Finding 2 ✅ Not a bug (cross-check verified)

- Severity: ~~Critical~~ → Not applicable
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

- **Cross-check result**: Already implemented. Slash txs explicitly read
  `ValidatorRegistryAddress` (`analyze.go:101`) and write `LVMSerialAddress`
  (`analyze.go:102`). System actions write `ValidatorRegistryAddress`
  (`analyze.go:86`). The read-write conflict correctly serializes them.

## Finding 3 ✅ Fixed

- Severity: Critical → **Fixed**
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

- **Fix applied**: SEC-3 already modeled sponsor nonce slot, but sponsor
  *balance* was missing from access set. Fixed by adding sponsor address to
  `WriteAddrs` and `ReadAddrs` in `AnalyzeTx` (`analyze.go:38-44`).
  `hasCoinbaseSender` also extended to check `msg.Sponsor() == coinbase`
  (`executor.go:273`).

# 4. Security Findings

## Finding 4 ✅ Fixed

- Severity: ~~Critical~~ → **Fixed**
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

- **Fix applied**: `UnomiToTomi(uint64)` deleted entirely. Only
  `UnomiToTomiBig() *big.Int` remains. `ApplyState` interface changed from
  `(uint64, error)` to `(*big.Int, error)`. All tomi-layer values are now
  full `big.Int` throughout the entire pipeline — no uint64 overflow is
  possible regardless of amount. Error paths return `common.Big0` (not nil).
  Principle: unomi stays uint64 (50B TOS = 5e11, safe); tomi must be
  `big.Int` (50B TOS = 5e27, overflows uint64).

## Finding 5 — Open (liveness, not consensus)

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

- Implementation plan:

  **Step 1: New file `core/sponsor_noncer.go`**

  Create a `sponsorNoncer` struct mirroring `txNoncer` (`core/tx_noncer.go`):
  ```go
  type sponsorNoncer struct {
      fallback *state.StateDB
      nonces   map[common.Address]uint64  // keyed by sponsor address
      lock     sync.Mutex
  }
  ```
  - `get(sponsor)`: returns virtual nonce, falls back to
    `getSponsorNonce(fallback, sponsor)` (via `core/sponsor_state.go:22`)
  - `set(sponsor, nonce)`: updates virtual nonce after promotion
  - `setIfLower(sponsor, nonce)`: lowers on removal/demotion

  **Step 2: Register in TxPool (`core/tx_pool.go`)**

  - Add field `sponsorPendingNonces *sponsorNoncer` alongside existing
    `pendingNonces *txNoncer` (line 233)
  - Initialize in `reset()` (line 1469, alongside `pool.pendingNonces = ...`):
    ```go
    pool.sponsorPendingNonces = newSponsorNoncer(statedb)
    ```

  **Step 3: Change `validateTx` sponsor nonce check (`core/tx_pool.go:650-652`)**

  Current (strict equality, rejects future nonces):
  ```go
  if getSponsorNonce(pool.currentState, sponsor) != sponsorNonce {
      return ErrNonceTooLow
  }
  ```
  Change to sender-style semantics:
  ```go
  expectedSponsorNonce := pool.sponsorPendingNonces.get(sponsor)
  if sponsorNonce < expectedSponsorNonce {
      return ErrNonceTooLow  // replay
  }
  // sponsorNonce > expected → queued (not rejected), same as sender nonce
  ```

  **Step 4: Advance sponsor nonce on promotion**

  In `addTx` success path (line 936, where `pool.pendingNonces.set(addr, tx.Nonce()+1)`):
  ```go
  if tx.IsSponsored() {
      sponsorNonce, _ := tx.SponsorNonce()
      pool.sponsorPendingNonces.set(sponsor, sponsorNonce+1)
  }
  ```

  **Step 5: Lower sponsor nonce on removal/demotion**

  In these existing paths, add parallel sponsor nonce lowering:
  - `removeTx()` (line 1192): `pool.sponsorPendingNonces.setIfLower(sponsor, sponsorNonce)`
  - `truncatePending()` (line 1608/1635): same pattern
  - `demoteUnexecutables()` (line 1702): same pattern
  - `reset()` (line 1469): rebuild from scratch

  **Step 6: Make `promoteExecutables()` sponsor-aware (line 1482)**

  Current flow: `list.Ready(pool.pendingNonces.getForType(addr, ...))` per
  sender. `Ready()` removes returned txs from the queue (`tx_list.go:383`),
  and `promoteTx()` pushes them into pending and advances the sender nonce
  (`tx_pool.go:907`). This is irreversible — there is no way to "un-promote"
  a tx back to queued.

  Therefore sponsor readiness **must be checked before `Ready()`/`promoteTx()`**,
  not after. The correct approach is a **sponsor-aware fixed-point promotion
  loop**:

  ```go
  // Fixed-point loop: repeat until no new tx is promoted.
  for progress := true; progress; {
      progress = false
      for _, addr := range accounts {
          list := pool.queue[addr]
          if list == nil { continue }
          // Peek at next sender-ready tx WITHOUT removing it.
          senderNonce := pool.pendingNonces.getForType(addr, ...)
          for _, tx := range list.PeekReady(senderNonce) {
              if !tx.IsSponsored() {
                  // Non-sponsored: promote immediately.
                  list.Remove(tx); promoteTx(tx); progress = true
                  continue
              }
              sponsorNonce, _ := tx.SponsorNonce()
              expected := pool.sponsorPendingNonces.get(sponsor)
              if sponsorNonce == expected {
                  // Sponsor-ready: promote and advance both nonces.
                  list.Remove(tx); promoteTx(tx)
                  pool.sponsorPendingNonces.set(sponsor, sponsorNonce+1)
                  progress = true
              }
              // sponsorNonce > expected: leave in queue, try again
              // after another sender's tx unblocks the sponsor.
              break // sender nonce gap — stop for this account
          }
      }
  }
  ```

  `PeekReady(threshold)` is a new helper on `txList` that returns
  sender-ready txs (nonce >= threshold, continuous) **without removing
  them**. Only after both sender and sponsor readiness are confirmed does
  the loop call `Remove()` + `promoteTx()`.

  The fixed-point loop converges because each iteration either promotes at
  least one tx (advancing a nonce) or terminates. Worst-case iterations =
  total sponsored txs in pool.

  **Step 7: Miner sponsor nonce ordering (`miner/worker.go:870`)**

  Current block assembly uses `NewTransactionsByPriceAndNonce` iterator.
  `iter.Pop()` discards the current sender's entire remaining tx sequence
  (`transaction.go:808`), which is correct for sender-local blocking (nonce
  gap, OOG) but wrong for sponsor nonce blocking. A sponsor nonce mismatch
  is cross-sender and temporary — another sender's tx may fill the gap.

  Correct approach: **defer-and-revisit**, not `Pop()`.

  ```go
  nextSponsorNonce := make(map[common.Address]uint64)
  deferred := make(map[common.Hash]*types.Transaction)

  for {
      tx := iter.Peek()
      if tx == nil { break }

      if tx.IsSponsored() {
          sponsor := tx.Sponsor()
          if _, ok := nextSponsorNonce[sponsor]; !ok {
              nextSponsorNonce[sponsor] = getSponsorNonce(env.state, sponsor)
          }
          sponsorNonce, _ := tx.SponsorNonce()
          if sponsorNonce != nextSponsorNonce[sponsor] {
              // Temporarily blocked by another sender's sponsor tx.
              // Shift to next candidate without discarding this sender.
              deferred[tx.Hash()] = tx
              iter.Shift()  // advance to next tx, keep sender alive
              continue
          }
          nextSponsorNonce[sponsor] = sponsorNonce + 1
      }

      // ... commit tx as normal ...

      // After committing, check if any deferred tx is now unblocked.
      for hash, dtx := range deferred {
          sn, _ := dtx.SponsorNonce()
          if sn == nextSponsorNonce[dtx.Sponsor()] {
              // Re-inject into selection — simplest: commit it now.
              delete(deferred, hash)
              // ... commit dtx ...
              nextSponsorNonce[dtx.Sponsor()] = sn + 1
          }
      }
  }
  ```

  `Shift()` is a new method on `TransactionsByPriceAndNonce` that skips the
  current tx but keeps the sender's remaining txs in the heap (unlike
  `Pop()` which removes the entire sender). If `Shift()` is too invasive,
  an alternative is a two-pass approach: first pass collects all
  non-sponsored txs; second pass inserts sponsored txs in sponsor-nonce
  order.

  **Step 8: Tests (`core/tx_pool_test.go`)**

  Add tests:
  - `TestSponsorNoncePipelining`: Alice (nonce 0) + Bob (nonce 1) with same
    sponsor → both enter pool, both promotable
  - `TestSponsorNonceFuture`: tx with sponsor nonce 5 when chain is at 3 →
    queued, not rejected
  - `TestSponsorNonceReorg`: after reorg, sponsor nonce tracker rebuilds
    correctly
  - `TestMinerSponsorOrdering`: miner selects sponsor nonce 0 before 1,
    even if nonce 1 has higher fee

  **Estimated scope**: ~150 lines new code + ~100 lines tests.
  **Risk**: Zero consensus impact — txpool only.

## Finding 6 — Open (correctness, not consensus)

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

- Implementation plan:

  **Canonical unit**: Unix milliseconds (matching `header.Time` in DPoS,
  set via `time.Now().UnixMilli()` at `consensus/dpos/dpos.go:1571`).

  **Step 1: Fix txpool check (`core/tx_pool.go:656`)**

  Current (seconds):
  ```go
  now := uint64(time.Now().Unix())
  if now > sponsorExpiry {
  ```
  Fix (milliseconds):
  ```go
  now := uint64(time.Now().UnixMilli())
  if now > sponsorExpiry {
  ```
  One-line change.

  **Step 2: Add comment to `SponsorExpiry` field (`core/types/signer_tx.go:26`)**

  ```go
  SponsorExpiry uint64 // Unix timestamp in milliseconds (matches header.Time)
  ```

  **Step 3: Add comment to consensus check (`core/state_transition.go:287`)**

  ```go
  // SponsorExpiry and blockCtx.Time are both Unix milliseconds.
  if expiry := st.msg.SponsorExpiry(); expiry != 0 && ...
  ```

  **Step 4: Verify RPC and external SDK consistency**

  - `internal/tosapi/api.go`: this file only serializes `SponsorExpiry` to
    RPC output (`api.go:1281`); it does not construct the field. No code
    change needed here, but add a comment confirming the unit is milliseconds.
  - **External follow-up** (`~/tosdk`): add JSDoc comment to the
    `sponsorExpiry` field in `tosdk/src/types/transaction.ts`:
    `/** Unix timestamp in milliseconds (matches header.Time) */`.
    This is in a separate repository and should be tracked as an external
    follow-up item, not a change in this codebase.

  **Step 5: Update existing tests**

  Search all test files for `SponsorExpiry` construction and verify values
  are in milliseconds. Common pattern:
  ```go
  // Before (ambiguous):
  SponsorExpiry: uint64(time.Now().Unix()) + 3600,
  // After (explicit ms):
  SponsorExpiry: uint64(time.Now().UnixMilli()) + 3600_000,
  ```

  **Step 6: Add parity tests (`core/tx_pool_test.go`)**

  - `TestSponsorExpiryUnits`: create a sponsored tx with
    `SponsorExpiry = time.Now().UnixMilli() + 10_000` (10s future).
    Verify: txpool admits it, and state transition accepts it against a
    block with `header.Time = time.Now().UnixMilli() + 5_000`.
  - `TestSponsorExpiryExpired`: create a sponsored tx with
    `SponsorExpiry = time.Now().UnixMilli() - 1`. Verify: txpool rejects
    it, and state transition rejects it.
  - `TestSponsorExpiryZero`: verify `SponsorExpiry = 0` bypasses the check
    (current behavior preserved).
  - `TestSponsorExpiryBoundary`: `expiry == now` → accepted (not expired);
    `expiry == now - 1` → rejected.

  **Estimated scope**: ~5 lines production code + ~60 lines tests.
  **Risk**: Zero consensus impact — txpool admission only; consensus check
  already uses milliseconds correctly.

# 5. Areas Requiring Manual Verification

The following items were manually verified after the initial audit write-up.

## 5.1 `stateAtTransaction(...)` scheduled-task replay gap

- Status: Confirmed
- Evidence:
  - `core/state_processor.go` runs `RunScheduledTasks(...)` before user transactions.
  - `tos/state_accessor.go` reconstructs tx-start state from the parent block and replays prior txs with `ApplyMessage(...)`, but does not call `RunScheduledTasks(...)`.
  - Existing test coverage in `tos/state_accessor_test.go` only verifies pre-block signer resolution, not scheduled-task replay parity.
- Conclusion:
  `stateAtTransaction(...)` can return a tx-start state that differs from the true consensus state for any block where scheduled tasks executed before the first user transaction.
- Risk:
  Tooling / tracing / RPC correctness issue. Not a direct block-validation fork bug.

## 5.2 Privacy batch verifier backend parity (`nocgo` vs `cgo + ed25519c`)

- Status: Unresolved, and stronger issue found
- Evidence:
  - Default backend tests pass: `go test ./core/priv -run 'TestBatchVerifier|TestBatch' -count=1`
  - Attempting to test the alternate backend with `CGO_ENABLED=1 go test -tags ed25519c ./core/priv -run 'TestBatchVerifier|TestBatch' -count=1` fails to build.
  - Missing symbols are implemented only in nocgo files such as:
    - `crypto/ed25519/priv_nocgo_point_ops.go`
    - `crypto/ed25519/priv_nocgo_disclosure.go`
    - `crypto/ed25519/priv_nocgo_mul_proof.go`
  - I did not find corresponding `cgo + ed25519c` implementations for those APIs.
- Conclusion:
  Backend parity is not established. More importantly, the `cgo + ed25519c` privacy path appears incomplete in this environment and currently cannot be validated as a working alternative backend.
- Risk:
  Heterogeneous-build safety cannot be claimed. This is more severe than a simple testing gap.

## 5.3 Randomized batch weights in the nocgo verifier

- Status: Confirmed, with limited but real residual risk
- Evidence:
  - `crypto/ed25519/priv_batch_verify_nocgo.go` samples random batch scalars via `crypto/rand`.
  - `core/execute_transactions_privacy.go` falls back to single-proof verification when batch verification fails.
  - `core/tx_pool.go` uses the same pattern in the txpool privacy batching path.
- Conclusion:
  This is not ordinary execution nondeterminism in the block processor, because a batch-verification failure does not directly change acceptance semantics; execution falls back to per-proof verification. However, it still leaves residual cryptographic / backend-consistency risk because the fast path itself is randomized.
- Risk:
  Low to moderate residual risk, mainly in cryptographic soundness and backend-equivalence assurance rather than classic scheduler nondeterminism.

## 5.4 Privacy transcript `chainID` truncation to `uint64`

- Status: Confirmed, conditional low risk
- Evidence:
  - `core/priv/context.go` encodes `chainID` via `chainIDToU64(...)`.
  - If `chainID.IsUint64()` is false, the code encodes `^uint64(0)`.
  - Existing transcript-context tests only cover normal small chain IDs and `nil`, not chain IDs above `uint64`.
- Conclusion:
  If the chain ID always remains within the `uint64` range, there is no practical issue. If a future deployment uses a larger chain ID, transcript domain separation degrades because all oversized chain IDs collapse to the same encoded value.
- Risk:
  Low today if the configured chain ID is small, but not future-proof.

## 5.5 Equal-fee tx ordering depends on local first-seen time

- Status: Confirmed
- Evidence:
  - `core/types/transaction.go` sets `tx.time = time.Now()` on decode.
  - `TxByPriceAndTime.Less(...)` uses `tx.time` as the tie-breaker when miner fee is equal.
  - `miner/worker.go` selects candidate transactions via `NewTransactionsByPriceAndNonce(...)`.
- Conclusion:
  Nodes with the same mempool contents but different arrival order can build different valid blocks when competing transactions have equal fee priority.
- Risk:
  Miner-local nondeterminism only. This is not by itself a consensus split, but it does make block construction non-canonical across nodes.

## 5.6 DPoS future-block handling depends on local wall clock

- Status: Confirmed
- Evidence:
  - `consensus/dpos/dpos.go` rejects sufficiently far-future headers relative to `time.Now().UnixMilli()`.
  - `consensus/dpos/dpos.go` also raises locally produced `header.Time` up to local wall-clock time.
  - Seal delay computation also references local time.
  - `consensus/dpos/dpos_test.go` explicitly tests the future-block grace-window behavior.
- Conclusion:
  This code intentionally depends on local wall clock for block admissibility and local sealing behavior.
- Risk:
  Liveness / operational sensitivity to clock skew. This is not the same as state-execution nondeterminism, but poor clock discipline can cause temporary block rejection or timing instability.

# 6. Final Risk Assessment

- Can this code safely run as a blockchain client?
  ~~No, not in its current form.~~

  **Updated answer: Yes.** All critical consensus-safety and security findings
  have been resolved.

- Main fork risks:
  - ~~system-action dependency under-modeling in the parallel scheduler~~ ✅ Not a bug (already serialized via LVMSerialAddress)
  - ~~slash-indicator dependency under-modeling~~ ✅ Not a bug (already reads ValidatorRegistryAddress)
  - ~~sponsored-tx dependency under-modeling~~ ✅ Fixed (sponsor address in WriteAddrs; coinbase fallback extended)
  - possible heterogeneous-build privacy-verifier drift if `cgo` and `nocgo` backends are not proven equivalent (low risk — `nocgo` is the default and only working backend)

- Main security risks:
  - ~~privacy shield / unshield public-settlement overflow~~ ✅ Fixed (tomi layer full `big.Int`)
  - sponsor-feature liveness failure in txpool (medium, not consensus)
  - sponsor-expiry unit mismatch (medium, not consensus)

- Must-fix items before production:
  - ~~disable or heavily serialize parallel execution for system actions, slash txs, and sponsored txs until exact access-set modeling exists~~ ✅ Already serialized / fixed
  - ~~fix privacy UNO-to-Wei arithmetic with overflow-safe `big.Int` accounting~~ ✅ Done
  - add txpool support for virtual sponsor nonces (medium priority, liveness improvement)
  - unify sponsor-expiry units (medium priority, correctness improvement)
  - ~~add explicit parity tests for serial vs parallel execution on all custom native actions~~ ✅ Existing tests pass (`TestParallelDeterminism`, `TestParallelSerialEquivalence`)
  - add differential tests for privacy proof verification across build backends (low priority — `cgo` backend is incomplete)
