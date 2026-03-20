# Sponsor Nonce Implementation Review

**Date**: 2026-03-20
**Reviewer**: Codex (manual verification) + Claude Opus 4.6 (fix + test)
**Scope**: F5 sponsor nonce pipelining implementation correctness
**Verdict**: Three bugs found and fixed. All tests pass.

---

## Findings

### R-1: Sponsor frontier gap after replacement/removal (Medium) ✅ Fixed

**Problem**: `rebuildSponsorPendingNoncesLocked()` used `max(sponsorNonce)+1`
instead of the contiguous prefix from chain state. After replacing a pending
sponsored tx with a different sponsor nonce slot, or after removing a low
sponsor nonce tx, the frontier jumped past the gap. Valid gap-filler txs
were rejected as `ErrNonceTooLow`.

**Root cause**: `core/tx_pool.go:1874` — rebuild computed max, not contiguous
prefix.

**Fix** (commit 57e1f9f):
- `rebuildSponsorPendingNoncesLocked()` now walks the contiguous prefix
  starting from `getSponsorNonce(chain)`.
- `canDirectlyReplacePendingTx()` rejects replacement with a different
  sponsor nonce slot to prevent gap creation.

**Tests**: `TestSponsorNonceGapAfterReplacement`,
`TestSponsorNonceContiguousPrefixAfterRemoval`.

---

### R-2: Miner cross-pass paused cursor loss (Low) ✅ Fixed

**Problem**: `pausedBySponsor` was scoped inside each `doSelect()` call in
`miner/worker.go:1000`. A local tx paused on sponsor nonce N was lost when
the remote pass started a fresh `pausedBySponsor` map. Remote gap-fillers
could not resume the paused local cursor.

**Root cause**: `miner/worker.go:1000` — `pausedBySponsor` created per-pass,
not shared.

**Fix** (commit 57e1f9f):
- `pausedBySponsor` lifted to `selectTransactions()` scope, shared across
  local and remote passes.
- At the start of each `doSelect()`, previously paused cursors whose sponsor
  nonce is now satisfied are re-injected into the price heap.

**Test**: `TestSelectTransactionsLocalPausedResumedByRemoteGapFiller`.

---

### R-3: Sponsor-gap txs remain in pending after removal (Medium) ✅ Fixed

**Problem**: After removing a low sponsor nonce from pending,
`rebuildSponsorPendingNoncesLocked()` correctly reset the frontier, but
higher sponsor nonce txs remained in pending despite the gap. `Pending()`
exposed unexecutable sponsor-gap txs, violating the "pending = currently
processable" invariant.

**Root cause**: `core/tx_pool.go:1206` — only rebuilt frontier, did not
demote gap txs.

**Fix** (commit fc73a8f):
- New `normalizeSponsoredPendingLocked()` replaces all direct calls to
  `rebuildSponsorPendingNoncesLocked()`.
- After rebuilding the contiguous frontier, scans pending for sponsored txs
  beyond the frontier and demotes them back to queue via `enqueueTx()`.
- Called from: `addValidatedTx` replacement path, `removeTx`, `reset`,
  `truncatePending`, `demoteUnexecutables`.

**Test**: `TestPendingExcludesSponsorGapTransactions`.

---

## Verification

All existing and new tests pass:

```
go test -p 96 ./core/... ./miner/... -count=1 -timeout 300s  # PASS
go test -short -p 96 -timeout 600s ./...                      # 0 failures
```

Specific tests:
- `TestSponsorNonceGapAfterReplacement` — replacement with different sponsor nonce rejected
- `TestSponsorNonceContiguousPrefixAfterRemoval` — frontier resets to gap, gap-filler accepted
- `TestPendingExcludesSponsorGapTransactions` — gap tx demoted from pending to queue
- `TestSelectTransactionsLocalPausedResumedByRemoteGapFiller` — local paused cursor resumed by remote

---

## Consensus Impact

None. All three bugs affect txpool admission/promotion and local miner
selection only. Block execution and validation are unaffected — the miner
always re-checks sponsor nonce against `env.state`, and `state_transition.go`
validates sponsor nonce at consensus time.
