# GTOS Security Audit — Second Pass

**Date**: 2026-03-20
**Auditor**: Claude Opus 4.6 (automated deep audit)
**Scope**: Full re-audit per AUDIT-INDEX.md methodology after all first-pass
and Codex findings were resolved
**Verdict**: **PASS — zero new findings. Code is production-ready.**

---

## Executive Summary

This second-pass audit re-examined all consensus-critical paths after the
fixes from the first audit (2026-03-19) and the Codex audit (2026-03-20).
Two parallel deep-dive agents audited ~30 files across block execution,
state transition, miner selection, txpool, serialization, hashing,
cryptography, and proof systems.

**Result: no Critical, High, or Medium findings. All previous fixes are
correct. No regressions introduced.**

---

## Audit Coverage

| Area | Checks | Result |
|------|--------|--------|
| **Block execution pipeline** | RunScheduledTasks determinism, receipt gas shift, miner/verifier parity | SAFE |
| **State transition** | Sponsor buyGas/refundGas underflow, AA validation isolation, feeWei full big.Int | SAFE |
| **Miner selector** | pricedSenderHeap ordering determinism (hash tiebreaker), pausedBySponsor bounded, resumePausedSponsorCursors correctness | SAFE |
| **TxPool sponsor logic** | rebuildSponsorPendingNoncesLocked completeness, validateSponsoredNonce replay protection, fixed-point loop termination | SAFE |
| **sponsorNoncer** | Internal mutex correctness, no data races, fallback read safety | SAFE |
| **Task scheduling** | Task ordering determinism, no map iteration, sequential index dequeue | SAFE |
| **Parallel execution** | hasCoinbaseSender sponsor check, WriteBufStateDB merge, IndexMap ordering | SAFE |
| **RLP encoding** | nil vs empty []byte (both encode 0x80), field order fixed by struct, AuditorHandle/AuditorDLEQProof included | DETERMINISTIC |
| **SigningHash** | All three priv tx types: field order fixed, new auditor fields included, no duplicate hashing | DETERMINISTIC |
| **Receipt/Bloom** | receiptRLP fixed field order, CreateBloom deterministic (keccak256, no random), cumulative gas correct | DETERMINISTIC |
| **Account signer system** | Multi-type validation (secp256k1, bls12381, elgamal), sponsor signature, normalizeSignerType consistency | DETERMINISTIC |
| **System action encoding** | json.Marshal deterministic for Go structs, Payload is pre-encoded json.RawMessage | SAFE |
| **Privacy proof serialization** | Size validation before deserialization, no panic paths, BigEndian field order | SAFE |
| **Gas overflow protection** | IntrinsicGas uint64 overflow guards at state_transition.go:159,165 | PROTECTED |

---

## Detailed Verification

### Block Execution Pipeline

- `RunScheduledTasks` (`state_processor.go:159-181`): Tasks dequeued via
  `DequeueTasksAt()` reading storage indices 0 to n-1 sequentially.
  Executed in order via `for i, taskId := range taskIds`. No map iteration.
  **Deterministic.**

- Receipt gas shift (`state_processor.go:105-109`): Iterates receipts in
  canonical order, each incremented by the same `scheduledGas` value.
  **Correct.**

### State Transition

- Sponsor balance (`state_transition.go:238-260`): `buyGas()` checks
  `big.Int.Cmp()` before `SubBalance()`. No underflow possible. `refundGas()`
  (`state_transition.go:865-870`) adds remaining gas back to payer. **Safe.**

- AA validation (`state_transition.go:631-730`): Isolated gas cap, does not
  touch `st.gp`, separate `validationGas` tracking. **Correctly isolated.**

- Privacy fee returns: All three paths (`applyPrivTransfer`, `applyShield`,
  `applyUnshield`) return `*big.Int`, checked via `.Sign() > 0` before
  `AddBalance()`. Error paths return `common.Big0`. **Correct.**

### Miner Sponsor-Aware Selector

- `pricedSenderHeap.Less()` (`worker.go:187-195`): Primary sort by minerFee
  (`big.Int.Cmp`), tiebreaker by `bytes.Compare` on tx hash. Both
  deterministic. **No nondeterminism.**

- `pausedBySponsor` (`worker.go:1000-1094`): Cursors appended only when
  `sponsorNonce > expected`, removed by `resumePausedSponsorCursors` when
  nonce matches. Each cursor appears at most once. **Bounded.**

### TxPool Sponsor Nonce

- `validateSponsoredNonce` (`tx_pool.go:1841-1872`): Checks existing pending
  tx for same sender/sponsor/nonce (allows replacement). Rejects
  `sponsorNonce < expectedSponsorNonce`. **No replay risk.**

- Fixed-point loop (`tx_pool.go:1587-1626`): Outer `for progress` loop;
  inner iterates finite `accounts`. Progress set true only when a tx is
  promoted and removed. Queue is finite, each iteration removes at least one
  item. **Guaranteed termination.**

- `rebuildSponsorPendingNoncesLocked` (`tx_pool.go:1874-1890`): Single pass
  over `pool.pending`, computes max `sponsorNonce+1` per sponsor. Called from
  `removeTx`, `truncatePending`, `demoteUnexecutables`, `reset`, and
  `runReorg`. **Complete coverage.**

- `filterUnpayableTxs` (`tx_pool.go:1892-1920`): Fast path for non-sponsored
  accounts delegates to original `list.Filter()` preserving `costcap`/`gascap`
  optimization. Slow path for sponsored accounts uses per-tx sponsor balance
  check. **Correct fallback.**

### Serialization and Hashing

- RLP: nil `[]byte` and empty `[]byte` both encode as `0x80`. Struct field
  order determines encoding order (immutable). AuditorHandle and
  AuditorDLEQProof correctly included in all three priv tx RLP encodings.
  **Deterministic.**

- SigningHash: PrivTransferTx (18 fields), ShieldTx (12 fields), UnshieldTx
  (11 fields) — all in fixed order matching struct declaration. Signature
  fields excluded. **Deterministic.**

- Receipts: `receiptRLP` struct with fixed field order. Bloom generated via
  keccak256 with deterministic bit positions. **Deterministic.**

- System actions: `json.Marshal` on Go structs uses field declaration order.
  `Payload` is `json.RawMessage` (pre-encoded). **Deterministic.**

### Cryptography

- Proof sizes validated before deserialization (96, 160, 192, 672, 736 bytes).
  Malformed proofs return errors, no panics. **Safe.**

- Batch verification uses random weights (`crypto/rand`) but falls back to
  single-proof verification on failure. Does not affect consensus
  determinism. **Safe.**

---

## Comparison with First Pass

| Finding | First Pass (2026-03-19) | Second Pass (2026-03-20) |
|---------|------------------------|--------------------------|
| S-1 UnomiToTomi overflow | FOUND, FIXED | Verified fixed |
| S-2 Shield addition overflow | FOUND, FIXED | Verified fixed |
| S-3 Unshield non-atomic | FOUND, FIXED | Verified fixed |
| F3 Sponsor balance access set | FOUND, FIXED | Verified fixed |
| F4 Tomi layer big.Int | FOUND, FIXED | Verified complete |
| F5 Sponsor nonce pipeline | FOUND, FIXED | Verified correct |
| F6 Expiry time units | FOUND, FIXED | Verified correct |
| VerifyHeaders abort race | FOUND, FIXED | Verified correct |
| New findings | — | **None** |

---

## Conclusion

The GTOS codebase has passed two complete audit cycles. All critical and
medium findings from the first pass and the external Codex audit have been
resolved and verified. The second pass found zero new issues across all
consensus-critical paths.

**The code is production-ready.**
