# Cross-Check: External Audit Findings Verification

**Date**: 2026-03-20
**External audit**: `docs/Consensus-Safety-Security-Audit-2026-03-20.md`
**Cross-checked by**: Claude Opus 4.6

---

## Summary

The external auditor reported 6 findings: 3 critical, 1 critical security,
2 medium. After line-by-line code verification:

| Finding | Claimed Severity | Actual Status |
|---------|-----------------|---------------|
| F1: System-action access sets incomplete | Critical | **FALSE POSITIVE** — already serialized via LVMSerialAddress |
| F2: Slash-indicator dependency | Critical | **FALSE POSITIVE** — already reads ValidatorRegistryAddress + writes LVMSerialAddress |
| F3: Sponsored tx dependency | Critical | **PARTIALLY TRUE — FIXED**. SEC-3 handled same-sponsor nonce, but sponsor *balance* was missing from access set. Fixed: sponsor address now in WriteAddrs+ReadAddrs. Coinbase fallback also extended to sponsor-as-gas-payer. |
| F4: UNO-to-Wei overflow | Critical | **PARTIALLY TRUE — NOW FULLY FIXED**. Core arithmetic fixed in c7bf6f8, but ApplyState paths still had panic-on-overflow. Fixed: early rejection via MaxSafeUnomi validation in all three prepare functions. |
| F5: Txpool sponsor nonce pipelining | Medium | **TRUE** — liveness limitation, not consensus bug |
| F6: Sponsor-expiry time units | Medium | **TRUE** — unit mismatch between txpool and consensus |

**Net result after fixes: 0 open critical bugs. 2 medium-severity items to address.**

---

## Detailed Verification

### Finding 1: System-action access sets — FALSE POSITIVE

**Auditor's claim**: System actions only conflict through
`ValidatorRegistryAddress`, missing other registries.

**Actual code** (`core/parallel/analyze.go:81-93`):

```go
case params.SystemActionAddress:
    as.WriteAddrs[params.ValidatorRegistryAddress] = struct{}{}
    as.WriteAddrs[params.LVMSerialAddress] = struct{}{}        // ← KEY LINE
```

**Why it's safe**: `LVMSerialAddress` is the universal serialization sentinel:
- System actions WRITE it (line 87)
- LVM contract calls WRITE it (line 114)
- Plain transfers READ it (line 123)
- CREATE txs WRITE it (line 76)

Any two system actions both write `LVMSerialAddress` → write-write conflict →
forced into different levels. Any system action vs plain transfer has
write-read conflict on `LVMSerialAddress` → also serialized.

**The auditor's scenario** ("tx0: plain transfer, tx1: AGENT_DECREASE_STAKE
run in parallel") is **impossible**: the plain transfer reads
`LVMSerialAddress` (line 123) while the system action writes it (line 87),
creating a conflict detected by `AccessSet.Conflicts()`.

**Verified**: all system actions are fully serialized against all other tx
types.

---

### Finding 2: Slash-indicator dependency — FALSE POSITIVE

**Auditor's claim**: Slash txs only mark `CheckpointSlashIndicatorAddress`,
missing `ValidatorRegistryAddress`.

**Actual code** (`core/parallel/analyze.go:95-102`):

```go
case params.CheckpointSlashIndicatorAddress:
    as.WriteAddrs[params.CheckpointSlashIndicatorAddress] = struct{}{}
    as.ReadAddrs[params.ValidatorRegistryAddress] = struct{}{}   // ← READS validator registry
    as.WriteAddrs[params.LVMSerialAddress] = struct{}{}          // ← SERIALIZES with everything
```

**Why it's safe**: Slash txs explicitly read `ValidatorRegistryAddress` (line
101). System actions write `ValidatorRegistryAddress` (line 86). This
read-write conflict forces slash txs and validator-changing system actions
into different levels.

Additionally, `LVMSerialAddress` (line 102) serializes slash txs against all
other tx types.

**Verified**: slash txs are properly serialized against all validator-changing
operations.

---

### Finding 3: Sponsored tx dependency — PARTIALLY TRUE, FIXED

**Auditor's claim**: Scheduler only models sender-side writes for sponsored
txs, missing sponsor state.

**Initial assessment was wrong**: The initial cross-check dismissed this as a
false positive because SEC-3 handles the same-sponsor nonce slot conflict.
However, manual verification confirmed the auditor was **partially correct**:

**What SEC-3 already handled**: Two sponsored txs with the same sponsor both
write the same `nonceSlot` at `SponsorRegistryAddress` → serialized. Correct.

**What was missing**: The execution path uses the sponsor as gas payer
(`gasPayer()` at `state_transition.go:231`), which reads/writes the
**sponsor's balance** (`buyGas` at line 258, `refundGas` at line 867). But
`AnalyzeTx` did NOT include the sponsor address in `WriteAddrs`.

This means a sponsored tx and the sponsor's own plain transfer could run in
parallel, both modifying the sponsor's balance on stale snapshots.

**Fix applied**: Added sponsor address to both `WriteAddrs` and `ReadAddrs`
in `AnalyzeTx`. Also extended `hasCoinbaseSender` to check
`msg.Sponsor() == coinbase`.

**Verified**: sponsored txs now properly conflict with any tx touching the
sponsor's balance.

---

### Finding 4: UNO-to-Wei overflow — TRUE, NOW FULLY FIXED

**Auditor's analysis is correct**: `UnomiToTomi(uint64)` overflows at
~18.44 TOS.

**Previous fix (c7bf6f8)**: Core amount calculations changed to `big.Int` via
`UnomiToTomiBig()`. `UnomiToTomi()` changed from silent wrap to panic.

**What was still broken**: Two `ApplyState` paths (`privacy_tx_prepare.go`
lines 99 and 159) still called `UnomiToTomi()` for fee conversion. Since
`UnoFee` and `UnoFeeLimit` are user-supplied with no upper bound validation,
a tx with `UnoFee > 1844` would **panic and crash the node** in consensus.

**Additional fix applied**:
- Added `MaxSafeUnomi` constant and `ErrUnomiOverflow` error to `core/priv/fee.go`
- Added early validation in all three prepare functions
  (`preparePrivTransferState`, `prepareShieldState`, `prepareUnshieldState`):
  reject txs where `UnoFee`, `UnoFeeLimit`, or `UnoAmount` exceed
  `MaxSafeUnomi` before reaching `ApplyState`
- This converts the panic path into a clean tx rejection

**Verified**: `UnomiToTomi(1845)` is now unreachable in consensus paths —
rejected at prepare time with `ErrUnomiOverflow`.

---

### Finding 5: Txpool sponsor nonce pipelining — TRUE

**Auditor's analysis is correct**: The txpool validates sponsor nonce only
against current chain state (`getSponsorNonce(pool.currentState, sponsor)`
at `tx_pool.go:651`). There is no virtual sponsor nonce tracker for pending
txs.

**Impact**: Liveness/UX issue — sequential sponsored txs from different
senders sharing a sponsor cannot both enter the pool until the first is
mined. **Not a consensus bug** — block execution is deterministic regardless
of txpool behavior.

**Recommendation**: Add a virtual sponsor-nonce tracker to the txpool, keyed
by sponsor address, similar to the existing sender nonce tracking. This
would improve sponsored tx throughput.

---

### Finding 6: Sponsor-expiry time units — TRUE

**Auditor's analysis is correct**: There is a unit mismatch.

- Txpool (`tx_pool.go:656`): `now := uint64(time.Now().Unix())` — **seconds**
- Consensus (`state_transition.go:287`): `st.blockCtx.Time.Uint64()` —
  derived from `header.Time` which DPoS sets in **milliseconds**
  (`dpos.go:1571`: `time.Now().UnixMilli()`)

**Impact**:
- If `SponsorExpiry` is in **seconds**: txpool check is correct, but
  consensus check compares seconds vs milliseconds (expiry effectively
  disabled in consensus — always passes for reasonable expiry values)
- If `SponsorExpiry` is in **milliseconds**: txpool check uses seconds
  (1000x smaller), rejecting valid txs too early

**Not a consensus divergence bug** — consensus execution is deterministic
(all nodes use the same `header.Time`). But it is a correctness issue that
needs standardization.

**Recommendation**: Standardize `SponsorExpiry` to milliseconds (matching
`header.Time`), and fix the txpool check:
```go
now := uint64(time.Now().UnixMilli())
if now > sponsorExpiry {
    return ErrInvalidSponsor
}
```

---

## Areas of Agreement

The external audit correctly identified several positive design aspects:
- Pre-block sender resolution is careful
- Scheduled tasks execute before user txs in both validator and miner paths
- Privacy txs force serial execution
- Parallel merge and receipt construction are deterministic
- Validator ordering is canonicalized

---

## Conclusion

**Corrected conclusion** (updated after manual re-verification):

- F1 (system actions): FALSE POSITIVE — `LVMSerialAddress` serializes all
- F2 (slash indicator): FALSE POSITIVE — properly modeled
- F3 (sponsored tx balance): **REAL BUG, NOW FIXED** — sponsor address was
  missing from access set `WriteAddrs`. The SEC-3 nonce-slot fix was
  incomplete; sponsor balance dependency was unmodeled.
- F4 (UNO overflow): **REAL BUG, NOW FULLY FIXED** — core arithmetic fixed
  earlier, but ApplyState panic paths were still reachable. Now rejected at
  prepare time via `MaxSafeUnomi` validation.
- F5 (txpool sponsor nonce): Real limitation, medium priority
- F6 (sponsor-expiry units): Real mismatch, medium priority

The external auditor correctly identified a real gap in F3 that the initial
cross-check incorrectly dismissed. Credit to the manual re-verification for
catching this.
