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
| F3: Sponsored tx dependency | Critical | **FALSE POSITIVE** — sponsor nonce slot modeled since SEC-3 fix |
| F4: UNO-to-Wei overflow | Critical | **TRUE — ALREADY FIXED** (commit c7bf6f8) |
| F5: Txpool sponsor nonce pipelining | Medium | **TRUE** — liveness limitation, not consensus bug |
| F6: Sponsor-expiry time units | Medium | **TRUE** — unit mismatch between txpool and consensus |

**Net result: 0 open critical bugs. 2 medium-severity items to address.**

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

### Finding 3: Sponsored tx dependency — FALSE POSITIVE

**Auditor's claim**: Scheduler only models sender-side writes for sponsored
txs, missing sponsor state.

**Actual code** (`core/parallel/analyze.go:34-44`):

```go
// SEC-3: Sponsored transactions read/write the sponsor's nonce slot at
// SponsorRegistryAddress.
if sponsor := msg.Sponsor(); sponsor != (common.Address{}) {
    nonceSlot := crypto.Keccak256Hash([]byte("tos.sponsor.nonce"), sponsor.Bytes())
    if as.WriteSlots[params.SponsorRegistryAddress] == nil {
        as.WriteSlots[params.SponsorRegistryAddress] = make(map[common.Hash]struct{})
    }
    as.WriteSlots[params.SponsorRegistryAddress][nonceSlot] = struct{}{}
}
```

**Why it's safe**: Two sponsored txs with the same sponsor both write the
same `nonceSlot` at `SponsorRegistryAddress`. This creates a write-write
slot conflict detected by `AccessSet.Conflicts()`, forcing them into
different levels.

The SEC-3 fix was specifically designed for this case and is clearly
documented in the code comments.

**The auditor's scenario** ("tx0 and tx1 with same sponsor run in parallel")
is **impossible** because both write the same sponsor nonce slot.

**Regarding coinbase fallback**: The coinbase fallback handles **balance**
delta merging (coinbase receives fees from all txs). Sponsor nonce
serialization is handled separately via slot-level conflict detection. These
are orthogonal concerns.

**Verified**: sponsored txs are properly serialized via sponsor nonce slot.

---

### Finding 4: UNO-to-Wei overflow — TRUE, ALREADY FIXED

**Auditor's analysis is correct**: `UnomiToTomi(uint64)` overflows at
~18.44 TOS.

**Status**: Fixed in commit c7bf6f8 (2026-03-19):
- `UnomiToTomiBig()` returns `*big.Int` (no overflow)
- `UnomiToTomi()` now panics on overflow instead of silent wrap
- All callers in `privacy_tx_prepare.go` updated to use `big.Int`
- Shield cost computed as separate `big.Int` additions

**Verified**: fix is correct and complete.

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

The external audit's 3 "critical" findings about the parallel scheduler
(F1, F2, F3) are **all false positives**. The auditor appears to have
reviewed an older version of the code or missed the SEC-1/SEC-2/SEC-3
security fixes and the `LVMSerialAddress` serialization mechanism.

The overflow finding (F4) was valid but already fixed. The two medium
findings (F5, F6) are real and should be addressed for production hardening.
