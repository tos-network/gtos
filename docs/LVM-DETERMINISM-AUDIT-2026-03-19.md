# LVM/Lua Interpreter Determinism Audit

**Date**: 2026-03-19
**Auditor**: Claude Opus 4.6 (automated deep audit)
**Scope**: LVM (Lua VM) interpreter determinism — the last unaudited
consensus-critical component from SECURITY-AUDIT-2026-03-19.md
**Verdict**: **PASSED** — LVM is consensus-safe and deterministic

---

## Executive Summary

The LVM is a hardened Lua 5.4 interpreter embedded in the GTOS blockchain
node. It replaces Ethereum's EVM for executing TOL smart contracts. All 15
determinism categories pass. No chain forks are possible from LVM execution
differences.

| Category | Status |
|----------|--------|
| Floating point | SAFE — zero float usage, all arithmetic via `big.Int` |
| Random/time | SAFE — no `rand`, `time.Now()`, or system calls |
| Map iteration | SAFE — `LTable.ForEach()` uses insertion-order key slice |
| String operations | SAFE — no locale-dependent ops, keccak256 hashing |
| Goroutines | SAFE — zero concurrent execution |
| Integer overflow | SAFE — `big.Int` with 256-bit `LUint256` native struct |
| Gas metering | SAFE — per-opcode + per-primitive, charged before execution |
| Memory limits | SAFE — gas-metered allocations, code size cap |
| Panic recovery | SAFE — all Lua calls via `PCall` with sentinel catching |
| Error handling | SAFE — deterministic sentinel-based signaling |
| Standard library | SAFE — io, os, debug, coroutine removed |
| External calls | SAFE — deterministic keccak256 storage slots, snapshot/revert |
| Bytecode format | SAFE — platform-independent with SHA256 checksum validation |
| Gas costs | SAFE — hardcoded constants, no runtime variance |
| Child call gas | SAFE — 1/64 rule uses integer division (no float rounding) |

---

## Detailed Findings

### 1. Floating Point — ELIMINATED

Zero uses of `float32`, `float64`, or transcendental math functions anywhere
in the LVM execution path. All numeric operations use `big.Int`
(arbitrary-precision integers). The `math` import is used only for
`math.MaxUint64` constant.

### 2. Random/Time — ELIMINATED

Zero uses of `math/rand`, `crypto/rand`, `time.Now()`, or system calls in
execution paths. Nondeterministic Lua stdlib modules explicitly not loaded:
- `io` (file I/O) — NOT LOADED
- `os` (system calls) — NOT LOADED
- `debug` (abstraction-breaking) — REMOVED
- `coroutine` (nondeterministic state) — REMOVED
- `math.random()` — NOT AVAILABLE

Loaded only: base, table, string, math (floor/ceil/max/min — all deterministic).

### 3. Map Iteration — INSERTION-ORDER PRESERVED

**Critical design decision**: Tolang's `LTable.ForEach()` iterates hash-part
entries in insertion order via a preserved key slice:

```go
// tolang/table.go:344-349
for _, key := range tb.keys {  // insertion order
    if v := tb.RawGetH(key); v != LNil {
        cb(key, v)
    }
}
```

This prevents Go's random hash-map iteration from leaking into consensus.
Used in `tos.dispatch()` handler table iteration and global field injection.

### 4. Gas Metering — EXHAUSTIVE

Every primitive is metered **before** execution:

| Function | Gas | Charged Before Execution |
|----------|-----|--------------------------|
| `tos.sload` | 100 | Yes (lvm.go:698) |
| `tos.sstore` | 5000 | Yes (lvm.go:717) |
| `tos.transfer` | 2300 | Yes (lvm.go:765) |
| `tos.balance` | 400 | Yes (lvm.go:823) |
| `tos.emit` | 375 + 375/topic + 8/byte | Yes (lvm.go:3892) |
| `tos.create` | 3200000 + 200/byte | Yes (lvm.go:3262) |
| `tos.compileBytecode` | 5000 + 50/byte | Yes (lvm.go:3595) |
| `tos.setStr` | per-slot writes | Yes (lvm.go:3915) |
| `tos.getStr` | per-slot reads | Yes (lvm.go:3937) |
| `tos.mapGet` | 100 | Yes (lvm.go:3983) |
| `tos.mapSet` | 5000 | Yes (lvm.go:4012) |

Per-opcode gas limit enforced in the Lua VM:
```go
// tolang/vm.go:31-36
if L.gasLimit > 0 {
    L.gasUsed++
    if L.gasUsed > L.gasLimit {
        L.RaiseError("lua: gas limit exceeded")
    }
}
```

### 5. State Revert on OOG/Error

Snapshot/revert pattern ensures no partial state modification:
- Snapshot taken before code execution (lvm.go:160, 395)
- State reverted on error/OOG (lvm.go:189, 419, 428)
- Gas consumed still charged (correct EVM-compatible semantics)

### 6. Bytecode Platform Independence

- Fixed magic bytes: `{'T', 'O', 'L', 'B'}`
- Fixed format version: `BytecodeFormatVersion = 1`
- VMID embeds version info for reproducibility
- SHA256 checksum validation at load time
- Mismatches rejected → prevents stale/corrupted bytecode divergence

### 7. Child Call Gas (1/64 Rule)

```go
childGasLimit := available - available/64  // integer division
```

Uses Go integer division (always floor). No floating-point rounding variance.
Same calculation produces same result on all platforms.

### 8. Error Propagation

Sentinel-based signaling via package-level Go pointers:
- `lvmResultSentinel` / `lvmRevertSentinel` are singletons
- Checked via pointer equality (unforgeable by user code)
- Gas accounting happens before error classification
- Same input always produces same error on all nodes

---

## Minor Observations (No Fix Required)

### `tos.send` Gas Ordering

In soft-fail `tos.send`, gas is charged after parameter validation but before
tombstone check. This is inconsistent with `tos.transfer` (which charges
immediately after readonly check). **No impact**: tombstone check doesn't
modify state, and gas is still charged in all success paths.

### Call Depth Limit

Maximum call depth is hardcoded (`maxCallDepth = 8`). This prevents stack
overflow attacks but limits contract composability. Adequate for current use
cases.

---

## Files Audited

| File | Lines | Purpose |
|------|-------|---------|
| `core/vm/lvm.go` | ~4590 | Core VM execution, all host primitives |
| `core/vm/lvm_abi.go` | ~593 | ABI encoding/decoding |
| `core/vm/lvm_stdlib.go` | ~680 | Pre-compiled stdlib modules |
| `core/vm/lvm_crypto.go` | ~1200 | Cryptographic operations (keccak, ristretto, elgamal) |
| `tolang/vm.go` | — | Opcode dispatch, per-opcode gas metering |
| `tolang/table.go` | — | LTable with insertion-order ForEach() |
| `tolang/bytecode.go` | — | Platform-independent bytecode format |
| `tolang/linit.go` | — | Stdlib module loading (io/os/debug/coroutine removed) |

---

## Conclusion

The LVM interpreter is **consensus-safe and ready for mainnet deployment**.
All nondeterminism vectors have been eliminated:

- No floating point, no random, no time, no system calls
- Insertion-order table iteration (no Go map randomness leaks)
- Gas metered before execution at both opcode and primitive levels
- State reverted on error via snapshot mechanism
- Bytecode validated with SHA256 checksums
- Errors propagated deterministically via sentinel objects

**This resolves the last remaining item from SECURITY-AUDIT-2026-03-19.md.**
