# Plan: Init/Runtime Split with `main_contract` + `init_toc`

## Goal

Adopt Ethereum-like init/runtime separation for TOL packages:

1. Deploy executes init code (`init_toc`) once.
2. Chain state stores only runtime package code (no init code persisted).
3. Normal calls cannot reach constructor/init path.

---

## Manifest Contract

Keep one manifest source: existing `manifest.json`.

Required new fields:

```json
{
  "name": "tokenpkg",
  "version": "1.0.0",
  "main_contract": "TRC20",
  "init_toc": "bytecode/TRC20.init.toc",
  "contracts": [
    {"name":"TRC20","toc":"bytecode/TRC20.toc"},
    {"name":"Helper","toc":"bytecode/Helper.toc"}
  ]
}
```

Rules:

1. `main_contract` must exist in `contracts`.
2. `contracts[main_contract].toc` must be present and valid (this is runtime toc).
3. `init_toc` must exist and decode as valid `.toc`.
4. `init_toc` must **not** be listed in `contracts`.
5. Any mismatch => deployment reject (deterministic consensus behavior).

No `runtime_toc` field is needed. Runtime toc is already defined by `contracts` entry of `main_contract`.

---

## Deploy Calldata Format

Deployment tx data:

`[tor_deploy_zip][ctor_args_abi_bytes]`

`SplitDeployDataAndConstructorArgs(data)` splits by ZIP boundary and returns:

1. `deployPkgBytes`
2. `ctorArgs`

`SplitDeployDataAndConstructorArgs` must use strict ZIP validation (not signature-only scan):

1. Search EOCD within ZIP spec window (`maxComment=65535`).
2. Parse EOCD fields and validate:
   - central directory offset/size bounds;
   - EOCD length consistency (`22 + commentLen`);
   - central directory lies before EOCD.
3. Candidate `deployPkgBytes` must pass `DecodePackage(...)`.
4. If any check fails: reject deploy data split (do not fall back silently).

---

## Deploy Semantics (Create Path)

`Create()` uses `deployPkgBytes` and executes in this order:

1. Decode deploy package and validate manifest.
2. Resolve `main_contract` runtime toc and `init_toc`.
3. Create account snapshot context.
4. Execute `init_toc` with:
   - `ctx.IsCreate = true`
   - `ctx.To = new contract address`
   - `ctx.Data = ctorArgs`
5. If init fails: revert full create snapshot.
6. If init succeeds: build runtime package and persist only runtime package as account code.
7. Return leftover gas.

Important:

1. `init_toc` is execution-only, never stored on-chain.
2. `init_toc` must not depend on runtime toc execution.

---

## Runtime Package Persistence

After successful init:

1. Produce `runtimePkgBytes` from deploy package by removing:
   - manifest field `init_toc`
   - the `init_toc` file entry itself
2. Keep `contracts` unchanged.
3. Store only `runtimePkgBytes` via `SetCode`.

This guarantees normal package routing can never dispatch to init code.

### Package Signature and Runtime Package

The `.tor` package signature covers the original deploy package (`deployPkgBytes`), computed
as `keccak256(manifestJSON_without_signature || sorted_file_contents)`. Removing `init_toc`
from the manifest and files invalidates this signature.

**Decision: Runtime package carries no signature; signature is verified at deploy time only.**

Rationale:
- Signature semantics are "publisher vouches for this artifact" — relevant at deploy time,
  not for the on-chain runtime state.
- This mirrors EVM: a signed deploy transaction covers the initcode; the stored runtime
  bytecode is a chain-state derivation and carries no signature.
- No runtime rewriting of signature fields is needed; the stored runtime package simply
  omits the `signature` and `publisher_key` manifest fields alongside `init_toc`.

Verification timing:
1. `Create()` entry: verify signature on `deployPkgBytes` (optional policy, not a
   mandatory consensus rule — same as today).
2. `Call()` / `executePackage()`: no signature check on stored runtime package.

---

## Execute/Context Changes

## 1) `CallCtx`

Add:

```go
IsCreate bool
```

## 2) `Execute()`

1. Always expose `tos.calldata = "0x" + hex(ctx.Data)`.
2. Post-module dispatch:
   - `IsCreate=true`: allow init lifecycle path.
   - `IsCreate=false`: normal invoke path only.

## 3) `oninvoke` argument strategy (final)

Use a single deterministic strategy:

1. VM calls `tos.oninvoke(selector)` (selector only; no ABI args in varargs path).
2. TOL-generated `oninvoke` decodes arguments from `tos.calldata` for **all** external functions.
3. Remove dependency on `...` forwarding for non-struct functions in generated dispatch code.

This removes ambiguity between direct vararg call and calldata-based call, and closes the previous parameter-loss risk.

## 4) Permission hardening

`tos.oncreate` (or equivalent init lifecycle entry) must hard-check create context.

If `IsCreate != true`, raise error immediately.

No first-call initialization side effect is allowed.

---

## `tos.create` / `tos.create2`

Keep semantics aligned with top-level Create:

1. Child deploy should run child init in create context.
2. Child init failure reverts child creation effects.
3. No fallback to first external call for initialization.

---

## Backward Compatibility

Suggested rollout:

1. New compiler output always emits `main_contract` + `init_toc`.
2. Chain rule (recommended): reject deploy packages missing these fields after fork height.
3. Pre-fork legacy behavior can be retained temporarily if needed.

---

## Determinism and Gas

1. Deterministic manifest resolution and package rewriting.
2. Full snapshot rollback on init failure.
3. Gas model:
   - code storage gas charged by persisted runtime package size;
   - init execution gas charged separately from remaining create gas;
   - OOG mapped consistently to create failure.

---

## Files to Change

1. `core/state_transition.go`
   - split deploy calldata into `deployPkgBytes` + `ctorArgs`
   - call updated `Create(...)`
2. `core/lvm/lvm.go`
   - `CallCtx.IsCreate`
   - `SplitDeployDataAndConstructorArgs`
   - new create flow (init execute -> runtime package persist)
   - manifest parse/validation for `main_contract` + `init_toc`
   - runtime-package rewrite helper
   - `Execute()` calldata + create-context lifecycle enforcement
3. `docs/lua-vm-integration.md`
   - update docs to constructor-at-create and init/runtime separation
4. `~/tolang/tol_ir_direct_lowering.go`
   - update generated `tos.oninvoke` branches to decode args from `tos.calldata` for all external methods
   - remove reliance on varargs forwarding for runtime tx path

---

## Verification Checklist

```bash
go build ./...
go test ./core/lvm/... -count=1
```

Add tests:

1. Init runs at deploy and storage is visible before first call.
2. Init revert rolls back create completely.
3. Missing/invalid `main_contract` fails deploy.
4. Missing/invalid `init_toc` fails deploy.
5. Stored runtime package excludes `init_toc`.
6. Normal call cannot trigger init path.
7. `tos.create` / `tos.create2` run child init at create-time.
8. Non-struct function dispatch still works when `oninvoke` receives selector-only (args decoded from `tos.calldata`).
9. Malformed deploy data (invalid EOCD / invalid central directory bounds) is rejected by split logic.
