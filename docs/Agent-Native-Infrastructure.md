# Agent-Native gtos Infrastructure

## Overview

This document specifies the on-chain infrastructure that gtos must provide for TOL to become
an Agent-Native language. The TVM has been removed; the only executor is the LVM (tolang Lua
VM, `core/lvm/lvm.go`). The existing `validator/` package (sysaction handler + storage in a
system-contract account) is the canonical pattern replicated for all four system contracts.

**Scope**: `~/gtos` only. Changes on the tolang side (§III oracle/vote/task VM primitives
compiled by the compiler, §VI ABI/codegen extensions) are separate work.

---

## Existing gtos Architecture (Pattern to Replicate)

- **Blank import** in `tos/backend.go` → triggers `init()` → `sysaction.DefaultRegistry.Register(&handler{})`
- **`sysaction.Handler` interface**: `CanHandle(ActionKind) bool` + `Handle(*Context, *SysAction) error`
- **Storage**: keccak256-based slots per field, written into the system contract account
  (`params.ValidatorRegistryAddress`), read via `db.GetState(registryAddr, slot)`
- **LVM `tos.*`**: Go functions registered on `tosTable` inside `Execute()`, with direct
  access to `stateDB`, `blockCtx`, and `contractAddr`

---

## Files to Create / Modify

### 1. `params/tos_params.go` — New Addresses and Constants

Add the following to the existing file:

```go
// Agent-Native system contract addresses.
AgentRegistryAddress      = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000101")
CapabilityRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000102")
DelegationRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000103")
ReputationHubAddress      = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000104")

// AA constants.
ValidationGasCap uint64 = 50_000 // hard cap for account.validate() call
AgentLoadGas     uint64 = 100    // cost of tos.agentload() = 1 SLOAD equivalent
```

Agent minimum stake (analogous to `DPoSMinValidatorStake`):

```go
AgentMinStake = new(big.Int).Mul(big.NewInt(1_000), big.NewInt(1e18)) // 1,000 TOS
```

---

### 2. `sysaction/types.go` — New ActionKind Constants

```go
// Agent lifecycle.
ActionAgentRegister      ActionKind = "AGENT_REGISTER"
ActionAgentUpdateProfile ActionKind = "AGENT_UPDATE_PROFILE"
ActionAgentIncreaseStake ActionKind = "AGENT_INCREASE_STAKE"
ActionAgentDecreaseStake ActionKind = "AGENT_DECREASE_STAKE"
ActionAgentSuspend       ActionKind = "AGENT_SUSPEND"
ActionAgentUnsuspend     ActionKind = "AGENT_UNSUSPEND"

// Capability management.
ActionCapabilityRegister ActionKind = "CAPABILITY_REGISTER"
ActionCapabilityGrant    ActionKind = "CAPABILITY_GRANT"
ActionCapabilityRevoke   ActionKind = "CAPABILITY_REVOKE"

// Delegation nonce tracking.
ActionDelegationMarkUsed ActionKind = "DELEGATION_MARK_USED"
ActionDelegationRevoke   ActionKind = "DELEGATION_REVOKE"

// Reputation scoring.
ActionReputationAuthorizeScorer ActionKind = "REPUTATION_AUTHORIZE_SCORER"
ActionReputationRecordScore     ActionKind = "REPUTATION_RECORD_SCORE"
```

---

### 3. `agent/` — New Package (3 Files)

#### `agent/types.go`

```go
package agent

import "errors"

type AgentStatus uint8

const (
    AgentInactive AgentStatus = 0
    AgentActive   AgentStatus = 1
)

var (
    ErrAgentAlreadyRegistered   = errors.New("agent: already registered")
    ErrAgentNotRegistered       = errors.New("agent: not registered")
    ErrAgentSuspended           = errors.New("agent: suspended")
    ErrAgentInsufficientStake   = errors.New("agent: insufficient stake")
    ErrAgentInsufficientBalance = errors.New("agent: sender balance below stake amount")
    ErrCapabilityRequired       = errors.New("agent: Registrar capability required")
)
```

#### `agent/state.go` — Storage Layout

Storage account: `params.AgentRegistryAddress`

| Slot key | Formula | Value |
|---|---|---|
| Per-agent field | `keccak256(addr[20] \|\| 0x00 \|\| field)` | varies |
| Agent count | `keccak256("agent\x00count")` | uint64 |
| Agent list[i] | `keccak256("agent\x00list\x00" \|\| i[8])` | address |
| Metadata URI | `keccak256("agent\x00meta\x00" \|\| addr[20])` | bytes32 (hash of URI string) |

Fields per agent: `"stake"` (u256), `"status"` (u8), `"registered"` (bool), `"suspended"` (bool).

Exported functions:

```go
func IsRegistered(db vm.StateDB, addr common.Address) bool
func IsSuspended(db vm.StateDB, addr common.Address) bool
func ReadStake(db vm.StateDB, addr common.Address) *big.Int
func ReadStatus(db vm.StateDB, addr common.Address) AgentStatus
func WriteStake(db vm.StateDB, addr common.Address, stake *big.Int)
func WriteSuspended(db vm.StateDB, addr common.Address, suspended bool)
func WriteStatus(db vm.StateDB, addr common.Address, s AgentStatus)
func MetadataOf(db vm.StateDB, addr common.Address) string
func WriteMetadata(db vm.StateDB, addr common.Address, uri string)
```

#### `agent/handler.go` — SysAction Handler

- `init()` → `sysaction.DefaultRegistry.Register(&agentHandler{})`
- `CanHandle`: all 6 `ActionAgent*` kinds
- `handleRegister`: value >= `AgentMinStake`, balance check, `!IsRegistered` → SubBalance sender,
  AddBalance registry, WriteStake, WriteStatus(Active), append to list
- `handleIncreaseStake` / `handleDecreaseStake`: adjust stake with guards
- `handleSuspend` / `handleUnsuspend`: requires Registrar capability (reads capability bitmap
  from `CapabilityRegistryAddress`)
- `handleUpdateProfile`: updates metadata URI

---

### 4. `capability/` — New Package (3 Files)

#### `capability/types.go`

```go
var (
    ErrCapabilityNameExists = errors.New("capability: name already registered")
    ErrCapabilityBitFull    = errors.New("capability: all 256 bits allocated")
    ErrCapabilityRegistrar  = errors.New("capability: Registrar required")
)
```

#### `capability/state.go` — Storage Layout

Storage account: `params.CapabilityRegistryAddress`

| Slot key | Formula | Value |
|---|---|---|
| Bitmap for addr | `keccak256("cap\x00bitmap\x00" \|\| addr[20])` | u256 bitmap |
| Bit index by name | `keccak256("cap\x00name\x00" \|\| name)` | u8 (0xFF = not registered) |
| Next available bit | `keccak256("cap\x00bitCount")` | u8 (0–255) |
| Eligible count[bit] | `keccak256("cap\x00eligible\x00" \|\| [1]byte{bit})` | u256 count |

Exported functions:

```go
func HasCapability(db vm.StateDB, addr common.Address, bit uint8) bool
func CapabilitiesOf(db vm.StateDB, addr common.Address) *big.Int
func CapabilityBit(db vm.StateDB, name string) (uint8, bool)
func TotalEligible(db vm.StateDB, bit uint8) *big.Int
func GrantCapability(db vm.StateDB, addr common.Address, bit uint8)
func RevokeCapability(db vm.StateDB, addr common.Address, bit uint8)
func RegisterCapabilityName(db vm.StateDB, name string) (uint8, error)
```

#### `capability/handler.go`

- `init()` → register
- `handleRegister`: allocate next bit, store name→bit mapping
- `handleGrant`: set bit in addr's bitmap, increment `totalEligible`
- `handleRevoke`: clear bit, decrement `totalEligible`

---

### 5. `delegation/` — New Package (3 Files)

#### `delegation/state.go` — Storage Layout

Storage account: `params.DelegationRegistryAddress`

| Slot key | Formula | Value |
|---|---|---|
| Nonce used | `keccak256("del\x00used\x00" \|\| principal[20] \|\| nonce[32])` | bool |
| Next nonce hint | `keccak256("del\x00nonce\x00" \|\| principal[20])` | u256 |

Exported functions:

```go
func IsUsed(db vm.StateDB, principal common.Address, nonce *big.Int) bool
func MarkUsed(db vm.StateDB, principal common.Address, nonce *big.Int)
func Revoke(db vm.StateDB, principal common.Address, nonce *big.Int)
func NextNonce(db vm.StateDB, principal common.Address) *big.Int
```

#### `delegation/handler.go`

- `handleMarkUsed`: decode payload `{principal, nonce}`, assert `ctx.From == principal`,
  check `!IsUsed`, then `MarkUsed`
- `handleRevoke`: decode payload `{principal, nonce}`, assert `ctx.From == principal`,
  mark as used (same effect — consumed nonces cannot be replayed)

**Security invariant**: only the principal can consume or revoke their own nonces.

---

### 6. `reputation/` — New Package (3 Files)

#### `reputation/state.go` — Storage Layout

Storage account: `params.ReputationHubAddress`

| Slot key | Formula | Value |
|---|---|---|
| Cumulative score | `keccak256("rep\x00score\x00" \|\| addr[20])` | i256 (two's complement) |
| Rating count | `keccak256("rep\x00count\x00" \|\| addr[20])` | u256 |
| Authorized scorer | `keccak256("rep\x00scorer\x00" \|\| addr[20])` | bool |

Exported functions:

```go
func TotalScoreOf(db vm.StateDB, addr common.Address) *big.Int   // signed, two's complement
func RatingCountOf(db vm.StateDB, addr common.Address) *big.Int
func IsAuthorizedScorer(db vm.StateDB, addr common.Address) bool
func AuthorizeScorer(db vm.StateDB, scorer common.Address, enabled bool)
func RecordScore(db vm.StateDB, who common.Address, delta *big.Int) // signed delta
```

#### `reputation/handler.go`

- `handleAuthorizeScorer`: requires Registrar capability; set/clear scorer flag
- `handleRecordScore`: payload `{who, delta (i256 as hex), reason, ref_id}`; requires
  `IsAuthorizedScorer(ctx.From)`; reads current score, adds delta, writes back

---

### 7. `core/lvm/lvm.go` — New `tos.*` Primitives

**Additional imports:**

```go
"github.com/tos-network/gtos/agent"
"github.com/tos-network/gtos/capability"
"github.com/tos-network/gtos/delegation"
"github.com/tos-network/gtos/reputation"
```

#### `block.timestamp_ms`

Added to the `blockTable` setup:

```go
L.SetField(blockTable, "timestamp_ms", lua.Lu256FromUint64(blockCtx.Time.Uint64()*1000))
```

#### `tos.agentload(addr, field) → value`

Gas cost: `params.AgentLoadGas` (100).

Supported fields:

| Field | Source | Return type |
|---|---|---|
| `"stake"` | `agent.ReadStake` | u256 |
| `"suspended"` | `agent.IsSuspended` | bool (0/1) |
| `"is_registered"` | `agent.IsRegistered` | bool (0/1) |
| `"capabilities"` | `capability.CapabilitiesOf` | u256 bitmap |
| `"reputation"` | `reputation.TotalScoreOf` | i256 as u256 |
| `"rating_count"` | `reputation.RatingCountOf` | u256 |

Unknown fields return `nil`.

#### `tos.hascapability(addr, bit) → bool`

Gas cost: `params.AgentLoadGas`. Direct bitmap bit-check via `capability.HasCapability`.

#### `tos.capabilitybit(name) → u8`

Gas cost: `params.AgentLoadGas`. Resolves capability name to bit index via
`capability.CapabilityBit`. Returns `nil` if name not registered. Intended for
compile-time constant resolution by TOL contracts.

#### Escrow VM Primitives

Gas cost: `gasSStore` per write, `gasSLoad` per read.

Storage key formula: `keccak256("tol.escrow." || contractAddr[20] || agentAddr[20] || purpose_u8)`

```
tos.escrow(agentAddr, amount, purpose_bit)
    Deduct `amount` from contract balance, credit to escrow slot.

tos.release(agentAddr, amount, purpose_bit)
    Deduct from escrow slot, transfer `amount` to agent address.

tos.slash(agentAddr, amount, recipientAddr, purpose_bit)
    Deduct from escrow slot, transfer `amount` to recipient address.

tos.escrowbalanceof(agentAddr, purpose_bit) → u256
    Returns current escrow balance for (contractAddr, agentAddr, purpose_bit).
```

#### `tos.delegationused(principal, nonce) → bool`

Gas cost: `params.AgentLoadGas`. Reads `delegation.IsUsed(stateDB, principal, nonce)`.

---

### 8. `core/state_transition.go` — Account Abstraction Two-Phase

#### Detection

An "account contract" is identified by a known storage slot set by the TOL compiler
in the constructor:

```go
var aaMarkerSlot = crypto.Keccak256Hash([]byte("tol.aa.validate"))

func (st *StateTransition) isAccountContract(addr common.Address) bool {
    return st.state.GetState(addr, aaMarkerSlot) != (common.Hash{})
}
```

#### Flow Insertion

After `preCheck()`, before nonce increment:

```go
if msg.To() != nil && st.isAccountContract(*msg.To()) {
    if err := st.validateAccountContract(); err != nil {
        return nil, err // reject, no gas charged
    }
}
```

#### `validateAccountContract()`

1. Check `balance >= ValidationGasCap * GTOSPriceWei + estimated_exec_gas`
2. Call `validate(tx_hash, sig)` via `lvm.Execute()` with gas cap 50k, `Readonly=false`
3. If the call returns false, reverts, or runs OOG → return `ErrAAValidationFailed` (no gas consumed)
4. Deduct actual validation gas from balance

Selector: `keccak256("validate(bytes32,bytes)")[:4]` — precomputed constant.

---

### 9. `tos/backend.go` — Blank Imports

```go
_ "github.com/tos-network/gtos/agent"
_ "github.com/tos-network/gtos/capability"
_ "github.com/tos-network/gtos/delegation"
_ "github.com/tos-network/gtos/reputation"
```

---

## Implementation Order

| Step | Target | Dependencies |
|------|--------|--------------|
| 1 | `params/tos_params.go` | none |
| 2 | `sysaction/types.go` | none |
| 3 | `agent/` (3 files) | params, sysaction, crypto |
| 4 | `capability/` (3 files) | params, sysaction, crypto |
| 5 | `delegation/` (3 files) | params, sysaction, crypto |
| 6 | `reputation/` (3 files) | params, sysaction, capability, crypto |
| 7 | `tos/backend.go` | all packages above |
| 8 | `core/lvm/lvm.go` | agent, capability, delegation, reputation |
| 9 | `core/state_transition.go` | params, lvm |

---

## Out of Scope (tolang, Separate Work)

- §III oracle/vote/task VM primitives → `tolang/tol_ir_direct_lowering.go` + `vm.go`
- §VI `.toc` ABI extensions (agent type in events) → `tolang/tol/codegen/`

---

## Verification

```bash
cd ~/gtos
go build ./...              # zero compilation errors
go test ./agent/...         # AGENT_REGISTER / SUSPEND / STAKE
go test ./capability/...    # CAPABILITY_REGISTER / GRANT / REVOKE
go test ./delegation/...    # DELEGATION_MARK_USED replay protection
go test ./reputation/...    # REPUTATION_RECORD_SCORE
go test ./core/lvm/...      # tos.agentload, block.timestamp_ms, escrow
go test ./...               # full suite
```

Each package will have tests analogous to `validator/validator_test.go`:

- Happy path registration / grant / revoke
- Duplicate rejection
- Insufficient capability rejection
- Cross-package invariants (e.g., `reputation.RecordScore` requires `IsAuthorizedScorer`)

---

## Storage Slot Summary

| Contract | Address | Namespace prefix |
|---|---|---|
| AgentRegistry | `0x...0101` | `agent\x00` |
| CapabilityRegistry | `0x...0102` | `cap\x00` |
| DelegationRegistry | `0x...0103` | `del\x00` |
| ReputationHub | `0x...0104` | `rep\x00` |
| Escrow (in-contract) | contract address | `tol.escrow.` |

All slot keys are `keccak256`-hashed before use, matching the pattern established by
`validator/state.go`.
