# Native KYC / TNS / Referral Infrastructure

## Overview

This document specifies three additional native system contracts for gtos, following the
same pattern established by `validator/` and `agent/`:

| System | Address | Package |
|--------|---------|---------|
| KYC Registry | `0x...0105` | `kyc/` |
| TNS Registry | `0x...0106` | `tns/` |
| Referral Registry | `0x...0107` | `referral/` |

All three use:
- keccak256-slotted storage in a fixed system-contract account
- `sysaction.Handler` + `init()` self-registration
- Blank import in `tos/backend.go`
- New `tos.*` LVM primitives in `core/lvm/lvm.go`

Dependency on the existing `capability/` package: KYC committee authorization
reuses `capability.HasCapability(db, addr, kycCommitteeBit)` (a reserved bit,
see §1.1).

---

## Source Reference

Design derived from:
- `~/memo/14-Compliance-KYC/TOS-KYC-Level-Design.md` (v2.3)
- `~/memo/30-AccountName/TNS-Implementation-Plan.md`
- `~/memo/13-Referral-System/TOS-Native-Referral-System-Design.md` (v1.9)

---

## 1. `params/tos_params.go` — New Addresses and Constants

```go
// KYC / TNS / Referral system contract addresses.
KYCRegistryAddress      = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000105")
TNSRegistryAddress      = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000106")
ReferralRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000107")

// TNS constants.
TNSRegistrationFee = new(big.Int).Mul(big.NewInt(1e17), big.NewInt(1)) // 0.1 TOS
TNSMinNameLen      = 3
TNSMaxNameLen      = 64

// Referral constants.
MaxReferralDepth uint8  = 20   // maximum upline levels for get_uplines / is_downline
ReferralBindGas  uint64 = 500  // flat gas for REFERRAL_BIND sysaction

// LVM read gas (same family as AgentLoadGas = 100).
KYCLoadGas      uint64 = 100
TNSLoadGas      uint64 = 200  // 2 SLOADs (name_hash + address)
ReferralLoadGas uint64 = 100  // per read; get_uplines charges 100 + 100*N
```

### 1.1 KYC Committee Capability Bit

The KYC committee capability is allocated as bit 1 in the `capability/` bitmap
(bit 0 is Registrar, defined in `agent/handler.go`):

```go
// KYCCommitteeBit is the well-known capability bit for KYC committee members.
// Only addresses holding this bit may call KYC_SET / KYC_SUSPEND.
KYCCommitteeBit uint8 = 1
```

---

## 2. `sysaction/types.go` — New ActionKind Constants

```go
// KYC lifecycle.
ActionKYCSet                ActionKind = "KYC_SET"
ActionKYCSuspend            ActionKind = "KYC_SUSPEND"

// TNS (TOS Name Service).
ActionTNSRegister           ActionKind = "TNS_REGISTER"

// Referral relationship.
ActionReferralBind          ActionKind = "REFERRAL_BIND"
```

Notes:
- `KYC_AUTHORIZE_COMMITTEE` is not a separate sysaction — committee membership
  is granted via the existing `CAPABILITY_GRANT` action (bit = `KYCCommitteeBit`).
- `REFERRAL_ADD_VOLUME` is not a sysaction — it is a direct LVM write primitive
  (`tos.addteamvolume`), analogous to `tos.escrow`.

---

## 3. `kyc/` — New Package (3 Files)

### `kyc/types.go`

```go
package kyc

import "errors"

// KycStatus mirrors the on-chain status byte.
type KycStatus uint8

const (
    KycNone      KycStatus = 0 // never set
    KycActive    KycStatus = 1 // valid KYC
    KycSuspended KycStatus = 2 // suspended by committee
)

// Valid cumulative KYC levels (2^n − 1 pattern).
// Each level is a bitmask; higher levels are strict supersets of lower ones.
const (
    KycLevelAnonymous  uint16 = 0      // Tier 0: no verification
    KycLevelBasic      uint16 = 7      // Tier 1: email+phone+basic_info
    KycLevelIdentity   uint16 = 31     // Tier 2: +gov_id+liveness
    KycLevelAddress    uint16 = 63     // Tier 3: +proof_of_address
    KycLevelFunds      uint16 = 255    // Tier 4: +source_of_funds+source_of_wealth
    KycLevelEDD        uint16 = 2047   // Tier 5: +background+screening+UBO
    KycLevelInstitute  uint16 = 8191   // Tier 6: +company+directors
    KycLevelAudit      uint16 = 16383  // Tier 7: +compliance_audit
    KycLevelRegulated  uint16 = 32767  // Tier 8: +financial_license
)

var (
    ErrKYCNotCommittee    = errors.New("kyc: caller is not an authorized committee member")
    ErrKYCInvalidLevel    = errors.New("kyc: level is not a valid cumulative value")
    ErrKYCNotActive       = errors.New("kyc: account has no active KYC record")
    ErrKYCAlreadySuspended = errors.New("kyc: account is already suspended")
)

// IsValidLevel returns true if level is one of the nine defined cumulative values.
func IsValidLevel(level uint16) bool {
    switch level {
    case 0, 7, 31, 63, 255, 2047, 8191, 16383, 32767:
        return true
    }
    return false
}

// TierOf returns the tier number (0–8) for a valid cumulative level.
// Returns 0 for unrecognised values.
func TierOf(level uint16) uint8 {
    switch level {
    case 7:     return 1
    case 31:    return 2
    case 63:    return 3
    case 255:   return 4
    case 2047:  return 5
    case 8191:  return 6
    case 16383: return 7
    case 32767: return 8
    }
    return 0
}
```

### `kyc/state.go` — Storage Layout

Storage account: `params.KYCRegistryAddress`

`level` (u16) 和 `status` (u8) 打包进**同一个 32 字节槽**，每个账户只需 1 次 SLOAD/SSTORE：

```
slot[29:31] = level (u16, big-endian)
slot[31]    = status (u8)
slot[0:29]  = zero padding
```

| Slot key | Formula | Value |
|---|---|---|
| KYC record | `keccak256("kyc\x00" \|\| addr[32])` | packed: `[29 zero bytes][level u16][status u8]` |

```go
package kyc

import (
    "encoding/binary"

    "github.com/tos-network/gtos/common"
    "github.com/tos-network/gtos/core/vm"
    "github.com/tos-network/gtos/crypto"
    "github.com/tos-network/gtos/params"
)

func kycSlot(addr common.Address) common.Hash {
    return common.BytesToHash(crypto.Keccak256(
        append([]byte("kyc\x00"), addr.Bytes()...)))
}

func readPacked(db vm.StateDB, addr common.Address) (level uint16, status KycStatus) {
    raw := db.GetState(params.KYCRegistryAddress, kycSlot(addr))
    level = binary.BigEndian.Uint16(raw[29:31])
    status = KycStatus(raw[31])
    return
}

func writePacked(db vm.StateDB, addr common.Address, level uint16, status KycStatus) {
    var val common.Hash
    binary.BigEndian.PutUint16(val[29:31], level)
    val[31] = byte(status)
    db.SetState(params.KYCRegistryAddress, kycSlot(addr), val)
}

func ReadLevel(db vm.StateDB, addr common.Address) uint16 {
    level, _ := readPacked(db, addr)
    return level
}

func ReadStatus(db vm.StateDB, addr common.Address) KycStatus {
    _, status := readPacked(db, addr)
    return status
}

func WriteKYC(db vm.StateDB, addr common.Address, level uint16, status KycStatus) {
    writePacked(db, addr, level, status)
}

// MeetsLevel returns true if addr has active KYC and (level & required) == required.
func MeetsLevel(db vm.StateDB, addr common.Address, required uint16) bool {
    level, status := readPacked(db, addr)
    return status == KycActive && (level&required) == required
}
```

### `kyc/handler.go` — SysAction Handler

- `init()` → `sysaction.DefaultRegistry.Register(&kycHandler{})`
- `CanHandle`: `ActionKYCSet`, `ActionKYCSuspend`

```
handleSet payload: { target: hex_addr, level: uint16 }
    1. Caller must have capability.HasCapability(db, ctx.From, params.KYCCommitteeBit)
    2. IsValidLevel(level) must be true
    3. WriteKYC(target, level, KycActive)  — 1 SSTORE

handleSuspend payload: { target: hex_addr }
    1. Caller must have KYCCommitteeBit
    2. ReadStatus(target) must be KycActive
    3. WriteKYC(target, ReadLevel(target), KycSuspended)  — preserve level, flip status
```

Security invariant: only capability-authorized committee members can set or
suspend KYC. The account whose KYC is being set has no role in the transaction.

---

## 4. `tns/` — New Package (3 Files)

### `tns/types.go`

```go
package tns

import "errors"

var (
    ErrTNSAlreadyRegistered = errors.New("tns: name already registered")
    ErrTNSAccountHasName    = errors.New("tns: account already has a registered name")
    ErrTNSInvalidName       = errors.New("tns: invalid name format")
    ErrTNSInsufficientFee   = errors.New("tns: registration fee not met")
    ErrTNSNameNotFound      = errors.New("tns: name not found")
)
```

### `tns/state.go` — Storage Layout

Storage account: `params.TNSRegistryAddress`

The name itself is NOT stored on-chain (privacy). Only the keccak256 hash of
the lowercase name string is stored.

| Slot key | Formula | Value |
|---|---|---|
| name_hash → address | `keccak256("tns\x00n2a\x00" \|\| name_hash[32])` | address |
| address → name_hash | `keccak256("tns\x00a2n\x00" \|\| addr[32])` | bytes32 |

```go
func nameToAddrSlot(nameHash common.Hash) common.Hash {
    return common.BytesToHash(crypto.Keccak256(
        append([]byte("tns\x00n2a\x00"), nameHash.Bytes()...)))
}

func addrToNameSlot(addr common.Address) common.Hash {
    return common.BytesToHash(crypto.Keccak256(
        append([]byte("tns\x00a2n\x00"), addr.Bytes()...)))
}

// HashName returns keccak256 of the canonical (lowercase) name string.
func HashName(name string) common.Hash {
    return common.BytesToHash(crypto.Keccak256([]byte(name)))
}

func ResolveHash(db vm.StateDB, nameHash common.Hash) common.Address {
    raw := db.GetState(params.TNSRegistryAddress, nameToAddrSlot(nameHash))
    return common.BytesToAddress(raw[:])
}

func ReverseHash(db vm.StateDB, addr common.Address) common.Hash {
    return db.GetState(params.TNSRegistryAddress, addrToNameSlot(addr))
}

func HasName(db vm.StateDB, addr common.Address) bool {
    return ReverseHash(db, addr) != (common.Hash{})
}

func writeNameMapping(db vm.StateDB, nameHash common.Hash, addr common.Address) {
    var addrVal common.Hash
    copy(addrVal[:], addr.Bytes())
    db.SetState(params.TNSRegistryAddress, nameToAddrSlot(nameHash), addrVal)
    db.SetState(params.TNSRegistryAddress, addrToNameSlot(addr), nameHash)
}
```

### `tns/handler.go` — SysAction Handler

- `init()` → `sysaction.DefaultRegistry.Register(&tnsHandler{})`
- `CanHandle`: `ActionTNSRegister`

```
handleRegister payload: { name: string }
    1. ctx.Value >= params.TNSRegistrationFee (0.1 TOS)
    2. Balance check: ctx.StateDB.GetBalance(ctx.From) >= ctx.Value
    3. Validate name format (3–64 chars, a-z0-9._-, starts with letter,
       no consecutive separators, not a reserved word)
    4. nameHash = keccak256(lowercase(name))
    5. ResolveHash(nameHash) must be zero address (name not taken)
    6. HasName(ctx.From) must be false (one name per account)
    7. SubBalance(ctx.From, fee); AddBalance(TNSRegistryAddress, fee)
       — registration fee held in registry account (treasury)
    8. writeNameMapping(nameHash, ctx.From)
```

Name validation rules (aligned with RFC 5321 dot-atom):

| Rule | Detail |
|------|--------|
| Length | 3–64 characters |
| Allowed chars | `a-z`, `0-9`, `.`, `-`, `_` |
| Must start with | lowercase letter `a-z` |
| Must not end with | separator (`. - _`) |
| No consecutive separators | `..` `--` `__` `.-` etc. forbidden |
| Reserved names | `admin`, `system`, `tos`, `root`, `null`, `test`, `node`, `validator` |

The name is normalised to lowercase before hashing. The original-case string is
never stored on-chain; users who know the name can compute the hash themselves.

---

## 5. `referral/` — New Package (3 Files)

### `referral/types.go`

```go
package referral

import "errors"

var (
    ErrReferralAlreadyBound   = errors.New("referral: already bound to a referrer")
    ErrReferralSelf           = errors.New("referral: cannot refer yourself")
    ErrReferralCircular       = errors.New("referral: would create a circular reference")
    ErrReferralDepthExceeded  = errors.New("referral: upline depth exceeds maximum")
    ErrReferralInvalidLevels  = errors.New("referral: levels must be 1–20")
)
```

### `referral/state.go` — Storage Layout

Storage account: `params.ReferralRegistryAddress`

| Slot key | Formula | Value |
|---|---|---|
| referrer | `keccak256("ref\x00referrer\x00" \|\| addr[32])` | address (zero = none) |
| bound_block | `keccak256("ref\x00block\x00" \|\| addr[32])` | u64 |
| direct_count | `keccak256("ref\x00dcount\x00" \|\| addr[32])` | u32 |
| team_size | `keccak256("ref\x00tsize\x00" \|\| addr[32])` | u64 (updated on bind) |
| team_volume | `keccak256("ref\x00tvol\x00" \|\| addr[32])` | u256 (cumulative, additive) |
| direct_volume | `keccak256("ref\x00dvol\x00" \|\| addr[32])` | u256 (from direct downlines) |

```go
func refSlot(addr common.Address, field string) common.Hash {
    key := append([]byte(field), addr.Bytes()...)
    return common.BytesToHash(crypto.Keccak256(key))
}

func ReadReferrer(db vm.StateDB, addr common.Address) common.Address {
    raw := db.GetState(params.ReferralRegistryAddress, refSlot(addr, "ref\x00referrer\x00"))
    return common.BytesToAddress(raw[:])
}

func HasReferrer(db vm.StateDB, addr common.Address) bool {
    return ReadReferrer(db, addr) != (common.Address{})
}

func ReadDirectCount(db vm.StateDB, addr common.Address) uint32 {
    raw := db.GetState(params.ReferralRegistryAddress, refSlot(addr, "ref\x00dcount\x00"))
    return uint32(raw.Big().Uint64())
}

func ReadTeamSize(db vm.StateDB, addr common.Address) uint64 {
    raw := db.GetState(params.ReferralRegistryAddress, refSlot(addr, "ref\x00tsize\x00"))
    return raw.Big().Uint64()
}

func ReadTeamVolume(db vm.StateDB, addr common.Address) *big.Int {
    raw := db.GetState(params.ReferralRegistryAddress, refSlot(addr, "ref\x00tvol\x00"))
    return raw.Big()
}

func ReadDirectVolume(db vm.StateDB, addr common.Address) *big.Int {
    raw := db.GetState(params.ReferralRegistryAddress, refSlot(addr, "ref\x00dvol\x00"))
    return raw.Big()
}

// GetUplines walks the referrer chain and returns up to `levels` ancestors.
func GetUplines(db vm.StateDB, addr common.Address, levels uint8) []common.Address {
    if levels > params.MaxReferralDepth {
        levels = params.MaxReferralDepth
    }
    result := make([]common.Address, 0, levels)
    cur := addr
    for i := uint8(0); i < levels; i++ {
        ref := ReadReferrer(db, cur)
        if ref == (common.Address{}) {
            break
        }
        result = append(result, ref)
        cur = ref
    }
    return result
}

// GetReferralDepth returns how deep addr is in the referral tree (0 = root / unbound).
func GetReferralDepth(db vm.StateDB, addr common.Address) uint8 {
    var depth uint8
    cur := addr
    for depth < params.MaxReferralDepth {
        ref := ReadReferrer(db, cur)
        if ref == (common.Address{}) {
            break
        }
        depth++
        cur = ref
    }
    return depth
}

// IsDownline checks whether descendant is within maxDepth levels below ancestor.
func IsDownline(db vm.StateDB, ancestor, descendant common.Address, maxDepth uint8) bool {
    cur := descendant
    for i := uint8(0); i < maxDepth; i++ {
        ref := ReadReferrer(db, cur)
        if ref == (common.Address{}) {
            return false
        }
        if ref == ancestor {
            return true
        }
        cur = ref
    }
    return false
}

// AddTeamVolume adds amount to team_volume for each upline up to `levels`,
// and also adds to direct_volume of the immediate referrer (level 1 only).
// Returns the number of levels actually updated.
func AddTeamVolume(db vm.StateDB, addr common.Address, amount *big.Int, levels uint8) uint8 {
    if levels > params.MaxReferralDepth {
        levels = params.MaxReferralDepth
    }
    cur := addr
    for i := uint8(0); i < levels; i++ {
        ref := ReadReferrer(db, cur)
        if ref == (common.Address{}) {
            return i
        }
        // Add to team_volume of this upline.
        slot := refSlot(ref, "ref\x00tvol\x00")
        old := db.GetState(params.ReferralRegistryAddress, slot).Big()
        db.SetState(params.ReferralRegistryAddress, slot,
            common.BigToHash(new(big.Int).Add(old, amount)))
        // Level 1 only: also update direct_volume.
        if i == 0 {
            dslot := refSlot(ref, "ref\x00dvol\x00")
            dold := db.GetState(params.ReferralRegistryAddress, dslot).Big()
            db.SetState(params.ReferralRegistryAddress, dslot,
                common.BigToHash(new(big.Int).Add(dold, amount)))
        }
        cur = ref
    }
    return levels
}
```

### `referral/handler.go` — SysAction Handler

- `init()` → `sysaction.DefaultRegistry.Register(&referralHandler{})`
- `CanHandle`: `ActionReferralBind`

```
handleBind payload: { referrer: hex_addr }
    1. HasReferrer(ctx.From) must be false
    2. referrer != ctx.From  (no self-referral)
    3. HasReferrer(referrer) OR referrer is a known root — referrer need not have
       a referrer themselves (they may be a root node)
    4. IsDownline(referrer, ctx.From, MaxReferralDepth) must be false
       (circular reference check: ctx.From must not already be above the referrer)
    5. Write referrer slot for ctx.From
    6. Write bound_block = ctx.BlockNumber
    7. Increment direct_count for referrer (+1)
    8. Walk up to MaxReferralDepth uplines, increment team_size for each (+1)
       Gas: ReferralBindGas + gasSStore × actual_levels_updated
```

Binding is permanent: once a referrer is set, it cannot be changed or removed.
This matches the original design's immutability requirement.

---

## 6. `core/lvm/lvm.go` — New `tos.*` Primitives

**Additional imports:**

```go
"github.com/tos-network/gtos/kyc"
"github.com/tos-network/gtos/tns"
"github.com/tos-network/gtos/referral"
```

### 6.1 KYC Primitives

Gas cost: `params.KYCLoadGas` (100) per call.

#### `tos.kyc(addr, field) → value`

| field | Source | Return type |
|-------|--------|-------------|
| `"level"` | `kyc.ReadLevel` | u256 (u16 bitmask) |
| `"tier"` | `kyc.TierOf(ReadLevel)` | u256 (0–8) |
| `"active"` | `kyc.ReadStatus == KycActive` | bool (0/1) |

Both fields are read from **one SLOAD** (packed slot). Unknown fields return `nil`.

#### `tos.meetskyclevel(addr, required_level) → bool`

Gas cost: `params.KYCLoadGas`.

Convenience check: `kyc.MeetsLevel(stateDB, addr, required_level)`.
Returns true iff addr has active KYC AND `(level & required_level) == required_level`.

```lua
-- Example: require at least Identity Verified (tier 2, level=31)
if not tos.meetskyclevel(msg.sender, 31) then
    error("KYC: identity verification required")
end
```

### 6.2 TNS Primitives

Gas cost: `params.TNSLoadGas` (200) per call.

#### `tos.tnsresolve(name_hash_hex) → address_hex | nil`

Resolves a name hash to an address. `name_hash_hex` is the hex-encoded
keccak256 of the lowercase name string. Returns nil if not registered.

```lua
local nameHash = tos.keccak256("alice")  -- caller computes hash off-chain or in Lua
local addr = tos.tnsresolve(nameHash)
if addr then
    tos.transfer(addr, amount)
end
```

#### `tos.tnsreverse(addr) → name_hash_hex | nil`

Reverse lookup: address → name hash. Returns nil if addr has no registered name.

#### `tos.tnshasname(addr) → bool`

Gas cost: `params.TNSLoadGas`. Returns `tns.HasName(stateDB, addr)`.

### 6.3 Referral Primitives

#### Read primitives (gas: `params.ReferralLoadGas` = 100 per call)

| Primitive | Returns | Notes |
|-----------|---------|-------|
| `tos.hasreferrer(addr)` | bool | `referral.HasReferrer` |
| `tos.getreferrer(addr)` | address_hex \| nil | zero address → nil |
| `tos.getdirectcount(addr)` | u256 (u32) | `referral.ReadDirectCount` |
| `tos.getteamsize(addr)` | u256 (u64) | `referral.ReadTeamSize` (cached) |
| `tos.getteamvolume(addr)` | u256 | `referral.ReadTeamVolume` |
| `tos.getdirectvolume(addr)` | u256 | `referral.ReadDirectVolume` |

#### `tos.getuplines(addr, levels) → table`

Gas cost: `params.ReferralLoadGas + params.ReferralLoadGas * levels`.
`levels` is capped at `params.MaxReferralDepth` (20).

Returns a Lua table `{ [1]=addr1_hex, [2]=addr2_hex, ... }` in upline order
(index 1 = direct referrer). Length may be shorter than `levels` if the chain
is shallower.

```lua
-- Three-level reward distribution example
local uplines = tos.getuplines(msg.sender, 3)
local ratios  = {1000, 500, 300}  -- 10%, 5%, 3% in basis points
for i = 1, #uplines do
    local reward = amount * ratios[i] / 10000
    if reward > 0 then
        tos.transfer(uplines[i], reward)
    end
end
```

#### `tos.getreferrallevel(addr) → u256`

Gas cost: `params.ReferralLoadGas + params.ReferralLoadGas * depth` (walks up).
Returns `referral.GetReferralDepth(stateDB, addr)`.

#### `tos.isdownline(ancestor, descendant, max_depth) → bool`

Gas cost: `params.ReferralLoadGas + params.ReferralLoadGas * max_depth`.
`max_depth` capped at `params.MaxReferralDepth`.
Returns `referral.IsDownline(stateDB, ancestor, descendant, max_depth)`.

#### `tos.addteamvolume(addr, amount, levels)` — WRITE

Gas cost: `gasSStore * levels` (one storage write per upline level updated).
`levels` capped at `params.MaxReferralDepth`.

Calls `referral.AddTeamVolume(stateDB, addr, amount, levels)`.

This is a **state-writing** primitive callable from within an LVM contract.
It propagates the volume amount upward through the referral tree, updating
`team_volume` for each ancestor, and `direct_volume` for the immediate referrer.

```lua
-- Called inside a purchase/investment handler:
tos.addteamvolume(msg.sender, purchase_amount, 10)
```

---

## 7. `tos/backend.go` — Blank Imports

```go
_ "github.com/tos-network/gtos/kyc"
_ "github.com/tos-network/gtos/tns"
_ "github.com/tos-network/gtos/referral"
```

---

## 8. Implementation Order

| Step | Target | Dependencies |
|------|--------|--------------|
| 1 | `params/tos_params.go` (new addresses + constants) | none |
| 2 | `sysaction/types.go` (new ActionKind constants) | none |
| 3 | `kyc/` (3 files) | params, sysaction, capability, crypto |
| 4 | `tns/` (3 files) | params, sysaction, crypto |
| 5 | `referral/` (3 files) | params, sysaction, crypto |
| 6 | `tos/backend.go` (blank imports) | kyc, tns, referral |
| 7 | `core/lvm/lvm.go` (new tos.* primitives) | kyc, tns, referral |

---

## 9. Verification

```bash
cd ~/gtos
go build ./...

go test ./kyc/...       # KYC_SET committee gating, level validation, suspend
go test ./tns/...       # TNS_REGISTER name format, collision, one-per-account
go test ./referral/...  # REFERRAL_BIND anti-self, anti-circular, upline walk
go test ./core/lvm/...  # tos.kyc, tos.meetskyclevel, tos.tnsresolve,
                        # tos.hasreferrer, tos.getuplines, tos.addteamvolume
go test ./...           # full suite
```

Test coverage targets per package:

| Package | Cases |
|---------|-------|
| `kyc/` | Set by non-committee (rejected), set invalid level (rejected), set valid level, suspend active, suspend already-suspended (rejected), MeetsLevel bitmask check |
| `tns/` | Register valid name, register duplicate (rejected), register second name for same account (rejected), invalid format (rejected), insufficient fee (rejected), resolve and reverse lookup |
| `referral/` | Bind referrer, self-referral (rejected), circular reference (rejected), already-bound (rejected), GetUplines depth, IsDownline positive and negative, AddTeamVolume propagation |

---

## 10. Storage Slot Summary

| Contract | Address | Namespace prefix |
|---|---|---|
| KYCRegistry | `0x...0105` | `kyc\x00` |
| TNSRegistry | `0x...0106` | `tns\x00` |
| ReferralRegistry | `0x...0107` | `ref\x00` |

All slot keys are keccak256-hashed before use, matching the pattern in
`validator/state.go` and `agent/state.go`.

---

## 11. Design Decisions and Rationale

| Decision | Rationale |
|----------|-----------|
| KYC level+status packed into 1 slot | 1 SLOAD/SSTORE per KYC read/write; no data_hash or verified_at on-chain (off-chain committee DB holds audit trail) |
| KYC level stored as u16 bitmask | Bitmask enables partial-flag checks in contracts (`level & required == required`) without tier numeric comparison |
| KYC committee via `capability/` bit 1 | Reuses existing access-control infrastructure; no new auth mechanism needed |
| Name stored as hash only | Privacy: full name string never appears on-chain; callers who know the name can compute the hash |
| TNS registration immutable | Prevents name squatting churn; V2 upgrade path (annual change) deferred |
| TNS fee held in TNSRegistryAddress | Simple treasury accounting; fee not burned to keep accounting auditable |
| Referral binding immutable | Prevents relationship fraud (rebinding to capture better uplines after earning) |
| `REFERRAL_ADD_VOLUME` as LVM primitive, not sysaction | Volume updates are called inside contract execution, not as standalone user txs; direct write avoids sysaction dispatch overhead and matches `tos.escrow` pattern |
| `team_size` updated on every bind (walk up N levels) | Deterministic; no lazy cache divergence across nodes; bounded cost (max 20 writes per bind) |
| `team_volume` uses u256, not u64 | Future-proof for high-value chains; matches on-chain big.Int storage convention |
