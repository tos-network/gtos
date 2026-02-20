# GTOS DPoS Consensus Engine Implementation Plan

## Context

gtos currently uses Tosash (PoW) consensus. This plan replaces it with DPoS (Delegated Proof of Stake):
- Node operators stake TOS tokens to become validators, replacing PoW mining
- Round-robin block production, no computational competition
- Block rewards replace miner rewards
- **MVP scope**: self-staking + round-robin block production + block rewards (no slashing, no delegation)

Reference: Ronin `consensus/consortium/v2` (snapshot + in/out-of-turn difficulty + rotation),
but using gtos's existing system action + StateDB storage slots instead of Solidity contracts.

---

## New Files

```
consensus/dpos/
├── dpos.go       # Engine main body, implements full consensus.Engine interface
├── snapshot.go   # Snapshot struct + rotation/cache logic
└── api.go        # dpos_* RPC (getSnapshot, getValidators)

validator/
├── types.go      # ValidatorStatus enum
├── state.go      # TOS3 storage slot encoding + StateDB read/write helpers
└── handler.go    # VALIDATOR_REGISTER / VALIDATOR_WITHDRAW system action handler
```

---

## Modified Existing Files

| File | Changes |
|------|---------|
| `params/tos_params.go` | Add `ValidatorRegistryAddress` (TOS3), DPoS parameter constants |
| `params/config.go` | Add `DPoSConfig` struct, add `DPoS *DPoSConfig` field to `ChainConfig` |
| `sysaction/types.go` | Add `ActionValidatorRegister`, `ActionValidatorWithdraw` constants and empty payload types |
| `tos/tosconfig/config.go` | `CreateConsensusEngine()` adds DPoS branch (takes priority over Tosash) |
| `tos/backend.go` | `import _ "github.com/tos-network/gtos/validator"` to trigger init() |

---

## Detailed Design

### 1. Parameters (`params/tos_params.go`)

```go
var ValidatorRegistryAddress = common.HexToAddress(
    "0x0000000000000000000000000000000054534F33") // "TOS3"

var (
    DPoSMinValidatorStake = new(big.Int).Mul(big.NewInt(10_000), big.NewInt(1e18)) // 10,000 TOS
    DPoSBlockReward       = new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18))      // 2 TOS/block
)

const (
    DPoSEpochLength   uint64 = 200
    DPoSMaxValidators uint64 = 21
    DPoSBlockPeriod   uint64 = 3   // seconds
    DPoSDiffInTurn           = 2
    DPoSDiffNoTurn           = 1
)
```

### 2. ChainConfig Extension (`params/config.go`)

```go
type DPoSConfig struct {
    Period        uint64 `json:"period"`
    Epoch         uint64 `json:"epoch"`
    MaxValidators uint64 `json:"maxValidators"`
}

// Added to ChainConfig alongside Tosash/Clique, existing fields unchanged:
DPoS *DPoSConfig `json:"dpos,omitempty"`
```

### 3. New System Action Types (`sysaction/types.go`)

```go
ActionValidatorRegister ActionKind = "VALIDATOR_REGISTER"
ActionValidatorWithdraw ActionKind = "VALIDATOR_WITHDRAW"
// Both have empty payloads (stake amount read from tx.Value)
```

### 4. Validator On-Chain State (`validator/state.go`, stored in TOS3)

```go
// Slot encoding
func validatorSlot(addr common.Address, field string) common.Hash {
    return common.BytesToHash(crypto.Keccak256(append(addr.Bytes(), "\x00"+field...)))
}

// Fields: selfStake (uint256), status (uint8: 0=inactive, 1=active), joinedBlock (uint64)

func ReadSelfStake(db vm.StateDB, addr common.Address) *big.Int
func WriteValidatorStatus(db vm.StateDB, addr common.Address, s ValidatorStatus)
// Read all active validators (sorted by stake descending, take top MaxValidators)
func ReadActiveValidators(db vm.StateDB) []common.Address
```

**Challenge**: `ReadActiveValidators` needs to iterate all validators.
**Solution**: Maintain a counter slot + address list slot (append-only, in join order) in TOS3.
On each epoch, read list in Go, sort by stake, truncate to MaxValidators — no on-chain sorting needed.

### 5. System Action Handler (`validator/handler.go`)

```go
func init() { sysaction.DefaultRegistry.Register(&validatorHandler{}) }
```

**VALIDATOR_REGISTER**:
1. Verify `ctx.Value >= DPoSMinValidatorStake`
2. Verify no duplicate registration (`selfStake == 0`)
3. `ctx.StateDB.SubBalance(ctx.From, ctx.Value)` — lock funds
4. `ctx.StateDB.AddBalance(params.ValidatorRegistryAddress, ctx.Value)` — deposit into TOS3
5. Write selfStake, status=active, joinedBlock to TOS3; append ctx.From to address list

**VALIDATOR_WITHDRAW**:
1. Verify `status == active`
2. Refund selfStake from TOS3 to ctx.From
3. Clear selfStake, status=inactive (no lockup period in MVP)

### 6. Snapshot (`consensus/dpos/snapshot.go`)

```go
type Snapshot struct {
    Number        uint64
    Hash          common.Hash
    Validators    []common.Address            // sorted active validators
    ValidatorsMap map[common.Address]struct{} // O(1) lookup
    Recents       map[uint64]common.Address   // blockNum → signer
}

func (s *Snapshot) inturn(validator common.Address, number uint64) bool {
    // number % len(Validators) == index(validator)
}
func (s *Snapshot) IsRecentlySigned(validator common.Address, number uint64) bool {
    // signed within recent len(Validators)/2+1 blocks
}
// apply processes headers sequentially: update Recents; at epoch blocks parse new validator set from header.Extra
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error)
```

**header.Extra format** (identical to Clique):
```
[32B vanity][epoch blocks only: N×20B validator addresses][65B secp256k1 signature]
```

Snapshot persistence: stored in DB (JSON) at epoch boundaries, loaded on startup; 128-entry in-memory LRU.

### 7. DPoS Engine (`consensus/dpos/dpos.go`)

```go
type DPoS struct {
    config     *params.DPoSConfig
    db         tosdb.Database
    recents    *arc.ARCCache  // hash → *Snapshot (128 entries)
    signatures *arc.ARCCache  // hash → common.Address (4096 entries)
    validator  common.Address
    signFn     SignerFn
    lock       sync.RWMutex
}

func New(config *params.DPoSConfig, db tosdb.Database) *DPoS
func NewFaker() *DPoS  // for testing, skips signature verification
```

**Method summary:**

| Method | Core Logic |
|--------|-----------|
| `Author` | Return header.Coinbase |
| `Prepare` | Set Coinbase/Difficulty/Time; write validators to Extra on epoch blocks |
| `Finalize` | `state.AddBalance(coinbase, DPoSBlockReward)`; `header.Root = state.IntermediateRoot(...)` |
| `FinalizeAndAssemble` | Read TOS3 → sort → write Extra (epoch blocks) → call Finalize → assemble block |
| `VerifyHeader` | ecrecover signer; verify in validator set; verify not recently signed; verify difficulty |
| `Seal` | Check authorization; compute delay (in-turn small, out-of-turn adds random wiggle); sign |
| `CalcDifficulty` | inturn → 2, otherwise → 1 |
| `VerifyUncles` | Reject all uncle blocks (DPoS has no uncles) |
| `APIs` | Register `dpos` namespace |

**snapshot() load priority**: in-memory cache → epoch block on disk → genesis (parsed from Extra) → apply block by block

### 8. CreateConsensusEngine (`tos/tosconfig/config.go`)

```go
if chainConfig.DPoS != nil {
    return dpos.New(chainConfig.DPoS, db)  // production path
}
if chainConfig.Clique != nil {
    return clique.New(chainConfig.Clique, db)  // --dev path unchanged
}
// Tosash fallback (for tests)
```

---

## Import Dependency Graph (acyclic)

```
tos/backend.go ──→ consensus/dpos/    creates engine
tos/backend.go ──→ validator/         triggers init()
core/          ──→ consensus/         interface (no concrete impl reference)
core/          ──→ sysaction/
sysaction/     ──→ core/vm/           StateDB interface
validator/     ──→ sysaction/         registers handler
validator/     ──→ params/
consensus/dpos/ ─→ consensus/         Engine interface
consensus/dpos/ ─→ params/
consensus/dpos/ ─→ core/state/        state.StateDB (existing)
```

---

## Genesis Initial Validators

The genesis block (block 0) `header.Extra` encodes the initial validator address list (same format as Clique).
The DPoS engine at `snapshot(number=0)` parses the initial validator set from Extra — no VALIDATOR_REGISTER tx needed.

`--dev` mode continues using Clique, unaffected.

---

## Implementation Order

1. `params/tos_params.go` — Add TOS3, DPoS constants
2. `params/config.go` — Add DPoSConfig + ChainConfig.DPoS field
3. `sysaction/types.go` — Add VALIDATOR_* types
4. `validator/types.go` + `validator/state.go` — TOS3 state read/write layer
5. `validator/handler.go` — system action handler
6. `consensus/dpos/snapshot.go` — Snapshot structure
7. `consensus/dpos/dpos.go` — Engine main body
8. `consensus/dpos/api.go` — RPC
9. `tos/tosconfig/config.go` — Register DPoS engine branch
10. `tos/backend.go` — import validator

---

## Verification

```bash
go build ./...                                          # must compile
go test -short ./consensus/dpos/... ./validator/...     # new package unit tests
go test -short -p 48 ./core/... ./consensus/... ./tos/... # existing tests all pass
go test -race ./consensus/dpos/... ./validator/...      # race detector clean
```

Manual verification: start multi-node dev network, send VALIDATOR_REGISTER tx, observe validators taking turns producing blocks and rewards accumulating.
