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

---

## Security & Correctness Review (2026-02-20)

Cross-referenced against `~/ronin/consensus/consortium/v2/` and `~/gtos/consensus/clique/`.
Issues are ranked: **CRITICAL** → **HIGH** → **MEDIUM** → **LOW**.

---

### CRITICAL

#### C1. Empty validator set causes panic in `inturn()`

In `clique/snapshot.go:325`:
```go
return (number % uint64(len(signers))) == uint64(offset)
```
If `len(signers) == 0`, this is `number % 0` — **integer division by zero, runtime panic in Go**.
The same panic occurs in `apply()` at the `Recents` limit calculation: `len(snap.Validators)/2 + 1`.

**Fix**: Guard in `newSnapshot`, `apply`, and the genesis snapshot loader:
```go
if len(validators) == 0 {
    return nil, errors.New("dpos: empty validator set")
}
```
Also in `inturn()`: return `false` immediately if `len(snap.Validators) == 0`.

---

#### C2. Genesis block Extra has NO signature slot

Block 0 is never signed. Its Extra layout is:
```
[32B vanity][N×20B validator addresses]    // NO trailing 65B seal
```
Regular blocks (number > 0):
```
[32B vanity][validators at epoch only][65B secp256k1 seal]
```
The plan's `snapshot()` at `number == 0` must parse `Extra[extraVanity : len(Extra)]` as raw addresses (no seal subtraction). The `VerifyHeader` cascade check must short-circuit at `number == 0` (same as `clique/clique.go:316`).

**Fix**: Clique pattern — `if number == 0 { return nil }` at the top of `verifyCascadingFields`. Genesis Extra length validation: `len(Extra) >= extraVanity` and `(len(Extra) - extraVanity) % 20 == 0` with no `extraSeal` required.

---

#### C3. `sysaction.Execute()` does not populate `ctx.BlockNumber`

In `sysaction/executor.go:51–55`:
```go
ctx := &Context{
    From:    msg.From(),
    Value:   msg.Value(),
    StateDB: db,
    // BlockNumber is NOT set → nil
}
```
The VALIDATOR_REGISTER handler needs the current block number to write `joinedBlock`. Calling `ctx.BlockNumber.Uint64()` will **nil-pointer panic**.

**Fix (option A)**: Add `blockNumber *big.Int` parameter to `Execute()` and populate it — requires updating `core/state_transition.go` call site (`st.evm.Context.BlockNumber` is available there).

**Fix (option B)**: Skip persisting `joinedBlock` for MVP (it's informational only; the validator list iteration order is determined by address, not join time).

---

### HIGH

#### H1. Missing `Authorize(validator common.Address, signFn SignerFn)` method

The miner calls `engine.Authorize(...)` at startup to inject the signing key (see `clique/clique.go:585`). Without it, `DPoS.Seal()` has no signing function and will panic or return immediately.

**Fix**: Add the method (exact same pattern as Clique):
```go
func (d *DPoS) Authorize(validator common.Address, signFn SignerFn) {
    d.lock.Lock()
    defer d.lock.Unlock()
    d.validator = validator
    d.signFn = signFn
}
```

---

#### H2. Missing `VerifyHeaders` (batch) implementation

`consensus.Engine` requires `VerifyHeaders(chain, headers, seals) (chan<- struct{}, <-chan error)`. The plan only mentions `VerifyHeader` (singular). Missing this method causes a **compile error** (interface not satisfied).

**Fix**: Implement exactly as Clique does (goroutine + abort channel):
```go
func (d *DPoS) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
    abort := make(chan struct{})
    results := make(chan error, len(headers))
    go func() {
        for i, header := range headers {
            err := d.verifyHeader(chain, header, headers[:i])
            select {
            case <-abort:
                return
            case results <- err:
            }
        }
    }()
    return abort, results
}
```

---

#### H3. `SealHash` not defined — ecrecover will hash wrong data

`VerifyHeader` recovers the signer via `ecrecover(header, sigcache)`. The signing hash must be the RLP hash of the header **without** the last 65 bytes of `Extra` (the seal itself). If `SealHash` is not defined or uses the full `Extra`, the recovered address will never match the signer.

**Fix**: Implement `SealHash` as Clique does (`CliqueRLP` / `clique/clique.go:735`):
```go
// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
    hasher := sha3.NewLegacyKeccak256()
    encodeSigHeader(hasher, header)  // strips last 65B from Extra
    hasher.Sum(hash[:0])
    return hash
}
```
This is also what `signFn` must sign in `Seal()`.

---

#### H4. Coinbase impersonation — missing signer == Coinbase check

After ecrecover, the plan does not explicitly check that `signer == header.Coinbase`. Without this check, a malicious block proposer could:
- Sign with key A (valid validator)
- Set `Coinbase = B` (another account)
- Block reward goes to B, not A

Ronin explicitly rejects this at `consortium.go:827–829`.

**Fix**: In `verifySeal()`:
```go
if signer != header.Coinbase {
    return errInvalidCoinbase  // new sentinel error
}
```

---

#### H5. VALIDATOR_WITHDRAW: no defensive balance check on TOS3

`SubBalance(ValidatorRegistryAddress, selfStake)` on TOS3 can produce a **negative balance** if the invariant is ever broken (e.g., by a future bug). go-ethereum's `stateObject.SubBalance` does not check for underflow — it calls `big.Int.Sub` directly.

**Fix**: Defensive guard before withdrawal:
```go
if db.GetBalance(params.ValidatorRegistryAddress).Cmp(selfStake) < 0 {
    return errors.New("validator: TOS3 balance invariant broken")
}
```

---

### MEDIUM

#### M1. `VerifyHeader` missing mandatory header sanity checks

Clique's `verifyHeader` (`clique/clique.go:246–306`) checks several fields that the plan omits:

| Check | Why it matters |
|-------|---------------|
| `header.MixDigest == (common.Hash{})` | Prevents PoW fork confusion |
| `header.UncleHash == types.EmptyUncleHash` | DPoS has no uncles |
| `len(header.Extra) >= extraVanity + extraSeal` | Prevent out-of-bounds in ecrecover |
| At non-epoch blocks: no validator bytes in Extra | Prevents validator set injection mid-epoch |
| At epoch blocks: `(len(Extra) - extraVanity - extraSeal) % 20 == 0` | Malformed validator list |
| `header.Difficulty` must be 1 or 2 | Reject garbage difficulty |
| `header.Time > parent.Time` | Reject timestamp regression |
| `header.Time <= now + allowedFutureBlockTime` | Reject far-future blocks |

---

#### M2. Validator list slot design in `validator/state.go` is underspecified

The plan says "counter slot + address list slot" but gives no concrete slot formulas. Two implementors could derive incompatible storage layouts.

**Proposed canonical design**:
```go
var (
    validatorCountSlot = common.BytesToHash(crypto.Keccak256([]byte("validatorCount")))
)

func validatorListSlot(i uint64) common.Hash {
    idx := make([]byte, 8)
    binary.BigEndian.PutUint64(idx, i)
    return common.BytesToHash(crypto.Keccak256(append([]byte("validatorList\x00"), idx...)))
}
```
Address stored right-aligned in the 32-byte slot value (same convention as EVM address storage).

---

#### M3. LRU import: `arc.ARCCache` is wrong — use `lru.ARCCache`

The plan struct uses `*arc.ARCCache`. The correct import in gtos is:
```go
lru "github.com/hashicorp/golang-lru"
// usage: lru.NewARC(128) → *lru.ARCCache
```
There is no standalone `arc` package in the dependency tree; `ARCCache` lives in the `lru` package.

---

#### M4. Snapshot `apply()` must deep-copy before mutating

`apply()` must begin with `snap := s.copy()` before any modification, because multiple goroutines share the same `*Snapshot` pointer from the LRU cache. Modifying in place is a **data race**.

Clique enforces this at `snapshot.go:200`. The plan describes the copy pattern but must make it explicit (not optional).

---

#### M5. Validators in Snapshot must be sorted by address (ascending), not by stake

The plan says `Validators []common.Address // sorted active validators` but doesn't specify the sort key. For **deterministic round-robin**, all nodes must agree on the same ordering. The ordering must be:

1. **Selection** (in `ReadActiveValidators`): sort by `selfStake` descending, take top `MaxValidators`
2. **Storage in Snapshot and Extra**: re-sort the selected addresses by **address ascending** (same as Clique `signersAscending`)

The address-order sort must happen before writing to `header.Extra` and before storing in `Snapshot.Validators`. `inturn()` depends on a fixed index within this sorted slice.

---

#### M6. DB key prefix collision

Clique snapshots use prefix `"clique-"` + hash bytes. DPoS must use `"dpos-"` + hash bytes to avoid key collision if both engines ever coexist (e.g., during testing with the same DB).

---

### LOW

#### L1. Out-of-turn wiggle must use `math/rand`, not `crypto/rand`

Clique uses `rand.Int63n(int64(wiggle))` from `math/rand` for the delay randomness. `crypto/rand` is overkill and would require error handling. The source of non-determinism here is intentional (each validator independently randomizes its delay), not a security requirement.

#### L2. Difficulty values must be `*big.Int` for comparison in `VerifyHeader`

`DPoSDiffInTurn = 2` and `DPoSDiffNoTurn = 1` are untyped constants. `VerifyHeader` and `CalcDifficulty` return/compare `*big.Int`. Declare package-level vars:
```go
var (
    diffInTurn = big.NewInt(DPoSDiffInTurn)
    diffNoTurn = big.NewInt(DPoSDiffNoTurn)
)
```

#### L3. Re-registration after VALIDATOR_WITHDRAW is allowed

The plan checks `selfStake == 0` to prevent duplicate registration. After a withdraw, `selfStake` is reset to 0, so re-registration is permitted. This is intentional for MVP but should be documented as a known behavior (not a bug).

---

### Summary Table

| ID | Severity | Issue | Fix Required |
|----|----------|-------|--------------|
| C1 | CRITICAL | Empty validator set → panic | Guard in newSnapshot/apply/inturn |
| C2 | CRITICAL | Genesis Extra has no seal slot | Parse without -65B on block 0 |
| C3 | CRITICAL | ctx.BlockNumber is nil in Execute() | Pass blockNumber to Execute, or skip joinedBlock |
| H1 | HIGH | Missing Authorize() method | Add Authorize(addr, signFn) |
| H2 | HIGH | Missing VerifyHeaders (plural) | Add goroutine + abort channel impl |
| H3 | HIGH | SealHash undefined — ecrecover wrong | Define SealHash stripping last 65B |
| H4 | HIGH | Coinbase != signer allows reward theft | Check signer == header.Coinbase |
| H5 | HIGH | SubBalance(TOS3) can underflow | Defensive balance check before withdraw |
| M1 | MEDIUM | VerifyHeader missing sanity checks | Add MixDigest, UncleHash, Extra len, Time |
| M2 | MEDIUM | Address list slot design unspecified | Define validatorCountSlot + validatorListSlot(i) |
| M3 | MEDIUM | Wrong LRU type `arc.ARCCache` | Use `lru "github.com/hashicorp/golang-lru"` |
| M4 | MEDIUM | apply() must deep-copy snapshot | Call s.copy() before any mutation |
| M5 | MEDIUM | Validator sort order ambiguous | Select by stake desc, store by address asc |
| M6 | MEDIUM | DB key prefix collision with Clique | Use `"dpos-"` prefix |
| L1 | LOW | Wiggle source unspecified | Use math/rand.Int63n |
| L2 | LOW | Difficulty consts need *big.Int vars | Declare diffInTurn/diffNoTurn as *big.Int |
| L3 | LOW | Re-registration after withdraw | Document as known behavior |
