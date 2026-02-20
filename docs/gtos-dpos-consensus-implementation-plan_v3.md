# GTOS DPoS Consensus Engine — Implementation Plan v3

> **v3 changelog** (vs v2): All 9 issues from Round-2 security review (2026-02-20) resolved.
> - R2-C1 `addressAscending` type added to snapshot.go
> - R2-C2 `appendValidatorToList` logic fixed (save isNewRegistration before writes)
> - R2-C3 `snap.store()` guarded with `if d.db != nil` in all call sites
> - R2-C4 `New()` returns error; validates Epoch/Period/MaxValidators > 0
> - R2-C5 Sender balance check added in VALIDATOR_REGISTER validation phase
> - R2-H1 Epoch Extra verification gap documented; accepted MVP limitation
> - R2-M1 `allowedFutureBlockTime = 5` constant defined
> - R2-M2 `ReadActiveValidators` pre-loads stakes (O(N) reads, not O(N log N))
> - R2-L1 `accounts.MimetypeDPoS` defined; used in Seal()

---

## Context

gtos currently uses Tosash (PoW) consensus. This plan replaces it with DPoS (Delegated Proof
of Stake):
- Node operators stake TOS tokens to become validators, replacing PoW mining
- Round-robin block production, no computational competition
- Block rewards replace miner rewards
- **MVP scope**: self-staking + round-robin block production + block rewards (no slashing, no
  delegation)

Reference: Ronin `consensus/consortium/v2` (snapshot + in/out-of-turn difficulty + rotation),
but using gtos's existing system action + StateDB storage slots instead of Solidity contracts.
Also mirrors `consensus/clique/` structurally (snapshot, Authorize, SealHash, VerifyHeaders).

---

## New Files

```
consensus/dpos/
├── dpos.go       # Engine — implements consensus.Engine in full
├── snapshot.go   # Snapshot struct + rotation/cache/apply logic
└── api.go        # dpos_getSnapshot, dpos_getValidators RPC

validator/
├── types.go      # ValidatorStatus enum + sentinel errors
├── state.go      # TOS3 storage slot definitions + StateDB read/write helpers
└── handler.go    # VALIDATOR_REGISTER / VALIDATOR_WITHDRAW system action handler
```

---

## Modified Existing Files

| File | Change |
|------|--------|
| `params/tos_params.go` | Add `ValidatorRegistryAddress` (TOS3) + DPoS constants |
| `params/config.go` | Add `DPoSConfig` struct + `ChainConfig.DPoS` field |
| `sysaction/types.go` | Add `ActionValidatorRegister`, `ActionValidatorWithdraw` |
| `accounts/accounts.go` | Add `MimetypeDPoS` constant (R2-L1) |
| `tos/tosconfig/config.go` | `CreateConsensusEngine()` — DPoS branch before Clique/Tosash |
| `tos/backend.go` | `import _ "github.com/tos-network/gtos/validator"` |

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
    DPoSBlockPeriod   uint64 = 3 // target seconds per block
)
```

Difficulty values are declared as `*big.Int` inside `consensus/dpos/dpos.go`, not here.

---

### 2. ChainConfig Extension (`params/config.go`)

```go
type DPoSConfig struct {
    Period        uint64 `json:"period"`        // target block interval (seconds)
    Epoch         uint64 `json:"epoch"`         // blocks between validator-set snapshots
    MaxValidators uint64 `json:"maxValidators"` // maximum active validators
}

func (c *DPoSConfig) String() string {
    return fmt.Sprintf("{period: %d, epoch: %d, maxValidators: %d}",
        c.Period, c.Epoch, c.MaxValidators)
}

// Added to ChainConfig alongside Tosash/Clique; existing fields unchanged:
DPoS *DPoSConfig `json:"dpos,omitempty"`
```

---

### 3. System Action Types (`sysaction/types.go`)

```go
const (
    ActionValidatorRegister ActionKind = "VALIDATOR_REGISTER"
    ActionValidatorWithdraw ActionKind = "VALIDATOR_WITHDRAW"
)
// Both actions carry empty payloads; the stake amount is read from ctx.Value (tx.Value).
```

---

### 4. MIME type (`accounts/accounts.go`)

```go
// R2-L1: define DPoS-specific MIME type; avoids confusion with Clique in logs/wallets.
MimetypeDPoS = "application/x-dpos-header"
```

---

### 5. Validator On-Chain State (`validator/state.go`, stored at TOS3)

#### 5a. Per-validator slots

```go
// validatorSlot hashes (addr[20B] || 0x00 || field) for a per-validator storage slot.
// addr is always exactly 20 bytes → no length-extension ambiguity.
func validatorSlot(addr common.Address, field string) common.Hash {
    key := make([]byte, 0, 21+len(field))
    key = append(key, addr.Bytes()...)
    key = append(key, 0x00)
    key = append(key, field...)
    return common.BytesToHash(crypto.Keccak256(key))
}

// Stored fields per-validator at TOS3:
//   "selfStake" → 32-byte big-endian uint256 (standard EVM encoding)
//   "status"    → right-aligned uint8: 0x00 = inactive, 0x01 = active
```

`joinedBlock` is excluded from MVP. It would require passing the block number through
`sysaction.Execute()`, which currently has no such parameter. Plan to add in a future version.

#### 5b. Validator list slots (append-only index)

```go
// validatorCountSlot stores the total count of ever-registered addresses (uint64).
var validatorCountSlot = common.BytesToHash(
    crypto.Keccak256([]byte("dpos\x00validatorCount")))

// validatorListSlot(i) stores the i-th registered address (right-aligned, 0-based).
// The list is append-only; withdrawn validators remain with status=inactive.
func validatorListSlot(i uint64) common.Hash {
    var idx [8]byte
    binary.BigEndian.PutUint64(idx[:], i)
    return common.BytesToHash(
        crypto.Keccak256(append([]byte("dpos\x00validatorList\x00"), idx[:]...)))
}
```

#### 5c. Internal helpers

```go
func readValidatorCount(db vm.StateDB) uint64 {
    raw := db.GetState(params.ValidatorRegistryAddress, validatorCountSlot)
    return raw.Big().Uint64()
}

func writeValidatorCount(db vm.StateDB, n uint64) {
    var val common.Hash
    binary.BigEndian.PutUint64(val[24:], n) // right-aligned in 32 bytes
    db.SetState(params.ValidatorRegistryAddress, validatorCountSlot, val)
}

func readValidatorAt(db vm.StateDB, i uint64) common.Address {
    raw := db.GetState(params.ValidatorRegistryAddress, validatorListSlot(i))
    return common.BytesToAddress(raw[12:]) // address is right-aligned
}

func appendValidatorToList(db vm.StateDB, addr common.Address) {
    n := readValidatorCount(db)
    slot := validatorListSlot(n)
    var val common.Hash
    copy(val[12:], addr.Bytes())
    db.SetState(params.ValidatorRegistryAddress, slot, val)
    writeValidatorCount(db, n+1)
}

func writeSelfStake(db vm.StateDB, addr common.Address, stake *big.Int) {
    db.SetState(params.ValidatorRegistryAddress, validatorSlot(addr, "selfStake"),
        common.BigToHash(stake))
}

func WriteValidatorStatus(db vm.StateDB, addr common.Address, s ValidatorStatus) {
    var val common.Hash
    val[31] = byte(s)
    db.SetState(params.ValidatorRegistryAddress, validatorSlot(addr, "status"), val)
}
```

#### 5d. Public API of `validator/state.go`

```go
// ReadSelfStake returns the locked stake for addr (0 if not registered).
func ReadSelfStake(db vm.StateDB, addr common.Address) *big.Int {
    raw := db.GetState(params.ValidatorRegistryAddress, validatorSlot(addr, "selfStake"))
    return raw.Big()
}

// ReadValidatorStatus returns the current status for addr.
func ReadValidatorStatus(db vm.StateDB, addr common.Address) ValidatorStatus {
    raw := db.GetState(params.ValidatorRegistryAddress, validatorSlot(addr, "status"))
    return ValidatorStatus(raw[31])
}

// ReadActiveValidators returns up to maxValidators active validators.
//
// Two-phase sort (R2-M2 fix):
//   Phase 1 — collect all registered entries into memory (O(N) StateDB reads total).
//   Phase 2 — filter active, sort by stake desc (address asc as tiebreak), truncate.
//   Phase 3 — re-sort the truncated result by address ascending (deterministic round-robin).
//
// Pre-loading all stakes into a []validatorEntry avoids the O(N log N) StateDB reads
// that would result from calling ReadSelfStake inside sort.SliceStable comparisons.
func ReadActiveValidators(db vm.StateDB, maxValidators uint64) []common.Address {
    count := readValidatorCount(db)

    type entry struct {
        addr  common.Address
        stake *big.Int
    }

    // Phase 1: read all entries in one pass (O(N) reads).
    entries := make([]entry, 0, count)
    for i := uint64(0); i < count; i++ {
        addr := readValidatorAt(db, i)
        if ReadValidatorStatus(db, addr) == Active {
            entries = append(entries, entry{addr, ReadSelfStake(db, addr)})
        }
    }

    // Phase 2: sort by stake descending; address ascending as tiebreak (stable).
    sort.SliceStable(entries, func(i, j int) bool {
        cmp := entries[i].stake.Cmp(entries[j].stake)
        if cmp != 0 {
            return cmp > 0 // higher stake first
        }
        return bytes.Compare(entries[i].addr[:], entries[j].addr[:]) < 0
    })
    if uint64(len(entries)) > maxValidators {
        entries = entries[:maxValidators]
    }

    // Phase 3: re-sort by address ascending on the truncated slice.
    result := make([]common.Address, len(entries))
    for i, e := range entries {
        result[i] = e.addr
    }
    sort.Sort(addressAscending(result))
    return result
}
```

#### 5e. `validator/types.go`

```go
type ValidatorStatus uint8

const (
    Inactive ValidatorStatus = 0
    Active   ValidatorStatus = 1
)

var (
    ErrAlreadyRegistered   = errors.New("validator: already registered")
    ErrNotActive           = errors.New("validator: not active")
    ErrInsufficientStake   = errors.New("validator: insufficient stake")
    ErrInsufficientBalance = errors.New("validator: sender balance below stake amount")
    ErrTOS3BalanceBroken   = errors.New("validator: TOS3 balance invariant violated")
)
```

---

### 6. System Action Handler (`validator/handler.go`)

```go
func init() { sysaction.DefaultRegistry.Register(&validatorHandler{}) }
```

#### 6a. VALIDATOR_REGISTER

```go
func (h *validatorHandler) handleRegister(ctx *sysaction.Context, _ *sysaction.SysAction) error {
    // ── Validation phase (no state writes) ──────────────────────────────────

    // 1. Stake must meet minimum.
    if ctx.Value.Cmp(params.DPoSMinValidatorStake) < 0 {
        return ErrInsufficientStake
    }

    // 2. R2-C5: explicit sender balance check.
    //    For EIP-1559 txs, buyGas() already includes tx.Value in its balance check.
    //    For legacy txs (no gasFeeCap), buyGas() only checks gas*gasPrice — the value
    //    is NOT checked, so SubBalance below could make the balance negative without
    //    this guard.
    if ctx.StateDB.GetBalance(ctx.From).Cmp(ctx.Value) < 0 {
        return ErrInsufficientBalance
    }

    // 3. Reject duplicate registration.
    //    After VALIDATOR_WITHDRAW selfStake is reset to 0, so re-registration is
    //    permitted (documented known behaviour, intentional for MVP).
    if ReadSelfStake(ctx.StateDB, ctx.From).Sign() != 0 {
        return ErrAlreadyRegistered
    }

    // 4. R2-C2: record whether this is a first-ever registration BEFORE any writes.
    isNewRegistration := ReadSelfStake(ctx.StateDB, ctx.From).Sign() == 0
    //    (Always true here since check #3 passed, but evaluated before mutation.)

    // ── Mutation phase ───────────────────────────────────────────────────────

    // 5. Lock stake: sender → TOS3.
    ctx.StateDB.SubBalance(ctx.From, ctx.Value)
    ctx.StateDB.AddBalance(params.ValidatorRegistryAddress, ctx.Value)

    // 6. Write per-validator fields.
    writeSelfStake(ctx.StateDB, ctx.From, ctx.Value)
    WriteValidatorStatus(ctx.StateDB, ctx.From, Active)

    // 7. Append address to list only on first-ever registration.
    //    Re-registration after withdraw: address already in list (status was inactive,
    //    now active again). Do NOT append → no duplicates in the list.
    if isNewRegistration {
        appendValidatorToList(ctx.StateDB, ctx.From)
    }

    return nil
}
```

> **Atomicity**: all validation precedes all writes. A failed validation returns before any
> `StateDB` mutation, leaving state unchanged. No `Snapshot()/RevertToSnapshot()` needed.

#### 6b. VALIDATOR_WITHDRAW

```go
func (h *validatorHandler) handleWithdraw(ctx *sysaction.Context, _ *sysaction.SysAction) error {
    // ── Validation phase ─────────────────────────────────────────────────────

    if ReadValidatorStatus(ctx.StateDB, ctx.From) != Active {
        return ErrNotActive
    }
    selfStake := ReadSelfStake(ctx.StateDB, ctx.From)

    // Defensive: TOS3 balance should always >= selfStake if invariant holds.
    // Guards against future bugs that could corrupt the accounting.
    if ctx.StateDB.GetBalance(params.ValidatorRegistryAddress).Cmp(selfStake) < 0 {
        return ErrTOS3BalanceBroken
    }

    // ── Mutation phase ───────────────────────────────────────────────────────

    // Refund stake: TOS3 → sender.
    ctx.StateDB.SubBalance(params.ValidatorRegistryAddress, selfStake)
    ctx.StateDB.AddBalance(ctx.From, selfStake)

    // Clear fields. Address remains in list; status=Inactive is the tombstone.
    writeSelfStake(ctx.StateDB, ctx.From, new(big.Int))
    WriteValidatorStatus(ctx.StateDB, ctx.From, Inactive)

    // MVP: no lockup period. Funds returned immediately.
    return nil
}
```

---

### 7. Snapshot (`consensus/dpos/snapshot.go`)

#### 7a. Extra data format

```
Genesis block (number == 0):
  [32B vanity][N × 20B validator addresses]         ← NO seal
  Length: 32 + N*20  (N ≥ 1)

Non-genesis, non-epoch block (number % Epoch != 0):
  [32B vanity][65B secp256k1 seal]
  Length: 97

Non-genesis epoch block (number % Epoch == 0, number > 0):
  [32B vanity][N × 20B validator addresses][65B secp256k1 seal]
  Length: 32 + N*20 + 65  where (length - 97) % 20 == 0
```

```go
const (
    extraVanity = 32                     // fixed prefix
    extraSeal   = crypto.SignatureLength // 65 bytes
)
```

#### 7b. `addressAscending` sort type (R2-C1)

```go
// addressAscending sorts common.Address slices in ascending byte order.
// Required for deterministic validator ordering in inturn() and Extra encoding.
type addressAscending []common.Address

func (a addressAscending) Len() int      { return len(a) }
func (a addressAscending) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a addressAscending) Less(i, j int) bool {
    return bytes.Compare(a[i][:], a[j][:]) < 0
}
```

#### 7c. Snapshot structure

```go
type Snapshot struct {
    config   *params.DPoSConfig
    sigcache *lru.ARCCache // hash → common.Address, shared with engine

    Number        uint64                     `json:"number"`
    Hash          common.Hash                `json:"hash"`
    Validators    []common.Address           `json:"validators"` // always sorted ascending by address
    ValidatorsMap map[common.Address]struct{} `json:"validatorsMap"`
    Recents       map[uint64]common.Address   `json:"recents"`   // blockNum → signer
}
```

`Validators` is always in ascending-address order. This is the canonical order used by
`inturn()` and written into `header.Extra` at epoch blocks.

#### 7d. newSnapshot

```go
func newSnapshot(
    config     *params.DPoSConfig,
    sigcache   *lru.ARCCache,
    number     uint64,
    hash       common.Hash,
    validators []common.Address, // must already be sorted ascending by address
) (*Snapshot, error) {
    if len(validators) == 0 {
        return nil, errors.New("dpos: empty validator set")
    }
    snap := &Snapshot{
        config:        config,
        sigcache:      sigcache,
        Number:        number,
        Hash:          hash,
        Validators:    validators,
        ValidatorsMap: make(map[common.Address]struct{}, len(validators)),
        Recents:       make(map[uint64]common.Address),
    }
    for _, v := range validators {
        snap.ValidatorsMap[v] = struct{}{}
    }
    return snap, nil
}
```

#### 7e. copy()

```go
// copy returns a deep copy of the snapshot.
// apply() MUST call copy() before mutating: LRU-cached snapshots are shared across
// goroutines; in-place mutation causes data races.
func (s *Snapshot) copy() *Snapshot {
    cpy := &Snapshot{
        config:        s.config,
        sigcache:      s.sigcache,
        Number:        s.Number,
        Hash:          s.Hash,
        Validators:    make([]common.Address, len(s.Validators)),
        ValidatorsMap: make(map[common.Address]struct{}, len(s.ValidatorsMap)),
        Recents:       make(map[uint64]common.Address, len(s.Recents)),
    }
    copy(cpy.Validators, s.Validators)
    for v := range s.ValidatorsMap {
        cpy.ValidatorsMap[v] = struct{}{}
    }
    for block, signer := range s.Recents {
        cpy.Recents[block] = signer
    }
    return cpy
}
```

#### 7f. inturn / recentlySigned

```go
// inturn returns true if validator is the expected proposer for the given block number.
// Guard against empty Validators (newSnapshot prevents it, but defensive here too).
func (s *Snapshot) inturn(number uint64, validator common.Address) bool {
    if len(s.Validators) == 0 {
        return false
    }
    for i, v := range s.Validators {
        if v == validator {
            return number%uint64(len(s.Validators)) == uint64(i)
        }
    }
    return false
}

// recentlySigned returns true if validator signed within the last len(Validators)/2+1 blocks.
func (s *Snapshot) recentlySigned(validator common.Address) bool {
    for _, recent := range s.Recents {
        if recent == validator {
            return true
        }
    }
    return false
}
```

#### 7g. apply()

```go
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
    if len(headers) == 0 {
        return s, nil
    }
    // Sanity: contiguous range immediately following s.
    for i := 0; i < len(headers)-1; i++ {
        if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
            return nil, errInvalidChain
        }
    }
    if headers[0].Number.Uint64() != s.Number+1 {
        return nil, errInvalidChain
    }

    // Always deep-copy before mutating (concurrent readers share LRU-cached snapshot).
    snap := s.copy()

    for _, header := range headers {
        number := header.Number.Uint64()

        // Evict oldest Recents entry to allow that validator to sign again.
        limit := uint64(len(snap.Validators)/2 + 1)
        if number >= limit {
            delete(snap.Recents, number-limit)
        }

        // Recover signer; validate membership and recency.
        signer, err := ecrecover(header, snap.sigcache)
        if err != nil {
            return nil, err
        }
        if _, ok := snap.ValidatorsMap[signer]; !ok {
            return nil, errUnauthorizedValidator
        }
        if snap.recentlySigned(signer) {
            return nil, errRecentlySigned
        }
        snap.Recents[number] = signer

        // Epoch boundary: update validator set from header.Extra.
        //
        // R2-H1 NOTE (accepted MVP limitation): apply() has no access to StateDB,
        // so it cannot independently verify that header.Extra matches TOS3 state.
        // Honest nodes use FinalizeAndAssemble which always reads TOS3 correctly.
        // A byzantine validator (with >0% but <50% stake) could embed a wrong list,
        // but cannot sustain a fork since honest nodes build on the honest chain.
        // Full protection requires adding an error return to consensus.Engine.Finalize()
        // — planned for a future refactor.
        if number%s.config.Epoch == 0 {
            validators, err := parseEpochValidators(header.Extra)
            if err != nil {
                return nil, err
            }
            if len(validators) == 0 {
                return nil, errors.New("dpos: epoch produced empty validator set")
            }
            snap.Validators = validators
            snap.ValidatorsMap = make(map[common.Address]struct{}, len(validators))
            for _, v := range validators {
                snap.ValidatorsMap[v] = struct{}{}
            }
            // Trim Recents entries outside the new window.
            newLimit := uint64(len(validators)/2 + 1)
            for blockNum := range snap.Recents {
                if number >= newLimit && blockNum < number-newLimit {
                    delete(snap.Recents, blockNum)
                }
            }
        }
    }

    snap.Number += uint64(len(headers))
    snap.Hash = headers[len(headers)-1].Hash()
    return snap, nil
}
```

#### 7h. Extra parsers

```go
// parseEpochValidators extracts the validator list from an epoch block's Extra.
// Format: [32B vanity][N×20B addresses][65B seal]
func parseEpochValidators(extra []byte) ([]common.Address, error) {
    if len(extra) < extraVanity+extraSeal {
        return nil, errMissingSignature
    }
    payload := extra[extraVanity : len(extra)-extraSeal]
    if len(payload)%common.AddressLength != 0 {
        return nil, errInvalidCheckpointValidators
    }
    n := len(payload) / common.AddressLength
    out := make([]common.Address, n)
    for i := range out {
        copy(out[i][:], payload[i*common.AddressLength:])
    }
    return out, nil
}

// parseGenesisValidators extracts the validator list from block-0 Extra (no seal).
// Format: [32B vanity][N×20B addresses]
func parseGenesisValidators(extra []byte) ([]common.Address, error) {
    if len(extra) < extraVanity {
        return nil, errMissingVanity
    }
    payload := extra[extraVanity:]
    if len(payload)%common.AddressLength != 0 {
        return nil, errInvalidCheckpointValidators
    }
    n := len(payload) / common.AddressLength
    out := make([]common.Address, n)
    for i := range out {
        copy(out[i][:], payload[i*common.AddressLength:])
    }
    return out, nil
}
```

#### 7i. Snapshot persistence

```go
// DB key prefix "dpos-" avoids collision with Clique's "clique-" prefix.

func loadSnapshot(config *params.DPoSConfig, sigcache *lru.ARCCache,
    db tosdb.Database, hash common.Hash) (*Snapshot, error) {
    blob, err := db.Get(append([]byte("dpos-"), hash[:]...))
    if err != nil {
        return nil, err
    }
    snap := new(Snapshot)
    if err := json.Unmarshal(blob, snap); err != nil {
        return nil, err
    }
    snap.config = config
    snap.sigcache = sigcache
    return snap, nil
}

// store persists the snapshot to db.
// R2-C3: callers must guard with "if d.db != nil" — NewFaker passes nil db.
func (s *Snapshot) store(db tosdb.Database) error {
    blob, err := json.Marshal(s)
    if err != nil {
        return err
    }
    return db.Put(append([]byte("dpos-"), s.Hash[:]...), blob)
}
```

---

### 8. DPoS Engine (`consensus/dpos/dpos.go`)

#### 8a. Package-level declarations

```go
import (
    lru        "github.com/hashicorp/golang-lru" // *lru.ARCCache
    "math/rand"                                   // for wiggle delay (not crypto/rand)
    ...
)

var (
    diffInTurn = big.NewInt(2) // in-turn validator
    diffNoTurn = big.NewInt(1) // out-of-turn validator
)

const (
    extraVanity            = 32
    extraSeal              = 65  // crypto.SignatureLength
    inmemorySnapshots      = 128
    inmemorySignatures     = 4096
    wiggleTime             = 500 * time.Millisecond
    allowedFutureBlockTime = uint64(5) // R2-M1: seconds of clock-skew grace period
)

// SignerFn is the callback used by the miner to sign a header.
type SignerFn func(accounts.Account, string, []byte) ([]byte, error)
```

#### 8b. DPoS struct

```go
type DPoS struct {
    config     *params.DPoSConfig
    db         tosdb.Database    // nil in NewFaker()
    recents    *lru.ARCCache     // hash → *Snapshot (128 entries)
    signatures *lru.ARCCache     // hash → common.Address (4096 entries)

    validator common.Address
    signFn    SignerFn
    lock      sync.RWMutex

    fakeDiff bool // skip difficulty check in tests
}
```

#### 8c. New / NewFaker (R2-C4)

```go
// New creates a DPoS engine. Returns error if config values are invalid.
func New(config *params.DPoSConfig, db tosdb.Database) (*DPoS, error) {
    if config.Epoch == 0 {
        return nil, errors.New("dpos: epoch must be > 0")
    }
    if config.Period == 0 {
        return nil, errors.New("dpos: period must be > 0")
    }
    if config.MaxValidators == 0 {
        return nil, errors.New("dpos: maxValidators must be > 0")
    }
    recents, _    := lru.NewARC(inmemorySnapshots)
    signatures, _ := lru.NewARC(inmemorySignatures)
    return &DPoS{config: config, db: db, recents: recents, signatures: signatures}, nil
}

// NewFaker returns an engine suitable for unit tests. Skips difficulty checks
// and uses nil db (no disk persistence). Panics on invalid config (test hygiene).
func NewFaker() *DPoS {
    d, err := New(&params.DPoSConfig{Epoch: 200, MaxValidators: 21, Period: 3}, nil)
    if err != nil {
        panic(err)
    }
    d.fakeDiff = true
    return d
}
```

`CreateConsensusEngine` in `tos/tosconfig/config.go` must propagate the error from `New()`.

#### 8d. Authorize

```go
// Authorize injects the signing key for this validator. Called by the miner at startup.
func (d *DPoS) Authorize(validator common.Address, signFn SignerFn) {
    d.lock.Lock()
    defer d.lock.Unlock()
    d.validator = validator
    d.signFn = signFn
}
```

#### 8e. SealHash / encodeSigHeader

```go
// SealHash (method) satisfies consensus.Engine.
func (d *DPoS) SealHash(header *types.Header) common.Hash { return SealHash(header) }

// SealHash (package function) returns the hash of a block prior to sealing.
// Covers the entire header RLP except the last 65 bytes of Extra (the seal itself).
func SealHash(header *types.Header) (hash common.Hash) {
    hasher := sha3.NewLegacyKeccak256()
    encodeSigHeader(hasher, header)
    hasher.(crypto.KeccakState).Read(hash[:])
    return hash
}

// encodeSigHeader writes the RLP of the header without its seal.
// Panics if Extra < 65 bytes; callers must validate length first.
func encodeSigHeader(w io.Writer, header *types.Header) {
    enc := []interface{}{
        header.ParentHash, header.UncleHash, header.Coinbase,
        header.Root, header.TxHash, header.ReceiptHash, header.Bloom,
        header.Difficulty, header.Number, header.GasLimit, header.GasUsed,
        header.Time,
        header.Extra[:len(header.Extra)-extraSeal], // strip seal
        header.MixDigest, header.Nonce,
    }
    rlp.Encode(w, enc)
}

// ecrecover extracts the validator address from a signed header; caches in sigcache.
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
    hash := header.Hash()
    if addr, ok := sigcache.Get(hash); ok {
        return addr.(common.Address), nil
    }
    if len(header.Extra) < extraSeal {
        return common.Address{}, errMissingSignature
    }
    sig := header.Extra[len(header.Extra)-extraSeal:]
    pub, err := crypto.Ecrecover(SealHash(header).Bytes(), sig)
    if err != nil {
        return common.Address{}, err
    }
    var signer common.Address
    copy(signer[:], crypto.Keccak256(pub[1:])[12:])
    sigcache.Add(hash, signer)
    return signer, nil
}
```

#### 8f. Author

```go
func (d *DPoS) Author(header *types.Header) (common.Address, error) {
    return ecrecover(header, d.signatures)
}
```

#### 8g. VerifyHeader / VerifyHeaders

```go
func (d *DPoS) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
    return d.verifyHeader(chain, header, nil)
}

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

func (d *DPoS) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
    if header.Number == nil {
        return errUnknownBlock
    }
    number := header.Number.Uint64()

    // Reject far-future blocks (R2-M1 constant defined).
    if header.Time > uint64(time.Now().Unix())+allowedFutureBlockTime {
        return consensus.ErrFutureBlock
    }
    // DPoS produces no uncles.
    if header.UncleHash != types.EmptyUncleHash {
        return errInvalidUncleHash
    }
    // No PoW: MixDigest must be zero.
    if header.MixDigest != (common.Hash{}) {
        return errInvalidMixDigest
    }
    // Difficulty must be exactly 1 or 2 (for non-genesis blocks).
    if number > 0 {
        if header.Difficulty == nil ||
            (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
            return errInvalidDifficulty
        }
    }

    // Validate Extra length and structure.
    if number == 0 {
        // Genesis: no seal; just vanity + validator addresses.
        if len(header.Extra) < extraVanity {
            return errMissingVanity
        }
        if (len(header.Extra)-extraVanity)%common.AddressLength != 0 {
            return errInvalidCheckpointValidators
        }
    } else {
        if len(header.Extra) < extraVanity+extraSeal {
            return errMissingSignature
        }
        isEpoch := number%d.config.Epoch == 0
        validatorBytes := len(header.Extra) - extraVanity - extraSeal
        if !isEpoch && validatorBytes != 0 {
            return errExtraValidators
        }
        if isEpoch && validatorBytes%common.AddressLength != 0 {
            return errInvalidCheckpointValidators
        }
    }

    if header.GasLimit > params.MaxGasLimit {
        return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
    }

    // Genesis is always valid (no parent, no seal).
    if number == 0 {
        return nil
    }
    return d.verifyCascadingFields(chain, header, parents)
}

func (d *DPoS) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
    number := header.Number.Uint64()

    var parent *types.Header
    if len(parents) > 0 {
        parent = parents[len(parents)-1]
    } else {
        parent = chain.GetHeader(header.ParentHash, number-1)
    }
    if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
        return consensus.ErrUnknownAncestor
    }
    if header.Time < parent.Time+d.config.Period {
        return errInvalidTimestamp
    }

    snap, err := d.snapshot(chain, number-1, header.ParentHash, parents)
    if err != nil {
        return err
    }
    return d.verifySeal(snap, header)
}

func (d *DPoS) verifySeal(snap *Snapshot, header *types.Header) error {
    if header.Number.Uint64() == 0 {
        return errUnknownBlock
    }
    signer, err := ecrecover(header, d.signatures)
    if err != nil {
        return err
    }
    // Signer must equal Coinbase (prevents reward redirection to third parties).
    if signer != header.Coinbase {
        return errInvalidCoinbase
    }
    if _, ok := snap.ValidatorsMap[signer]; !ok {
        return errUnauthorizedValidator
    }
    if snap.recentlySigned(signer) {
        return errRecentlySigned
    }
    if !d.fakeDiff {
        inturn := snap.inturn(header.Number.Uint64(), signer)
        if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
            return errWrongDifficulty
        }
        if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
            return errWrongDifficulty
        }
    }
    return nil
}
```

#### 8h. snapshot() — multi-level fallback

```go
func (d *DPoS) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
    var (
        headers []*types.Header
        snap    *Snapshot
    )

    for snap == nil {
        // 1. In-memory LRU cache.
        if s, ok := d.recents.Get(hash); ok {
            snap = s.(*Snapshot)
            break
        }

        // 2. Genesis: parse Extra directly (no seal on block 0).
        if number == 0 {
            genesis := chain.GetHeaderByNumber(0)
            if genesis == nil {
                return nil, errors.New("dpos: missing genesis block")
            }
            validators, err := parseGenesisValidators(genesis.Extra)
            if err != nil {
                return nil, fmt.Errorf("dpos: genesis extra: %w", err)
            }
            sort.Sort(addressAscending(validators))
            snap, err = newSnapshot(d.config, d.signatures, 0, genesis.Hash(), validators)
            if err != nil {
                return nil, err
            }
            // R2-C3: guard nil db (NewFaker uses nil).
            if d.db != nil {
                if err := snap.store(d.db); err != nil {
                    return nil, err
                }
            }
            break
        }

        // 3. Epoch checkpoint from disk.
        if number%d.config.Epoch == 0 && d.db != nil {
            if s, err := loadSnapshot(d.config, d.signatures, d.db, hash); err == nil {
                snap = s
                break
            }
        }

        // 4. Walk backwards: collect headers until we find a cached/checkpoint ancestor.
        var header *types.Header
        if len(parents) > 0 {
            header = parents[len(parents)-1]
            if header.Hash() != hash || header.Number.Uint64() != number {
                return nil, consensus.ErrUnknownAncestor
            }
            parents = parents[:len(parents)-1]
        } else {
            header = chain.GetHeader(hash, number)
            if header == nil {
                return nil, consensus.ErrUnknownAncestor
            }
        }
        headers = append(headers, header)
        number, hash = number-1, header.ParentHash
    }

    // Replay collected headers (oldest first) onto the base snapshot.
    for i, j := 0, len(headers)-1; i < j; i, j = i+1, j-1 {
        headers[i], headers[j] = headers[j], headers[i]
    }
    var err error
    snap, err = snap.apply(headers)
    if err != nil {
        return nil, err
    }
    d.recents.Add(snap.Hash, snap)

    // Persist epoch snapshots.
    if snap.Number%d.config.Epoch == 0 && len(headers) > 0 && d.db != nil {
        if err := snap.store(d.db); err != nil {
            return nil, err
        }
    }
    return snap, nil
}
```

#### 8i. Prepare

```go
func (d *DPoS) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
    d.lock.RLock()
    validator := d.validator
    d.lock.RUnlock()

    header.Coinbase = validator
    header.Nonce = types.BlockNonce{}

    number := header.Number.Uint64()
    snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
    if err != nil {
        return err
    }
    header.Difficulty = calcDifficulty(snap, validator)

    // Ensure Extra has vanity prefix.
    if len(header.Extra) < extraVanity {
        header.Extra = append(header.Extra,
            bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
    }
    header.Extra = header.Extra[:extraVanity]
    // Reserve space for the seal; FinalizeAndAssemble may insert validator list before it.
    header.Extra = append(header.Extra, make([]byte, extraSeal)...)

    // Set block timestamp.
    parent := chain.GetHeader(header.ParentHash, number-1)
    if parent == nil {
        return consensus.ErrUnknownAncestor
    }
    header.Time = parent.Time + d.config.Period
    if now := uint64(time.Now().Unix()); header.Time < now {
        header.Time = now
    }
    return nil
}
```

#### 8j. Finalize / FinalizeAndAssemble

```go
// Finalize adds the block reward and computes the state root.
//
// R2-H1 — Accepted MVP limitation: Finalize() has no error return in
// consensus.Engine (gtos interface, line 92-93 of consensus/consensus.go), so we
// cannot verify that header.Extra matches TOS3 state here. FinalizeAndAssemble
// (the honest proposer path) always reads TOS3 and embeds the correct list.
// A byzantine validator could produce an epoch block with a wrong Extra, but
// cannot sustain a fork without >50% of validators. Mitigation: plan to add
// error return to consensus.Engine.Finalize() in a future interface revision.
func (d *DPoS) Finalize(chain consensus.ChainHeaderReader, header *types.Header,
    state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {

    state.AddBalance(header.Coinbase, params.DPoSBlockReward)
    header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
    header.UncleHash = types.EmptyUncleHash
}

func (d *DPoS) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header,
    state *state.StateDB, txs []*types.Transaction, uncles []*types.Header,
    receipts []*types.Receipt) (*types.Block, error) {

    number := header.Number.Uint64()

    // At epoch boundaries, embed the current active validator set into Extra.
    if number%d.config.Epoch == 0 {
        validators := validator.ReadActiveValidators(state, d.config.MaxValidators)
        if len(validators) == 0 {
            return nil, errors.New("dpos: no active validators at epoch boundary")
        }
        // validators is already address-sorted (ReadActiveValidators phase 3).
        vanity := header.Extra[:extraVanity]
        extra := make([]byte, extraVanity+len(validators)*common.AddressLength+extraSeal)
        copy(extra, vanity)
        for i, v := range validators {
            copy(extra[extraVanity+i*common.AddressLength:], v.Bytes())
        }
        header.Extra = extra // seal placeholder is the trailing extraSeal zero bytes
    }

    d.Finalize(chain, header, state, txs, uncles)
    return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}
```

#### 8k. Seal

```go
func (d *DPoS) Seal(chain consensus.ChainHeaderReader, block *types.Block,
    results chan<- *types.Block, stop <-chan struct{}) error {

    header := block.Header()
    number := header.Number.Uint64()
    if number == 0 {
        return errUnknownBlock
    }
    if d.config.Period == 0 && len(block.Transactions()) == 0 {
        return errors.New("dpos: sealing paused, no transactions")
    }

    d.lock.RLock()
    validator, signFn := d.validator, d.signFn
    d.lock.RUnlock()

    snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
    if err != nil {
        return err
    }
    if _, ok := snap.ValidatorsMap[validator]; !ok {
        return errUnauthorizedValidator
    }
    for seen, recent := range snap.Recents {
        if recent == validator {
            limit := uint64(len(snap.Validators)/2 + 1)
            if number < limit || seen > number-limit {
                return errors.New("dpos: signed recently, must wait")
            }
        }
    }

    // Compute delay. In-turn: honour header.Time. Out-of-turn: add random wiggle.
    delay := time.Unix(int64(header.Time), 0).Sub(time.Now())
    if header.Difficulty.Cmp(diffNoTurn) == 0 {
        // math/rand is intentional: delay randomness is not a security property.
        wiggle := time.Duration(len(snap.Validators)/2+1) * wiggleTime
        delay += time.Duration(rand.Int63n(int64(wiggle)))
    }

    // Sign with the DPoS MIME type (R2-L1).
    sighash, err := signFn(accounts.Account{Address: validator},
        accounts.MimetypeDPoS, SealHash(header).Bytes())
    if err != nil {
        return err
    }
    copy(header.Extra[len(header.Extra)-extraSeal:], sighash)

    go func() {
        select {
        case <-stop:
            return
        case <-time.After(delay):
        }
        select {
        case results <- block.WithSeal(header):
        default:
            log.Warn("DPoS sealing result not read by miner", "sealhash", SealHash(header))
        }
    }()
    return nil
}
```

#### 8l. CalcDifficulty / VerifyUncles / APIs / Close

```go
func (d *DPoS) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
    snap, err := d.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
    if err != nil {
        return nil
    }
    d.lock.RLock()
    validator := d.validator
    d.lock.RUnlock()
    return calcDifficulty(snap, validator)
}

func calcDifficulty(snap *Snapshot, validator common.Address) *big.Int {
    if snap.inturn(snap.Number+1, validator) {
        return new(big.Int).Set(diffInTurn)
    }
    return new(big.Int).Set(diffNoTurn)
}

func (d *DPoS) VerifyUncles(_ consensus.ChainReader, block *types.Block) error {
    if len(block.Uncles()) > 0 {
        return errors.New("dpos: uncles not allowed")
    }
    return nil
}

func (d *DPoS) APIs(chain consensus.ChainHeaderReader) []rpc.API {
    return []rpc.API{{Namespace: "dpos", Service: &API{chain: chain, dpos: d}}}
}

func (d *DPoS) Close() error { return nil }
```

---

### 9. Sentinel Errors (`consensus/dpos/dpos.go`)

```go
var (
    errUnknownBlock                = errors.New("dpos: unknown block")
    errUnauthorizedValidator       = errors.New("dpos: unauthorized validator")
    errRecentlySigned              = errors.New("dpos: validator signed recently")
    errInvalidCoinbase             = errors.New("dpos: signer does not match coinbase")
    errInvalidMixDigest            = errors.New("dpos: non-zero mix digest")
    errInvalidUncleHash            = errors.New("dpos: non-empty uncle hash")
    errInvalidDifficulty           = errors.New("dpos: invalid difficulty")
    errWrongDifficulty             = errors.New("dpos: wrong difficulty for turn")
    errMissingVanity               = errors.New("dpos: extra missing vanity")
    errMissingSignature            = errors.New("dpos: extra missing seal")
    errExtraValidators             = errors.New("dpos: non-epoch block has validator list")
    errInvalidCheckpointValidators = errors.New("dpos: invalid checkpoint validator list")
    errInvalidTimestamp            = errors.New("dpos: invalid timestamp")
    errInvalidChain                = errors.New("dpos: non-contiguous header chain")
)
```

---

### 10. RPC API (`consensus/dpos/api.go`)

```go
type API struct {
    chain consensus.ChainHeaderReader
    dpos  *DPoS
}

// dpos_getSnapshot → returns snapshot at block N (latest if omitted).
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*Snapshot, error) { ... }

// dpos_getValidators → returns current active validator addresses.
func (api *API) GetValidators(number *rpc.BlockNumber) ([]common.Address, error) { ... }
```

---

### 11. CreateConsensusEngine (`tos/tosconfig/config.go`)

```go
import "github.com/tos-network/gtos/consensus/dpos"

func CreateConsensusEngine(stack *node.Node, chainConfig *params.ChainConfig,
    config *tosash.Config, notify []string, noverify bool, db tosdb.Database) consensus.Engine {

    if chainConfig.DPoS != nil {
        // R2-C4: New() now returns error; propagate it.
        engine, err := dpos.New(chainConfig.DPoS, db)
        if err != nil {
            panic(fmt.Sprintf("invalid dpos config: %v", err))
        }
        return engine
    }
    if chainConfig.Clique != nil {
        return clique.New(chainConfig.Clique, db) // --dev path unchanged
    }
    // Tosash PoW fallback (tests / legacy)
    ...
}
```

---

### 12. Backend (`tos/backend.go`)

```go
import _ "github.com/tos-network/gtos/validator" // registers VALIDATOR_* handlers via init()
```

---

## Import Dependency Graph (acyclic)

```
tos/backend.go   ──→ consensus/dpos/    creates engine
tos/backend.go   ──→ validator/         triggers init()
core/            ──→ consensus/         Engine interface only
core/            ──→ sysaction/
sysaction/       ──→ core/vm/           vm.StateDB interface
validator/       ──→ sysaction/         registers handler
validator/       ──→ params/
consensus/dpos/  ──→ consensus/         Engine interface
consensus/dpos/  ──→ validator/         ReadActiveValidators (FinalizeAndAssemble only)
consensus/dpos/  ──→ params/
consensus/dpos/  ──→ core/state/        *state.StateDB (Finalize signature)
```

---

## Genesis Block Configuration

```json
{
  "extraData": "0x<32-byte vanity hex><addr1 20B><addr2 20B>...<addrN 20B>"
}
```

Block 0 Extra has **no trailing seal** — genesis is never signed.
`--dev` mode: `chainConfig.DPoS == nil`, `chainConfig.Clique != nil` → Clique selected, no DPoS code runs.

---

## Known Accepted Limitation (MVP)

**Epoch Extra not verified against TOS3 during block import** (`Finalize()` has no error
return in `consensus.Engine`). Honest nodes always produce correct epoch blocks via
`FinalizeAndAssemble`. A byzantine validator with < 50% stake cannot sustain a fork.
Full protection requires extending `consensus.Engine.Finalize() error` — planned for
a future interface revision that also updates Clique, Tosash, and `core/state_processor.go`.

---

## Implementation Order

1. `accounts/accounts.go` — Add `MimetypeDPoS`
2. `params/tos_params.go` — Add TOS3 address, DPoS constants
3. `params/config.go` — Add `DPoSConfig` + `ChainConfig.DPoS`
4. `sysaction/types.go` — Add `VALIDATOR_REGISTER`, `VALIDATOR_WITHDRAW`
5. `validator/types.go` — `ValidatorStatus`, sentinel errors
6. `validator/state.go` — Slot helpers, `ReadActiveValidators` (with pre-loaded stakes)
7. `validator/handler.go` — Handler with `isNewRegistration` flag + sender balance check
8. `consensus/dpos/snapshot.go` — `addressAscending`, `Snapshot`, parsers, persistence
9. `consensus/dpos/dpos.go` — Engine: `New()` returns error, all methods, `snapshot()` with nil-db guards
10. `consensus/dpos/api.go` — RPC
11. `tos/tosconfig/config.go` — DPoS branch, propagate `New()` error
12. `tos/backend.go` — blank import of `validator`

---

## Verification

```bash
go build ./...

go test -short ./consensus/dpos/... ./validator/...

go test -short -p 48 -parallel 48 ./core/... ./consensus/... ./tos/...

go test -race ./consensus/dpos/... ./validator/...
```

### Required unit tests

| Test | What it covers |
|------|---------------|
| `TestNewInvalidConfig` | `New()` returns error for Epoch=0, Period=0, MaxValidators=0 |
| `TestEmptyValidatorSet` | `newSnapshot` errors; `inturn` returns false |
| `TestGenesisExtraParse` | `parseGenesisValidators`: N=0 error, N=1,21 ok, bad length error |
| `TestEpochExtraParse` | `parseEpochValidators`: requires vanity+seal, bad alignment error |
| `TestSealHashRoundTrip` | `ecrecover(sign(SealHash(h))) == signer` |
| `TestCoinbaseMismatch` | `verifySeal` rejects Coinbase ≠ signer |
| `TestRecentlySigned` | Block rejected when validator signs within N/2+1 window |
| `TestSnapshotDeepCopy` | Mutating applied snap does not affect original in LRU |
| `TestRegisterTwice` | Second `VALIDATOR_REGISTER` returns `ErrAlreadyRegistered` |
| `TestReregisterAfterWithdraw` | After withdraw, re-register succeeds; list has one entry |
| `TestWithdrawTOS3BalanceGuard` | Handler rejects when TOS3 balance < selfStake |
| `TestRegisterLegacyTxLowBalance` | Handler rejects when sender balance < stake value |
| `TestValidatorSortOrder` | Selection by stake desc, snapshot ordering by address asc |
| `TestReadActiveValidatorsPerf` | O(N) StateDB reads in collection phase (mocked db) |
| `TestNilDbFaker` | `NewFaker()` snapshot() does not panic; no store called |
| `TestAllowedFutureBlock` | Header 4s ahead accepted; 6s ahead rejected |
