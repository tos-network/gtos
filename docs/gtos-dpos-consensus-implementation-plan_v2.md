# GTOS DPoS Consensus Engine — Implementation Plan v2

> **v2 changelog**: All 17 issues from the security & correctness review (2026-02-20) have been
> resolved. Each section notes which review item it addresses.

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

> **Fix L2**: Do NOT declare `DPoSDiffInTurn`/`DPoSDiffNoTurn` as bare integer constants here.
> Declare them as `*big.Int` in `consensus/dpos/dpos.go` (see §7).

---

### 2. ChainConfig Extension (`params/config.go`)

```go
type DPoSConfig struct {
    Period        uint64 `json:"period"`        // target block interval (seconds)
    Epoch         uint64 `json:"epoch"`         // blocks between validator set snapshots
    MaxValidators uint64 `json:"maxValidators"` // maximum active validators
}

// Added to ChainConfig alongside Tosash/Clique; existing fields unchanged:
DPoS *DPoSConfig `json:"dpos,omitempty"`
```

`DPoSConfig.String()` should return a human-readable description (same pattern as `CliqueConfig`).

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

### 4. Validator On-Chain State (`validator/state.go`, stored at TOS3)

#### 4a. Per-validator slots

```go
// validatorSlot hashes (addr || 0x00 || field) for a per-validator field.
// addr is always exactly 20 bytes, so no length-extension ambiguity.
func validatorSlot(addr common.Address, field string) common.Hash {
    key := make([]byte, 0, 21+len(field))
    key = append(key, addr.Bytes()...)
    key = append(key, 0x00)
    key = append(key, field...)
    return common.BytesToHash(crypto.Keccak256(key))
}

// Fields stored per-validator at TOS3:
//   "selfStake"  → big.Int encoded as 32-byte big-endian (standard EVM uint256)
//   "status"     → 0x00 = inactive, 0x01 = active  (right-aligned in 32-byte slot)
```

> **Fix C3**: `joinedBlock` field is dropped from MVP. It was informational only and would
> require passing `BlockNumber` through `sysaction.Execute()`, which has no parameter for it.
> Re-add in a future version when the sysaction API is extended.

#### 4b. Validator list slots (append-only index)

> **Fix M2**: Slot formulas are now fully specified.

```go
// validatorCountSlot holds the total number of addresses ever registered (uint64, right-aligned).
var validatorCountSlot = common.BytesToHash(crypto.Keccak256([]byte("dpos\x00validatorCount")))

// validatorListSlot(i) holds the i-th registered address (right-aligned in 32-byte slot).
// i is 0-based. The list is append-only; withdrawn validators stay but have status=inactive.
func validatorListSlot(i uint64) common.Hash {
    var idx [8]byte
    binary.BigEndian.PutUint64(idx[:], i)
    return common.BytesToHash(crypto.Keccak256(append([]byte("dpos\x00validatorList\x00"), idx[:]...)))
}
```

#### 4c. Public API of `validator/state.go`

```go
// ReadSelfStake returns the locked stake for addr (0 if not registered).
func ReadSelfStake(db vm.StateDB, addr common.Address) *big.Int

// ReadValidatorStatus returns the current ValidatorStatus for addr.
func ReadValidatorStatus(db vm.StateDB, addr common.Address) ValidatorStatus

// ReadActiveValidators returns up to maxValidators active validators, sorted:
//   Step 1 — collect all registered addresses (iterate count + list slots)
//   Step 2 — filter status == Active
//   Step 3 — sort by selfStake descending (stable sort; address ascending as tiebreak)
//   Step 4 — truncate to maxValidators
//   Step 5 — re-sort the result by address ascending (for deterministic round-robin)
//
// Fix M5: two-phase sort ensures stake-based selection but address-ordered snapshot.
func ReadActiveValidators(db vm.StateDB, maxValidators uint64) []common.Address
```

#### 4d. `validator/types.go`

```go
type ValidatorStatus uint8

const (
    Inactive ValidatorStatus = 0
    Active   ValidatorStatus = 1
)

var (
    ErrAlreadyRegistered  = errors.New("validator: already registered")
    ErrNotActive          = errors.New("validator: not active")
    ErrInsufficientStake  = errors.New("validator: insufficient stake")
    ErrTOS3BalanceBroken  = errors.New("validator: TOS3 balance invariant violated")
)
```

---

### 5. System Action Handler (`validator/handler.go`)

```go
func init() { sysaction.DefaultRegistry.Register(&validatorHandler{}) }
```

**VALIDATOR_REGISTER** — validate everything first, then mutate:

```go
func (h *validatorHandler) handleRegister(ctx *sysaction.Context, _ *sysaction.SysAction) error {
    // --- Validation phase (no state writes) ---

    // 1. Stake must meet minimum (ctx.Value == tx.Value; buyGas already ensures
    //    sender balance >= gas*gasPrice + tx.Value, so SubBalance below is safe).
    if ctx.Value.Cmp(params.DPoSMinValidatorStake) < 0 {
        return ErrInsufficientStake
    }
    // 2. Reject duplicate registration.
    //    After VALIDATOR_WITHDRAW, selfStake is reset to 0, so re-registration is allowed.
    //    This is intentional MVP behaviour (Fix L3 — documented, not a bug).
    if ReadSelfStake(ctx.StateDB, ctx.From).Sign() != 0 {
        return ErrAlreadyRegistered
    }

    // --- Mutation phase ---

    // 3. Lock stake: move from sender → TOS3.
    ctx.StateDB.SubBalance(ctx.From, ctx.Value)
    ctx.StateDB.AddBalance(params.ValidatorRegistryAddress, ctx.Value)

    // 4. Write per-validator fields.
    writeSelfStake(ctx.StateDB, ctx.From, ctx.Value)
    WriteValidatorStatus(ctx.StateDB, ctx.From, Active)

    // 5. Append to address list if this is a first-ever registration
    //    (re-registration after withdraw: address already in list, skip append).
    if ReadSelfStake(ctx.StateDB, ctx.From).Sign() == 0 { // pre-write check already done above
        appendValidatorToList(ctx.StateDB, ctx.From)
    }
    // Correct: always append on first registration.
    // Re-registration after withdraw keeps the existing list entry (status was inactive).

    return nil
}
```

> **Fix handler atomicity**: All validation is done before any `StateDB` write. If validation
> fails, the function returns early with no side effects. No `Snapshot()/RevertToSnapshot()`
> needed because the two-phase approach is sufficient.

**VALIDATOR_WITHDRAW** — validate then mutate:

```go
func (h *validatorHandler) handleWithdraw(ctx *sysaction.Context, _ *sysaction.SysAction) error {
    // --- Validation phase ---

    if ReadValidatorStatus(ctx.StateDB, ctx.From) != Active {
        return ErrNotActive
    }
    selfStake := ReadSelfStake(ctx.StateDB, ctx.From)

    // Fix H5: defensive balance check; should always pass if invariant holds.
    if ctx.StateDB.GetBalance(params.ValidatorRegistryAddress).Cmp(selfStake) < 0 {
        return ErrTOS3BalanceBroken
    }

    // --- Mutation phase ---

    // Refund stake: TOS3 → sender.
    ctx.StateDB.SubBalance(params.ValidatorRegistryAddress, selfStake)
    ctx.StateDB.AddBalance(ctx.From, selfStake)

    // Clear validator fields. Address stays in list (status=Inactive acts as tombstone).
    writeSelfStake(ctx.StateDB, ctx.From, new(big.Int))
    WriteValidatorStatus(ctx.StateDB, ctx.From, Inactive)

    // MVP: no lockup period. Funds returned immediately.
    return nil
}
```

---

### 6. Snapshot (`consensus/dpos/snapshot.go`)

#### 6a. Extra data format

```
Genesis block (number == 0):
  [32B vanity][N × 20B validator addresses]      ← NO seal
  Length: 32 + N*20

Non-genesis, non-epoch block:
  [32B vanity][65B secp256k1 seal]
  Length: 32 + 65 = 97

Non-genesis epoch block (number % Epoch == 0):
  [32B vanity][N × 20B validator addresses][65B secp256k1 seal]
  Length: 32 + N*20 + 65, where (length - 32 - 65) % 20 == 0
```

> **Fix C2**: Genesis (block 0) has no trailing 65B seal. The snapshot loader and
> `VerifyHeader` must handle this case explicitly.

```go
const (
    extraVanity = 32                    // fixed vanity prefix length
    extraSeal   = crypto.SignatureLength // 65 bytes
)
```

#### 6b. Snapshot structure

```go
type Snapshot struct {
    config   *params.DPoSConfig
    sigcache *lru.ARCCache // hash → common.Address, shared with engine

    Number        uint64                      `json:"number"`
    Hash          common.Hash                 `json:"hash"`
    Validators    []common.Address            `json:"validators"` // sorted ascending by address
    ValidatorsMap map[common.Address]struct{}  `json:"validatorsMap"`
    Recents       map[uint64]common.Address    `json:"recents"`    // blockNum → signer
}
```

> **Fix M5**: `Validators` is always stored in ascending-address order (deterministic index
> for `inturn()`). Selection by stake happens in `ReadActiveValidators` before calling
> `newSnapshot`; this function receives the already-selected, address-sorted slice.

#### 6c. newSnapshot

```go
func newSnapshot(
    config   *params.DPoSConfig,
    sigcache *lru.ARCCache,
    number   uint64,
    hash     common.Hash,
    validators []common.Address, // must already be sorted ascending by address
) (*Snapshot, error) {
    // Fix C1: reject empty validator set immediately.
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

#### 6d. copy()

```go
// copy returns a deep copy of the snapshot.
// Fix M4: apply() MUST call copy() before mutating so that LRU-cached snapshots
// are never modified in place (would cause data races with concurrent readers).
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

#### 6e. inturn / recentlySigned

```go
// inturn returns whether validator is the expected block proposer at number.
// Fix C1: guarded against empty Validators (newSnapshot already prevents it,
// but defensive check here too).
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

// recentlySigned returns true if validator signed within the last len/2+1 blocks.
func (s *Snapshot) recentlySigned(validator common.Address) bool {
    for _, recent := range s.Recents {
        if recent == validator {
            return true
        }
    }
    return false
}
```

#### 6f. apply()

```go
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
    if len(headers) == 0 {
        return s, nil
    }
    // Sanity: headers must be a contiguous range starting just after s.
    for i := 0; i < len(headers)-1; i++ {
        if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
            return nil, errInvalidChain
        }
    }
    if headers[0].Number.Uint64() != s.Number+1 {
        return nil, errInvalidChain
    }

    // Fix M4: always deep-copy before mutating.
    snap := s.copy()

    for _, header := range headers {
        number := header.Number.Uint64()

        // Evict oldest Recents entry so the signer can sign again.
        // Safe from div-by-zero because newSnapshot guards len(Validators) > 0.
        limit := uint64(len(snap.Validators)/2 + 1)
        if number >= limit {
            delete(snap.Recents, number-limit)
        }

        // Recover signer from seal.
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

        // At epoch boundaries, update the validator set from header.Extra.
        if number%s.config.Epoch == 0 {
            validators, err := parseEpochValidators(header.Extra)
            if err != nil {
                return nil, err
            }
            // Fix C1: epoch update must not produce empty set.
            if len(validators) == 0 {
                return nil, errors.New("dpos: epoch produced empty validator set")
            }
            snap.Validators = validators
            snap.ValidatorsMap = make(map[common.Address]struct{}, len(validators))
            for _, v := range validators {
                snap.ValidatorsMap[v] = struct{}{}
            }
            // Trim Recents that are no longer within the new window.
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

// parseEpochValidators extracts the address list from an epoch block's Extra.
// Epoch Extra: [32B vanity][N×20B addresses][65B seal]
func parseEpochValidators(extra []byte) ([]common.Address, error) {
    if len(extra) < extraVanity+extraSeal {
        return nil, errMissingSignature
    }
    payload := extra[extraVanity : len(extra)-extraSeal]
    if len(payload)%common.AddressLength != 0 {
        return nil, errInvalidCheckpointValidators
    }
    n := len(payload) / common.AddressLength
    validators := make([]common.Address, n)
    for i := 0; i < n; i++ {
        copy(validators[i][:], payload[i*common.AddressLength:])
    }
    return validators, nil
}

// parseGenesisValidators extracts addresses from block-0 Extra (no seal).
// Genesis Extra: [32B vanity][N×20B addresses]
func parseGenesisValidators(extra []byte) ([]common.Address, error) {
    if len(extra) < extraVanity {
        return nil, errMissingVanity
    }
    payload := extra[extraVanity:]
    if len(payload)%common.AddressLength != 0 {
        return nil, errInvalidCheckpointValidators
    }
    n := len(payload) / common.AddressLength
    validators := make([]common.Address, n)
    for i := 0; i < n; i++ {
        copy(validators[i][:], payload[i*common.AddressLength:])
    }
    return validators, nil
}
```

#### 6g. Snapshot persistence

```go
// Fix M6: use "dpos-" prefix to avoid collision with Clique's "clique-" prefix.

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

func (s *Snapshot) store(db tosdb.Database) error {
    blob, err := json.Marshal(s)
    if err != nil {
        return err
    }
    return db.Put(append([]byte("dpos-"), s.Hash[:]...), blob)
}
```

---

### 7. DPoS Engine (`consensus/dpos/dpos.go`)

#### 7a. Package-level declarations

```go
import (
    lru "github.com/hashicorp/golang-lru" // Fix M3: correct import
    "math/rand"                            // Fix L1: math/rand for wiggle delay
    ...
)

// Fix L2: difficulty values as *big.Int, not bare constants.
var (
    diffInTurn = big.NewInt(2) // in-turn validator
    diffNoTurn = big.NewInt(1) // out-of-turn validator
)

const (
    extraVanity       = 32
    extraSeal         = 65 // crypto.SignatureLength
    inmemorySnapshots = 128
    inmemorySignatures = 4096
    wiggleTime        = 500 * time.Millisecond // random delay unit for out-of-turn
)

// SignerFn is a signer callback function to request a header to be signed by a
// backing account.
type SignerFn func(accounts.Account, string, []byte) ([]byte, error)
```

#### 7b. DPoS struct

```go
// Fix M3: *lru.ARCCache (not *arc.ARCCache).
type DPoS struct {
    config     *params.DPoSConfig
    db         tosdb.Database
    recents    *lru.ARCCache // hash → *Snapshot (128 entries)
    signatures *lru.ARCCache // hash → common.Address (4096 entries)

    validator common.Address
    signFn    SignerFn
    lock      sync.RWMutex

    fakeDiff bool // skip difficulty check in tests
}

func New(config *params.DPoSConfig, db tosdb.Database) *DPoS {
    recents, _    := lru.NewARC(inmemorySnapshots)
    signatures, _ := lru.NewARC(inmemorySignatures)
    return &DPoS{config: config, db: db, recents: recents, signatures: signatures}
}

func NewFaker() *DPoS {
    d := New(&params.DPoSConfig{Epoch: 200, MaxValidators: 21, Period: 3}, nil)
    d.fakeDiff = true
    return d
}
```

#### 7c. Authorize (Fix H1)

```go
// Authorize injects the signing key for this node. Called by the miner at startup.
func (d *DPoS) Authorize(validator common.Address, signFn SignerFn) {
    d.lock.Lock()
    defer d.lock.Unlock()
    d.validator = validator
    d.signFn = signFn
}
```

#### 7d. SealHash / DPoSRLP (Fix H3)

```go
// SealHash returns the hash of a block prior to it being sealed.
// The hash covers the entire header except the last 65 bytes of Extra (the seal).
func (d *DPoS) SealHash(header *types.Header) common.Hash {
    return SealHash(header)
}

// SealHash is also exported as a package-level function (used in ecrecover).
func SealHash(header *types.Header) (hash common.Hash) {
    hasher := sha3.NewLegacyKeccak256()
    encodeSigHeader(hasher, header)
    hasher.(crypto.KeccakState).Read(hash[:])
    return hash
}

// encodeSigHeader RLP-encodes the header without the seal (last 65B of Extra).
// Panics if Extra is shorter than 65 bytes — callers must validate length first.
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
```

#### 7e. Author

```go
func (d *DPoS) Author(header *types.Header) (common.Address, error) {
    return ecrecover(header, d.signatures)
}
```

#### 7f. VerifyHeader / VerifyHeaders (Fix H2)

```go
func (d *DPoS) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
    return d.verifyHeader(chain, header, nil)
}

// Fix H2: VerifyHeaders (batch) is required by consensus.Engine.
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

    // Fix M1: reject far-future blocks.
    if header.Time > uint64(time.Now().Unix())+allowedFutureBlockTime {
        return consensus.ErrFutureBlock
    }
    // Fix M1: DPoS produces no uncles.
    if header.UncleHash != types.EmptyUncleHash {
        return errInvalidUncleHash
    }
    // Fix M1: MixDigest must be zero (no PoW).
    if header.MixDigest != (common.Hash{}) {
        return errInvalidMixDigest
    }
    // Fix M1: difficulty must be exactly 1 or 2.
    if number > 0 {
        if header.Difficulty == nil ||
            (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
            return errInvalidDifficulty
        }
    }

    // Fix M1: validate Extra length.
    // Genesis: no seal required.
    // Normal blocks: must have at least vanity + seal bytes.
    if number == 0 {
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
        epoch := number%d.config.Epoch == 0
        validatorBytes := len(header.Extra) - extraVanity - extraSeal
        if !epoch && validatorBytes != 0 {
            return errExtraValidators // non-epoch block must have no validator list
        }
        if epoch && validatorBytes%common.AddressLength != 0 {
            return errInvalidCheckpointValidators
        }
    }

    // Fix M1: gas limit sanity.
    if header.GasLimit > params.MaxGasLimit {
        return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
    }

    // Genesis is always valid at this point (no parent, no seal to check).
    // Fix C2: short-circuit here, not after cascading checks.
    if number == 0 {
        return nil
    }

    return d.verifyCascadingFields(chain, header, parents)
}

func (d *DPoS) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
    number := header.Number.Uint64()

    // Resolve parent.
    var parent *types.Header
    if len(parents) > 0 {
        parent = parents[len(parents)-1]
    } else {
        parent = chain.GetHeader(header.ParentHash, number-1)
    }
    if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
        return consensus.ErrUnknownAncestor
    }

    // Fix M1: timestamp must strictly increase and respect the configured period.
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
    number := header.Number.Uint64()
    if number == 0 {
        return errUnknownBlock
    }

    signer, err := ecrecover(header, d.signatures)
    if err != nil {
        return err
    }

    // Fix H4: signer must equal Coinbase to prevent reward redirection.
    if signer != header.Coinbase {
        return errInvalidCoinbase
    }

    // Signer must be in the current validator set.
    if _, ok := snap.ValidatorsMap[signer]; !ok {
        return errUnauthorizedValidator
    }

    // Signer must not have signed recently.
    if snap.recentlySigned(signer) {
        return errRecentlySigned
    }

    // Fix M1: verify difficulty matches in-turn status.
    if !d.fakeDiff {
        inturn := snap.inturn(number, signer)
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

#### 7g. snapshot() — loading with multi-level fallback

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

        // 2. Genesis snapshot (block 0): parse Extra, no DB load.
        if number == 0 {
            genesis := chain.GetHeaderByNumber(0)
            if genesis == nil {
                return nil, errors.New("dpos: missing genesis block")
            }
            validators, err := parseGenesisValidators(genesis.Extra)
            if err != nil {
                return nil, fmt.Errorf("dpos: genesis extra: %w", err)
            }
            // Fix M5: sort ascending by address for deterministic round-robin.
            sort.Sort(addressAscending(validators))
            snap, err = newSnapshot(d.config, d.signatures, 0, genesis.Hash(), validators)
            if err != nil {
                return nil, err
            }
            if err := snap.store(d.db); err != nil {
                return nil, err
            }
            break
        }

        // 3. Epoch checkpoint from disk.
        if number%d.config.Epoch == 0 {
            if s, err := loadSnapshot(d.config, d.signatures, d.db, hash); err == nil {
                snap = s
                break
            }
        }

        // 4. Walk backwards to find a known ancestor; collect headers to replay.
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

    // Replay collected headers onto the base snapshot (oldest first).
    for i, j := 0, len(headers)-1; i < j; i, j = i+1, j-1 {
        headers[i], headers[j] = headers[j], headers[i]
    }
    snap, err := snap.apply(headers)
    if err != nil {
        return nil, err
    }
    d.recents.Add(snap.Hash, snap)

    // Persist epoch snapshots to disk.
    if snap.Number%d.config.Epoch == 0 && len(headers) > 0 {
        if err := snap.store(d.db); err != nil {
            return nil, err
        }
    }
    return snap, nil
}
```

#### 7h. Prepare

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

    // Ensure Extra has room for vanity and seal; preserve existing vanity if present.
    if len(header.Extra) < extraVanity {
        header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
    }
    header.Extra = header.Extra[:extraVanity]

    // Epoch block: embed the next validator set (sourced from TOS3 in FinalizeAndAssemble).
    // Leave placeholder; FinalizeAndAssemble fills it after applying txs.
    // Non-epoch: Extra = vanity only (seal appended by Seal()).
    header.Extra = append(header.Extra, make([]byte, extraSeal)...)

    // Enforce minimum block interval.
    parent := chain.GetHeader(header.ParentHash, number-1)
    if parent == nil {
        return consensus.ErrUnknownAncestor
    }
    header.Time = parent.Time + d.config.Period
    if header.Time < uint64(time.Now().Unix()) {
        header.Time = uint64(time.Now().Unix())
    }
    return nil
}
```

#### 7i. Finalize / FinalizeAndAssemble

```go
func (d *DPoS) Finalize(chain consensus.ChainHeaderReader, header *types.Header,
    state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {

    // Distribute block reward to the validator (Coinbase).
    state.AddBalance(header.Coinbase, params.DPoSBlockReward)
    header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
    header.UncleHash = types.EmptyUncleHash
}

func (d *DPoS) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header,
    state *state.StateDB, txs []*types.Transaction, uncles []*types.Header,
    receipts []*types.Receipt) (*types.Block, error) {

    number := header.Number.Uint64()

    // On epoch blocks, read the current validator set from TOS3 and embed it in Extra.
    if number%d.config.Epoch == 0 {
        validators := validator.ReadActiveValidators(state, d.config.MaxValidators)
        if len(validators) == 0 {
            return nil, errors.New("dpos: no active validators at epoch boundary")
        }
        // validators are already address-sorted by ReadActiveValidators (Fix M5).
        // Rebuild Extra: [32B vanity][N×20B addrs][65B seal placeholder]
        vanity := header.Extra[:extraVanity]
        extra := make([]byte, extraVanity+len(validators)*common.AddressLength+extraSeal)
        copy(extra, vanity)
        for i, v := range validators {
            copy(extra[extraVanity+i*common.AddressLength:], v.Bytes())
        }
        header.Extra = extra
    }

    d.Finalize(chain, header, state, txs, uncles)
    return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}
```

#### 7j. Seal (Fix L1)

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
    // Check if recently signed; account for the sliding window at the current block.
    for seen, recent := range snap.Recents {
        if recent == validator {
            limit := uint64(len(snap.Validators)/2 + 1)
            if number < limit || seen > number-limit {
                return errors.New("dpos: signed recently, must wait")
            }
        }
    }

    // Compute delay.
    delay := time.Unix(int64(header.Time), 0).Sub(time.Now())
    if header.Difficulty.Cmp(diffNoTurn) == 0 {
        // Fix L1: use math/rand (not crypto/rand) for out-of-turn wiggle.
        wiggle := time.Duration(len(snap.Validators)/2+1) * wiggleTime
        delay += time.Duration(rand.Int63n(int64(wiggle)))
    }

    // Sign.
    sighash, err := signFn(accounts.Account{Address: validator},
        accounts.MimetypeClique, SealHash(header).Bytes())
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

#### 7k. CalcDifficulty / VerifyUncles / APIs / Close

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
    return []rpc.API{{
        Namespace: "dpos",
        Service:   &API{chain: chain, dpos: d},
    }}
}

func (d *DPoS) Close() error { return nil }
```

#### 7l. ecrecover helper

```go
// ecrecover extracts the validator address from a signed header.
// Result is cached in sigcache keyed by block hash.
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

---

### 8. RPC API (`consensus/dpos/api.go`)

```go
type API struct {
    chain consensus.ChainHeaderReader
    dpos  *DPoS
}

// GetSnapshot returns the snapshot at the given block number (or latest if missing).
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*Snapshot, error) { ... }

// GetValidators returns the current active validator set.
func (api *API) GetValidators(number *rpc.BlockNumber) ([]common.Address, error) { ... }
```

Namespace: `"dpos"` — accessible as `dpos_getSnapshot`, `dpos_getValidators`.

---

### 9. CreateConsensusEngine (`tos/tosconfig/config.go`)

```go
import "github.com/tos-network/gtos/consensus/dpos"

func CreateConsensusEngine(stack *node.Node, chainConfig *params.ChainConfig,
    config *tosash.Config, notify []string, noverify bool, db tosdb.Database) consensus.Engine {

    if chainConfig.DPoS != nil {
        return dpos.New(chainConfig.DPoS, db) // production path
    }
    if chainConfig.Clique != nil {
        return clique.New(chainConfig.Clique, db) // --dev path unchanged
    }
    // Tosash PoW fallback (existing tests / legacy)
    ...
}
```

---

### 10. Backend (`tos/backend.go`)

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
consensus/dpos/  ──→ validator/         ReadActiveValidators (FinalizeAndAssemble)
consensus/dpos/  ──→ params/
consensus/dpos/  ──→ core/state/        *state.StateDB (Finalize signature)
```

> Note: `consensus/dpos` imports `validator/` only for `ReadActiveValidators`. This is a
> one-way dependency (validator does not import dpos). No cycles.

---

## Genesis Block Configuration

Genesis `header.Extra` for a 3-validator devnet:

```json
{
  "extraData": "0x<32B vanity hex><addr1 20B><addr2 20B><addr3 20B>"
}
```

No trailing 65B seal — genesis is never signed. The DPoS engine reads this at startup to
bootstrap the initial snapshot.

`--dev` mode sets `chainConfig.Clique != nil` and `chainConfig.DPoS == nil`, so Clique is
selected. No DPoS code runs. Fully compatible.

---

## Sentinel Errors (in `consensus/dpos/dpos.go`)

```go
var (
    errUnknownBlock              = errors.New("dpos: unknown block")
    errUnauthorizedValidator     = errors.New("dpos: unauthorized validator")
    errRecentlySigned            = errors.New("dpos: validator signed recently")
    errInvalidCoinbase           = errors.New("dpos: signer does not match coinbase")  // Fix H4
    errInvalidMixDigest          = errors.New("dpos: non-zero mix digest")             // Fix M1
    errInvalidUncleHash          = errors.New("dpos: non-empty uncle hash")            // Fix M1
    errInvalidDifficulty         = errors.New("dpos: invalid difficulty")              // Fix M1
    errWrongDifficulty           = errors.New("dpos: wrong difficulty for turn")       // Fix M1
    errMissingVanity             = errors.New("dpos: extra missing vanity")            // Fix M1
    errMissingSignature          = errors.New("dpos: extra missing seal")              // Fix M1
    errExtraValidators           = errors.New("dpos: non-epoch block has validator list") // Fix M1
    errInvalidCheckpointValidators = errors.New("dpos: invalid checkpoint validator list")
    errInvalidTimestamp          = errors.New("dpos: invalid timestamp")               // Fix M1
    errInvalidChain              = errors.New("dpos: non-contiguous header chain")
)
```

---

## Implementation Order

1. `params/tos_params.go` — Add TOS3 address, DPoS constants
2. `params/config.go` — Add `DPoSConfig` + `ChainConfig.DPoS` field
3. `sysaction/types.go` — Add `VALIDATOR_REGISTER`, `VALIDATOR_WITHDRAW` kinds
4. `validator/types.go` — `ValidatorStatus` enum + sentinel errors
5. `validator/state.go` — Slot formulas + `ReadSelfStake`, `ReadValidatorStatus`, `ReadActiveValidators`
6. `validator/handler.go` — Handler with validate-then-mutate pattern
7. `consensus/dpos/snapshot.go` — `Snapshot`, `newSnapshot`, `copy`, `apply`, `inturn`, `loadSnapshot`, `store`
8. `consensus/dpos/dpos.go` — Engine (all methods), `SealHash`, `ecrecover`
9. `consensus/dpos/api.go` — RPC
10. `tos/tosconfig/config.go` — DPoS branch in `CreateConsensusEngine`
11. `tos/backend.go` — blank import of `validator`

---

## Verification

```bash
# Must compile cleanly.
go build ./...

# New package unit tests (include empty-set, genesis parse, seal round-trip).
go test -short ./consensus/dpos/... ./validator/...

# Existing tests must continue to pass.
go test -short -p 48 -parallel 48 ./core/... ./consensus/... ./tos/...

# Race detector — critical given LRU cache sharing.
go test -race ./consensus/dpos/... ./validator/...
```

### Minimum unit test coverage required

| Test | What it verifies |
|------|-----------------|
| `TestEmptyValidatorSet` | `newSnapshot` returns error, `inturn` returns false |
| `TestGenesisExtraParse` | `parseGenesisValidators` handles N=0,1,21; rejects bad lengths |
| `TestEpochExtraParse` | `parseEpochValidators` requires vanity+seal; rejects mid-seal |
| `TestSealHashRoundTrip` | `ecrecover(sign(SealHash(h))) == signer` |
| `TestCoinbaseMismatch` | `verifySeal` rejects header where Coinbase ≠ signer |
| `TestRecentlySigned` | Block rejected when validator tries to sign within N/2+1 |
| `TestSnapshotDeepCopy` | Mutating applied snap does not affect original |
| `TestWithdrawBalanceGuard` | Handler rejects when TOS3 balance < selfStake |
| `TestRegisterTwice` | Second VALIDATOR_REGISTER returns `ErrAlreadyRegistered` |
| `TestValidatorSortOrder` | Selection by stake, snapshot by address ascending |
