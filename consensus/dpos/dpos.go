// Package dpos implements the Delegated Proof of Stake consensus engine.
//
// Block production is round-robin among staked validators. Validators are
// registered via VALIDATOR_REGISTER system actions; their on-chain state is
// stored at params.ValidatorRegistryAddress (validator registry account).
//
// The Extra field format mirrors Clique:
//
//	Genesis (block 0):   [32B vanity][N×AddressLength addrs]             (no seal)
//	Normal block:        [32B vanity][seal]
//	Epoch block (N>0):   [32B vanity][N×AddressLength addrs][seal]
//
// Seal encoding depends on dpos.sealSignerType:
//   - secp256k1: [65B secp256k1 signature]
//   - ed25519:   [32B pubkey || 64B signature]
package dpos

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/tos-network/gtos/crypto/ed25519"
	"io"
	"math/big"
	"math/rand"
	"sort"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/log"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rlp"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/tosdb"
	"github.com/tos-network/gtos/trie"
	"github.com/tos-network/gtos/validator"
	"golang.org/x/crypto/sha3"
)

// Package-level sentinel errors.
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
	errInvalidSignature            = errors.New("dpos: invalid seal signature")
	errExtraValidators             = errors.New("dpos: non-epoch block has validator list")
	errInvalidCheckpointValidators = errors.New("dpos: invalid checkpoint validator list")
	errInvalidTimestamp            = errors.New("dpos: invalid timestamp")
	errInvalidChain                = errors.New("dpos: non-contiguous header chain")
)

// Package-level difficulty values.
var (
	diffInTurn = big.NewInt(2) // in-turn validator
	diffNoTurn = big.NewInt(1) // out-of-turn validator
)

const (
	extraVanity            = 32   // bytes of vanity prefix in Extra
	extraSeal              = 65   // legacy/test helper: secp256k1 seal length
	extraSealSecp256k1     = 65   // bytes of secp256k1 seal in Extra (crypto.SignatureLength)
	extraSealEd25519       = 96   // bytes of ed25519 seal in Extra: [pub(32) || sig(64)]
	inmemorySnapshots      = 128  // recent snapshots to keep in LRU
	inmemorySignatures     = 4096 // recent signatures to cache
	minWiggleTime          = 100 * time.Millisecond
	maxWiggleTime          = 1 * time.Second
	allowedFutureBlockTime = uint64(1080) // milliseconds: 3 × periodMs(360ms) clock-skew grace period
)

// SignerFn is the callback the miner uses to sign a header hash.
type SignerFn func(accounts.Account, string, []byte) ([]byte, error)

// DPoS is the delegated proof-of-stake consensus engine.
type DPoS struct {
	config     *params.DPoSConfig
	db         tosdb.Database // nil in NewFaker()
	recents    *lru.ARCCache  // hash → *Snapshot (inmemorySnapshots entries)
	signatures *lru.ARCCache  // hash → common.Address (inmemorySignatures entries)
	sealLength int

	validator common.Address
	signFn    SignerFn
	lock      sync.RWMutex

	fakeDiff    bool   // skip difficulty check in unit tests
	fakeFailAt  uint64 // fail VerifyHeader at this block number (0 = disabled)
	fakeFailSet bool   // true when fakeFailAt is active
}

// New creates a DPoS engine. Returns error if config values are invalid (R2-C4).
func New(config *params.DPoSConfig, db tosdb.Database) (*DPoS, error) {
	if config == nil {
		return nil, errors.New("dpos: missing config")
	}
	if config.Epoch == 0 {
		return nil, errors.New("dpos: epoch must be > 0")
	}
	if config.TargetBlockPeriodMs() == 0 {
		return nil, errors.New("dpos: periodMs must be > 0")
	}
	if config.MaxValidators == 0 {
		return nil, errors.New("dpos: maxValidators must be > 0")
	}
	sealSignerType, err := params.NormalizeDPoSSealSignerType(config.SealSignerType)
	if err != nil {
		return nil, err
	}
	config.SealSignerType = sealSignerType
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)
	return &DPoS{
		config:     config,
		db:         db,
		recents:    recents,
		signatures: signatures,
		sealLength: sealLengthForSignerType(config.SealSignerType),
	}, nil
}

// NewFaker returns a DPoS engine suitable for unit tests. It skips difficulty
// checks and uses nil db (no disk persistence). Panics on invalid config.
func NewFaker() *DPoS {
	d, err := New(&params.DPoSConfig{
		Epoch:          200,
		MaxValidators:  params.DPoSMaxValidators,
		PeriodMs:       3000,
		SealSignerType: params.DPoSSealSignerTypeSecp256k1,
	}, nil)
	if err != nil {
		panic(err)
	}
	d.fakeDiff = true
	return d
}

// NewFakeFailer creates a test engine that returns an error for VerifyHeader on
// the block with the given number (and all subsequent blocks).
func NewFakeFailer(fail uint64) *DPoS {
	d := NewFaker()
	d.fakeFailAt = fail
	d.fakeFailSet = true
	return d
}

// Authorize injects the signing key for this validator. Called by the miner at startup.
func (d *DPoS) Authorize(v common.Address, signFn SignerFn) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.validator = v
	d.signFn = signFn
}

// ValidatorAddress returns the locally configured validator address.
func (d *DPoS) ValidatorAddress() common.Address {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return d.validator
}

// CanSignVotes reports whether the local validator vote signer is configured.
func (d *DPoS) CanSignVotes() bool {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return d.validator != (common.Address{}) && d.signFn != nil
}

// SignVote signs a vote digest with the local validator key.
func (d *DPoS) SignVote(digest common.Hash) ([]byte, error) {
	d.lock.RLock()
	v, signFn := d.validator, d.signFn
	d.lock.RUnlock()
	if v == (common.Address{}) || signFn == nil {
		return nil, errors.New("dpos: vote signer not configured")
	}
	return signFn(accounts.Account{Address: v}, accounts.MimetypeDPoS, digest.Bytes())
}

// Author implements consensus.Engine.
func (d *DPoS) Author(header *types.Header) (common.Address, error) {
	// Faker: the seal is zero bytes, so ecrecover is meaningless.
	// Return Coinbase directly so gas rewards are credited consistently.
	if d.fakeDiff {
		return header.Coinbase, nil
	}
	return recoverHeaderSigner(d.config, header, d.signatures)
}

// SealHash implements consensus.Engine (method form).
func (d *DPoS) SealHash(header *types.Header) common.Hash {
	return sealHashWithSealLength(header, d.sealLength)
}

// SealHash (package function) returns the hash of a block prior to sealing.
// This package-level helper uses legacy secp256k1 seal length for compatibility.
func SealHash(header *types.Header) (hash common.Hash) {
	return sealHashWithSealLength(header, extraSealSecp256k1)
}

func sealHashWithSealLength(header *types.Header, sealLen int) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, sealLen)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

// encodeSigHeader writes the RLP of the header without its seal.
func encodeSigHeader(w io.Writer, header *types.Header, sealLen int) {
	extraNoSeal := header.Extra
	if sealLen >= 0 && len(header.Extra) >= sealLen {
		extraNoSeal = header.Extra[:len(header.Extra)-sealLen]
	}
	enc := []interface{}{
		header.ParentHash, header.UncleHash, header.Coinbase,
		header.Root, header.TxHash, header.ReceiptHash, header.Bloom,
		header.Difficulty, header.Number, header.GasLimit, header.GasUsed,
		header.Time,
		extraNoSeal, // strip seal bytes
		header.MixDigest, header.Nonce,
	}
	rlp.Encode(w, enc)
}

func sealLengthForSignerType(signerType string) int {
	if signerType == params.DPoSSealSignerTypeEd25519 {
		return extraSealEd25519
	}
	return extraSealSecp256k1
}

func (d *DPoS) normalizeSealPayload(payload []byte) ([]byte, error) {
	switch d.config.SealSignerType {
	case params.DPoSSealSignerTypeEd25519:
		if len(payload) != extraSealEd25519 {
			return nil, fmt.Errorf("dpos: invalid ed25519 seal length: have %d want %d", len(payload), extraSealEd25519)
		}
		return append([]byte(nil), payload...), nil
	default:
		if len(payload) != extraSealSecp256k1 {
			return nil, fmt.Errorf("dpos: invalid secp256k1 seal length: have %d want %d", len(payload), extraSealSecp256k1)
		}
		return append([]byte(nil), payload...), nil
	}
}

// recoverHeaderSigner extracts the validator address from a signed header; caches in sigcache.
func recoverHeaderSigner(config *params.DPoSConfig, header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	hash := header.Hash()
	if addr, ok := sigcache.Get(hash); ok {
		return addr.(common.Address), nil
	}
	sealSignerType := params.DefaultDPoSSealSignerType
	if config != nil {
		sealSignerType = config.SealSignerType
	}
	sealLen := sealLengthForSignerType(sealSignerType)
	if len(header.Extra) < sealLen {
		return common.Address{}, errMissingSignature
	}
	sig := header.Extra[len(header.Extra)-sealLen:]
	digest := sealHashWithSealLength(header, sealLen).Bytes()

	var signer common.Address
	switch sealSignerType {
	case params.DPoSSealSignerTypeEd25519:
		pub := sig[:ed25519.PublicKeySize]
		signature := sig[ed25519.PublicKeySize:]
		if !ed25519.Verify(ed25519.PublicKey(pub), digest, signature) {
			return common.Address{}, errInvalidSignature
		}
		copy(signer[:], crypto.Keccak256(pub))
	default:
		pub, err := crypto.Ecrecover(digest, sig)
		if err != nil {
			return common.Address{}, err
		}
		copy(signer[:], crypto.Keccak256(pub[1:]))
	}
	sigcache.Add(hash, signer)
	return signer, nil
}

// VerifyHeader implements consensus.Engine.
func (d *DPoS) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return d.verifyHeader(chain, header, nil)
}

// VerifyHeaders implements consensus.Engine.
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

	// Inject failure for testing (NewFakeFailer).
	if d.fakeFailSet && number >= d.fakeFailAt {
		return errUnknownBlock
	}

	// Reject far-future blocks (R2-M1 constant). Checked even in faker mode.
	if header.Time > uint64(time.Now().UnixMilli())+allowedFutureBlockTime {
		return consensus.ErrFutureBlock
	}
	// NewFaker: skip DPoS-specific structural validation, but still check ancestry
	// so tests that deliberately pass broken chains (missing link) get an error
	// rather than a nil panic later in GetTd / chainmu deadlock.
	if d.fakeDiff {
		if number > 0 {
			var parent *types.Header
			if len(parents) > 0 && parents[len(parents)-1].Number.Uint64() == number-1 {
				parent = parents[len(parents)-1]
			} else {
				parent = chain.GetHeader(header.ParentHash, number-1)
			}
			if parent == nil {
				return consensus.ErrUnknownAncestor
			}
		}
		return nil
	}
	// DPoS produces no uncles.
	if header.UncleHash != types.EmptyUncleHash {
		return errInvalidUncleHash
	}
	// No PoW: MixDigest must be zero.
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Non-genesis: difficulty must be exactly 1 or 2.
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
		if len(header.Extra) < extraVanity+d.sealLength {
			return errMissingSignature
		}
		isEpoch := number%d.config.Epoch == 0
		validatorBytes := len(header.Extra) - extraVanity - d.sealLength
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
	if header.Time < parent.Time+d.config.TargetBlockPeriodMs() {
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
	signer, err := recoverHeaderSigner(d.config, header, d.signatures)
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
	// Check recency: if signer appears in Recents, only reject if this block
	// does NOT shift that entry out of the window. Mirrors Clique's logic.
	limit := snap.config.RecentSignerWindowSize(len(snap.Validators))
	for seen, recent := range snap.Recents {
		if recent == signer {
			if number < limit || seen > number-limit {
				return errRecentlySigned
			}
		}
	}
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

// VerifyUncles implements consensus.Engine. DPoS never produces uncles.
func (d *DPoS) VerifyUncles(_ consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("dpos: uncles not allowed")
	}
	return nil
}

// snapshot returns the snapshot at the given block, computing it if necessary.
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

	// Persist epoch snapshots to disk.
	if snap.Number%d.config.Epoch == 0 && len(headers) > 0 && d.db != nil {
		if err := snap.store(d.db); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

// Prepare implements consensus.Engine.
func (d *DPoS) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Nonce = types.BlockNonce{}
	number := header.Number.Uint64()

	// Set block timestamp from parent.
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = parent.Time + d.config.TargetBlockPeriodMs()
	if now := uint64(time.Now().UnixMilli()); header.Time < now {
		header.Time = now
	}

	if d.fakeDiff {
		// Faker: set difficulty and pad Extra without consulting the snapshot.
		header.Difficulty = diffNoTurn
		if len(header.Extra) < extraVanity {
			header.Extra = append(header.Extra,
				bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
		}
		header.Extra = header.Extra[:extraVanity]
		header.Extra = append(header.Extra, make([]byte, d.sealLength)...)
		return nil
	}

	d.lock.RLock()
	v := d.validator
	d.lock.RUnlock()

	header.Coinbase = v

	snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	header.Difficulty = calcDifficulty(snap, v)

	// Ensure Extra has vanity prefix.
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra,
			bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]
	// Reserve space for the seal; FinalizeAndAssemble may insert validator list before it.
	header.Extra = append(header.Extra, make([]byte, d.sealLength)...)
	return nil
}

// Finalize implements consensus.Engine, adding the block reward.
//
// R2-H1 — Accepted MVP limitation: Finalize() has no error return in
// consensus.Engine, so we cannot verify that header.Extra matches validator
// registry state here. FinalizeAndAssemble (the honest proposer path) always
// reads validator registry state and
// embeds the correct list. A byzantine validator could produce an epoch block
// with a wrong Extra, but cannot sustain a fork without >50% of validators.
func (d *DPoS) Finalize(chain consensus.ChainHeaderReader, header *types.Header,
	st *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {

	st.AddBalance(header.Coinbase, params.DPoSBlockReward)
	header.Root = st.IntermediateRoot(true)
	header.UncleHash = types.EmptyUncleHash
}

// FinalizeAndAssemble implements consensus.Engine.
func (d *DPoS) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header,
	st *state.StateDB, txs []*types.Transaction, uncles []*types.Header,
	receipts []*types.Receipt) (*types.Block, error) {

	number := header.Number.Uint64()

	// At epoch boundaries, embed the current active validator set into Extra.
	// In faker mode, skip this step (no on-chain validator state in unit tests).
	if number%d.config.Epoch == 0 && !d.fakeDiff {
		validators := validator.ReadActiveValidators(st, d.config.MaxValidators)
		if len(validators) == 0 {
			return nil, errors.New("dpos: no active validators at epoch boundary")
		}
		// validators is already address-sorted (ReadActiveValidators phase 3).
		vanity := header.Extra[:extraVanity]
		extra := make([]byte, extraVanity+len(validators)*common.AddressLength+d.sealLength)
		copy(extra, vanity)
		for i, v := range validators {
			copy(extra[extraVanity+i*common.AddressLength:], v.Bytes())
		}
		header.Extra = extra // trailing seal bytes are the seal placeholder
	}

	d.Finalize(chain, header, st, txs, uncles)
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

// Seal implements consensus.Engine.
func (d *DPoS) Seal(chain consensus.ChainHeaderReader, block *types.Block,
	results chan<- *types.Block, stop <-chan struct{}) error {

	header := block.Header()
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// Faker: immediately produce the block without signing or waiting.
	if d.fakeDiff {
		go func() {
			select {
			case <-stop:
			case results <- block:
			}
		}()
		return nil
	}

	if d.config.TargetBlockPeriodMs() == 0 && len(block.Transactions()) == 0 {
		return errors.New("dpos: sealing paused, no transactions")
	}

	d.lock.RLock()
	v, signFn := d.validator, d.signFn
	d.lock.RUnlock()

	snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if _, ok := snap.ValidatorsMap[v]; !ok {
		return errUnauthorizedValidator
	}
	limit := snap.config.RecentSignerWindowSize(len(snap.Validators))
	for seen, recent := range snap.Recents {
		if recent == v {
			if number < limit || seen > number-limit {
				return errors.New("dpos: signed recently, must wait")
			}
		}
	}

	// Compute delay. In-turn: honour header.Time. Out-of-turn: add random wiggle.
	delay := time.UnixMilli(int64(header.Time)).Sub(time.Now())
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// Sub-second tuning: widen out-of-turn jitter and cap it to 1s.
		// math/rand is intentional: delay randomness is not a security property.
		wiggle := d.outOfTurnWiggleWindow()
		delay += time.Duration(rand.Int63n(int64(wiggle)))
	}

	// Sign with DPoS MIME type (R2-L1).
	sighash, err := signFn(accounts.Account{Address: v},
		accounts.MimetypeDPoS, d.SealHash(header).Bytes())
	if err != nil {
		return err
	}
	seal, err := d.normalizeSealPayload(sighash)
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-d.sealLength:], seal)

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

// CalcDifficulty implements consensus.Engine.
func (d *DPoS) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	// Faker: skip snapshot; used by GenerateChain/OffsetTime in unit tests.
	if d.fakeDiff {
		return new(big.Int).Set(diffNoTurn)
	}
	snap, err := d.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	d.lock.RLock()
	v := d.validator
	d.lock.RUnlock()
	return calcDifficulty(snap, v)
}

func calcDifficulty(snap *Snapshot, v common.Address) *big.Int {
	if snap.inturn(snap.Number+1, v) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

func (d *DPoS) outOfTurnWiggleWindow() time.Duration {
	period := time.Duration(d.config.TargetBlockPeriodMs()) * time.Millisecond
	if period <= 0 {
		return minWiggleTime
	}
	wiggle := period * 2
	if wiggle > maxWiggleTime {
		wiggle = maxWiggleTime
	}
	if wiggle < minWiggleTime {
		return minWiggleTime
	}
	return wiggle
}

// APIs implements consensus.Engine.
func (d *DPoS) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{Namespace: "dpos", Service: &API{chain: chain, dpos: d}}}
}

// Close implements consensus.Engine.
func (d *DPoS) Close() error { return nil }
