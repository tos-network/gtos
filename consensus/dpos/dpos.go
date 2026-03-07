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
// Seal encoding is fixed to ed25519:
//   - [32B pubkey || 64B signature]
package dpos

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/tos-network/gtos/crypto/ed25519"
	"io"
	"math/big"
	"math/bits"
	"math/rand"
	"sort"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/tos-network/gtos/accounts"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus"
	"github.com/tos-network/gtos/consensus/misc"
	"github.com/tos-network/gtos/core/rawdb"
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
	errInvalidSlot                 = errors.New("dpos: slot did not advance")
	errMissingParentState          = errors.New("dpos: missing parent state")

	// Checkpoint QC sentinel errors (Phase 1 structural + Phase 2 cryptographic).
	errInvalidCheckpointQC        = errors.New("dpos: invalid checkpoint QC")
	errInvalidQCChainID           = errors.New("dpos: checkpoint QC chain ID mismatch")
	errInvalidQCNumber            = errors.New("dpos: checkpoint QC number invalid")
	errQCTooStale                 = errors.New("dpos: checkpoint QC too stale")
	errQCBitmapOverflow           = errors.New("dpos: checkpoint QC bitmap exceeds validator count")
	errQCSignatureCountMismatch   = errors.New("dpos: checkpoint QC signature count != popcount(bitmap)")
	errQCInsufficientSignatures   = errors.New("dpos: checkpoint QC below 2/3 quorum")
	errQCInvalidSignature         = errors.New("dpos: checkpoint QC signature verification failed")
	errQCValidatorSetHashMismatch = errors.New("dpos: checkpoint QC ValidatorSetHash mismatch")
	errQCNotAncestor              = errors.New("dpos: checkpoint QC target is not an ancestor")
)

// Package-level difficulty values.
var (
	diffInTurn = big.NewInt(2) // in-turn validator
	diffNoTurn = big.NewInt(1) // out-of-turn validator
)

// headerSlot returns the slot number for a given header timestamp.
// Returns (slot, true) on success; (0, false) if inputs are invalid.
func headerSlot(headerTime, genesisTime, periodMs uint64) (uint64, bool) {
	if periodMs == 0 || headerTime < genesisTime {
		return 0, false
	}
	return (headerTime - genesisTime) / periodMs, true
}

const (
	extraVanity        = 32   // bytes of vanity prefix in Extra
	extraSealEd25519   = 96   // bytes of ed25519 seal in Extra: [pub(32) || sig(64)]
	inmemorySnapshots  = 128  // recent snapshots to keep in LRU
	inmemorySignatures = 4096 // recent signatures to cache
	minWiggleTime      = 100 * time.Millisecond
	maxWiggleTime      = 1 * time.Second
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

	votePool *checkpointVotePool // in-memory checkpoint vote cache (nil when inactive)

	// Callbacks wired by the network/chain layer at startup (nil = inactive).
	broadcastVoteFn func(*types.CheckpointVoteEnvelope) // send vote to all peers
	setFinalizedFn  func(*types.Header)                  // update blockchain finality state
	chainID         *big.Int                             // local chain ID for vote admission (§9 rule 3)

	finalizedVSHash sync.Map // stores common.Hash for most-recently-finalized ValidatorSetHash

	fakeDiff    bool   // skip difficulty check in unit tests
	fakeFailAt  uint64 // fail VerifyHeader at this block number (0 = disabled)
	fakeFailSet bool   // true when fakeFailAt is active
}

type rawChainReader struct {
	config *params.ChainConfig
	db     tosdb.Database
}

func (r *rawChainReader) Config() *params.ChainConfig  { return r.config }
func (r *rawChainReader) CurrentHeader() *types.Header { return nil }
func (r *rawChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	return rawdb.ReadHeader(r.db, hash, number)
}
func (r *rawChainReader) GetHeaderByNumber(number uint64) *types.Header {
	hash := rawdb.ReadCanonicalHash(r.db, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return rawdb.ReadHeader(r.db, hash, number)
}
func (r *rawChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	number := rawdb.ReadHeaderNumber(r.db, hash)
	if number == nil {
		return nil
	}
	return rawdb.ReadHeader(r.db, hash, *number)
}
func (r *rawChainReader) GetTd(hash common.Hash, number uint64) *big.Int { return nil }

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
	if err := config.ValidateCheckpointConfig(); err != nil {
		return nil, err
	}
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)
	d := &DPoS{
		config:     config,
		db:         db,
		recents:    recents,
		signatures: signatures,
		sealLength: sealLengthForSignerType(config.SealSignerType),
	}
	if config.CheckpointFinalityBlock != nil {
		d.votePool = newCheckpointVotePool()
	}
	return d, nil
}

// NewFaker returns a DPoS engine suitable for unit tests. It skips difficulty
// checks and uses nil db (no disk persistence). Panics on invalid config.
func NewFaker() *DPoS {
	d, err := New(&params.DPoSConfig{
		Epoch:          200,
		MaxValidators:  params.DPoSMaxValidators,
		PeriodMs:       3000,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
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

// SetVoteCallbacks wires the DPoS engine to the network and blockchain layers.
// Must be called once after New() and before Seal() is invoked.
// broadcastFn: called to send a signed vote envelope to all connected peers.
// setFinalizedFn: called when a QC is cryptographically verified; updates blockchain finality.
// chainID: local chain ID stored for vote admission ChainID check (§9 rule 3).
func (d *DPoS) SetVoteCallbacks(
	broadcastFn func(*types.CheckpointVoteEnvelope),
	setFinalizedFn func(*types.Header),
	chainID *big.Int,
) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.broadcastVoteFn = broadcastFn
	d.setFinalizedFn = setFinalizedFn
	if chainID != nil {
		d.chainID = new(big.Int).Set(chainID)
	}
}

// HandleIncomingVote is the P2P handler callback. Called for each checkpoint vote
// envelope received from peers. Performs basic admission (chain ID, eligible number)
// and queues the vote in the pool, or in the pending queue if the snapshot is not yet
// available.
func (d *DPoS) HandleIncomingVote(env *types.CheckpointVoteEnvelope) {
	if d.votePool == nil || env == nil {
		return
	}
	d.lock.RLock()
	cfg, localChainID := d.config, d.chainID
	d.lock.RUnlock()

	// Basic structural admission (§9 rules 1–3; no state access).
	if cfg.CheckpointInterval == 0 || cfg.CheckpointFinalityBlock == nil {
		return
	}
	// Rule 3: ChainID must match local chain config.
	if env.Vote.ChainID == nil || localChainID == nil || env.Vote.ChainID.Cmp(localChainID) != 0 {
		return
	}
	// Rule 1: must be an eligible checkpoint height.
	firstEligible := firstCheckpointAtOrAfter(cfg.CheckpointFinalityBlock.Uint64(), cfg.CheckpointInterval)
	if env.Vote.Number < firstEligible {
		return
	}
	if env.Vote.Number%cfg.CheckpointInterval != 0 {
		return
	}
	// Queue for later full verification; QC assembly promotes and verifies sigs.
	d.votePool.AddPending(env)
}

// FinalizedValidatorSetHash returns the ValidatorSetHash of the most recently
// finalized checkpoint QC, or zero if no checkpoint has been finalized yet.
func (d *DPoS) FinalizedValidatorSetHash() common.Hash {
	if v, ok := d.finalizedVSHash.Load("vsHash"); ok {
		return v.(common.Hash)
	}
	return common.Hash{}
}

// RestartGossip re-gossips signed checkpoint votes for checkpoints that this node
// has signed but that are not yet finalized. Called once on startup after Authorize.
// Implements §11 "Restart re-gossip" requirement.
func (d *DPoS) RestartGossip(chain consensus.ChainHeaderReader, finalizedNumber uint64) {
	if d.db == nil || d.votePool == nil {
		return
	}
	numbers, hashes, err := ListUnsettledSignedCheckpoints(d.db, finalizedNumber)
	if err != nil {
		log.Debug("DPoS restart gossip: failed to list checkpoints", "err", err)
		return
	}
	if len(numbers) == 0 {
		return
	}

	d.lock.RLock()
	v, signFn, bcastFn := d.validator, d.signFn, d.broadcastVoteFn
	d.lock.RUnlock()

	if v == (common.Address{}) || signFn == nil {
		return // not authorized yet
	}

	chainID := chain.Config().ChainID
	for i, candidate := range numbers {
		hash := hashes[i]
		cpHeader := chain.GetHeaderByNumber(candidate)
		if cpHeader == nil || cpHeader.Hash() != hash {
			continue // reorganized away
		}
		preSnap, err := d.snapshot(chain, candidate-1, cpHeader.ParentHash, nil)
		if err != nil {
			continue
		}
		records, err := d.buildSignerSet(preSnap)
		if err != nil {
			continue
		}
		found := false
		for _, r := range records {
			if r.Address == v {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		vsHash := computeValidatorSetHash(records)
		vote := types.CheckpointVote{
			ChainID:          new(big.Int).Set(chainID),
			Number:           candidate,
			Hash:             hash,
			ValidatorSetHash: vsHash,
		}
		signingHash := vote.SigningHash()
		rawSig, err := signFn(accounts.Account{Address: v}, accounts.MimetypeDPoS, signingHash[:])
		if err != nil || len(rawSig) != ed25519.SignatureSize {
			continue
		}
		var sig [64]byte
		copy(sig[:], rawSig)
		env := &types.CheckpointVoteEnvelope{Vote: vote, Signer: v, Signature: sig}
		d.votePool.AddVote(env)
		if bcastFn != nil {
			bcastFn(env)
		}
		log.Debug("DPoS restart gossip: re-gossiped checkpoint vote", "number", candidate, "hash", hash)
	}
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
// This package-level helper uses the chain-wide default ed25519 seal length.
func SealHash(header *types.Header) (hash common.Hash) {
	return sealHashWithSealLength(header, extraSealEd25519)
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
	return extraSealEd25519
}

// firstCheckpointAtOrAfter returns the smallest h such that
// h >= activationBlock && h % interval == 0.
// interval must be > 0.
func firstCheckpointAtOrAfter(activationBlock, interval uint64) uint64 {
	if interval == 0 {
		return activationBlock
	}
	rem := activationBlock % interval
	if rem == 0 {
		return activationBlock
	}
	return activationBlock + (interval - rem)
}

// parseCheckpointQCFromExtra extracts the CheckpointQC RLP bytes from header.Extra.
// Returns (qc, nil) if present and valid RLP, (nil, nil) if absent, (nil, err) if malformed.
// sealLen is extraSealEd25519 (96).
func parseCheckpointQCFromExtra(extra []byte, isEpoch bool, isCheckpointFinality bool) (*types.CheckpointQC, error) {
	sealLen := extraSealEd25519
	if len(extra) < extraVanity+sealLen {
		return nil, nil
	}
	middle := extra[extraVanity : len(extra)-sealLen]

	var qcBytes []byte
	if isEpoch && isCheckpointFinality {
		// New format: [1B count=N][N×AddressLength][QC RLP (optional)]
		if len(middle) == 0 {
			return nil, nil
		}
		n := int(middle[0])
		valEnd := 1 + n*common.AddressLength
		if valEnd > len(middle) {
			return nil, errInvalidCheckpointQC
		}
		qcBytes = middle[valEnd:]
	} else if isEpoch {
		// Old format: no QC possible
		return nil, nil
	} else {
		// Non-epoch: middle is entirely the QC (if any)
		qcBytes = middle
	}

	if len(qcBytes) == 0 {
		return nil, nil
	}
	var qc types.CheckpointQC
	if err := rlp.DecodeBytes(qcBytes, &qc); err != nil {
		return nil, fmt.Errorf("%w: RLP decode: %v", errInvalidCheckpointQC, err)
	}
	return &qc, nil
}

// verifyCheckpointQCStructure performs Phase 1 (structural-only) QC checks.
// Called from verifyCascadingFields during VerifyHeader; no pre-state access.
func (d *DPoS) verifyCheckpointQCStructure(chain consensus.ChainHeaderReader, header *types.Header) error {
	if !d.config.IsCheckpointFinality(header.Number) {
		return nil
	}
	number := header.Number.Uint64()
	isEpoch := number%d.config.Epoch == 0
	qc, err := parseCheckpointQCFromExtra(header.Extra, isEpoch, true)
	if err != nil {
		return err
	}
	if qc == nil {
		return nil // absent QC is always valid
	}

	// Step 3: compute firstEligible
	firstEligible := firstCheckpointAtOrAfter(d.config.CheckpointFinalityBlock.Uint64(), d.config.CheckpointInterval)

	// Step 4: qc.Vote.Number >= firstEligible
	if qc.Vote.Number < firstEligible {
		return fmt.Errorf("%w: vote number %d below firstEligible %d", errInvalidQCNumber, qc.Vote.Number, firstEligible)
	}
	// Step 5: qc.Vote.Number % CheckpointInterval == 0
	if d.config.CheckpointInterval > 0 && qc.Vote.Number%d.config.CheckpointInterval != 0 {
		return fmt.Errorf("%w: vote number %d not a checkpoint multiple", errInvalidQCNumber, qc.Vote.Number)
	}
	// Step 6: header.Number > qc.Vote.Number
	if number <= qc.Vote.Number {
		return fmt.Errorf("%w: header %d must be after checkpoint %d", errInvalidQCNumber, number, qc.Vote.Number)
	}
	// Step 7: staleness limit: header.Number - qc.Vote.Number <= 2 * CheckpointInterval
	if d.config.CheckpointInterval > 0 && number-qc.Vote.Number > 2*d.config.CheckpointInterval {
		return fmt.Errorf("%w: gap %d exceeds 2*interval %d", errQCTooStale, number-qc.Vote.Number, 2*d.config.CheckpointInterval)
	}
	// Step 8: ChainID check
	chainID := chain.Config().ChainID
	if qc.Vote.ChainID == nil || chainID == nil || qc.Vote.ChainID.Cmp(chainID) != 0 {
		return errInvalidQCChainID
	}
	// Step 9: popcount(Bitmap) > 0 && <= MaxValidators
	pop := bits.OnesCount64(qc.Bitmap)
	if pop == 0 {
		return fmt.Errorf("%w: empty bitmap", errQCBitmapOverflow)
	}
	if uint64(pop) > d.config.MaxValidators {
		return fmt.Errorf("%w: popcount %d exceeds maxValidators %d", errQCBitmapOverflow, pop, d.config.MaxValidators)
	}
	// Step 10: len(Signatures) == popcount(Bitmap)
	if len(qc.Signatures) != pop {
		return fmt.Errorf("%w: have %d sigs, bitmap pop %d", errQCSignatureCountMismatch, len(qc.Signatures), pop)
	}
	return nil
}

// verifyCheckpointQCFull performs Phase 2 (cryptographic) QC checks.
// Called from VerifyFinalizedState after state and ancestors are available.
func (d *DPoS) verifyCheckpointQCFull(chain consensus.ChainHeaderReader, header *types.Header, snap *Snapshot) error {
	if !d.config.IsCheckpointFinality(header.Number) {
		return nil
	}
	number := header.Number.Uint64()
	isEpoch := number%d.config.Epoch == 0
	qc, err := parseCheckpointQCFromExtra(header.Extra, isEpoch, true)
	if err != nil {
		return err
	}
	if qc == nil {
		return nil // absent QC is valid
	}

	// Step 1: walk ancestors of header back to qc.Vote.Number.
	// We follow ParentHash links (not the canonical chain index) so the check is correct
	// even when the block being verified is not yet the canonical head — e.g. during a
	// reorg where the importing block is on a side branch.
	// The staleness limit from Phase 1 bounds this walk to at most 2*CheckpointInterval.
	cur := chain.GetHeader(header.ParentHash, number-1)
	for cur != nil && cur.Number.Uint64() > qc.Vote.Number {
		cur = chain.GetHeader(cur.ParentHash, cur.Number.Uint64()-1)
	}
	if cur == nil || cur.Number.Uint64() != qc.Vote.Number {
		return fmt.Errorf("%w: cannot find ancestor at %d", errQCNotAncestor, qc.Vote.Number)
	}
	ancestor := cur
	if ancestor.Hash() != qc.Vote.Hash {
		return fmt.Errorf("%w: hash mismatch at height %d", errQCNotAncestor, qc.Vote.Number)
	}

	// Step 2: load snapshot at qc.Vote.Number - 1 (checkpoint pre-state).
	if qc.Vote.Number == 0 {
		return fmt.Errorf("%w: checkpoint number must be > 0", errInvalidQCNumber)
	}
	preSnap, err := d.snapshot(chain, qc.Vote.Number-1, ancestor.ParentHash, nil)
	if err != nil {
		return fmt.Errorf("dpos: checkpoint pre-state snapshot unavailable: %w", err)
	}

	// Steps 3–4: build ordered signer set and validate all metadata.
	// The signer set is the validators in preSnap, sorted ascending by address.
	signerSet, err := d.buildSignerSet(preSnap)
	if err != nil {
		return err
	}

	// Recompute ValidatorSetHash and compare.
	vsHash := computeValidatorSetHash(signerSet)
	if vsHash != qc.Vote.ValidatorSetHash {
		return errQCValidatorSetHashMismatch
	}

	// Step 5–6: verify signatures against bitmap.
	signingHash := qc.Vote.SigningHash()
	N := len(signerSet)
	sigIdx := 0
	for i := 0; i < 64 && sigIdx < len(qc.Signatures); i++ {
		if qc.Bitmap&(1<<uint(i)) == 0 {
			continue
		}
		if i >= N {
			return fmt.Errorf("%w: bitmap bit %d exceeds signer set size %d", errQCBitmapOverflow, i, N)
		}
		rec := signerSet[i]
		if rec.SignerType != accountsigner.SignerTypeEd25519 {
			return fmt.Errorf("%w: validator %s has non-ed25519 signer type %q", errQCInvalidSignature, rec.Address.Hex(), rec.SignerType)
		}
		pub := ed25519.PublicKey(rec.SignerPub)
		sig := qc.Signatures[sigIdx][:]
		if !ed25519.Verify(pub, signingHash[:], sig) {
			return fmt.Errorf("%w: validator %s index %d", errQCInvalidSignature, rec.Address.Hex(), i)
		}
		sigIdx++
	}

	// Step 7: require >= ceil(2*N/3) valid signatures.
	quorum := (2*N + 2) / 3 // ceil(2N/3)
	if sigIdx < quorum {
		return fmt.Errorf("%w: have %d, need %d (N=%d)", errQCInsufficientSignatures, sigIdx, quorum, N)
	}

	// Step 8: advance finalized state on snapshot.
	if snap.UpdateFinalized(qc.Vote.Number, qc.Vote.Hash) {
		// §14: keep both layers in sync. Store vsHash for RPC.
		d.finalizedVSHash.Store("vsHash", qc.Vote.ValidatorSetHash)
		// ancestor header was already retrieved above for the hash check.
		d.lock.RLock()
		setFn := d.setFinalizedFn
		d.lock.RUnlock()
		if setFn != nil {
			setFn(ancestor)
		}
	}
	return nil
}

// buildSignerSet loads the ordered ValidatorSigner list for a checkpoint pre-state.
// It opens the state at preSnap and delegates to loadSignerSet from signer_set.go.
func (d *DPoS) buildSignerSet(preSnap *Snapshot) ([]ValidatorSigner, error) {
	if d.db == nil {
		return nil, errors.New("dpos: missing database for signer set lookup")
	}
	preHeader := rawdb.ReadHeader(d.db, preSnap.Hash, preSnap.Number)
	if preHeader == nil {
		return nil, fmt.Errorf("dpos: missing header for snapshot at %d", preSnap.Number)
	}
	stateDB, err := state.New(preHeader.Root, state.NewDatabase(d.db), nil)
	if err != nil {
		return nil, fmt.Errorf("dpos: cannot open pre-state at %d: %w", preSnap.Number, err)
	}
	return loadSignerSet(preSnap, stateDB)
}

// assembleCheckpointQC assembles a CheckpointQC from the vote pool for the latest
// unfinalized eligible checkpoint preceding the given header, if a quorum exists.
// Returns (nil, nil) if no quorum is available.
func (d *DPoS) assembleCheckpointQC(chain consensus.ChainHeaderReader, header *types.Header, snap *Snapshot) (*types.CheckpointQC, error) {
	if d.votePool == nil || d.config.CheckpointInterval == 0 || d.config.CheckpointFinalityBlock == nil {
		return nil, nil
	}
	number := header.Number.Uint64()
	firstEligible := firstCheckpointAtOrAfter(d.config.CheckpointFinalityBlock.Uint64(), d.config.CheckpointInterval)

	// Find the latest unfinalized eligible checkpoint strictly before this block.
	// Walk backwards in multiples of CheckpointInterval.
	k := d.config.CheckpointInterval
	// Largest checkpoint < number that is a multiple of k and >= firstEligible.
	if number <= firstEligible {
		return nil, nil
	}
	candidate := (number - 1) / k * k
	if candidate < firstEligible {
		return nil, nil
	}
	if candidate <= snap.FinalizedNumber {
		return nil, nil // already finalized
	}

	// Load the checkpoint block header to get its hash.
	cpHeader := chain.GetHeaderByNumber(candidate)
	if cpHeader == nil {
		return nil, nil
	}
	cpHash := cpHeader.Hash()

	// Load pre-state snapshot for this checkpoint.
	preSnap, err := d.snapshot(chain, candidate-1, cpHeader.ParentHash, nil)
	if err != nil {
		return nil, nil // pre-state not available; skip silently
	}

	// Build signer set.
	records, err := d.buildSignerSet(preSnap)
	if err != nil {
		return nil, nil
	}
	N := len(records)
	quorum := (2*N + 2) / 3

	// Build address→index map for fast lookup.
	addrIdx := make(map[common.Address]int, N)
	for i, r := range records {
		addrIdx[r.Address] = i
	}

	// Compute ValidatorSetHash and the canonical signing hash for this checkpoint.
	// Both are needed before we can verify vote signatures (§12 step 5).
	vsHash := computeValidatorSetHash(records)
	signingHash := (&types.CheckpointVote{
		ChainID:          chain.Config().ChainID,
		Number:           candidate,
		Hash:             cpHash,
		ValidatorSetHash: vsHash,
	}).SigningHash()

	// Promote pending votes (§9): votes received while the snapshot was unavailable.
	// Now that we have the signer set, run admission checks 4–6 and move valid ones
	// into the main vote cache so they contribute to the QC.
	for _, env := range d.votePool.DrainPending(candidate) {
		idx, ok := addrIdx[env.Signer]
		if !ok {
			continue
		}
		pub := ed25519.PublicKey(records[idx].SignerPub)
		if !ed25519.Verify(pub, signingHash[:], env.Signature[:]) {
			continue
		}
		d.votePool.AddVote(env)
	}

	// Collect valid votes — verify each signature before including in the QC (§12 step 5).
	type validVote struct {
		idx int
		sig [64]byte
	}
	var validVotes []validVote
	for _, env := range d.votePool.GetVotes(candidate, cpHash) {
		idx, ok := addrIdx[env.Signer]
		if !ok {
			continue
		}
		pub := ed25519.PublicKey(records[idx].SignerPub)
		if !ed25519.Verify(pub, signingHash[:], env.Signature[:]) {
			continue // invalid sig; exclude from QC
		}
		validVotes = append(validVotes, validVote{idx: idx, sig: env.Signature})
	}
	if len(validVotes) < quorum {
		return nil, nil
	}
	// Sort by index for deterministic bitmap.
	sort.Slice(validVotes, func(i, j int) bool { return validVotes[i].idx < validVotes[j].idx })

	var bitmap uint64
	sigs := make([][64]byte, 0, len(validVotes))
	for _, v := range validVotes {
		bitmap |= 1 << uint(v.idx)
		sigs = append(sigs, v.sig)
	}

	qc := &types.CheckpointQC{
		Vote: types.CheckpointVote{
			ChainID:          chain.Config().ChainID,
			Number:           candidate,
			Hash:             cpHash,
			ValidatorSetHash: vsHash,
		},
		Bitmap:     bitmap,
		Signatures: sigs,
	}
	return qc, nil
}

func (d *DPoS) normalizeSealPayload(payload []byte) ([]byte, error) {
	if len(payload) != extraSealEd25519 {
		return nil, fmt.Errorf("dpos: invalid ed25519 seal length: have %d want %d", len(payload), extraSealEd25519)
	}
	return append([]byte(nil), payload...), nil
}

func recoverHeaderSigner(config *params.DPoSConfig, header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	hash := header.Hash()
	if addr, ok := sigcache.Get(hash); ok {
		return addr.(common.Address), nil
	}
	sealLen := sealLengthForSignerType(params.DefaultDPoSSealSignerType)
	if config != nil && config.SealSignerType != "" {
		sealLen = sealLengthForSignerType(config.SealSignerType)
	}
	if len(header.Extra) < sealLen {
		return common.Address{}, errMissingSignature
	}
	sig := header.Extra[len(header.Extra)-sealLen:]
	digest := sealHashWithSealLength(header, sealLen).Bytes()

	pub := sig[:ed25519.PublicKeySize]
	signature := sig[ed25519.PublicKeySize:]
	if !ed25519.Verify(ed25519.PublicKey(pub), digest, signature) {
		return common.Address{}, errInvalidSignature
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pub))
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

	// Reject far-future blocks (3× periodMs grace period). Checked even in faker mode.
	if header.Time > uint64(time.Now().UnixMilli())+3*d.config.TargetBlockPeriodMs() {
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
		cfActive := d.config.IsCheckpointFinality(header.Number)
		middle := header.Extra[extraVanity : len(header.Extra)-d.sealLength]
		if isEpoch && cfActive {
			// New format: [1B count=N][N×AddressLength][QC RLP (optional)]
			if len(middle) == 0 {
				return errInvalidCheckpointValidators
			}
			n := int(middle[0])
			valEnd := 1 + n*common.AddressLength
			if valEnd > len(middle) {
				return errInvalidCheckpointValidators
			}
			// validator bytes must be a non-zero multiple of AddressLength (n > 0)
			if n == 0 {
				return errInvalidCheckpointValidators
			}
		} else if isEpoch {
			// Old epoch format: [N×AddressLength]
			if len(middle) == 0 || len(middle)%common.AddressLength != 0 {
				return errInvalidCheckpointValidators
			}
		} else if !cfActive {
			// Pre-activation non-epoch: no validator bytes allowed.
			if len(middle) != 0 {
				return errExtraValidators
			}
		}
		// Post-activation non-epoch: middle may contain a QC (any length is OK here;
		// structural QC checks are done in verifyCheckpointQCStructure).
	}

	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	if number > 0 {
		var parent *types.Header
		if len(parents) > 0 {
			parent = parents[len(parents)-1]
		} else {
			parent = chain.GetHeaderByNumber(number - 1)
		}
		if parent != nil {
			if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
				return err
			}
		}
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
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d",
			header.GasUsed, header.GasLimit)
	}
	// Shape-check epoch Extra: validator bytes must be a non-zero multiple of AddressLength.
	isEpoch := number%d.config.Epoch == 0
	cfActive := d.config.IsCheckpointFinality(header.Number)
	if isEpoch {
		middle := header.Extra[extraVanity : len(header.Extra)-d.sealLength]
		if cfActive {
			// New format: [1B count=N][N×AddressLength][optional QC]
			if len(middle) == 0 {
				return errInvalidCheckpointValidators
			}
			n := int(middle[0])
			if n == 0 {
				return errInvalidCheckpointValidators
			}
			valEnd := 1 + n*common.AddressLength
			if valEnd > len(middle) {
				return errInvalidCheckpointValidators
			}
		} else {
			// Old format: [N×AddressLength]
			if len(middle) <= 0 || len(middle)%common.AddressLength != 0 {
				return errInvalidCheckpointValidators
			}
		}
	}
	if header.Time < parent.Time+d.config.TargetBlockPeriodMs() {
		return errInvalidTimestamp
	}

	snap, err := d.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// M2: guard against uint64 underflow before slot computation.
	if header.Time < snap.GenesisTime || parent.Time < snap.GenesisTime {
		return errInvalidTimestamp
	}

	// Rule 1: slot must strictly advance (redundant with interval check; kept defensive).
	// Explicitly check ok even though M2 guard above guarantees validity: defence in depth.
	parentSlot, ok1 := headerSlot(parent.Time, snap.GenesisTime, snap.PeriodMs)
	hdrSlot, ok2 := headerSlot(header.Time, snap.GenesisTime, snap.PeriodMs)
	if !ok1 || !ok2 {
		return errInvalidTimestamp
	}
	if hdrSlot <= parentSlot {
		return errInvalidSlot
	}
	if isEpoch {
		expected, err := d.activeValidatorsAtRoot(parent.Root, state.NewDatabase(d.db))
		switch {
		case err == nil:
			if len(expected) == 0 {
				expected = append([]common.Address(nil), snap.Validators...)
			}
			if err := d.verifyEpochExtraAgainstValidators(header, expected); err != nil {
				return err
			}
		case errors.Is(err, errMissingParentState):
			// Header verification may run ahead of block-state import for batched
			// segments. Defer the definitive epoch-extra check to finalized-state
			// verification once the parent root is available through the state DB.
		default:
			return err
		}
	}

	// Phase 1 structural QC checks (no state access required).
	if err := d.verifyCheckpointQCStructure(chain, header); err != nil {
		return err
	}

	return d.verifySeal(snap, header)
}

func (d *DPoS) activeValidatorsAtRoot(root common.Hash, db state.Database) ([]common.Address, error) {
	if db == nil {
		return nil, errors.New("dpos: missing database for validator lookup")
	}
	statedb, err := state.New(root, db, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errMissingParentState, err)
	}
	return validator.ReadActiveValidators(statedb, d.config.MaxValidators), nil
}

func (d *DPoS) expectedEpochValidators(parent *types.Header, fallback []common.Address, db state.Database) ([]common.Address, error) {
	actual, err := d.activeValidatorsAtRoot(parent.Root, db)
	if err == nil && len(actual) > 0 {
		return actual, nil
	}
	if len(fallback) > 0 {
		out := make([]common.Address, len(fallback))
		copy(out, fallback)
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("dpos: no active validators at epoch boundary")
}

func (d *DPoS) fallbackValidatorsFromHeader(chain consensus.ChainHeaderReader, header *types.Header) ([]common.Address, error) {
	for header != nil {
		number := header.Number.Uint64()
		if number == 0 {
			return parseGenesisValidators(header.Extra)
		}
		if number%d.config.Epoch == 0 {
			cfActive := d.config.IsCheckpointFinality(header.Number)
			return parseEpochValidators(header.Extra, d.config, cfActive)
		}
		header = chain.GetHeader(header.ParentHash, number-1)
	}
	return nil, consensus.ErrUnknownAncestor
}

func (d *DPoS) verifyEpochExtraAgainstValidators(header *types.Header, actual []common.Address) error {
	cfActive := d.config.IsCheckpointFinality(header.Number)
	claimed, err := parseEpochValidators(header.Extra, d.config, cfActive)
	if err != nil {
		return err
	}
	number := header.Number.Uint64()
	if len(claimed) != len(actual) {
		return fmt.Errorf("dpos: epoch %d validator count mismatch: Extra has %d, expected %d",
			number, len(claimed), len(actual))
	}
	for i, v := range actual {
		if claimed[i] != v {
			return fmt.Errorf("dpos: epoch %d validator mismatch at index %d: Extra=%s, expected=%s",
				number, i, claimed[i].Hex(), v.Hex())
		}
	}
	return nil
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
	// Compute slot for this header.
	slot, ok := headerSlot(header.Time, snap.GenesisTime, snap.PeriodMs)
	if !ok {
		return errInvalidTimestamp
	}
	// Check recency: reject if signer signed within the slot-based recency window.
	limit := snap.config.RecentSignerWindowSize(len(snap.Validators))
	for seenSlot, recent := range snap.Recents {
		if recent == signer {
			if slot < limit || seenSlot > slot-limit {
				return errRecentlySigned
			}
		}
	}
	if !d.fakeDiff {
		inturn := snap.inturnSlot(slot, signer)
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
			snap, err = newSnapshot(d.config, d.signatures, 0, genesis.Hash(), validators,
				genesis.Time, d.config.TargetBlockPeriodMs())
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
	header.Difficulty = calcDifficultySlot(snap, header.Time, v)

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

// VerifyEpochExtra checks that an epoch block's Extra validator list matches
// the validator registry in the parent-state snapshot. This keeps epoch Extra
// fully header-verifiable and prevents malformed epoch headers from being
// admitted into the header chain before full block execution.
func (d *DPoS) VerifyEpochExtra(header *types.Header, statedb *state.StateDB) error {
	if d.fakeDiff {
		return nil
	}
	number := header.Number.Uint64()
	if number == 0 || number%d.config.Epoch != 0 {
		return nil
	}
	if d.db == nil {
		return errors.New("dpos: missing database for epoch verification")
	}
	parent := rawdb.ReadHeader(d.db, header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	chainCfg := &params.ChainConfig{DPoS: d.config}
	rawChain := &rawChainReader{config: chainCfg, db: d.db}
	fallback, err := d.fallbackValidatorsFromHeader(rawChain, parent)
	if err != nil {
		return err
	}
	parentDB := state.NewDatabase(d.db)
	if statedb != nil {
		parentDB = statedb.Database()
	}
	expected, err := d.expectedEpochValidators(parent, fallback, parentDB)
	if err != nil {
		return err
	}
	return d.verifyEpochExtraAgainstValidators(header, expected)
}

// VerifyFinalizedState implements consensus.FinalizedStateVerifier.
// It delegates to VerifyEpochExtra for epoch blocks, and additionally runs
// Phase 2 checkpoint QC verification when checkpoint finality is active.
func (d *DPoS) VerifyFinalizedState(header *types.Header, st *state.StateDB) error {
	if err := d.VerifyEpochExtra(header, st); err != nil {
		return err
	}
	if d.config.IsCheckpointFinality(header.Number) && header.Number.Uint64() > 0 {
		if d.db == nil {
			return nil // no db in faker mode; skip Phase 2
		}
		chainCfg := &params.ChainConfig{DPoS: d.config}
		rawChain := &rawChainReader{config: chainCfg, db: d.db}
		number := header.Number.Uint64()
		snap, err := d.snapshot(rawChain, number-1, header.ParentHash, nil)
		if err != nil {
			return err
		}
		if err := d.verifyCheckpointQCFull(rawChain, header, snap); err != nil {
			return err
		}
	}
	return nil
}

// Finalize implements consensus.Engine, adding the block reward.
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

	// At epoch boundaries, embed the validator set from the parent-state snapshot
	// into Extra so the value is fully header-verifiable. Validator registry
	// mutations inside the epoch block itself take effect at the next epoch.
	if number%d.config.Epoch == 0 && !d.fakeDiff {
		parent := chain.GetHeader(header.ParentHash, number-1)
		if parent == nil && d.db != nil {
			parent = rawdb.ReadHeader(d.db, header.ParentHash, number-1)
		}
		if parent == nil {
			return nil, consensus.ErrUnknownAncestor
		}
		fallback, err := d.fallbackValidatorsFromHeader(chain, parent)
		if err != nil {
			return nil, err
		}
		validators, err := d.expectedEpochValidators(parent, fallback, st.Database())
		if err != nil {
			return nil, err
		}
		// validators is already address-sorted (ReadActiveValidators phase 3).
		vanity := header.Extra[:extraVanity]
		cfActive := d.config.IsCheckpointFinality(header.Number)
		if cfActive {
			// New format: [32B vanity][1B count=N][N×AddressLength][QC RLP (optional)][seal]
			snap, snapErr := d.snapshot(chain, number-1, header.ParentHash, nil)
			var qcBytes []byte
			if snapErr == nil {
				qc, qcErr := d.assembleCheckpointQC(chain, header, snap)
				if qcErr == nil && qc != nil {
					qcBytes, _ = rlp.EncodeToBytes(qc)
				}
			}
			valPayload := make([]byte, 1+len(validators)*common.AddressLength)
			valPayload[0] = byte(len(validators))
			for i, v := range validators {
				copy(valPayload[1+i*common.AddressLength:], v.Bytes())
			}
			extra := make([]byte, extraVanity+len(valPayload)+len(qcBytes)+d.sealLength)
			copy(extra, vanity)
			copy(extra[extraVanity:], valPayload)
			copy(extra[extraVanity+len(valPayload):], qcBytes)
			header.Extra = extra
		} else {
			// Old format: [32B vanity][N×AddressLength][seal]
			extra := make([]byte, extraVanity+len(validators)*common.AddressLength+d.sealLength)
			copy(extra, vanity)
			for i, v := range validators {
				copy(extra[extraVanity+i*common.AddressLength:], v.Bytes())
			}
			header.Extra = extra // trailing seal bytes are the seal placeholder
		}
	} else if !d.fakeDiff && d.config.IsCheckpointFinality(header.Number) {
		// Non-epoch block with checkpoint finality active: try to embed a QC.
		snap, snapErr := d.snapshot(chain, number-1, header.ParentHash, nil)
		if snapErr == nil {
			qc, qcErr := d.assembleCheckpointQC(chain, header, snap)
			if qcErr == nil && qc != nil {
				qcBytes, encErr := rlp.EncodeToBytes(qc)
				if encErr == nil {
					vanity := header.Extra[:extraVanity]
					extra := make([]byte, extraVanity+len(qcBytes)+d.sealLength)
					copy(extra, vanity)
					copy(extra[extraVanity:], qcBytes)
					header.Extra = extra
				}
			}
		}
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
	sealSlot, ok := headerSlot(header.Time, snap.GenesisTime, snap.PeriodMs)
	if !ok {
		return errInvalidTimestamp
	}
	limit := snap.config.RecentSignerWindowSize(len(snap.Validators))
	for seenSlot, recent := range snap.Recents {
		if recent == v {
			if sealSlot < limit || seenSlot > sealSlot-limit {
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

	// Vote production: if checkpoint finality is active and the parent block is an
	// eligible checkpoint, produce a CheckpointVote and store it in the vote pool.
	if d.config.IsCheckpointFinality(header.Number) && d.votePool != nil {
		d.maybeProduceCheckpointVote(chain, header, snap, v, signFn)
		// Prune stale votes to bound memory usage (§9 cache cleanup).
		d.votePool.Prune(snap.FinalizedNumber, header.Number.Uint64(), d.config.CheckpointInterval)
	}

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

// maybeProduceCheckpointVote checks if the block being sealed follows an eligible
// checkpoint, and if so produces a signed CheckpointVoteEnvelope and stores it in
// the vote pool. Errors are logged but not propagated (vote production is best-effort).
func (d *DPoS) maybeProduceCheckpointVote(
	chain consensus.ChainHeaderReader,
	header *types.Header,
	snap *Snapshot,
	v common.Address,
	signFn SignerFn,
) {
	if d.config.CheckpointInterval == 0 || d.config.CheckpointFinalityBlock == nil {
		return
	}
	number := header.Number.Uint64()
	firstEligible := firstCheckpointAtOrAfter(d.config.CheckpointFinalityBlock.Uint64(), d.config.CheckpointInterval)
	k := d.config.CheckpointInterval

	// Find eligible checkpoints strictly less than the current block that the validator
	// has not yet voted for. We attempt the most recent one.
	if number <= firstEligible {
		return
	}
	candidate := (number - 1) / k * k
	if candidate < firstEligible || candidate <= snap.FinalizedNumber {
		return
	}

	cpHeader := chain.GetHeaderByNumber(candidate)
	if cpHeader == nil {
		return
	}
	cpHash := cpHeader.Hash()

	// §11 step 3–4: double-sign guard. Check DB before committing to this hash.
	if d.db != nil {
		if existing, ok := ReadSignedCheckpoint(d.db, candidate); ok && existing != cpHash {
			log.Debug("DPoS checkpoint vote: different hash already signed, skipping",
				"checkpoint", candidate, "signed", existing, "current", cpHash)
			return
		}
	}

	// Build the vote.
	chainID := chain.Config().ChainID
	vote := types.CheckpointVote{
		ChainID: new(big.Int).Set(chainID),
		Number:  candidate,
		Hash:    cpHash,
		// ValidatorSetHash will be filled after loading the signer set below.
	}

	// Load pre-state snapshot to get signer set and ValidatorSetHash.
	preSnap, err := d.snapshot(chain, candidate-1, cpHeader.ParentHash, nil)
	if err != nil {
		log.Debug("DPoS checkpoint vote: pre-state snapshot unavailable", "checkpoint", candidate, "err", err)
		return
	}
	records, err := d.buildSignerSet(preSnap)
	if err != nil {
		log.Debug("DPoS checkpoint vote: signer set unavailable", "checkpoint", candidate, "err", err)
		return
	}
	vsHash := computeValidatorSetHash(records)
	vote.ValidatorSetHash = vsHash

	// Check that this validator is in the signer set.
	found := false
	for _, r := range records {
		if r.Address == v {
			found = true
			break
		}
	}
	if !found {
		return
	}

	// Sign the vote digest.
	signingHash := vote.SigningHash()
	rawSig, err := signFn(accounts.Account{Address: v}, accounts.MimetypeDPoS, signingHash[:])
	if err != nil {
		log.Debug("DPoS checkpoint vote: signing failed", "checkpoint", candidate, "err", err)
		return
	}
	if len(rawSig) != ed25519.SignatureSize {
		log.Debug("DPoS checkpoint vote: unexpected signature length", "len", len(rawSig))
		return
	}
	var sig [64]byte
	copy(sig[:], rawSig)

	env := &types.CheckpointVoteEnvelope{
		Vote:      vote,
		Signer:    v,
		Signature: sig,
	}

	// §11 step 7: durably write before gossiping (write-ahead safety).
	if d.db != nil {
		if err := WriteSignedCheckpoint(d.db, candidate, cpHash); err != nil {
			log.Debug("DPoS checkpoint vote: failed to persist signed checkpoint", "err", err)
			return
		}
	}

	d.votePool.AddVote(env)

	// §11 step 8: gossip to peers.
	d.lock.RLock()
	bcastFn := d.broadcastVoteFn
	d.lock.RUnlock()
	if bcastFn != nil {
		bcastFn(env)
	}
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
	return calcDifficultySlot(snap, time, v)
}

func calcDifficultySlot(snap *Snapshot, headerTime uint64, v common.Address) *big.Int {
	slot, ok := headerSlot(headerTime, snap.GenesisTime, snap.PeriodMs)
	if !ok {
		return new(big.Int).Set(diffNoTurn)
	}
	if snap.inturnSlot(slot, v) {
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
