package dpos

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"

	lru "github.com/hashicorp/golang-lru"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/tosdb"
)

// addressAscending sorts common.Address slices in ascending byte order.
// Required for deterministic validator ordering in inturn() and Extra encoding.
type addressAscending []common.Address

func (a addressAscending) Len() int      { return len(a) }
func (a addressAscending) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a addressAscending) Less(i, j int) bool {
	return bytes.Compare(a[i][:], a[j][:]) < 0
}

// Snapshot is the state of the validator set at a given block.
type Snapshot struct {
	config   *params.DPoSConfig
	sigcache *lru.ARCCache // hash → common.Address, shared with engine

	Number        uint64                      `json:"number"`
	Hash          common.Hash                 `json:"hash"`
	Validators    []common.Address            `json:"validators"`    // sorted ascending by address
	ValidatorsMap map[common.Address]struct{} `json:"validatorsMap"` // O(1) lookup
	Recents       map[uint64]common.Address   `json:"recents"`       // blockNum → signer
}

// newSnapshot creates a new snapshot. validators must already be sorted ascending by address.
func newSnapshot(
	config *params.DPoSConfig,
	sigcache *lru.ARCCache,
	number uint64,
	hash common.Hash,
	validators []common.Address,
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

// inturn returns true if validator is the expected proposer for the given block number.
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

// recentlySigned returns true if validator signed within the active recency window.
func (s *Snapshot) recentlySigned(validator common.Address) bool {
	for _, recent := range s.Recents {
		if recent == validator {
			return true
		}
	}
	return false
}

// apply creates a new snapshot by sequentially applying the given headers to the base.
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
		limit := snap.config.RecentSignerWindowSize(len(snap.Validators))
		if number >= limit {
			delete(snap.Recents, number-limit)
		}

		// Recover signer; validate membership and recency.
		signer, err := recoverHeaderSigner(snap.config, header, snap.sigcache)
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
		// so it cannot independently verify that header.Extra matches validator
		// registry state. Honest nodes use FinalizeAndAssemble which always reads
		// validator registry state correctly.
		// A byzantine validator (with <50% stake) could embed a wrong list,
		// but cannot sustain a fork since honest nodes build on the honest chain.
		if number%s.config.Epoch == 0 {
			validators, err := parseEpochValidators(header.Extra, snap.config)
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
			newLimit := snap.config.RecentSignerWindowSize(len(validators))
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

// parseEpochValidators extracts the validator list from an epoch block's Extra.
// Format: [32B vanity][N×AddressLength addresses][seal]
func parseEpochValidators(extra []byte, cfg *params.DPoSConfig) ([]common.Address, error) {
	sealSignerType := params.DefaultDPoSSealSignerType
	if cfg != nil {
		sealSignerType = cfg.SealSignerType
	}
	sealLen := sealLengthForSignerType(sealSignerType)
	if len(extra) < extraVanity+sealLen {
		return nil, errMissingSignature
	}
	payload := extra[extraVanity : len(extra)-sealLen]
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
// Format: [32B vanity][N×AddressLength addresses]
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

// loadSnapshot loads a snapshot from the database.
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

// validatorList returns the sorted validator addresses (for RPC use).
func (s *Snapshot) validatorList() []common.Address {
	out := make([]common.Address, len(s.Validators))
	copy(out, s.Validators)
	sort.Sort(addressAscending(out))
	return out
}
