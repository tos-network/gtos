package bft

import (
	"sort"
	"sync"

	"github.com/tos-network/gtos/common"
)

type voteKey struct {
	height uint64
	round  uint64
	block  common.Hash
}

type instanceKey struct {
	height uint64
	round  uint64
}

// VotePool stores votes for QC assembly.
type VotePool struct {
	mu sync.RWMutex

	totalWeight uint64
	required    uint64

	// votesByTarget tracks votes for a specific (height,round,blockHash).
	votesByTarget map[voteKey]map[common.Address]Vote
	// votedTarget tracks which block hash a validator voted for at (height,round).
	votedTarget map[instanceKey]map[common.Address]common.Hash
}

func NewVotePool(totalWeight uint64) *VotePool {
	return &VotePool{
		totalWeight:   totalWeight,
		required:      RequiredQuorumWeight(totalWeight),
		votesByTarget: make(map[voteKey]map[common.Address]Vote),
		votedTarget:   make(map[instanceKey]map[common.Address]common.Hash),
	}
}

func (p *VotePool) RequiredWeight() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.required
}

func (p *VotePool) AddVote(v Vote) (bool, error) {
	if err := validateVote(v); err != nil {
		return false, err
	}
	target := voteKey{height: v.Height, round: v.Round, block: v.BlockHash}
	instance := instanceKey{height: v.Height, round: v.Round}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.votedTarget[instance] == nil {
		p.votedTarget[instance] = make(map[common.Address]common.Hash)
	}
	if prev, ok := p.votedTarget[instance][v.Validator]; ok {
		if prev != v.BlockHash {
			return false, ErrEquivocation
		}
		if existingSet, ok := p.votesByTarget[target]; ok {
			if _, exists := existingSet[v.Validator]; exists {
				return false, nil // duplicate vote, ignore
			}
		}
	}
	p.votedTarget[instance][v.Validator] = v.BlockHash

	if p.votesByTarget[target] == nil {
		p.votesByTarget[target] = make(map[common.Address]Vote)
	}
	p.votesByTarget[target][v.Validator] = v
	return true, nil
}

func (p *VotePool) Tally(height, round uint64, blockHash common.Hash) (uint64, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	target := voteKey{height: height, round: round, block: blockHash}
	votes := p.votesByTarget[target]
	var total uint64
	for _, v := range votes {
		total += v.Weight
	}
	return total, len(votes)
}

func (p *VotePool) BuildQC(height, round uint64, blockHash common.Hash) (*QC, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	target := voteKey{height: height, round: round, block: blockHash}
	votes := p.votesByTarget[target]
	if len(votes) == 0 {
		return nil, false
	}
	var total uint64
	att := make([]QCAttestation, 0, len(votes))
	for _, v := range votes {
		total += v.Weight
		att = append(att, QCAttestation{
			Validator: v.Validator,
			Weight:    v.Weight,
			Signature: append([]byte(nil), v.Signature...),
		})
	}
	if total < p.required {
		return nil, false
	}
	sort.Slice(att, func(i, j int) bool {
		return att[i].Validator.Hex() < att[j].Validator.Hex()
	})
	return &QC{
		Height:       height,
		Round:        round,
		BlockHash:    blockHash,
		TotalWeight:  total,
		Required:     p.required,
		Attestations: att,
	}, true
}

// PruneBelow drops vote data for heights strictly lower than minHeight.
func (p *VotePool) PruneBelow(minHeight uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for target := range p.votesByTarget {
		if target.height < minHeight {
			delete(p.votesByTarget, target)
		}
	}
	for inst := range p.votedTarget {
		if inst.height < minHeight {
			delete(p.votedTarget, inst)
		}
	}
}

func validateVote(v Vote) error {
	if v.Weight == 0 || v.Validator == (common.Address{}) || v.BlockHash == (common.Hash{}) {
		return ErrInvalidVote
	}
	if len(v.Signature) == 0 {
		return ErrInvalidVote
	}
	return nil
}
