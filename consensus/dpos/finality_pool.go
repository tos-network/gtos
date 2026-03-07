package dpos

import (
	"math/bits"
	"sync"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
)

// checkpointKey identifies a specific checkpoint proposal: the combination of
// block number and block hash. Different hashes at the same number indicate forks.
type checkpointKey struct {
	Number uint64
	Hash   common.Hash
}

// checkpointVotePool is a lightweight in-memory cache for CheckpointVoteEnvelopes.
//
// Design invariants:
//   - One validator contributes at most one vote per checkpoint number (per hash).
//   - Conflicting votes (same number, different hash) are stored as equivocation evidence.
//   - Votes whose snapshot pre-state is not yet available are queued in pending.
//   - Memory is bounded: Prune() must be called regularly.
type checkpointVotePool struct {
	mu sync.RWMutex

	// votes: (number, hash) -> signer -> envelope.
	// Only the first vote from a signer for a given (number, hash) is kept.
	votes map[checkpointKey]map[common.Address]*types.CheckpointVoteEnvelope

	// equivocations: number -> list of conflicting envelopes from the same signer.
	// Retained as evidence for future slashing (§9, §18).
	equivocations map[uint64][]*types.CheckpointVoteEnvelope

	// pending: number -> votes awaiting snapshot availability.
	// Votes here have not been cryptographically verified yet.
	pending map[uint64][]*types.CheckpointVoteEnvelope
}

// newCheckpointVotePool allocates and returns an empty checkpointVotePool.
func newCheckpointVotePool() *checkpointVotePool {
	return &checkpointVotePool{
		votes:         make(map[checkpointKey]map[common.Address]*types.CheckpointVoteEnvelope),
		equivocations: make(map[uint64][]*types.CheckpointVoteEnvelope),
		pending:       make(map[uint64][]*types.CheckpointVoteEnvelope),
	}
}

// AddVote adds a verified vote to the main cache.
//
// Returns (added bool, isEquivocation bool):
//   - (true,  false): vote was added normally.
//   - (false, false): exact duplicate; ignored.
//   - (false, true):  same signer, same number, different hash — stored as equivocation
//     evidence and NOT inserted into the main quorum cache.
func (p *checkpointVotePool) AddVote(env *types.CheckpointVoteEnvelope) (bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	number := env.Vote.Number
	hash := env.Vote.Hash
	signer := env.Signer

	key := checkpointKey{Number: number, Hash: hash}

	// Check whether this signer has already voted at this checkpoint number for any
	// hash (to detect equivocation across forks).
	for existingKey, signerMap := range p.votes {
		if existingKey.Number != number {
			continue
		}
		if _, exists := signerMap[signer]; exists {
			if existingKey.Hash == hash {
				// Exact duplicate — ignore silently.
				return false, false
			}
			// Different hash at same number from the same signer: equivocation.
			p.equivocations[number] = append(p.equivocations[number], env)
			return false, true
		}
	}

	// No prior vote from this signer at this number. Insert into main cache.
	if p.votes[key] == nil {
		p.votes[key] = make(map[common.Address]*types.CheckpointVoteEnvelope)
	}
	p.votes[key][signer] = env
	return true, false
}

// AddPending queues a vote whose checkpoint pre-state snapshot is not yet available.
// The caller must call DrainPending and re-verify once the snapshot becomes available.
func (p *checkpointVotePool) AddPending(env *types.CheckpointVoteEnvelope) {
	p.mu.Lock()
	defer p.mu.Unlock()
	number := env.Vote.Number
	p.pending[number] = append(p.pending[number], env)
}

// DrainPending removes and returns all pending votes for the given checkpoint number.
// The caller must re-run admission checks (steps 4–6 of §9) on the returned envelopes
// and call AddVote for those that pass.
func (p *checkpointVotePool) DrainPending(number uint64) []*types.CheckpointVoteEnvelope {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.pending[number]
	delete(p.pending, number)
	return out
}

// GetVotes returns a snapshot of all currently cached votes for the given (number, hash).
// The returned slice is a copy; the caller may iterate it without holding the lock.
func (p *checkpointVotePool) GetVotes(number uint64, hash common.Hash) []*types.CheckpointVoteEnvelope {
	p.mu.RLock()
	defer p.mu.RUnlock()
	key := checkpointKey{Number: number, Hash: hash}
	signerMap := p.votes[key]
	if len(signerMap) == 0 {
		return nil
	}
	out := make([]*types.CheckpointVoteEnvelope, 0, len(signerMap))
	for _, env := range signerMap {
		out = append(out, env)
	}
	return out
}

// VoteCount returns the number of distinct signers that have voted for (number, hash).
func (p *checkpointVotePool) VoteCount(number uint64, hash common.Hash) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.votes[checkpointKey{Number: number, Hash: hash}])
}

// Prune evicts stale votes to bound memory usage. Two eviction rules apply:
//
//  1. All votes for checkpoint numbers <= finalizedNumber are removed.
//     These checkpoints are already settled; their votes serve no further purpose.
//
//  2. All votes (and equivocations) for checkpoint numbers older than
//     currentHead - 2*checkpointInterval are removed regardless of finality state.
//     This prevents unbounded growth during prolonged finality stalls.
//
// This is a local memory policy only — it does not affect on-chain QC validity.
func (p *checkpointVotePool) Prune(finalizedNumber, currentHead, checkpointInterval uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Compute the sliding-window lower bound. Guard against underflow.
	var windowFloor uint64
	if checkpointInterval > 0 && currentHead > 2*checkpointInterval {
		windowFloor = currentHead - 2*checkpointInterval
	}

	for key := range p.votes {
		if key.Number <= finalizedNumber || key.Number <= windowFloor {
			delete(p.votes, key)
		}
	}
	for number := range p.equivocations {
		if number <= finalizedNumber || number <= windowFloor {
			delete(p.equivocations, number)
		}
	}
	for number := range p.pending {
		if number <= finalizedNumber || number <= windowFloor {
			delete(p.pending, number)
		}
	}
}

// Quorum returns the minimum number of votes required for a valid QC given N validators.
// quorum = ceil(2N/3).
func Quorum(n int) int {
	if n <= 0 {
		return 1
	}
	return (2*n + 2) / 3
}

// BitmapPopcount returns the number of set bits in the QC bitmap (number of signers).
func BitmapPopcount(bitmap uint64) int {
	return bits.OnesCount64(bitmap)
}
