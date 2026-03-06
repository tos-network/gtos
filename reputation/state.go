package reputation

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

var uint256Mod = new(big.Int).Lsh(big.NewInt(1), 256)

// scoreSlot returns the slot for the cumulative score (i256 as u256 two's complement).
func scoreSlot(addr common.Address) common.Hash {
	key := append([]byte("rep\x00score\x00"), addr.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// countSlot returns the slot for the rating count.
func countSlot(addr common.Address) common.Hash {
	key := append([]byte("rep\x00count\x00"), addr.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// scorerSlot returns the slot for the authorized scorer flag.
func scorerSlot(addr common.Address) common.Hash {
	key := append([]byte("rep\x00scorer\x00"), addr.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// TotalScoreOf returns the cumulative score for addr as a signed *big.Int.
// The value is stored as two's complement uint256; values >= 2^255 are negative.
func TotalScoreOf(db vm.StateDB, addr common.Address) *big.Int {
	raw := db.GetState(params.ReputationHubAddress, scoreSlot(addr))
	n := raw.Big()
	// Convert from two's complement: if bit 255 is set, the value is negative.
	half := new(big.Int).Lsh(big.NewInt(1), 255)
	if n.Cmp(half) >= 0 {
		n.Sub(n, uint256Mod)
	}
	return n
}

// RatingCountOf returns the total number of ratings recorded for addr.
func RatingCountOf(db vm.StateDB, addr common.Address) *big.Int {
	raw := db.GetState(params.ReputationHubAddress, countSlot(addr))
	return raw.Big()
}

// IsAuthorizedScorer returns true if addr is an authorized scorer.
func IsAuthorizedScorer(db vm.StateDB, addr common.Address) bool {
	raw := db.GetState(params.ReputationHubAddress, scorerSlot(addr))
	return raw[31] != 0
}

// AuthorizeScorer grants or revokes scorer authorization for scorer.
func AuthorizeScorer(db vm.StateDB, scorer common.Address, enabled bool) {
	var val common.Hash
	if enabled {
		val[31] = 1
	}
	db.SetState(params.ReputationHubAddress, scorerSlot(scorer), val)
}

// RecordScore adds a signed delta to the cumulative score for who,
// and increments the rating count. delta may be negative.
func RecordScore(db vm.StateDB, who common.Address, delta *big.Int) {
	// Read current score as two's complement uint256.
	raw := db.GetState(params.ReputationHubAddress, scoreSlot(who))
	current := raw.Big()

	// Add delta (converting negative delta to two's complement if needed).
	d := new(big.Int).Set(delta)
	if d.Sign() < 0 {
		d.Add(d, uint256Mod)
	}
	newScore := new(big.Int).Add(current, d)
	newScore.Mod(newScore, uint256Mod) // keep in uint256 range (wrapping arithmetic)

	db.SetState(params.ReputationHubAddress, scoreSlot(who), common.BigToHash(newScore))

	// Increment rating count.
	rawCount := db.GetState(params.ReputationHubAddress, countSlot(who))
	count := rawCount.Big()
	db.SetState(params.ReputationHubAddress, countSlot(who),
		common.BigToHash(new(big.Int).Add(count, big.NewInt(1))))
}
