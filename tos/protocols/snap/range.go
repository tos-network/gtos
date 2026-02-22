package snap

import (
	"math/big"

	"github.com/holiman/uint256"
	"github.com/tos-network/gtos/common"
)

// hashRange is a utility to handle ranges of hashes, Split up the
// hash-space into sections, and 'walk' over the sections
type hashRange struct {
	current *uint256.Int
	step    *uint256.Int
}

// newHashRange creates a new hashRange, initiated at the start position,
// and with the step set to fill the desired 'num' chunks
func newHashRange(start common.Hash, num uint64) *hashRange {
	left := new(big.Int).Sub(hashSpace, start.Big())
	step := new(big.Int).Div(
		new(big.Int).Add(left, new(big.Int).SetUint64(num-1)),
		new(big.Int).SetUint64(num),
	)
	step256 := new(uint256.Int)
	step256.SetFromBig(step)

	return &hashRange{
		current: new(uint256.Int).SetBytes32(start[:]),
		step:    step256,
	}
}

// Next pushes the hash range to the next interval.
func (r *hashRange) Next() bool {
	next, overflow := new(uint256.Int).AddOverflow(r.current, r.step)
	if overflow {
		return false
	}
	r.current = next
	return true
}

// Start returns the first hash in the current interval.
func (r *hashRange) Start() common.Hash {
	return r.current.Bytes32()
}

// End returns the last hash in the current interval.
func (r *hashRange) End() common.Hash {
	// If the end overflows (non divisible range), return a shorter interval
	next, overflow := new(uint256.Int).AddOverflow(r.current, r.step)
	if overflow {
		return common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	}
	return next.SubUint64(next, 1).Bytes32()
}

// incHash returns the next hash, in lexicographical order (a.k.a plus one)
func incHash(h common.Hash) common.Hash {
	var a uint256.Int
	a.SetBytes32(h[:])
	a.AddUint64(&a, 1)
	return common.Hash(a.Bytes32())
}
