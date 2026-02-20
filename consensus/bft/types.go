package bft

import (
	"errors"

	"github.com/tos-network/gtos/common"
)

var (
	ErrInvalidVote        = errors.New("bft: invalid vote")
	ErrEquivocation       = errors.New("bft: equivocation detected")
	ErrInsufficientQuorum = errors.New("bft: insufficient quorum")
)

// Vote is the minimum unit collected by the Phase-1 QC pool.
// Height+Round identify the instance, BlockHash identifies the proposal target.
type Vote struct {
	Height    uint64
	Round     uint64
	BlockHash common.Hash
	Validator common.Address
	Weight    uint64
	Signature []byte
}

// QCAttestation stores a validator's vote material included in a QC.
type QCAttestation struct {
	Validator common.Address
	Weight    uint64
	Signature []byte
}

// QC is a quorum certificate assembled from votes.
type QC struct {
	Height       uint64
	Round        uint64
	BlockHash    common.Hash
	TotalWeight  uint64
	Required     uint64
	Attestations []QCAttestation
}
