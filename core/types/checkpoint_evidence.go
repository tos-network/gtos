package types

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

var (
	errNilCheckpointVoteEvidence = errors.New("nil checkpoint vote evidence")
	errInvalidCheckpointEvidence = errors.New("invalid checkpoint vote evidence")
)

// MaliciousVoteEvidence is the canonical operator-facing evidence format for
// checkpoint vote equivocation.
type MaliciousVoteEvidence struct {
	Version string                 `json:"version"`
	Kind    string                 `json:"kind"`
	ChainID *big.Int               `json:"chainId"`
	Number  uint64                 `json:"number"`
	Signer  common.Address         `json:"signer"`
	First   CheckpointVoteEnvelope `json:"first"`
	Second  CheckpointVoteEnvelope `json:"second"`
}

// NewMaliciousVoteEvidence validates and canonicalizes a pair of conflicting
// checkpoint vote envelopes. The output order is deterministic.
func NewMaliciousVoteEvidence(a, b *CheckpointVoteEnvelope) (*MaliciousVoteEvidence, error) {
	if a == nil || b == nil {
		return nil, errNilCheckpointVoteEvidence
	}
	if a.Signer != b.Signer {
		return nil, errInvalidCheckpointEvidence
	}
	if a.Vote.Number != b.Vote.Number {
		return nil, errInvalidCheckpointEvidence
	}
	if a.Vote.Hash == b.Vote.Hash {
		return nil, errInvalidCheckpointEvidence
	}
	if a.Vote.ChainID == nil || b.Vote.ChainID == nil || a.Vote.ChainID.Cmp(b.Vote.ChainID) != 0 {
		return nil, errInvalidCheckpointEvidence
	}

	first, second := *a, *b
	if checkpointVoteEnvelopeLess(&second, &first) {
		first, second = second, first
	}
	return &MaliciousVoteEvidence{
		Version: "GTOS_MALICIOUS_VOTE_EVIDENCE_V1",
		Kind:    "checkpoint_equivocation",
		ChainID: new(big.Int).Set(a.Vote.ChainID),
		Number:  a.Vote.Number,
		Signer:  a.Signer,
		First:   first,
		Second:  second,
	}, nil
}

// Validate checks that the evidence is canonical and self-consistent.
func (e *MaliciousVoteEvidence) Validate() error {
	if e == nil {
		return errNilCheckpointVoteEvidence
	}
	if e.Version != "GTOS_MALICIOUS_VOTE_EVIDENCE_V1" {
		return errInvalidCheckpointEvidence
	}
	if e.Kind != "checkpoint_equivocation" {
		return errInvalidCheckpointEvidence
	}
	if e.ChainID == nil {
		return errInvalidCheckpointEvidence
	}
	want, err := NewMaliciousVoteEvidence(&e.First, &e.Second)
	if err != nil {
		return err
	}
	if want.Number != e.Number || want.Signer != e.Signer || want.ChainID.Cmp(e.ChainID) != 0 {
		return errInvalidCheckpointEvidence
	}
	if want.First != e.First || want.Second != e.Second {
		return errInvalidCheckpointEvidence
	}
	return nil
}

// Hash returns a stable identifier for the evidence body.
func (e *MaliciousVoteEvidence) Hash() common.Hash {
	if e == nil {
		return common.Hash{}
	}
	sha := hasherPool.Get().(crypto.KeccakState)
	defer hasherPool.Put(sha)
	sha.Reset()
	_ = rlp.Encode(sha, []interface{}{
		e.Version,
		e.Kind,
		e.ChainID,
		e.Number,
		e.Signer,
		e.First,
		e.Second,
	})
	var h common.Hash
	sha.Read(h[:])
	return h
}

func checkpointVoteEnvelopeLess(a, b *CheckpointVoteEnvelope) bool {
	if cmp := bytes.Compare(a.Vote.Hash[:], b.Vote.Hash[:]); cmp != 0 {
		return cmp < 0
	}
	if cmp := bytes.Compare(a.Vote.ValidatorSetHash[:], b.Vote.ValidatorSetHash[:]); cmp != 0 {
		return cmp < 0
	}
	return bytes.Compare(a.Signature[:], b.Signature[:]) < 0
}
