package tos

import (
	"errors"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/bft"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/crypto/blake3"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rlp"
)

var errInvalidBFTVoteSignature = errors.New("invalid bft vote signature")

func voteDigestTOSv1(chainID *big.Int, height, round uint64, blockHash common.Hash) (common.Hash, error) {
	payload, err := rlp.EncodeToBytes([]interface{}{
		"tos-bft-vote-v1",
		chainIDOrZero(chainID),
		height,
		round,
		blockHash,
	})
	if err != nil {
		return common.Hash{}, err
	}
	sum := blake3.Sum256(payload)
	return common.BytesToHash(sum[:]), nil
}

func voteDigestLegacy(height, round uint64, blockHash common.Hash) (common.Hash, error) {
	payload, err := rlp.EncodeToBytes([]interface{}{
		"gtos-bft-vote-v1",
		height,
		round,
		blockHash,
	})
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(payload), nil
}

func voteDigests(chainID *big.Int, height, round uint64, blockHash common.Hash) ([]common.Hash, error) {
	tosV1, err := voteDigestTOSv1(chainID, height, round, blockHash)
	if err != nil {
		return nil, err
	}
	legacy, err := voteDigestLegacy(height, round, blockHash)
	if err != nil {
		return nil, err
	}
	return []common.Hash{tosV1, legacy}, nil
}

func verifyVoteSignature(chainID *big.Int, v bft.Vote) error {
	digests, err := voteDigests(chainID, v.Height, v.Round, v.BlockHash)
	if err != nil {
		return err
	}
	for _, digest := range digests {
		recovered, recErr := recoverSignerAddress(digest, v.Signature)
		if recErr == nil && recovered == v.Validator {
			return nil
		}
	}
	return errInvalidBFTVoteSignature
}

func verifyQCAttestations(chainID *big.Int, qc *bft.QC) error {
	if qc == nil {
		return bft.ErrInsufficientQuorum
	}
	var (
		total uint64
		seen  = make(map[common.Address]struct{}, len(qc.Attestations))
	)
	for _, att := range qc.Attestations {
		if att.Validator == (common.Address{}) || att.Weight == 0 || len(att.Signature) == 0 {
			return bft.ErrInvalidVote
		}
		if _, exists := seen[att.Validator]; exists {
			return bft.ErrInvalidVote
		}
		seen[att.Validator] = struct{}{}

		vote := bft.Vote{
			Height:    qc.Height,
			Round:     qc.Round,
			BlockHash: qc.BlockHash,
			Validator: att.Validator,
			Weight:    att.Weight,
			Signature: att.Signature,
		}
		if err := verifyVoteSignature(chainID, vote); err != nil {
			return err
		}
		total += att.Weight
	}
	if total != qc.TotalWeight {
		return bft.ErrInsufficientQuorum
	}
	return nil
}

func chainIDFromBlockChain(blockchain interface {
	Config() *params.ChainConfig
}) *big.Int {
	if blockchain == nil {
		return big.NewInt(0)
	}
	if cfg := blockchain.Config(); cfg != nil && cfg.ChainID != nil {
		return new(big.Int).Set(cfg.ChainID)
	}
	return big.NewInt(0)
}

func chainIDOrZero(chainID *big.Int) *big.Int {
	if chainID == nil {
		return big.NewInt(0)
	}
	return chainID
}

func recoverSignerAddress(digest common.Hash, signature []byte) (common.Address, error) {
	if len(signature) != crypto.SignatureLength {
		return common.Address{}, errInvalidBFTVoteSignature
	}
	sig := append([]byte(nil), signature...)
	pub, err := crypto.SigToPub(digest.Bytes(), sig)
	if err != nil && sig[64] >= 27 {
		sig[64] -= 27
		pub, err = crypto.SigToPub(digest.Bytes(), sig)
	}
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pub), nil
}
