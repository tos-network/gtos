package types

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

// CheckpointVote is the payload validators sign for checkpoint finality.
// Validators sign keccak256(RLP(["GTOS_CHECKPOINT_V1", ChainID, Number, Hash, ValidatorSetHash])).
type CheckpointVote struct {
	ChainID          *big.Int    // replay protection; mirrors GTOS chain config semantics
	Number           uint64      // checkpoint block number
	Hash             common.Hash // checkpoint block hash
	ValidatorSetHash common.Hash // keccak256(RLP ordered {address,signerType,signerPub}) at Number-1
}

// SigningHash returns the hash that validators sign.
// Domain-separated with the version string "GTOS_CHECKPOINT_V1".
func (v *CheckpointVote) SigningHash() common.Hash {
	sha := hasherPool.Get().(crypto.KeccakState)
	defer hasherPool.Put(sha)
	sha.Reset()
	rlp.Encode(sha, []interface{}{
		[]byte("GTOS_CHECKPOINT_V1"),
		v.ChainID,
		v.Number,
		v.Hash,
		v.ValidatorSetHash,
	})
	var h common.Hash
	sha.Read(h[:])
	return h
}

// CheckpointVoteEnvelope wraps a signed CheckpointVote with the explicit signer
// address. ed25519 does not support signer recovery, so the verifier uses Signer
// to locate the canonical ed25519 public key in the checkpoint pre-state.
type CheckpointVoteEnvelope struct {
	Vote      CheckpointVote
	Signer    common.Address // explicit signer; used to locate the validator's ed25519 pubkey
	Signature [64]byte       // ed25519 signature, always exactly 64 bytes
}

// CheckpointQC is a quorum certificate for a checkpoint block.
// Bitmap encodes which validators (by ascending-address index) have signed.
// Signatures is densely packed: entry i corresponds to the i-th set bit in Bitmap.
type CheckpointQC struct {
	Vote       CheckpointVote
	Bitmap     uint64     // bit i set => validator at ordered index i has signed
	Signatures [][64]byte // ed25519 signatures, aligned with set bits in Bitmap ascending
}
