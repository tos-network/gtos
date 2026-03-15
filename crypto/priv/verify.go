package priv

import (
	"errors"

	"github.com/tos-network/gtos/crypto/ed25519"
)

var (
	// ErrBackendUnavailable indicates native priv proof backend is not enabled in this build.
	ErrBackendUnavailable = errors.New("priv crypto: backend unavailable")
	// ErrInvalidInput indicates malformed proof/context bytes.
	ErrInvalidInput = errors.New("priv crypto: invalid input")
	// ErrInvalidProof indicates proof verification failure.
	ErrInvalidProof = errors.New("priv crypto: invalid proof")
	// ErrOperationFailed indicates native cryptographic operation failure.
	ErrOperationFailed = errors.New("priv crypto: operation failed")
)

func VerifyShieldProof(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64) error {
	return mapBackendError(ed25519.VerifyPrivShieldProof(proof96, commitment, receiverHandle, receiverPubkey, amount))
}

func VerifyShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64, ctx []byte) error {
	return mapBackendError(ed25519.VerifyPrivShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey, amount, ctx))
}

func VerifyCTValidityProof(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool) error {
	return mapBackendError(ed25519.VerifyPrivCTValidityProof(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey, txVersionT1))
}

func VerifyCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool, ctx []byte) error {
	return mapBackendError(ed25519.VerifyPrivCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey, txVersionT1, ctx))
}

func VerifyCommitmentEqProof(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte) error {
	return mapBackendError(ed25519.VerifyPrivCommitmentEqProof(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment))
}

func VerifyBalanceProof(proof, publicKey, sourceCiphertext64 []byte) error {
	return mapBackendError(ed25519.VerifyPrivBalanceProof(proof, publicKey, sourceCiphertext64))
}

func VerifyBalanceProofWithContext(proof, publicKey, sourceCiphertext64 []byte, ctx []byte) error {
	return mapBackendError(ed25519.VerifyPrivBalanceProofWithContext(proof, publicKey, sourceCiphertext64, ctx))
}

func VerifyRangeProof(proof []byte, commitments []byte, bitLengths []byte, batchLen uint8) error {
	return mapBackendError(ed25519.VerifyPrivRangeProof(proof, commitments, bitLengths, batchLen))
}

// ProveRangeProof generates a 672-byte Bulletproofs range proof proving that
// the value committed in commitment32 (with blinding factor blinding32) is in [0, 2^64).
func ProveRangeProof(commitment32 []byte, value uint64, blinding32 []byte) ([]byte, error) {
	out, err := ed25519.ProvePrivRangeProof(commitment32, value, blinding32)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return out, nil
}
