package uno

import (
	"errors"

	"github.com/tos-network/gtos/crypto/ed25519"
)

var (
	// ErrBackendUnavailable indicates native UNO proof backend is not enabled in this build.
	ErrBackendUnavailable = errors.New("uno crypto: backend unavailable")
	// ErrInvalidInput indicates malformed proof/context bytes.
	ErrInvalidInput = errors.New("uno crypto: invalid input")
	// ErrInvalidProof indicates proof verification failure.
	ErrInvalidProof = errors.New("uno crypto: invalid proof")
)

func VerifyShieldProof(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64) error {
	return mapBackendError(ed25519.VerifyUNOShieldProof(proof96, commitment, receiverHandle, receiverPubkey, amount))
}

func VerifyCTValidityProof(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool) error {
	return mapBackendError(ed25519.VerifyUNOCTValidityProof(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey, txVersionT1))
}

func VerifyCommitmentEqProof(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte) error {
	return mapBackendError(ed25519.VerifyUNOCommitmentEqProof(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment))
}

func VerifyBalanceProof(proof, publicKey, sourceCiphertext64 []byte) error {
	return mapBackendError(ed25519.VerifyUNOBalanceProof(proof, publicKey, sourceCiphertext64))
}

func VerifyRangeProof(proof []byte, commitments []byte, bitLengths []byte, batchLen uint8) error {
	return mapBackendError(ed25519.VerifyUNORangeProof(proof, commitments, bitLengths, batchLen))
}
