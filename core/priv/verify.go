package priv

import (
	"errors"

	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

func mapCryptoVerifyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, cryptopriv.ErrBackendUnavailable) {
		return ErrProofNotImplemented
	}
	if errors.Is(err, cryptopriv.ErrInvalidInput) || errors.Is(err, cryptopriv.ErrInvalidProof) || errors.Is(err, cryptopriv.ErrOperationFailed) {
		return ErrInvalidPayload
	}
	return err
}

// VerifyCiphertextValidityProof verifies that the ciphertext (commitment,
// senderHandle, receiverHandle) is a valid ElGamal encryption under the given
// sender and receiver public keys.
func VerifyCiphertextValidityProof(commitment, senderHandle, receiverHandle [32]byte, senderPub, receiverPub [32]byte, proof []byte) error {
	decoded, err := decodeCTValidityProof(proof)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptopriv.VerifyCTValidityProof(
		decoded,
		commitment[:],
		senderHandle[:],
		receiverHandle[:],
		senderPub[:],
		receiverPub[:],
		true, // always T1 version in priv
	))
}

// VerifyCommitmentEqProof verifies that the sourceCommitment is a valid
// Pedersen commitment to the same value as the ciphertext under the given
// public key.
func VerifyCommitmentEqProof(pubkey [32]byte, ciphertext Ciphertext, sourceCommitment [32]byte, proof []byte) error {
	decoded, err := decodeCommitmentEqProof(proof)
	if err != nil {
		return err
	}
	ct64 := make([]byte, 64)
	copy(ct64[:32], ciphertext.Commitment[:])
	copy(ct64[32:], ciphertext.Handle[:])
	return mapCryptoVerifyError(cryptopriv.VerifyCommitmentEqProof(
		decoded,
		pubkey[:],
		ct64,
		sourceCommitment[:],
	))
}

// VerifyRangeProof verifies the aggregated Bulletproof range proof proving
// that the committed amounts are in [0, 2^64).
func VerifyRangeProof(sourceCommitment, transferCommitment [32]byte, proof []byte) error {
	decoded, err := decodeRangeProof(proof)
	if err != nil {
		return err
	}
	// Aggregate both commitments into a single range proof verification.
	commitments := make([]byte, 64)
	copy(commitments[:32], sourceCommitment[:])
	copy(commitments[32:], transferCommitment[:])
	return mapCryptoVerifyError(cryptopriv.VerifyRangeProof(
		decoded,
		commitments,
		[]byte{64, 64},
		2,
	))
}
