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

// VerifyCiphertextValidityProofWithContext is like VerifyCiphertextValidityProof
// but binds the proof to a chain-specific transcript context, preventing
// cross-chain/cross-nonce proof replay.
func VerifyCiphertextValidityProofWithContext(commitment, senderHandle, receiverHandle [32]byte, senderPub, receiverPub [32]byte, proof []byte, ctx []byte) error {
	decoded, err := decodeCTValidityProof(proof)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptopriv.VerifyCTValidityProofWithContext(
		decoded,
		commitment[:],
		senderHandle[:],
		receiverHandle[:],
		senderPub[:],
		receiverPub[:],
		true, // always T1 version in priv
		ctx,
	))
}

// VerifyCommitmentEqProofWithContext is like VerifyCommitmentEqProof but binds
// the proof to a chain-specific transcript context, preventing cross-chain/
// cross-nonce proof replay.
func VerifyCommitmentEqProofWithContext(pubkey [32]byte, ciphertext Ciphertext, sourceCommitment [32]byte, proof []byte, ctx []byte) error {
	decoded, err := decodeCommitmentEqProof(proof)
	if err != nil {
		return err
	}
	ct64 := make([]byte, 64)
	copy(ct64[:32], ciphertext.Commitment[:])
	copy(ct64[32:], ciphertext.Handle[:])
	return mapCryptoVerifyError(cryptopriv.VerifyCommitmentEqProofWithContext(
		decoded,
		pubkey[:],
		ct64,
		sourceCommitment[:],
		ctx,
	))
}

// VerifyBalanceProofWithContext verifies that subtracting the claimed amount
// from the source ciphertext yields a zero-value commitment opening.
func VerifyBalanceProofWithContext(pubkey [32]byte, ciphertext Ciphertext, proof []byte, ctx []byte) error {
	decoded, err := decodeBalanceProof(proof)
	if err != nil {
		return err
	}
	ct64 := make([]byte, 64)
	copy(ct64[:32], ciphertext.Commitment[:])
	copy(ct64[32:], ciphertext.Handle[:])
	return mapCryptoVerifyError(cryptopriv.VerifyBalanceProofWithContext(
		decoded,
		pubkey[:],
		ct64,
		ctx,
	))
}

// VerifyRangeProof verifies the two single-commitment Bulletproof range
// proofs carried by a PrivTransferTx.
func VerifyRangeProof(sourceCommitment, transferCommitment [32]byte, proof []byte) error {
	decoded, err := decodeTransferRangeProofs(proof)
	if err != nil {
		return err
	}
	if err := mapCryptoVerifyError(cryptopriv.VerifyRangeProof(
		decoded[0],
		sourceCommitment[:],
		[]byte{64},
		1,
	)); err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptopriv.VerifyRangeProof(
		decoded[1],
		transferCommitment[:],
		[]byte{64},
		1,
	))
}

// VerifySingleRangeProof verifies a range proof over a single commitment.
func VerifySingleRangeProof(commitment [32]byte, proof []byte) error {
	decoded, err := decodeSingleRangeProof(proof)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptopriv.VerifyRangeProof(
		decoded,
		commitment[:],
		[]byte{64},
		1,
	))
}

// VerifyShieldProofWithContext verifies that (commitment, handle) is a valid
// encryption of the given plaintext amount under the receiver's public key,
// bound to the transcript context.
func VerifyShieldProofWithContext(commitment, handle [32]byte, pubkey [32]byte, amount uint64, proof []byte, ctx []byte) error {
	decoded, err := decodeShieldProof(proof)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptopriv.VerifyShieldProofWithContext(
		decoded,
		commitment[:],
		handle[:],
		pubkey[:],
		amount,
		ctx,
	))
}
