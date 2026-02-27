package uno

import (
	"errors"

	cryptouno "github.com/tos-network/gtos/crypto/uno"
)

func mapCryptoVerifyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, cryptouno.ErrBackendUnavailable) {
		return ErrProofNotImplemented
	}
	if errors.Is(err, cryptouno.ErrInvalidInput) || errors.Is(err, cryptouno.ErrInvalidProof) || errors.Is(err, cryptouno.ErrOperationFailed) {
		return ErrInvalidPayload
	}
	return err
}

func ciphertextToBytes(ct Ciphertext) []byte {
	out := make([]byte, 64)
	copy(out[:32], ct.Commitment[:])
	copy(out[32:], ct.Handle[:])
	return out
}

func VerifyShieldProofBundle(bundle []byte, commitment, receiverHandle, receiverPubkey []byte, amount uint64) error {
	proof, err := decodeShieldProofBundle(bundle)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptouno.VerifyShieldProof(proof, commitment, receiverHandle, receiverPubkey, amount))
}

func VerifyCTValidityProofBundle(bundle []byte, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool) error {
	proof, err := decodeCTValidityProofBundle(bundle, txVersionT1)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptouno.VerifyCTValidityProof(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey, txVersionT1))
}

func VerifyCommitmentEqProofBundle(bundle []byte, sourcePubkey, sourceCiphertext, destinationCommitment []byte) error {
	proof, err := decodeCommitmentEqProofBundle(bundle)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptouno.VerifyCommitmentEqProof(proof, sourcePubkey, sourceCiphertext, destinationCommitment))
}

func VerifyBalanceProofBundle(bundle []byte, publicKey, sourceCiphertext []byte) error {
	proof, err := decodeBalanceProofBundle(bundle)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptouno.VerifyBalanceProof(proof, publicKey, sourceCiphertext))
}

func VerifyRangeProofBundle(bundle []byte, commitments []byte, bitLengths []byte, batchLen uint8) error {
	proof, err := decodeRangeProofBundle(bundle)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptouno.VerifyRangeProof(proof, commitments, bitLengths, batchLen))
}

// VerifyShieldProofBundleWithContext verifies a Shield proof bundle with chain
// context bound into the Merlin transcript for replay hardening.
func VerifyShieldProofBundleWithContext(bundle []byte, commitment, receiverHandle, receiverPubkey []byte, amount uint64, ctx []byte) error {
	proof, err := decodeShieldProofBundle(bundle)
	if err != nil {
		return err
	}
	return mapCryptoVerifyError(cryptouno.VerifyShieldProofWithContext(proof, commitment, receiverHandle, receiverPubkey, amount, ctx))
}

// VerifyTransferProofBundleWithContext verifies a Transfer proof bundle with
// chain context bound into the Merlin transcript for replay hardening.
func VerifyTransferProofBundleWithContext(bundle []byte, senderDelta, receiverDelta Ciphertext, senderPubkey, receiverPubkey []byte, ctx []byte) error {
	parts, err := decodeTransferProofBundle(bundle)
	if err != nil {
		return err
	}
	if senderDelta.Commitment != receiverDelta.Commitment {
		return ErrInvalidPayload
	}
	if err := mapCryptoVerifyError(cryptouno.VerifyCTValidityProofWithContext(
		parts.ctValidity,
		receiverDelta.Commitment[:],
		senderDelta.Handle[:],
		receiverDelta.Handle[:],
		senderPubkey,
		receiverPubkey,
		true,
		ctx,
	)); err != nil {
		return err
	}
	if err := mapCryptoVerifyError(cryptouno.VerifyBalanceProofWithContext(
		parts.balance,
		senderPubkey,
		ciphertextToBytes(senderDelta),
		ctx,
	)); err != nil {
		return err
	}
	if len(parts.rangeProof) == 0 {
		return nil
	}
	// Range proofs are self-contained; no chain context injection needed.
	return mapCryptoVerifyError(cryptouno.VerifyRangeProof(
		parts.rangeProof,
		receiverDelta.Commitment[:],
		[]byte{64},
		1,
	))
}

// VerifyUnshieldProofBundleWithContext verifies an Unshield proof bundle with
// chain context bound into the Merlin transcript for replay hardening.
func VerifyUnshieldProofBundleWithContext(bundle []byte, senderDelta Ciphertext, senderPubkey []byte, amount uint64, ctx []byte) error {
	parts, err := decodeUnshieldProofBundle(bundle)
	if err != nil {
		return err
	}
	proofAmount, err := decodeBalanceProofAmount(parts.balance)
	if err != nil {
		return err
	}
	if proofAmount != amount {
		return ErrInvalidPayload
	}
	return mapCryptoVerifyError(cryptouno.VerifyBalanceProofWithContext(
		parts.balance,
		senderPubkey,
		ciphertextToBytes(senderDelta),
		ctx,
	))
}

func VerifyTransferProofBundle(bundle []byte, senderDelta, receiverDelta Ciphertext, senderPubkey, receiverPubkey []byte) error {
	parts, err := decodeTransferProofBundle(bundle)
	if err != nil {
		return err
	}
	if senderDelta.Commitment != receiverDelta.Commitment {
		return ErrInvalidPayload
	}
	if err := mapCryptoVerifyError(cryptouno.VerifyCTValidityProof(
		parts.ctValidity,
		receiverDelta.Commitment[:],
		senderDelta.Handle[:],
		receiverDelta.Handle[:],
		senderPubkey,
		receiverPubkey,
		true,
	)); err != nil {
		return err
	}
	if err := mapCryptoVerifyError(cryptouno.VerifyBalanceProof(
		parts.balance,
		senderPubkey,
		ciphertextToBytes(senderDelta),
	)); err != nil {
		return err
	}
	if len(parts.rangeProof) == 0 {
		return nil
	}
	return mapCryptoVerifyError(cryptouno.VerifyRangeProof(
		parts.rangeProof,
		receiverDelta.Commitment[:],
		[]byte{64},
		1,
	))
}

func VerifyUnshieldProofBundle(bundle []byte, senderDelta Ciphertext, senderPubkey []byte, amount uint64) error {
	parts, err := decodeUnshieldProofBundle(bundle)
	if err != nil {
		return err
	}
	proofAmount, err := decodeBalanceProofAmount(parts.balance)
	if err != nil {
		return err
	}
	if proofAmount != amount {
		return ErrInvalidPayload
	}
	return mapCryptoVerifyError(cryptouno.VerifyBalanceProof(
		parts.balance,
		senderPubkey,
		ciphertextToBytes(senderDelta),
	))
}
