package priv

const (
	CTValidityProofSizeT1 = 160
	CommitmentEqProofSize = 192
	RangeProofSingle64    = 672
)

func decodeCTValidityProof(proof []byte) ([]byte, error) {
	if len(proof) != CTValidityProofSizeT1 {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), proof...), nil
}

func decodeCommitmentEqProof(proof []byte) ([]byte, error) {
	if len(proof) != CommitmentEqProofSize {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), proof...), nil
}

func decodeRangeProof(proof []byte) ([]byte, error) {
	if len(proof) != RangeProofSingle64 {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), proof...), nil
}

// ValidateCTValidityProofShape validates ciphertext validity proof blob size.
func ValidateCTValidityProofShape(proof []byte) error {
	_, err := decodeCTValidityProof(proof)
	return err
}

// ValidateCommitmentEqProofShape validates commitment equality proof blob size.
func ValidateCommitmentEqProofShape(proof []byte) error {
	_, err := decodeCommitmentEqProof(proof)
	return err
}

// ValidateRangeProofShape validates range proof blob size.
func ValidateRangeProofShape(proof []byte) error {
	_, err := decodeRangeProof(proof)
	return err
}
