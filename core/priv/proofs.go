package priv

const (
	CTValidityProofSizeT1    = 160
	CommitmentEqProofSize    = 192
	BalanceProofSize         = 8 + CommitmentEqProofSize
	RangeProofSingle64       = 672
	RangeProofTransfer       = 736
	RangeProofTransferLegacy = 2 * RangeProofSingle64
	ShieldProofSize          = 96
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

func decodeBalanceProof(proof []byte) ([]byte, error) {
	if len(proof) != BalanceProofSize {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), proof...), nil
}

func decodeRangeProof(proof []byte) ([]byte, error) {
	if len(proof) != RangeProofSingle64 && len(proof) != RangeProofTransfer && len(proof) != RangeProofTransferLegacy {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), proof...), nil
}

func decodeSingleRangeProof(proof []byte) ([]byte, error) {
	if len(proof) != RangeProofSingle64 {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), proof...), nil
}

func decodeTransferRangeProofs(proof []byte) ([][]byte, error) {
	if len(proof) != RangeProofTransferLegacy {
		return nil, ErrInvalidPayload
	}
	out := make([][]byte, 2)
	for i := range out {
		start := i * RangeProofSingle64
		end := start + RangeProofSingle64
		out[i] = append([]byte(nil), proof[start:end]...)
	}
	return out, nil
}

func decodeAggregatedTransferRangeProof(proof []byte) ([]byte, error) {
	if len(proof) != RangeProofTransfer {
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

// ValidateBalanceProofShape validates balance proof blob size.
func ValidateBalanceProofShape(proof []byte) error {
	_, err := decodeBalanceProof(proof)
	return err
}

// ValidateRangeProofShape validates range proof blob size.
func ValidateRangeProofShape(proof []byte) error {
	_, err := decodeRangeProof(proof)
	return err
}

func decodeShieldProof(proof []byte) ([]byte, error) {
	if len(proof) != ShieldProofSize {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), proof...), nil
}

// ValidateShieldProofShape validates shield proof blob size.
func ValidateShieldProofShape(proof []byte) error {
	_, err := decodeShieldProof(proof)
	return err
}
