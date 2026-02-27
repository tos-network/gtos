package uno

import "encoding/binary"

const (
	ShieldProofSize       = 96
	CTValidityProofSizeT0 = 128
	CTValidityProofSizeT1 = 160
	CommitmentEqProofSize = 192
	BalanceProofSize      = 200

	// RangeProofSingle64 is the expected proof size for one 64-bit commitment.
	RangeProofSingle64 = 672

	transferProofMinSize = CTValidityProofSizeT1 + BalanceProofSize
)

type transferProofBundleParts struct {
	ctValidity []byte
	balance    []byte
	rangeProof []byte
}

type unshieldProofBundleParts struct {
	balance []byte
}

func decodeShieldProofBundle(bundle []byte) ([]byte, error) {
	if len(bundle) != ShieldProofSize {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), bundle...), nil
}

func decodeCTValidityProofBundle(bundle []byte, txVersionT1 bool) ([]byte, error) {
	want := CTValidityProofSizeT0
	if txVersionT1 {
		want = CTValidityProofSizeT1
	}
	if len(bundle) != want {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), bundle...), nil
}

func decodeCommitmentEqProofBundle(bundle []byte) ([]byte, error) {
	if len(bundle) != CommitmentEqProofSize {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), bundle...), nil
}

func decodeBalanceProofBundle(bundle []byte) ([]byte, error) {
	if len(bundle) != BalanceProofSize {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), bundle...), nil
}

func decodeBalanceProofAmount(bundle []byte) (uint64, error) {
	if len(bundle) != BalanceProofSize {
		return 0, ErrInvalidPayload
	}
	return binary.BigEndian.Uint64(bundle[:8]), nil
}

func decodeRangeProofBundle(bundle []byte) ([]byte, error) {
	if len(bundle) != RangeProofSingle64 {
		return nil, ErrInvalidPayload
	}
	return append([]byte(nil), bundle...), nil
}

func decodeTransferProofBundle(bundle []byte) (transferProofBundleParts, error) {
	if len(bundle) < transferProofMinSize {
		return transferProofBundleParts{}, ErrInvalidPayload
	}
	ctValidity, err := decodeCTValidityProofBundle(bundle[:CTValidityProofSizeT1], true)
	if err != nil {
		return transferProofBundleParts{}, err
	}
	balance, err := decodeBalanceProofBundle(bundle[CTValidityProofSizeT1:transferProofMinSize])
	if err != nil {
		return transferProofBundleParts{}, err
	}
	parts := transferProofBundleParts{
		ctValidity: ctValidity,
		balance:    balance,
	}
	if len(bundle) == transferProofMinSize {
		return parts, nil
	}
	rangeProof, err := decodeRangeProofBundle(bundle[transferProofMinSize:])
	if err != nil {
		return transferProofBundleParts{}, err
	}
	parts.rangeProof = rangeProof
	return parts, nil
}

func decodeUnshieldProofBundle(bundle []byte) (unshieldProofBundleParts, error) {
	balance, err := decodeBalanceProofBundle(bundle)
	if err != nil {
		return unshieldProofBundleParts{}, err
	}
	return unshieldProofBundleParts{balance: balance}, nil
}
