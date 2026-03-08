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

	// TransferProofRequiredSize is the exact size for a transfer proof bundle:
	// CT validity (160) + balance (200) + range proof (672).
	// Range proofs are mandatory per XELIS-convergent design.
	TransferProofRequiredSize = CTValidityProofSizeT1 + BalanceProofSize + RangeProofSingle64
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
	if len(bundle) != TransferProofRequiredSize {
		return transferProofBundleParts{}, ErrInvalidPayload
	}
	ctOff := CTValidityProofSizeT1
	balOff := ctOff + BalanceProofSize
	ctValidity, err := decodeCTValidityProofBundle(bundle[:ctOff], true)
	if err != nil {
		return transferProofBundleParts{}, err
	}
	balance, err := decodeBalanceProofBundle(bundle[ctOff:balOff])
	if err != nil {
		return transferProofBundleParts{}, err
	}
	rangeProof, err := decodeRangeProofBundle(bundle[balOff:])
	if err != nil {
		return transferProofBundleParts{}, err
	}
	return transferProofBundleParts{
		ctValidity: ctValidity,
		balance:    balance,
		rangeProof: rangeProof,
	}, nil
}

func decodeUnshieldProofBundle(bundle []byte) (unshieldProofBundleParts, error) {
	balance, err := decodeBalanceProofBundle(bundle)
	if err != nil {
		return unshieldProofBundleParts{}, err
	}
	return unshieldProofBundleParts{balance: balance}, nil
}

// ValidateShieldProofBundleShape validates shield proof blob size/encoding shape.
func ValidateShieldProofBundleShape(bundle []byte) error {
	_, err := decodeShieldProofBundle(bundle)
	return err
}

// ValidateTransferProofBundleShape validates transfer proof blob size/encoding shape.
func ValidateTransferProofBundleShape(bundle []byte) error {
	_, err := decodeTransferProofBundle(bundle)
	return err
}

// ValidateUnshieldProofBundleShape validates unshield proof blob size/encoding shape.
func ValidateUnshieldProofBundleShape(bundle []byte) error {
	_, err := decodeUnshieldProofBundle(bundle)
	return err
}
