package uno

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestVerifyShieldProofBundleBackendUnavailable(t *testing.T) {
	proof := make([]byte, ShieldProofSize)
	commitment := make([]byte, 32)
	handle := make([]byte, 32)
	pubkey := make([]byte, 32)
	err := VerifyShieldProofBundle(proof, commitment, handle, pubkey, 1)
	if err == nil {
		t.Fatalf("expected verification error")
	}
	if !errors.Is(err, ErrProofNotImplemented) && !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrProofNotImplemented or ErrInvalidPayload, got %v", err)
	}
}

func TestDecodeCTValidityProofBundleLength(t *testing.T) {
	if _, err := decodeCTValidityProofBundle(make([]byte, CTValidityProofSizeT0), false); err != nil {
		t.Fatalf("unexpected error for T0 length: %v", err)
	}
	if _, err := decodeCTValidityProofBundle(make([]byte, CTValidityProofSizeT1), true); err != nil {
		t.Fatalf("unexpected error for T1 length: %v", err)
	}
	if _, err := decodeCTValidityProofBundle(make([]byte, CTValidityProofSizeT0), true); err == nil {
		t.Fatal("expected error for wrong T1 length")
	}
}

func TestDecodeCommitmentEqAndBalanceBundleLength(t *testing.T) {
	if _, err := decodeCommitmentEqProofBundle(make([]byte, CommitmentEqProofSize)); err != nil {
		t.Fatalf("unexpected commitment-eq decode error: %v", err)
	}
	if _, err := decodeBalanceProofBundle(make([]byte, BalanceProofSize)); err != nil {
		t.Fatalf("unexpected balance decode error: %v", err)
	}
	if _, err := decodeCommitmentEqProofBundle(make([]byte, CommitmentEqProofSize-1)); err == nil {
		t.Fatal("expected commitment-eq size error")
	}
	if _, err := decodeBalanceProofBundle(make([]byte, BalanceProofSize-1)); err == nil {
		t.Fatal("expected balance size error")
	}
	if _, err := decodeRangeProofBundle(nil); err == nil {
		t.Fatal("expected rangeproof size error")
	}
	if _, err := decodeRangeProofBundle(make([]byte, RangeProofSingle64)); err != nil {
		t.Fatalf("unexpected rangeproof decode error: %v", err)
	}
}

func TestDecodeTransferProofBundleLength(t *testing.T) {
	min := make([]byte, CTValidityProofSizeT1+BalanceProofSize)
	if _, err := decodeTransferProofBundle(min); err != nil {
		t.Fatalf("unexpected transfer bundle decode error: %v", err)
	}
	withRange := make([]byte, CTValidityProofSizeT1+BalanceProofSize+RangeProofSingle64)
	if _, err := decodeTransferProofBundle(withRange); err != nil {
		t.Fatalf("unexpected transfer bundle with range decode error: %v", err)
	}
	if _, err := decodeTransferProofBundle(make([]byte, CTValidityProofSizeT1+BalanceProofSize+1)); err == nil {
		t.Fatal("expected transfer bundle size error")
	}
}

func TestDecodeUnshieldProofBundleLength(t *testing.T) {
	if _, err := decodeUnshieldProofBundle(make([]byte, BalanceProofSize)); err != nil {
		t.Fatalf("unexpected unshield bundle decode error: %v", err)
	}
	if _, err := decodeUnshieldProofBundle(make([]byte, BalanceProofSize-1)); err == nil {
		t.Fatal("expected unshield bundle size error")
	}
}

func TestDecodeBalanceProofAmount(t *testing.T) {
	proof := make([]byte, BalanceProofSize)
	binary.BigEndian.PutUint64(proof[:8], 12345)
	amount, err := decodeBalanceProofAmount(proof)
	if err != nil {
		t.Fatalf("decodeBalanceProofAmount: %v", err)
	}
	if amount != 12345 {
		t.Fatalf("amount mismatch: got %d want %d", amount, 12345)
	}
}

func TestVerifyTransferProofBundleRejectsMismatchedCommitment(t *testing.T) {
	var senderDelta Ciphertext
	var receiverDelta Ciphertext
	senderDelta.Commitment[0] = 0x01
	receiverDelta.Commitment[0] = 0x02
	bundle := make([]byte, CTValidityProofSizeT1+BalanceProofSize)
	if err := VerifyTransferProofBundle(bundle, senderDelta, receiverDelta, make([]byte, 32), make([]byte, 32)); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload, got %v", err)
	}
}

func TestVerifyUnshieldProofBundleAmountMismatch(t *testing.T) {
	bundle := make([]byte, BalanceProofSize)
	binary.BigEndian.PutUint64(bundle[:8], 7)
	if err := VerifyUnshieldProofBundle(bundle, Ciphertext{}, make([]byte, 32), 8); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload, got %v", err)
	}
}
