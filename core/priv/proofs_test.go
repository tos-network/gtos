package priv

import (
	"testing"
)

func TestProofSizeConstants(t *testing.T) {
	if CTValidityProofSizeT1 != 160 {
		t.Fatalf("CTValidityProofSizeT1: got %d want 160", CTValidityProofSizeT1)
	}
	if CommitmentEqProofSize != 192 {
		t.Fatalf("CommitmentEqProofSize: got %d want 192", CommitmentEqProofSize)
	}
	if RangeProofSingle64 != 672 {
		t.Fatalf("RangeProofSingle64: got %d want 672", RangeProofSingle64)
	}
	if RangeProofTransfer != 1344 {
		t.Fatalf("RangeProofTransfer: got %d want 1344", RangeProofTransfer)
	}
}

func TestDecodeCTValidityProof_WrongSize(t *testing.T) {
	// Too short.
	if _, err := decodeCTValidityProof(make([]byte, CTValidityProofSizeT1-1)); err == nil {
		t.Fatal("expected error for short proof")
	}
	// Too long.
	if _, err := decodeCTValidityProof(make([]byte, CTValidityProofSizeT1+1)); err == nil {
		t.Fatal("expected error for long proof")
	}
	// Correct size should succeed.
	if _, err := decodeCTValidityProof(make([]byte, CTValidityProofSizeT1)); err != nil {
		t.Fatalf("unexpected error for correct size: %v", err)
	}
}

func TestDecodeCommitmentEqProof_WrongSize(t *testing.T) {
	if _, err := decodeCommitmentEqProof(make([]byte, CommitmentEqProofSize-1)); err == nil {
		t.Fatal("expected error for short proof")
	}
	if _, err := decodeCommitmentEqProof(make([]byte, CommitmentEqProofSize+1)); err == nil {
		t.Fatal("expected error for long proof")
	}
	if _, err := decodeCommitmentEqProof(make([]byte, CommitmentEqProofSize)); err != nil {
		t.Fatalf("unexpected error for correct size: %v", err)
	}
}

func TestDecodeRangeProof_WrongSize(t *testing.T) {
	if _, err := decodeRangeProof(make([]byte, RangeProofSingle64-1)); err == nil {
		t.Fatal("expected error for short proof")
	}
	if _, err := decodeRangeProof(make([]byte, RangeProofSingle64+1)); err == nil {
		t.Fatal("expected error for unsupported proof size")
	}
	if _, err := decodeRangeProof(make([]byte, RangeProofTransfer+1)); err == nil {
		t.Fatal("expected error for long proof")
	}
	if _, err := decodeRangeProof(make([]byte, RangeProofSingle64)); err != nil {
		t.Fatalf("unexpected error for single proof size: %v", err)
	}
	if _, err := decodeRangeProof(make([]byte, RangeProofTransfer)); err != nil {
		t.Fatalf("unexpected error for transfer proof size: %v", err)
	}
}

func TestDecodeSingleRangeProof_WrongSize(t *testing.T) {
	if _, err := decodeSingleRangeProof(make([]byte, RangeProofSingle64-1)); err == nil {
		t.Fatal("expected error for short proof")
	}
	if _, err := decodeSingleRangeProof(make([]byte, RangeProofTransfer)); err == nil {
		t.Fatal("expected error for transfer-sized proof")
	}
	if _, err := decodeSingleRangeProof(make([]byte, RangeProofSingle64)); err != nil {
		t.Fatalf("unexpected error for correct size: %v", err)
	}
}

func TestDecodeTransferRangeProofs_WrongSize(t *testing.T) {
	if _, err := decodeTransferRangeProofs(make([]byte, RangeProofSingle64)); err == nil {
		t.Fatal("expected error for single-sized proof")
	}
	if _, err := decodeTransferRangeProofs(make([]byte, RangeProofTransfer-1)); err == nil {
		t.Fatal("expected error for short proof")
	}
	if proofs, err := decodeTransferRangeProofs(make([]byte, RangeProofTransfer)); err != nil {
		t.Fatalf("unexpected error for correct size: %v", err)
	} else if len(proofs) != 2 || len(proofs[0]) != RangeProofSingle64 || len(proofs[1]) != RangeProofSingle64 {
		t.Fatalf("unexpected decoded proof layout: %#v", proofs)
	}
}

func TestValidateProofShapeFunctions(t *testing.T) {
	// ValidateCTValidityProofShape
	if err := ValidateCTValidityProofShape(make([]byte, CTValidityProofSizeT1)); err != nil {
		t.Fatalf("ValidateCTValidityProofShape valid: %v", err)
	}
	if err := ValidateCTValidityProofShape(make([]byte, 10)); err == nil {
		t.Fatal("expected error from ValidateCTValidityProofShape with bad size")
	}

	// ValidateCommitmentEqProofShape
	if err := ValidateCommitmentEqProofShape(make([]byte, CommitmentEqProofSize)); err != nil {
		t.Fatalf("ValidateCommitmentEqProofShape valid: %v", err)
	}
	if err := ValidateCommitmentEqProofShape(make([]byte, 10)); err == nil {
		t.Fatal("expected error from ValidateCommitmentEqProofShape with bad size")
	}

	// ValidateRangeProofShape
	if err := ValidateRangeProofShape(make([]byte, RangeProofSingle64)); err != nil {
		t.Fatalf("ValidateRangeProofShape valid: %v", err)
	}
	if err := ValidateRangeProofShape(make([]byte, RangeProofTransfer)); err != nil {
		t.Fatalf("ValidateRangeProofShape transfer valid: %v", err)
	}
	if err := ValidateRangeProofShape(make([]byte, 10)); err == nil {
		t.Fatal("expected error from ValidateRangeProofShape with bad size")
	}
}
