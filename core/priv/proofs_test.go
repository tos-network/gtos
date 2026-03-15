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
		t.Fatal("expected error for long proof")
	}
	if _, err := decodeRangeProof(make([]byte, RangeProofSingle64)); err != nil {
		t.Fatalf("unexpected error for correct size: %v", err)
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
	if err := ValidateRangeProofShape(make([]byte, 10)); err == nil {
		t.Fatal("expected error from ValidateRangeProofShape with bad size")
	}
}
