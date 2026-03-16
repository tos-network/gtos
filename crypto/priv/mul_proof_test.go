package priv

import (
	"testing"
)

func TestMulProofEndToEnd(t *testing.T) {
	aVal := uint64(17)
	bVal := uint64(5)
	cVal := aVal * bVal

	// Generate random openings.
	rA, err := GenerateOpening()
	if err != nil {
		t.Fatal(err)
	}
	rB, err := GenerateOpening()
	if err != nil {
		t.Fatal(err)
	}
	rC, err := GenerateOpening()
	if err != nil {
		t.Fatal(err)
	}

	comA, err := PedersenCommitmentWithOpening(rA, aVal)
	if err != nil {
		t.Fatal(err)
	}
	comB, err := PedersenCommitmentWithOpening(rB, bVal)
	if err != nil {
		t.Fatal(err)
	}
	comC, err := PedersenCommitmentWithOpening(rC, cVal)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := ProveMulProof(comA, comB, comC, aVal, rA, rB, rC)
	if err != nil {
		t.Fatalf("ProveMulProof: %v", err)
	}

	if len(proof) != 160 {
		t.Fatalf("proof size: got %d, want 160", len(proof))
	}

	if err := VerifyMulProof(proof, comA, comB, comC); err != nil {
		t.Fatalf("VerifyMulProof: %v", err)
	}
}

func TestMulProofWrongValueFails(t *testing.T) {
	aVal := uint64(3)
	bVal := uint64(7)

	rA, _ := GenerateOpening()
	rB, _ := GenerateOpening()
	rC, _ := GenerateOpening()

	comA, _ := PedersenCommitmentWithOpening(rA, aVal)
	comB, _ := PedersenCommitmentWithOpening(rB, bVal)
	comC, _ := PedersenCommitmentWithOpening(rC, 22) // wrong, should be 21

	proof, err := ProveMulProof(comA, comB, comC, aVal, rA, rB, rC)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyMulProof(proof, comA, comB, comC); err == nil {
		t.Fatal("expected verification to fail for wrong product")
	}
}

func TestMulProofZero(t *testing.T) {
	aVal := uint64(0)
	bVal := uint64(99)
	cVal := aVal * bVal

	rA, _ := GenerateOpening()
	rB, _ := GenerateOpening()
	rC, _ := GenerateOpening()

	comA, _ := PedersenCommitmentWithOpening(rA, aVal)
	comB, _ := PedersenCommitmentWithOpening(rB, bVal)
	comC, _ := PedersenCommitmentWithOpening(rC, cVal)

	proof, err := ProveMulProof(comA, comB, comC, aVal, rA, rB, rC)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyMulProof(proof, comA, comB, comC); err != nil {
		t.Fatalf("VerifyMulProof (zero): %v", err)
	}
}
