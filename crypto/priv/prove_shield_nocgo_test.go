//go:build !cgo || !ed25519c

package priv

import "testing"

func TestProveAndVerifyShieldProofWithContext_NoCgo(t *testing.T) {
	senderPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	opening, err := GenerateOpening()
	if err != nil {
		t.Fatalf("GenerateOpening: %v", err)
	}
	ctx := []byte("gtos-shield-test-context")
	amount := uint64(5000)

	// Prove
	proof, commitment, handle, err := ProveShieldProofWithContext(senderPub, amount, opening, ctx)
	if err != nil {
		t.Fatalf("ProveShieldProofWithContext: %v", err)
	}
	if len(proof) != 96 {
		t.Fatalf("unexpected shield proof size: %d, want 96", len(proof))
	}
	if len(commitment) != 32 {
		t.Fatalf("unexpected commitment size: %d, want 32", len(commitment))
	}
	if len(handle) != 32 {
		t.Fatalf("unexpected handle size: %d, want 32", len(handle))
	}

	// Verify
	if err := VerifyShieldProofWithContext(proof, commitment, handle, senderPub, amount, ctx); err != nil {
		t.Fatalf("VerifyShieldProofWithContext: %v", err)
	}

	// Wrong amount should fail
	if err := VerifyShieldProofWithContext(proof, commitment, handle, senderPub, amount+1, ctx); err == nil {
		t.Fatal("VerifyShieldProofWithContext should fail with wrong amount")
	}

	// Wrong context should fail
	if err := VerifyShieldProofWithContext(proof, commitment, handle, senderPub, amount, []byte("wrong-ctx")); err == nil {
		t.Fatal("VerifyShieldProofWithContext should fail with wrong context")
	}
}

func TestShieldRangeProofRoundTrip_NoCgo(t *testing.T) {
	amount := uint64(5000)
	commitment, opening, err := CommitmentNew(amount)
	if err != nil {
		t.Fatalf("CommitmentNew: %v", err)
	}

	proof, err := ProveRangeProof(commitment, amount, opening)
	if err != nil {
		t.Fatalf("ProveRangeProof: %v", err)
	}
	if len(proof) != 672 {
		t.Fatalf("unexpected proof size: %d, want 672", len(proof))
	}

	// Single-commitment verification (batchLen=1)
	if err := VerifyRangeProof(proof, commitment, []byte{64}, 1); err != nil {
		t.Fatalf("VerifyRangeProof (single): %v", err)
	}
}
