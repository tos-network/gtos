//go:build cgo && ed25519c

package uno

import "testing"

func TestProveAndVerifyShieldCTAndBalanceWithContext(t *testing.T) {
	senderPub, senderPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair(sender): %v", err)
	}
	receiverPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair(receiver): %v", err)
	}
	opening, err := GenerateOpening()
	if err != nil {
		t.Fatalf("GenerateOpening: %v", err)
	}
	ctx := []byte("gtos-uno-test-context")
	amount := uint64(17)

	shieldProof, shieldCommitment, shieldHandle, err := ProveShieldProofWithContext(senderPub, amount, opening, ctx)
	if err != nil {
		t.Fatalf("ProveShieldProofWithContext: %v", err)
	}
	if err := VerifyShieldProofWithContext(shieldProof, shieldCommitment, shieldHandle, senderPub, amount, ctx); err != nil {
		t.Fatalf("VerifyShieldProofWithContext: %v", err)
	}

	ctProof, commitment, senderHandle, receiverHandle, err := ProveCTValidityProofWithContext(senderPub, receiverPub, amount, opening, true, ctx)
	if err != nil {
		t.Fatalf("ProveCTValidityProofWithContext: %v", err)
	}
	if err := VerifyCTValidityProofWithContext(ctProof, commitment, senderHandle, receiverHandle, senderPub, receiverPub, true, ctx); err != nil {
		t.Fatalf("VerifyCTValidityProofWithContext: %v", err)
	}

	senderDelta := make([]byte, 64)
	copy(senderDelta[:32], commitment)
	copy(senderDelta[32:], senderHandle)
	balanceProof, err := ProveBalanceProofWithContext(senderPriv, senderDelta, amount, ctx)
	if err != nil {
		t.Fatalf("ProveBalanceProofWithContext: %v", err)
	}
	if err := VerifyBalanceProofWithContext(balanceProof, senderPub, senderDelta, ctx); err != nil {
		t.Fatalf("VerifyBalanceProofWithContext: %v", err)
	}
}

func TestProveAndVerifyRangeProof(t *testing.T) {
	amount := uint64(42)
	commitment, opening, err := CommitmentNew(amount)
	if err != nil {
		t.Fatalf("CommitmentNew: %v", err)
	}
	proof, err := ProveRangeProof(commitment, amount, opening)
	if err != nil {
		t.Fatalf("ProveRangeProof: %v", err)
	}
	if len(proof) != 672 {
		t.Fatalf("unexpected proof size: %d", len(proof))
	}
	if err := VerifyRangeProof(proof, commitment, []byte{64}, 1); err != nil {
		t.Fatalf("VerifyRangeProof: %v", err)
	}
}
