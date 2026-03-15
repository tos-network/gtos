//go:build !cgo || !ed25519c

package priv

import "testing"

func TestUnshieldCiphertextArithmetic_NoCgo(t *testing.T) {
	// Verify the ciphertext arithmetic used in unshield:
	// AddAmountCompressed(identity, amount) produces a valid ciphertext,
	// and SubCompressedCiphertexts works correctly.

	senderPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	depositAmount := uint64(10000)
	withdrawAmount := uint64(3000)

	// Create a deposit ciphertext via shield proof.
	opening, err := GenerateOpening()
	if err != nil {
		t.Fatalf("GenerateOpening: %v", err)
	}
	_, depositCommitment, depositHandle, err := ProveShieldProofWithContext(
		senderPub, depositAmount, opening, []byte("test"),
	)
	if err != nil {
		t.Fatalf("ProveShieldProofWithContext: %v", err)
	}
	if len(depositCommitment) != 32 || len(depositHandle) != 32 {
		t.Fatalf("unexpected shield output sizes")
	}

	balanceCt := make([]byte, 64)
	copy(balanceCt[:32], depositCommitment)
	copy(balanceCt[32:], depositHandle)

	// Build amount ciphertext from identity.
	identityCt := make([]byte, 64)
	// Ristretto identity is 32 zero bytes — validate AddAmountCompressed handles it.
	amountCt, err := AddAmountCompressed(identityCt, withdrawAmount)
	if err != nil {
		t.Fatalf("AddAmountCompressed: %v", err)
	}
	if len(amountCt) != 64 {
		t.Fatalf("unexpected amountCt size: %d", len(amountCt))
	}

	// Subtract to get zeroed ciphertext.
	zeroedCt, err := SubCompressedCiphertexts(balanceCt, amountCt)
	if err != nil {
		t.Fatalf("SubCompressedCiphertexts: %v", err)
	}
	if len(zeroedCt) != 64 {
		t.Fatalf("unexpected zeroedCt size: %d", len(zeroedCt))
	}

	// Verify that source commitment generation works.
	newBalance := depositAmount - withdrawAmount
	srcCommitment, srcOpening, err := CommitmentNew(newBalance)
	if err != nil {
		t.Fatalf("CommitmentNew: %v", err)
	}
	if len(srcCommitment) != 32 {
		t.Fatalf("unexpected srcCommitment size: %d", len(srcCommitment))
	}
	if len(srcOpening) != 32 {
		t.Fatalf("unexpected srcOpening size: %d", len(srcOpening))
	}

	// Verify single-commitment range proof for the new balance.
	rangeProof, err := ProveRangeProof(srcCommitment, newBalance, srcOpening)
	if err != nil {
		t.Fatalf("ProveRangeProof: %v", err)
	}
	if len(rangeProof) != 672 {
		t.Fatalf("unexpected range proof size: %d, want 672", len(rangeProof))
	}
	if err := VerifyRangeProof(rangeProof, srcCommitment, []byte{64}, 1); err != nil {
		t.Fatalf("VerifyRangeProof (single): %v", err)
	}
}
