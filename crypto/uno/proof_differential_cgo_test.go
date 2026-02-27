//go:build cgo && ed25519c

package uno

import (
	"bytes"
	"errors"
	"testing"
)

// fixedDiffInputs returns deterministic crypto material for differential tests.
// Uses small fixed scalars (sender=7, receiver=3, opening=1) so every test run
// starts from the same public keys and blinding factor.
func fixedDiffInputs(t *testing.T) (senderPub, senderPriv, receiverPub, opening []byte, amount uint64) {
	t.Helper()
	senderPriv = make([]byte, 32)
	senderPriv[0] = 7 // scalar 7
	var err error
	senderPub, err = PublicKeyFromPrivate(senderPriv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate(sender): %v", err)
	}
	receiverPriv := make([]byte, 32)
	receiverPriv[0] = 3 // scalar 3
	receiverPub, err = PublicKeyFromPrivate(receiverPriv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate(receiver): %v", err)
	}
	opening = make([]byte, 32)
	opening[0] = 1 // scalar 1
	amount = 42
	return senderPub, senderPriv, receiverPub, opening, amount
}

// diffCtx returns a synthetic 83-byte chain-context (canonical size) with
// deterministic non-zero bytes.
func diffCtx() []byte {
	ctx := make([]byte, 83)
	ctx[0] = 1    // context version
	ctx[1] = 0x06 // chain-id high byte (big-endian uint64 for 1666 = 0x0682)
	ctx[2] = 0x82
	ctx[9] = 0x02 // action tag = Shield (ActionIDShield)
	// bytes 11..42 = from address (all zero for synthetic test)
	// bytes 43..74 = to address (zero)
	// bytes 75..82 = nonce (zero)
	return ctx
}

// TestProofContextBindingAllTypes verifies that mutating any byte in the
// transcript context causes proof verification to fail for every proof type.
// This is the primary evidence for the prover/verifier differential gap in §7.1
// and the proof-vector differential in §1 / §7.4.
//
// Run:
//
//	go test -tags cgo,ed25519c ./crypto/uno/... -run TestProofContextBindingAllTypes -v
func TestProofContextBindingAllTypes(t *testing.T) {
	t.Parallel()
	senderPub, senderPriv, receiverPub, opening, amount := fixedDiffInputs(t)
	ctx := diffCtx()

	t.Run("shield", func(t *testing.T) {
		t.Parallel()
		proof, commitment, handle, err := ProveShieldProofWithContext(senderPub, amount, opening, ctx)
		if err != nil {
			t.Fatalf("ProveShieldProofWithContext: %v", err)
		}
		// Correct context must pass.
		if err := VerifyShieldProofWithContext(proof, commitment, handle, senderPub, amount, ctx); err != nil {
			t.Fatalf("baseline verify: %v", err)
		}
		// Any single-byte mutation of the context must cause failure.
		for _, pos := range []int{0, 1, 5, 9, 11, 40, 75, 82} {
			mutated := append([]byte(nil), ctx...)
			mutated[pos] ^= 0xFF
			err := VerifyShieldProofWithContext(proof, commitment, handle, senderPub, amount, mutated)
			if err == nil {
				t.Fatalf("expected failure mutating ctx[%d], got nil", pos)
			}
			if !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("ctx[%d] mutated: expected ErrInvalidProof, got %v", pos, err)
			}
		}
	})

	t.Run("ct_validity", func(t *testing.T) {
		t.Parallel()
		proof, commitment, senderHandle, receiverHandle, err := ProveCTValidityProofWithContext(senderPub, receiverPub, amount, opening, true, ctx)
		if err != nil {
			t.Fatalf("ProveCTValidityProofWithContext: %v", err)
		}
		if err := VerifyCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPub, receiverPub, true, ctx); err != nil {
			t.Fatalf("baseline verify: %v", err)
		}
		for _, pos := range []int{0, 1, 5, 9, 11, 40, 75, 82} {
			mutated := append([]byte(nil), ctx...)
			mutated[pos] ^= 0xFF
			err := VerifyCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPub, receiverPub, true, mutated)
			if err == nil {
				t.Fatalf("expected failure mutating ctx[%d], got nil", pos)
			}
			if !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("ctx[%d] mutated: expected ErrInvalidProof, got %v", pos, err)
			}
		}
	})

	t.Run("balance", func(t *testing.T) {
		t.Parallel()
		// Use a deterministic ciphertext (fixed opening so commitment is repeatable).
		ct64, err := EncryptWithOpening(senderPub, amount, opening)
		if err != nil {
			t.Fatalf("EncryptWithOpening: %v", err)
		}
		proof, err := ProveBalanceProofWithContext(senderPriv, ct64, amount, ctx)
		if err != nil {
			t.Fatalf("ProveBalanceProofWithContext: %v", err)
		}
		if err := VerifyBalanceProofWithContext(proof, senderPub, ct64, ctx); err != nil {
			t.Fatalf("baseline verify: %v", err)
		}
		for _, pos := range []int{0, 1, 5, 9, 11, 40, 75, 82} {
			mutated := append([]byte(nil), ctx...)
			mutated[pos] ^= 0xFF
			err := VerifyBalanceProofWithContext(proof, senderPub, ct64, mutated)
			if err == nil {
				t.Fatalf("expected failure mutating ctx[%d], got nil", pos)
			}
			if !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("ctx[%d] mutated: expected ErrInvalidProof, got %v", pos, err)
			}
		}
	})
}

// TestNoContextProofNotValidWithContext verifies that proofs generated without
// chain context are rejected by the context-aware verifier and vice versa.
// This proves the context-binding is cryptographically effective (not a no-op):
// adding the context changes the Merlin transcript challenge, producing a
// proof that is incompatible with the context-free verifier.
//
// Run:
//
//	go test -tags cgo,ed25519c ./crypto/uno/... -run TestNoContextProofNotValidWithContext -v
func TestNoContextProofNotValidWithContext(t *testing.T) {
	t.Parallel()
	senderPub, _, _, opening, amount := fixedDiffInputs(t)
	ctx := []byte("gtos-differential-test-sentinel-v1")

	t.Run("shield_nocontext_rejects_in_ctx_verifier", func(t *testing.T) {
		t.Parallel()
		proof, commitment, handle, err := ProveShieldProof(senderPub, amount, opening)
		if err != nil {
			t.Fatalf("ProveShieldProof: %v", err)
		}
		// No-context verifier must pass.
		if err := VerifyShieldProof(proof, commitment, handle, senderPub, amount); err != nil {
			t.Fatalf("VerifyShieldProof(no-ctx): %v", err)
		}
		// Context-aware verifier must reject (transcript diverges).
		err = VerifyShieldProofWithContext(proof, commitment, handle, senderPub, amount, ctx)
		if err == nil {
			t.Fatal("no-ctx proof passed ctx verifier — context binding is a no-op")
		}
		if !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("expected ErrInvalidProof, got %v", err)
		}
	})

	t.Run("shield_withcontext_rejects_in_nocontext_verifier", func(t *testing.T) {
		t.Parallel()
		proof, commitment, handle, err := ProveShieldProofWithContext(senderPub, amount, opening, ctx)
		if err != nil {
			t.Fatalf("ProveShieldProofWithContext: %v", err)
		}
		// Context verifier must pass.
		if err := VerifyShieldProofWithContext(proof, commitment, handle, senderPub, amount, ctx); err != nil {
			t.Fatalf("VerifyShieldProofWithContext: %v", err)
		}
		// No-context verifier must reject.
		err = VerifyShieldProof(proof, commitment, handle, senderPub, amount)
		if err == nil {
			t.Fatal("ctx proof passed no-ctx verifier — context binding is a no-op")
		}
		if !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("expected ErrInvalidProof, got %v", err)
		}
	})
}

// TestProofDeterminismFixedInputs generates each proof type twice with
// identical fixed inputs and asserts: (a) public ciphertext outputs are
// byte-identical (commitment/handle are deterministic from opening+pubkey),
// and (b) both proofs pass verification. Documents whether the prover nonce
// is transcript-derived (deterministic) or random.
//
// Run:
//
//	go test -tags cgo,ed25519c ./crypto/uno/... -run TestProofDeterminismFixedInputs -v
func TestProofDeterminismFixedInputs(t *testing.T) {
	t.Parallel()
	senderPub, senderPriv, receiverPub, opening, amount := fixedDiffInputs(t)
	ctx := []byte("gtos-determinism-fixed-input-ctx-v1")

	t.Run("shield", func(t *testing.T) {
		t.Parallel()
		proof1, commitment1, handle1, err := ProveShieldProofWithContext(senderPub, amount, opening, ctx)
		if err != nil {
			t.Fatalf("ProveShieldProofWithContext #1: %v", err)
		}
		proof2, commitment2, handle2, err := ProveShieldProofWithContext(senderPub, amount, opening, ctx)
		if err != nil {
			t.Fatalf("ProveShieldProofWithContext #2: %v", err)
		}
		if !bytes.Equal(commitment1, commitment2) {
			t.Fatal("Shield commitment not deterministic across identical calls")
		}
		if !bytes.Equal(handle1, handle2) {
			t.Fatal("Shield handle not deterministic across identical calls")
		}
		if bytes.Equal(proof1, proof2) {
			t.Log("Shield proof: transcript-derived nonce (fully deterministic)")
		} else {
			t.Log("Shield proof: random nonce (commitment/handle still deterministic)")
		}
		if err := VerifyShieldProofWithContext(proof1, commitment1, handle1, senderPub, amount, ctx); err != nil {
			t.Fatalf("verify proof1: %v", err)
		}
		if err := VerifyShieldProofWithContext(proof2, commitment2, handle2, senderPub, amount, ctx); err != nil {
			t.Fatalf("verify proof2: %v", err)
		}
	})

	t.Run("ct_validity", func(t *testing.T) {
		t.Parallel()
		p1, c1, sh1, rh1, err := ProveCTValidityProofWithContext(senderPub, receiverPub, amount, opening, true, ctx)
		if err != nil {
			t.Fatalf("ProveCTValidityProofWithContext #1: %v", err)
		}
		p2, c2, sh2, rh2, err := ProveCTValidityProofWithContext(senderPub, receiverPub, amount, opening, true, ctx)
		if err != nil {
			t.Fatalf("ProveCTValidityProofWithContext #2: %v", err)
		}
		if !bytes.Equal(c1, c2) || !bytes.Equal(sh1, sh2) || !bytes.Equal(rh1, rh2) {
			t.Fatal("CTValidity ciphertext outputs not deterministic")
		}
		if bytes.Equal(p1, p2) {
			t.Log("CTValidity proof: transcript-derived nonce")
		} else {
			t.Log("CTValidity proof: random nonce (ciphertext outputs still deterministic)")
		}
		if err := VerifyCTValidityProofWithContext(p1, c1, sh1, rh1, senderPub, receiverPub, true, ctx); err != nil {
			t.Fatalf("verify proof1: %v", err)
		}
		if err := VerifyCTValidityProofWithContext(p2, c2, sh2, rh2, senderPub, receiverPub, true, ctx); err != nil {
			t.Fatalf("verify proof2: %v", err)
		}
	})

	t.Run("balance", func(t *testing.T) {
		t.Parallel()
		// Fixed ciphertext: use EncryptWithOpening to get a deterministic ct64.
		ct64, err := EncryptWithOpening(senderPub, amount, opening)
		if err != nil {
			t.Fatalf("EncryptWithOpening: %v", err)
		}
		p1, err := ProveBalanceProofWithContext(senderPriv, ct64, amount, ctx)
		if err != nil {
			t.Fatalf("ProveBalanceProofWithContext #1: %v", err)
		}
		p2, err := ProveBalanceProofWithContext(senderPriv, ct64, amount, ctx)
		if err != nil {
			t.Fatalf("ProveBalanceProofWithContext #2: %v", err)
		}
		if bytes.Equal(p1, p2) {
			t.Log("Balance proof: transcript-derived nonce (fully deterministic)")
		} else {
			t.Log("Balance proof: random nonce")
		}
		if err := VerifyBalanceProofWithContext(p1, senderPub, ct64, ctx); err != nil {
			t.Fatalf("verify proof1: %v", err)
		}
		if err := VerifyBalanceProofWithContext(p2, senderPub, ct64, ctx); err != nil {
			t.Fatalf("verify proof2: %v", err)
		}
	})
}
