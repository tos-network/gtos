package priv

import (
	"encoding/binary"
	"testing"
)

func TestDisclosureExact_RoundTrip(t *testing.T) {
	if !BackendEnabled() {
		t.Skip("priv backend not enabled")
	}
	pub, privKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	amount := uint64(42)
	ct, err := Encrypt(pub, amount)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != 64 {
		t.Fatalf("expected 64-byte ciphertext, got %d", len(ct))
	}

	ctx := []byte("test-chain-context")
	proof, err := ProveDisclosureExact(privKey, pub, ct, amount, ctx)
	if err != nil {
		t.Fatal("prove failed:", err)
	}
	if len(proof) != 96 {
		t.Fatalf("expected 96-byte proof, got %d", len(proof))
	}

	if err := VerifyDisclosureExact(pub, ct, amount, proof, ctx); err != nil {
		t.Fatal("verify failed:", err)
	}
}

func TestDisclosureExact_WrongAmount(t *testing.T) {
	if !BackendEnabled() {
		t.Skip("priv backend not enabled")
	}
	pub, privKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	amount := uint64(100)
	ct, err := Encrypt(pub, amount)
	if err != nil {
		t.Fatal(err)
	}

	ctx := []byte("test-chain-context")
	// Can't even prove with wrong amount — ProveDisclosureExact should fail
	_, err = ProveDisclosureExact(privKey, pub, ct, amount+1, ctx)
	if err == nil {
		t.Fatal("expected prove to fail with wrong amount")
	}
}

func TestDisclosureExact_WrongKey(t *testing.T) {
	if !BackendEnabled() {
		t.Skip("priv backend not enabled")
	}
	pub, privKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	amount := uint64(50)
	ct, err := Encrypt(pub, amount)
	if err != nil {
		t.Fatal(err)
	}

	ctx := []byte("test-chain-context")
	// Generate proof with correct key
	proof, err := ProveDisclosureExact(privKey, pub, ct, amount, ctx)
	if err != nil {
		t.Fatal("prove failed:", err)
	}

	// Verify with wrong pubkey should fail
	if err := VerifyDisclosureExact(pub2, ct, amount, proof, ctx); err == nil {
		t.Fatal("expected verify to fail with wrong pubkey")
	}
}

func TestDisclosureExact_ReplayProtection(t *testing.T) {
	if !BackendEnabled() {
		t.Skip("priv backend not enabled")
	}
	pub, privKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	amount := uint64(1000)
	ct, err := Encrypt(pub, amount)
	if err != nil {
		t.Fatal(err)
	}

	ctx1 := make([]byte, 10)
	binary.BigEndian.PutUint64(ctx1[:8], 1) // chain ID 1
	ctx1[8] = 0x20
	ctx1[9] = 0x01

	proof, err := ProveDisclosureExact(privKey, pub, ct, amount, ctx1)
	if err != nil {
		t.Fatal("prove failed:", err)
	}

	// Valid with original context
	if err := VerifyDisclosureExact(pub, ct, amount, proof, ctx1); err != nil {
		t.Fatal("verify failed with correct context:", err)
	}

	// Invalid with different context (cross-chain replay)
	ctx2 := make([]byte, 10)
	binary.BigEndian.PutUint64(ctx2[:8], 2) // chain ID 2
	ctx2[8] = 0x20
	ctx2[9] = 0x01
	if err := VerifyDisclosureExact(pub, ct, amount, proof, ctx2); err == nil {
		t.Fatal("expected verify to fail with different context (replay)")
	}
}

func TestDisclosureExact_ZeroAmount(t *testing.T) {
	if !BackendEnabled() {
		t.Skip("priv backend not enabled")
	}
	pub, privKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	amount := uint64(0)
	ct, err := Encrypt(pub, amount)
	if err != nil {
		t.Fatal(err)
	}

	ctx := []byte("test-zero")
	proof, err := ProveDisclosureExact(privKey, pub, ct, amount, ctx)
	if err != nil {
		t.Fatal("prove failed:", err)
	}
	if err := VerifyDisclosureExact(pub, ct, amount, proof, ctx); err != nil {
		t.Fatal("verify failed:", err)
	}
}
