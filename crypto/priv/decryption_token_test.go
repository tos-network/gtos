package priv

import "testing"

func TestGenerateDecryptionToken_RoundTrip(t *testing.T) {
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

	// Generate token
	token, err := GenerateDecryptionToken(privKey, ct[32:64])
	if err != nil {
		t.Fatal("GenerateDecryptionToken failed:", err)
	}
	if len(token) != 32 {
		t.Fatalf("expected 32-byte token, got %d", len(token))
	}

	// Decrypt with token
	amountPoint, err := DecryptWithToken(token, ct[:32])
	if err != nil {
		t.Fatal("DecryptWithToken failed:", err)
	}

	// Verify by solving ECDLP
	recovered, found, err := SolveDiscreteLog(amountPoint, 1_000_000)
	if err != nil {
		t.Fatal("SolveDiscreteLog failed:", err)
	}
	if !found {
		t.Fatal("amount not found in BSGS range")
	}
	if recovered != amount {
		t.Fatalf("recovered amount %d != expected %d", recovered, amount)
	}
}

func TestGenerateDecryptionToken_ZeroAmount(t *testing.T) {
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

	token, err := GenerateDecryptionToken(privKey, ct[32:64])
	if err != nil {
		t.Fatal("GenerateDecryptionToken failed:", err)
	}

	amountPoint, err := DecryptWithToken(token, ct[:32])
	if err != nil {
		t.Fatal("DecryptWithToken failed:", err)
	}

	recovered, found, err := SolveDiscreteLog(amountPoint, 1_000_000)
	if err != nil {
		t.Fatal("SolveDiscreteLog failed:", err)
	}
	if !found {
		t.Fatal("zero amount not found")
	}
	if recovered != 0 {
		t.Fatalf("recovered amount %d != expected 0", recovered)
	}
}

func TestGenerateDecryptionToken_WrongKey(t *testing.T) {
	if !BackendEnabled() {
		t.Skip("priv backend not enabled")
	}

	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	amount := uint64(100)
	ct, err := Encrypt(pub, amount)
	if err != nil {
		t.Fatal(err)
	}

	// Generate token with wrong key
	token, err := GenerateDecryptionToken(wrongPriv, ct[32:64])
	if err != nil {
		t.Fatal("GenerateDecryptionToken failed:", err)
	}

	amountPoint, err := DecryptWithToken(token, ct[:32])
	if err != nil {
		t.Fatal("DecryptWithToken failed:", err)
	}

	// Should NOT recover the correct amount
	recovered, found, err := SolveDiscreteLog(amountPoint, 1_000_000)
	if err != nil {
		t.Fatal("SolveDiscreteLog failed:", err)
	}
	if found && recovered == amount {
		t.Fatal("expected wrong key to produce wrong amount (or not found)")
	}
}
