package priv

import (
	"math/big"
	"testing"

	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

func TestBuildDecryptionToken_RoundTrip(t *testing.T) {
	if !cryptopriv.BackendEnabled() {
		t.Skip("priv backend not enabled")
	}

	pub, privKey, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	amount := uint64(500)
	ct64, err := cryptopriv.Encrypt(pub, amount)
	if err != nil {
		t.Fatal(err)
	}

	var pubkey, privkey [32]byte
	copy(pubkey[:], pub)
	copy(privkey[:], privKey)

	ct := Ciphertext{}
	copy(ct.Commitment[:], ct64[:32])
	copy(ct.Handle[:], ct64[32:])

	chainID := big.NewInt(1)
	blockNum := uint64(100)

	dt, err := BuildDecryptionToken(privkey, pubkey, ct, chainID, blockNum)
	if err != nil {
		t.Fatal("BuildDecryptionToken failed:", err)
	}

	// Verify token honesty
	if err := VerifyDecryptionToken(dt, chainID); err != nil {
		t.Fatal("VerifyDecryptionToken failed:", err)
	}

	// Decrypt using token
	recovered, err := DecryptTokenAmount(dt)
	if err != nil {
		t.Fatal("DecryptTokenAmount failed:", err)
	}
	if recovered != amount {
		t.Fatalf("recovered %d, expected %d", recovered, amount)
	}
}

func TestBuildDecryptionToken_WrongChain(t *testing.T) {
	if !cryptopriv.BackendEnabled() {
		t.Skip("priv backend not enabled")
	}

	pub, privKey, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	amount := uint64(200)
	ct64, err := cryptopriv.Encrypt(pub, amount)
	if err != nil {
		t.Fatal(err)
	}

	var pubkey, privkey [32]byte
	copy(pubkey[:], pub)
	copy(privkey[:], privKey)

	ct := Ciphertext{}
	copy(ct.Commitment[:], ct64[:32])
	copy(ct.Handle[:], ct64[32:])

	dt, err := BuildDecryptionToken(privkey, pubkey, ct, big.NewInt(1), 50)
	if err != nil {
		t.Fatal("BuildDecryptionToken failed:", err)
	}

	// Verify on wrong chain should fail
	if err := VerifyDecryptionToken(dt, big.NewInt(999)); err == nil {
		t.Fatal("expected verification to fail on wrong chain")
	}
}
