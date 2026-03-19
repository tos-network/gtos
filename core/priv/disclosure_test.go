package priv

import (
	"math/big"
	"testing"

	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

func TestDisclosure_ContextBinding(t *testing.T) {
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

	proof, err := ProveDisclosure(privkey, pubkey, ct, amount, chainID, blockNum)
	if err != nil {
		t.Fatal("ProveDisclosure failed:", err)
	}

	var proof96 [96]byte
	copy(proof96[:], proof)

	claim := DisclosureClaim{
		Pubkey:      pubkey,
		Ciphertext:  ct,
		Amount:      amount,
		Proof:       proof96,
		BlockNumber: blockNum,
	}

	// Verify on correct chain
	if err := VerifyDisclosure(claim, chainID); err != nil {
		t.Fatal("VerifyDisclosure failed:", err)
	}

	// Verify on wrong chain should fail
	if err := VerifyDisclosure(claim, big.NewInt(2)); err == nil {
		t.Fatal("expected verification to fail on wrong chain ID")
	}

	// Verify with wrong block number should fail
	claim.BlockNumber = 999
	if err := VerifyDisclosure(claim, chainID); err == nil {
		t.Fatal("expected verification to fail with wrong block number")
	}
}
