package priv

import (
	"testing"

	"github.com/tos-network/gtos/crypto/ristretto255"
)

func TestZeroCiphertext(t *testing.T) {
	zero := ZeroCiphertext()

	// Both components must be 32 bytes (enforced by the array type).
	if len(zero.Commitment) != 32 {
		t.Fatalf("Commitment length: got %d want 32", len(zero.Commitment))
	}
	if len(zero.Handle) != 32 {
		t.Fatalf("Handle length: got %d want 32", len(zero.Handle))
	}

	// Both must equal the ristretto255 identity point encoding.
	id := ristretto255.NewIdentityElement().Bytes()
	var idWord [32]byte
	copy(idWord[:], id)
	if zero.Commitment != idWord {
		t.Fatal("Commitment is not the identity point")
	}
	if zero.Handle != idWord {
		t.Fatal("Handle is not the identity point")
	}
}

func TestZeroCiphertextAdditiveIdentity(t *testing.T) {
	zero := ZeroCiphertext()

	gen := ristretto255.NewGeneratorElement().Bytes()
	id := ristretto255.NewIdentityElement().Bytes()
	var genWord, idWord [32]byte
	copy(genWord[:], gen)
	copy(idWord[:], id)
	x := Ciphertext{Commitment: genWord, Handle: idWord}

	// zero + x == x
	sum, err := AddCiphertexts(zero, x)
	if err != nil {
		t.Fatalf("AddCiphertexts(zero, x): %v", err)
	}
	if sum != x {
		t.Fatal("zero + x != x; zero ciphertext is not additive identity")
	}
}
