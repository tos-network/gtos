package priv

import "github.com/tos-network/gtos/crypto/ristretto255"

// ZeroCiphertext returns the identity-point ciphertext representing encrypted(0).
func ZeroCiphertext() Ciphertext {
	var zero Ciphertext
	id := ristretto255.NewIdentityElement()
	copy(zero.Commitment[:], id.Bytes())
	copy(zero.Handle[:], id.Bytes())
	return zero
}
