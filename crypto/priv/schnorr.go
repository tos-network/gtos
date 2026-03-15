package priv

import "github.com/tos-network/gtos/crypto/ed25519"

// SignSchnorr signs a message with an ElGamal Ristretto-Schnorr signature.
// Returns two 32-byte scalars (s, e).
func SignSchnorr(privkey [32]byte, message []byte) (s [32]byte, e [32]byte, err error) {
	return ed25519.ElgamalSchnorrSign(privkey, message)
}

// VerifySchnorr verifies an ElGamal Ristretto-Schnorr signature.
func VerifySchnorr(pubkey [32]byte, message []byte, s [32]byte, e [32]byte) bool {
	return ed25519.ElgamalSchnorrVerify(pubkey, message, s, e)
}
