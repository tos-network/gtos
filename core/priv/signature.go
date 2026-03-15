package priv

import (
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

// VerifySchnorrSignature verifies an ElGamal Ristretto-Schnorr signature.
// The pubkey comes directly from the PrivTransferTx.From field — no storage lookup needed.
func VerifySchnorrSignature(pubkey [32]byte, message []byte, s, e [32]byte) bool {
	return cryptopriv.VerifySchnorr(pubkey, message, s, e)
}

// SignSchnorr signs a message with an ElGamal private key.
// Used client-side for building PrivTransferTx.
func SignSchnorr(privkey [32]byte, message []byte) (s, e [32]byte, err error) {
	return cryptopriv.SignSchnorr(privkey, message)
}
