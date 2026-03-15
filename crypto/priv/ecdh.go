package priv

import "github.com/tos-network/gtos/crypto/ed25519"

// X25519Exchange computes an ECDH shared secret using X25519.
func X25519Exchange(privkey [32]byte, peerPubkey [32]byte) ([32]byte, error) {
	return ed25519.X25519Exchange(privkey, peerPubkey)
}

// X25519Public derives the X25519 public key from a private key.
func X25519Public(privkey [32]byte) ([32]byte, error) {
	return ed25519.X25519Public(privkey)
}
