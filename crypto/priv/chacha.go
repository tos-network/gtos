package priv

import "github.com/tos-network/gtos/crypto/ed25519"

// ChaCha20Poly1305Encrypt encrypts plaintext with ChaCha20-Poly1305 AEAD.
// Returns ciphertext with 16-byte authentication tag appended.
func ChaCha20Poly1305Encrypt(key [32]byte, nonce [12]byte, plaintext, aad []byte) ([]byte, error) {
	return ed25519.ChaCha20Poly1305Encrypt(key, nonce, plaintext, aad)
}

// ChaCha20Poly1305Decrypt decrypts ciphertext with ChaCha20-Poly1305 AEAD.
// Input must include the 16-byte authentication tag at the end.
func ChaCha20Poly1305Decrypt(key [32]byte, nonce [12]byte, ciphertext, aad []byte) ([]byte, error) {
	return ed25519.ChaCha20Poly1305Decrypt(key, nonce, ciphertext, aad)
}
