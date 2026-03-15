//go:build !cgo || !ed25519c

package ed25519

import (
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func ChaCha20Poly1305Encrypt(key [32]byte, nonce [12]byte, plaintext []byte, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

func ChaCha20Poly1305Decrypt(key [32]byte, nonce [12]byte, ciphertext []byte, aad []byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, ErrPrivInvalidInput
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	pt, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, ErrPrivAuthFailed
	}
	return pt, nil
}

func X25519Exchange(privkey [32]byte, peerPubkey [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(privkey[:], peerPubkey[:])
	if err != nil {
		return [32]byte{}, ErrPrivOperationFailed
	}
	var result [32]byte
	copy(result[:], shared)
	return result, nil
}

func X25519Public(privkey [32]byte) ([32]byte, error) {
	pub, err := curve25519.X25519(privkey[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, ErrPrivOperationFailed
	}
	var result [32]byte
	copy(result[:], pub)
	return result, nil
}
