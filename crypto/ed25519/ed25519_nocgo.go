//go:build !cgo || !ed25519c

package ed25519

import (
	stded25519 "crypto/ed25519"
	"io"
)

func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return stded25519.GenerateKey(rand)
}

func NewKeyFromSeed(seed []byte) PrivateKey {
	return stded25519.NewKeyFromSeed(seed)
}

func Sign(privateKey PrivateKey, message []byte) []byte {
	return stded25519.Sign(privateKey, message)
}

func Verify(publicKey PublicKey, message []byte, sig []byte) bool {
	return stded25519.Verify(publicKey, message, sig)
}

func PublicFromPrivate(privateKey PrivateKey) PublicKey {
	pub, ok := stded25519.PrivateKey(privateKey).Public().(stded25519.PublicKey)
	if !ok {
		return nil
	}
	return PublicKey(pub)
}
