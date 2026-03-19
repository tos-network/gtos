package priv

import "github.com/tos-network/gtos/crypto/ed25519"

// GenerateDecryptionToken computes token = sk·D (32 bytes) where D is the
// decrypt handle from a ciphertext. The token allows a third party to recover
// the plaintext amount without knowing the private key.
func GenerateDecryptionToken(privkey32, handle32 []byte) ([]byte, error) {
	token, err := ed25519.ScalarMultPoint(privkey32, handle32)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return token, nil
}

// DecryptWithToken computes amountPoint = commitment - token (32-byte
// compressed Ristretto255 point). The caller must solve the ECDLP on
// the result to recover the plaintext amount (e.g., via BSGS).
func DecryptWithToken(token32, commitment32 []byte) ([]byte, error) {
	result, err := ed25519.PointSubtract(commitment32, token32)
	if err != nil {
		return nil, mapBackendError(err)
	}
	return result, nil
}
