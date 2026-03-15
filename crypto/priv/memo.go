package priv

import (
	"fmt"

	"golang.org/x/crypto/sha3"
)

const (
	MemoMaxSize  = 1024           // max plaintext memo size per transfer
	memoNonceStr = "gtos-priv-memo" // must be exactly 12 bytes for ChaCha20
)

var memoNonce [12]byte

func init() {
	// Pad or truncate to exactly 12 bytes
	copy(memoNonce[:], []byte(memoNonceStr))
}

// deriveSharedKey computes SHA3-256(ECDH(priv, peerPub)) for memo encryption.
func deriveSharedKey(privkey [32]byte, peerPubkey [32]byte) ([32]byte, error) {
	shared, err := X25519Exchange(privkey, peerPubkey)
	if err != nil {
		return [32]byte{}, err
	}
	return sha3.Sum256(shared[:]), nil
}

// EncryptMemo encrypts a plaintext memo for a sender/receiver pair.
// Returns (ciphertext, senderHandle, receiverHandle, error).
// Both sender and receiver can decrypt using their private key + the other's handle.
func EncryptMemo(senderPriv [32]byte, receiverPub [32]byte, plaintext []byte) (ciphertext []byte, err error) {
	if len(plaintext) > MemoMaxSize {
		return nil, fmt.Errorf("memo too large: %d > %d", len(plaintext), MemoMaxSize)
	}
	if len(plaintext) == 0 {
		return nil, nil
	}
	key, err := deriveSharedKey(senderPriv, receiverPub)
	if err != nil {
		return nil, fmt.Errorf("derive shared key: %w", err)
	}
	return ChaCha20Poly1305Encrypt(key, memoNonce, plaintext, nil)
}

// DecryptMemo decrypts a memo using the recipient's private key and the sender's public key.
func DecryptMemo(recipientPriv [32]byte, senderPub [32]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil
	}
	key, err := deriveSharedKey(recipientPriv, senderPub)
	if err != nil {
		return nil, fmt.Errorf("derive shared key: %w", err)
	}
	return ChaCha20Poly1305Decrypt(key, memoNonce, ciphertext, nil)
}
