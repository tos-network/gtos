package priv

import (
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

// EncryptMemo encrypts a plaintext memo for a PrivTransferTx.
// txHash provides a unique nonce to avoid nonce reuse with the same key pair.
func EncryptMemo(senderPriv [32]byte, receiverPub [32]byte, plaintext []byte, txHash [32]byte) ([]byte, error) {
	return cryptopriv.EncryptMemo(senderPriv, receiverPub, plaintext, txHash)
}

// DecryptMemo decrypts a memo from a PrivTransferTx.
// txHash must match the hash used during encryption.
func DecryptMemo(recipientPriv [32]byte, senderPub [32]byte, ciphertext []byte, txHash [32]byte) ([]byte, error) {
	return cryptopriv.DecryptMemo(recipientPriv, senderPub, ciphertext, txHash)
}
