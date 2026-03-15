package priv

import (
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

// EncryptMemo encrypts a plaintext memo for a PrivTransferTx.
func EncryptMemo(senderPriv [32]byte, receiverPub [32]byte, plaintext []byte) ([]byte, error) {
	return cryptopriv.EncryptMemo(senderPriv, receiverPub, plaintext)
}

// DecryptMemo decrypts a memo from a PrivTransferTx.
func DecryptMemo(recipientPriv [32]byte, senderPub [32]byte, ciphertext []byte) ([]byte, error) {
	return cryptopriv.DecryptMemo(recipientPriv, senderPub, ciphertext)
}
