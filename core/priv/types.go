package priv

const CiphertextSize = 32

type Ciphertext struct {
	Commitment [CiphertextSize]byte
	Handle     [CiphertextSize]byte
}

type AccountState struct {
	Ciphertext Ciphertext
	Version    uint64
	Nonce      uint64
}
