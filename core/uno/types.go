package uno

import "github.com/tos-network/gtos/common"

const (
	PayloadPrefix = "GTOSUNO1"

	ActionShield   uint8 = 0x02
	ActionTransfer uint8 = 0x03
	ActionUnshield uint8 = 0x04

	CiphertextSize = 32
)

type Envelope struct {
	Action uint8
	Body   []byte
}

type Ciphertext struct {
	Commitment [CiphertextSize]byte
	Handle     [CiphertextSize]byte
}

type ShieldPayload struct {
	Amount        uint64
	NewSender     Ciphertext
	ProofBundle   []byte
	EncryptedMemo []byte
}

type TransferPayload struct {
	To            common.Address
	NewSender     Ciphertext
	ReceiverDelta Ciphertext
	ProofBundle   []byte
	EncryptedMemo []byte
}

type UnshieldPayload struct {
	To            common.Address
	Amount        uint64
	NewSender     Ciphertext
	ProofBundle   []byte
	EncryptedMemo []byte
}

type AccountState struct {
	Ciphertext Ciphertext
	Version    uint64
}
