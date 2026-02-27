package uno

import "github.com/tos-network/gtos/common"

const (
	PayloadPrefix = ProtocolPayloadPrefix

	ActionShield   uint8 = ActionIDShield
	ActionTransfer uint8 = ActionIDTransfer
	ActionUnshield uint8 = ActionIDUnshield

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
