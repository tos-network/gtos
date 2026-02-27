package uno

import (
	"bytes"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/rlp"
)

type envelopeRLP struct {
	Action uint8
	Body   []byte
}

type ciphertextRLP struct {
	Commitment []byte
	Handle     []byte
}

type shieldPayloadRLP struct {
	Amount        uint64
	NewSender     ciphertextRLP
	ProofBundle   []byte
	EncryptedMemo []byte
}

type transferPayloadRLP struct {
	To            common.Address
	NewSender     ciphertextRLP
	ReceiverDelta ciphertextRLP
	ProofBundle   []byte
	EncryptedMemo []byte
}

type unshieldPayloadRLP struct {
	To            common.Address
	Amount        uint64
	NewSender     ciphertextRLP
	ProofBundle   []byte
	EncryptedMemo []byte
}

func validateAction(action uint8) error {
	switch action {
	case ActionShield, ActionTransfer, ActionUnshield:
		return nil
	default:
		return ErrUnsupportedAction
	}
}

func encodeCiphertext(ct Ciphertext) ciphertextRLP {
	return ciphertextRLP{
		Commitment: ct.Commitment[:],
		Handle:     ct.Handle[:],
	}
}

func decodeCiphertext(raw ciphertextRLP) (Ciphertext, error) {
	if len(raw.Commitment) != CiphertextSize || len(raw.Handle) != CiphertextSize {
		return Ciphertext{}, ErrInvalidPayload
	}
	var out Ciphertext
	copy(out.Commitment[:], raw.Commitment)
	copy(out.Handle[:], raw.Handle)
	return out, nil
}

func EncodeEnvelope(action uint8, body []byte) ([]byte, error) {
	if err := validateAction(action); err != nil {
		return nil, err
	}
	inner, err := rlp.EncodeToBytes(&envelopeRLP{Action: action, Body: common.CopyBytes(body)})
	if err != nil {
		return nil, ErrInvalidPayload
	}
	out := make([]byte, len(PayloadPrefix)+len(inner))
	copy(out, []byte(PayloadPrefix))
	copy(out[len(PayloadPrefix):], inner)
	return out, nil
}

func DecodeEnvelope(data []byte) (Envelope, error) {
	if len(data) <= len(PayloadPrefix) || !bytes.Equal(data[:len(PayloadPrefix)], []byte(PayloadPrefix)) {
		return Envelope{}, ErrInvalidPayload
	}
	var env envelopeRLP
	if err := rlp.DecodeBytes(data[len(PayloadPrefix):], &env); err != nil {
		return Envelope{}, ErrInvalidPayload
	}
	if err := validateAction(env.Action); err != nil {
		return Envelope{}, err
	}
	return Envelope{Action: env.Action, Body: common.CopyBytes(env.Body)}, nil
}

func EncodeShieldPayload(p ShieldPayload) ([]byte, error) {
	if p.Amount == 0 {
		return nil, ErrInvalidPayload
	}
	return rlp.EncodeToBytes(&shieldPayloadRLP{
		Amount:        p.Amount,
		NewSender:     encodeCiphertext(p.NewSender),
		ProofBundle:   common.CopyBytes(p.ProofBundle),
		EncryptedMemo: common.CopyBytes(p.EncryptedMemo),
	})
}

func DecodeShieldPayload(body []byte) (ShieldPayload, error) {
	var raw shieldPayloadRLP
	if err := rlp.DecodeBytes(body, &raw); err != nil {
		return ShieldPayload{}, ErrInvalidPayload
	}
	if raw.Amount == 0 {
		return ShieldPayload{}, ErrInvalidPayload
	}
	ct, err := decodeCiphertext(raw.NewSender)
	if err != nil {
		return ShieldPayload{}, err
	}
	return ShieldPayload{
		Amount:        raw.Amount,
		NewSender:     ct,
		ProofBundle:   common.CopyBytes(raw.ProofBundle),
		EncryptedMemo: common.CopyBytes(raw.EncryptedMemo),
	}, nil
}

func EncodeTransferPayload(p TransferPayload) ([]byte, error) {
	if p.To == (common.Address{}) {
		return nil, ErrInvalidPayload
	}
	return rlp.EncodeToBytes(&transferPayloadRLP{
		To:            p.To,
		NewSender:     encodeCiphertext(p.NewSender),
		ReceiverDelta: encodeCiphertext(p.ReceiverDelta),
		ProofBundle:   common.CopyBytes(p.ProofBundle),
		EncryptedMemo: common.CopyBytes(p.EncryptedMemo),
	})
}

func DecodeTransferPayload(body []byte) (TransferPayload, error) {
	var raw transferPayloadRLP
	if err := rlp.DecodeBytes(body, &raw); err != nil {
		return TransferPayload{}, ErrInvalidPayload
	}
	if raw.To == (common.Address{}) {
		return TransferPayload{}, ErrInvalidPayload
	}
	newSender, err := decodeCiphertext(raw.NewSender)
	if err != nil {
		return TransferPayload{}, err
	}
	receiverDelta, err := decodeCiphertext(raw.ReceiverDelta)
	if err != nil {
		return TransferPayload{}, err
	}
	return TransferPayload{
		To:            raw.To,
		NewSender:     newSender,
		ReceiverDelta: receiverDelta,
		ProofBundle:   common.CopyBytes(raw.ProofBundle),
		EncryptedMemo: common.CopyBytes(raw.EncryptedMemo),
	}, nil
}

func EncodeUnshieldPayload(p UnshieldPayload) ([]byte, error) {
	if p.To == (common.Address{}) || p.Amount == 0 {
		return nil, ErrInvalidPayload
	}
	return rlp.EncodeToBytes(&unshieldPayloadRLP{
		To:            p.To,
		Amount:        p.Amount,
		NewSender:     encodeCiphertext(p.NewSender),
		ProofBundle:   common.CopyBytes(p.ProofBundle),
		EncryptedMemo: common.CopyBytes(p.EncryptedMemo),
	})
}

func DecodeUnshieldPayload(body []byte) (UnshieldPayload, error) {
	var raw unshieldPayloadRLP
	if err := rlp.DecodeBytes(body, &raw); err != nil {
		return UnshieldPayload{}, ErrInvalidPayload
	}
	if raw.To == (common.Address{}) || raw.Amount == 0 {
		return UnshieldPayload{}, ErrInvalidPayload
	}
	newSender, err := decodeCiphertext(raw.NewSender)
	if err != nil {
		return UnshieldPayload{}, err
	}
	return UnshieldPayload{
		To:            raw.To,
		Amount:        raw.Amount,
		NewSender:     newSender,
		ProofBundle:   common.CopyBytes(raw.ProofBundle),
		EncryptedMemo: common.CopyBytes(raw.EncryptedMemo),
	}, nil
}
