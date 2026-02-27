package uno

import (
	"bytes"
	"testing"

	"github.com/tos-network/gtos/common"
)

func testCiphertext(seed byte) Ciphertext {
	var ct Ciphertext
	for i := 0; i < CiphertextSize; i++ {
		ct.Commitment[i] = seed + byte(i)
		ct.Handle[i] = seed + 0x40 + byte(i)
	}
	return ct
}

func TestShieldPayloadCodecRoundtrip(t *testing.T) {
	want := ShieldPayload{
		Amount:        11,
		NewSender:     testCiphertext(0x11),
		ProofBundle:   []byte{0x01, 0x02},
		EncryptedMemo: []byte{0xAA},
	}
	body, err := EncodeShieldPayload(want)
	if err != nil {
		t.Fatalf("EncodeShieldPayload: %v", err)
	}
	wire, err := EncodeEnvelope(ActionShield, body)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	env, err := DecodeEnvelope(wire)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if env.Action != ActionShield {
		t.Fatalf("unexpected action: %d", env.Action)
	}
	got, err := DecodeShieldPayload(env.Body)
	if err != nil {
		t.Fatalf("DecodeShieldPayload: %v", err)
	}
	if got.Amount != want.Amount {
		t.Fatalf("amount mismatch: got %d want %d", got.Amount, want.Amount)
	}
	if got.NewSender != want.NewSender {
		t.Fatalf("sender ciphertext mismatch")
	}
	if !bytes.Equal(got.ProofBundle, want.ProofBundle) {
		t.Fatalf("proof mismatch")
	}
	if !bytes.Equal(got.EncryptedMemo, want.EncryptedMemo) {
		t.Fatalf("memo mismatch")
	}
}

func TestTransferPayloadCodecRoundtrip(t *testing.T) {
	want := TransferPayload{
		To:            common.HexToAddress("0x0102"),
		NewSender:     testCiphertext(0x21),
		ReceiverDelta: testCiphertext(0x31),
		ProofBundle:   []byte{0x03, 0x04},
		EncryptedMemo: []byte{0xAB, 0xCD},
	}
	body, err := EncodeTransferPayload(want)
	if err != nil {
		t.Fatalf("EncodeTransferPayload: %v", err)
	}
	wire, err := EncodeEnvelope(ActionTransfer, body)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	env, err := DecodeEnvelope(wire)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	got, err := DecodeTransferPayload(env.Body)
	if err != nil {
		t.Fatalf("DecodeTransferPayload: %v", err)
	}
	if got.To != want.To {
		t.Fatalf("to mismatch: got %s want %s", got.To.Hex(), want.To.Hex())
	}
	if got.NewSender != want.NewSender || got.ReceiverDelta != want.ReceiverDelta {
		t.Fatalf("ciphertext mismatch")
	}
}

func TestUnshieldPayloadCodecRoundtrip(t *testing.T) {
	want := UnshieldPayload{
		To:            common.HexToAddress("0xCAFE"),
		Amount:        7,
		NewSender:     testCiphertext(0x41),
		ProofBundle:   []byte{0x09, 0x0A},
		EncryptedMemo: []byte{0xEF},
	}
	body, err := EncodeUnshieldPayload(want)
	if err != nil {
		t.Fatalf("EncodeUnshieldPayload: %v", err)
	}
	wire, err := EncodeEnvelope(ActionUnshield, body)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	env, err := DecodeEnvelope(wire)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	got, err := DecodeUnshieldPayload(env.Body)
	if err != nil {
		t.Fatalf("DecodeUnshieldPayload: %v", err)
	}
	if got.Amount != want.Amount || got.To != want.To {
		t.Fatalf("decoded payload mismatch")
	}
}

func TestDecodeEnvelopeRejectsInvalidPrefix(t *testing.T) {
	if _, err := DecodeEnvelope([]byte("bad")); err == nil {
		t.Fatal("expected error for invalid prefix")
	}
}

func TestDecodeShieldRejectsBadCiphertextLength(t *testing.T) {
	body, err := EncodeShieldPayload(ShieldPayload{
		Amount:      1,
		NewSender:   testCiphertext(0x01),
		ProofBundle: []byte{0x01},
	})
	if err != nil {
		t.Fatalf("EncodeShieldPayload: %v", err)
	}
	// Corrupt by trimming one byte from body (breaks RLP or field length).
	if _, err := DecodeShieldPayload(body[:len(body)-1]); err == nil {
		t.Fatal("expected invalid payload")
	}
}
