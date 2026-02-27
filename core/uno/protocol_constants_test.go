package uno

import (
	"reflect"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
)

func protocolTestCiphertext(seed byte) Ciphertext {
	var ct Ciphertext
	for i := 0; i < CiphertextSize; i++ {
		ct.Commitment[i] = seed + byte(i)
		ct.Handle[i] = seed + 0x40 + byte(i)
	}
	return ct
}

func TestFrozenActionWireIDs(t *testing.T) {
	if ActionShield != 0x02 {
		t.Fatalf("ActionShield changed: got 0x%x", ActionShield)
	}
	if ActionTransfer != 0x03 {
		t.Fatalf("ActionTransfer changed: got 0x%x", ActionTransfer)
	}
	if ActionUnshield != 0x04 {
		t.Fatalf("ActionUnshield changed: got 0x%x", ActionUnshield)
	}
}

func TestFrozenPayloadFieldOrder(t *testing.T) {
	cases := []struct {
		action uint8
		want   []string
	}{
		{ActionShield, []string{"amount", "new_sender_ciphertext", "proof_bundle", "encrypted_memo"}},
		{ActionTransfer, []string{"to", "new_sender_ciphertext", "receiver_delta_ciphertext", "proof_bundle", "encrypted_memo"}},
		{ActionUnshield, []string{"to", "amount", "new_sender_ciphertext", "proof_bundle", "encrypted_memo"}},
	}
	for _, tc := range cases {
		got, ok := FrozenPayloadFieldOrder[tc.action]
		if !ok {
			t.Fatalf("missing frozen field order for action 0x%x", tc.action)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("field order mismatch action 0x%x: got %v want %v", tc.action, got, tc.want)
		}
	}
}

func TestFrozenTranscriptConstants(t *testing.T) {
	if TranscriptContextVersion != 1 {
		t.Fatalf("TranscriptContextVersion changed: got %d", TranscriptContextVersion)
	}
	if TranscriptNativeAssetTag != 0 {
		t.Fatalf("TranscriptNativeAssetTag changed: got %d", TranscriptNativeAssetTag)
	}
	if TranscriptLabelChainContext != "chain-ctx" {
		t.Fatalf("TranscriptLabelChainContext changed: got %q", TranscriptLabelChainContext)
	}
	if TranscriptDomainShieldV1 != "uno-shield-v1" {
		t.Fatalf("TranscriptDomainShieldV1 changed: got %q", TranscriptDomainShieldV1)
	}
	if TranscriptDomainTransferV1 != "uno-transfer-v1" {
		t.Fatalf("TranscriptDomainTransferV1 changed: got %q", TranscriptDomainTransferV1)
	}
	if TranscriptDomainUnshieldV1 != "uno-unshield-v1" {
		t.Fatalf("TranscriptDomainUnshieldV1 changed: got %q", TranscriptDomainUnshieldV1)
	}
	if TranscriptDomainSeparator != "|" {
		t.Fatalf("TranscriptDomainSeparator changed: got %q", TranscriptDomainSeparator)
	}
}

func TestUNOEnvelopeGoldenVectors(t *testing.T) {
	shieldBody, err := EncodeShieldPayload(ShieldPayload{
		Amount:        1,
		NewSender:     protocolTestCiphertext(0x01),
		ProofBundle:   []byte{0xaa, 0xbb},
		EncryptedMemo: []byte{0xcc},
	})
	if err != nil {
		t.Fatalf("EncodeShieldPayload: %v", err)
	}
	shieldWire, err := EncodeEnvelope(ActionShield, shieldBody)
	if err != nil {
		t.Fatalf("EncodeEnvelope(shield): %v", err)
	}
	const wantShield = "0x47544f53554e4f31f84f02b84cf84a01f842a00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a04142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6082aabb81cc"
	if got := hexutil.Encode(shieldWire); got != wantShield {
		t.Fatalf("shield wire changed:\n got  %s\n want %s", got, wantShield)
	}

	transferBody, err := EncodeTransferPayload(TransferPayload{
		To:            common.HexToAddress("0x0102"),
		NewSender:     protocolTestCiphertext(0x02),
		ReceiverDelta: protocolTestCiphertext(0x03),
		ProofBundle:   []byte{0x01, 0x02, 0x03},
		EncryptedMemo: []byte{0x04, 0x05},
	})
	if err != nil {
		t.Fatalf("EncodeTransferPayload: %v", err)
	}
	transferWire, err := EncodeEnvelope(ActionTransfer, transferBody)
	if err != nil {
		t.Fatalf("EncodeEnvelope(transfer): %v", err)
	}
	const wantTransfer = "0x47544f53554e4f31f8b503b8b2f8b0a00000000000000000000000000000000000000000000000000000000000000102f842a002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021a042434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6061f842a0030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122a0434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616283010203820405"
	if got := hexutil.Encode(transferWire); got != wantTransfer {
		t.Fatalf("transfer wire changed:\n got  %s\n want %s", got, wantTransfer)
	}

	unshieldBody, err := EncodeUnshieldPayload(UnshieldPayload{
		To:            common.HexToAddress("0xcafe"),
		Amount:        7,
		NewSender:     protocolTestCiphertext(0x04),
		ProofBundle:   []byte{0x09, 0x0a},
		EncryptedMemo: []byte{0x0b},
	})
	if err != nil {
		t.Fatalf("EncodeUnshieldPayload: %v", err)
	}
	unshieldWire, err := EncodeEnvelope(ActionUnshield, unshieldBody)
	if err != nil {
		t.Fatalf("EncodeEnvelope(unshield): %v", err)
	}
	const wantUnshield = "0x47544f53554e4f31f86f04b86cf86aa0000000000000000000000000000000000000000000000000000000000000cafe07f842a00405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223a04445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6061626382090a0b"
	if got := hexutil.Encode(unshieldWire); got != wantUnshield {
		t.Fatalf("unshield wire changed:\n got  %s\n want %s", got, wantUnshield)
	}
}
