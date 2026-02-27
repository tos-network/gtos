package uno

import (
	"testing"

	"github.com/tos-network/gtos/common"
)

func fuzzCiphertext(seed byte) Ciphertext {
	var ct Ciphertext
	for i := 0; i < CiphertextSize; i++ {
		ct.Commitment[i] = seed + byte(i)
		ct.Handle[i] = seed + 0x20 + byte(i)
	}
	return ct
}

func mustEncodeFuzzEnvelope(action uint8, body []byte) []byte {
	wire, err := EncodeEnvelope(action, body)
	if err != nil {
		panic(err)
	}
	return wire
}

func FuzzUNOEnvelopeAndPayloadDecoderNoPanic(f *testing.F) {
	shieldBody, _ := EncodeShieldPayload(ShieldPayload{
		Amount:      1,
		NewSender:   fuzzCiphertext(0x11),
		ProofBundle: make([]byte, ShieldProofSize),
	})
	transferBody, _ := EncodeTransferPayload(TransferPayload{
		To:            common.HexToAddress("0x1234"),
		NewSender:     fuzzCiphertext(0x21),
		ReceiverDelta: fuzzCiphertext(0x31),
		ProofBundle:   make([]byte, transferProofMinSize),
	})
	unshieldBody, _ := EncodeUnshieldPayload(UnshieldPayload{
		To:          common.HexToAddress("0x5678"),
		Amount:      2,
		NewSender:   fuzzCiphertext(0x41),
		ProofBundle: make([]byte, BalanceProofSize),
	})

	f.Add(mustEncodeFuzzEnvelope(ActionShield, shieldBody))
	f.Add(mustEncodeFuzzEnvelope(ActionTransfer, transferBody))
	f.Add(mustEncodeFuzzEnvelope(ActionUnshield, unshieldBody))
	f.Add([]byte("not-uno-envelope"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := DecodeEnvelope(data)
		if err != nil {
			return
		}
		switch env.Action {
		case ActionShield:
			if payload, decErr := DecodeShieldPayload(env.Body); decErr == nil {
				if payload.Amount == 0 {
					t.Fatalf("decoded shield payload with zero amount")
				}
			}
		case ActionTransfer:
			if payload, decErr := DecodeTransferPayload(env.Body); decErr == nil {
				if payload.To == (common.Address{}) {
					t.Fatalf("decoded transfer payload with zero receiver")
				}
			}
		case ActionUnshield:
			if payload, decErr := DecodeUnshieldPayload(env.Body); decErr == nil {
				if payload.To == (common.Address{}) || payload.Amount == 0 {
					t.Fatalf("decoded unshield payload with invalid fields")
				}
			}
		default:
			t.Fatalf("unexpected action value %d", env.Action)
		}
	})
}

func FuzzUNOProofBundleParserNoPanic(f *testing.F) {
	f.Add(uint8(0), []byte{})
	f.Add(uint8(0), make([]byte, ShieldProofSize))
	f.Add(uint8(1), make([]byte, transferProofMinSize))
	f.Add(uint8(1), make([]byte, transferProofMinSize+RangeProofSingle64))
	f.Add(uint8(2), make([]byte, BalanceProofSize))
	f.Add(uint8(3), make([]byte, CTValidityProofSizeT0))
	f.Add(uint8(4), make([]byte, CTValidityProofSizeT1))
	f.Add(uint8(5), make([]byte, CommitmentEqProofSize))
	f.Add(uint8(6), make([]byte, RangeProofSingle64))

	f.Fuzz(func(t *testing.T, kind uint8, blob []byte) {
		switch kind % 7 {
		case 0:
			err := ValidateShieldProofBundleShape(blob)
			if err == nil && len(blob) != ShieldProofSize {
				t.Fatalf("shield accepted unexpected size %d", len(blob))
			}
		case 1:
			err := ValidateTransferProofBundleShape(blob)
			if err == nil && len(blob) != transferProofMinSize && len(blob) != transferProofMinSize+RangeProofSingle64 {
				t.Fatalf("transfer accepted unexpected size %d", len(blob))
			}
		case 2:
			err := ValidateUnshieldProofBundleShape(blob)
			if err == nil && len(blob) != BalanceProofSize {
				t.Fatalf("unshield accepted unexpected size %d", len(blob))
			}
		case 3:
			_, err := decodeCTValidityProofBundle(blob, false)
			if err == nil && len(blob) != CTValidityProofSizeT0 {
				t.Fatalf("ct-validity t0 accepted unexpected size %d", len(blob))
			}
		case 4:
			_, err := decodeCTValidityProofBundle(blob, true)
			if err == nil && len(blob) != CTValidityProofSizeT1 {
				t.Fatalf("ct-validity t1 accepted unexpected size %d", len(blob))
			}
		case 5:
			_, err := decodeCommitmentEqProofBundle(blob)
			if err == nil && len(blob) != CommitmentEqProofSize {
				t.Fatalf("commitment-eq accepted unexpected size %d", len(blob))
			}
		case 6:
			_, err := decodeRangeProofBundle(blob)
			if err == nil && len(blob) != RangeProofSingle64 {
				t.Fatalf("range proof accepted unexpected size %d", len(blob))
			}
		}
	})
}
