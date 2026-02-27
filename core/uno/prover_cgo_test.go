//go:build cgo && ed25519c

package uno

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	cryptouno "github.com/tos-network/gtos/crypto/uno"
)

func ctFromCompressed(t *testing.T, in []byte) Ciphertext {
	t.Helper()
	if len(in) != 64 {
		t.Fatalf("invalid ciphertext size: %d", len(in))
	}
	var out Ciphertext
	copy(out.Commitment[:], in[:32])
	copy(out.Handle[:], in[32:])
	return out
}

func TestBuildShieldPayloadProof(t *testing.T) {
	senderPub, _, err := cryptouno.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	args := ShieldBuildArgs{
		ChainID:   big.NewInt(1666),
		From:      common.HexToAddress("0x1001"),
		Nonce:     3,
		SenderOld: Ciphertext{},
		SenderPub: senderPub,
		Amount:    9,
	}
	payload, _, err := BuildShieldPayloadProof(args)
	if err != nil {
		t.Fatalf("BuildShieldPayloadProof: %v", err)
	}
	ctx := BuildUNOShieldTranscriptContext(args.ChainID, args.From, args.Nonce, payload.Amount, args.SenderOld, payload.NewSender)
	if err := VerifyShieldProofBundleWithContext(payload.ProofBundle, payload.NewSender.Commitment[:], payload.NewSender.Handle[:], senderPub, payload.Amount, ctx); err != nil {
		t.Fatalf("VerifyShieldProofBundleWithContext: %v", err)
	}
}

func TestBuildTransferPayloadProof(t *testing.T) {
	senderPub, senderPriv, err := cryptouno.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair(sender): %v", err)
	}
	receiverPub, _, err := cryptouno.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair(receiver): %v", err)
	}
	senderOldRaw, err := cryptouno.Encrypt(senderPub, 50)
	if err != nil {
		t.Fatalf("Encrypt(senderOld): %v", err)
	}
	receiverOldRaw, err := cryptouno.Encrypt(receiverPub, 7)
	if err != nil {
		t.Fatalf("Encrypt(receiverOld): %v", err)
	}
	senderOld := ctFromCompressed(t, senderOldRaw)
	receiverOld := ctFromCompressed(t, receiverOldRaw)

	args := TransferBuildArgs{
		ChainID:     big.NewInt(1666),
		From:        common.HexToAddress("0x2001"),
		To:          common.HexToAddress("0x2002"),
		Nonce:       4,
		SenderOld:   senderOld,
		ReceiverOld: receiverOld,
		SenderPriv:  senderPriv,
		ReceiverPub: receiverPub,
		Amount:      11,
	}
	payload, _, err := BuildTransferPayloadProof(args)
	if err != nil {
		t.Fatalf("BuildTransferPayloadProof: %v", err)
	}
	senderDelta, err := SubCiphertexts(senderOld, payload.NewSender)
	if err != nil {
		t.Fatalf("SubCiphertexts(senderDelta): %v", err)
	}
	ctx := BuildUNOTransferTranscriptContext(args.ChainID, args.From, args.To, args.Nonce, senderOld, payload.NewSender, receiverOld, payload.ReceiverDelta)
	if err := VerifyTransferProofBundleWithContext(payload.ProofBundle, senderDelta, payload.ReceiverDelta, senderPub, receiverPub, ctx); err != nil {
		t.Fatalf("VerifyTransferProofBundleWithContext: %v", err)
	}
	if _, err := AddCiphertexts(receiverOld, payload.ReceiverDelta); err != nil {
		t.Fatalf("AddCiphertexts(receiver): %v", err)
	}
}

func TestBuildUnshieldPayloadProof(t *testing.T) {
	senderPub, senderPriv, err := cryptouno.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair(sender): %v", err)
	}
	senderOldRaw, err := cryptouno.Encrypt(senderPub, 30)
	if err != nil {
		t.Fatalf("Encrypt(senderOld): %v", err)
	}
	senderOld := ctFromCompressed(t, senderOldRaw)

	args := UnshieldBuildArgs{
		ChainID:    big.NewInt(1666),
		From:       common.HexToAddress("0x3001"),
		To:         common.HexToAddress("0x3002"),
		Nonce:      5,
		SenderOld:  senderOld,
		SenderPriv: senderPriv,
		Amount:     13,
	}
	payload, _, err := BuildUnshieldPayloadProof(args)
	if err != nil {
		t.Fatalf("BuildUnshieldPayloadProof: %v", err)
	}
	senderDelta, err := SubCiphertexts(senderOld, payload.NewSender)
	if err != nil {
		t.Fatalf("SubCiphertexts(senderDelta): %v", err)
	}
	ctx := BuildUNOUnshieldTranscriptContext(args.ChainID, args.From, args.To, args.Nonce, payload.Amount, senderOld, payload.NewSender)
	if err := VerifyUnshieldProofBundleWithContext(payload.ProofBundle, senderDelta, senderPub, payload.Amount, ctx); err != nil {
		t.Fatalf("VerifyUnshieldProofBundleWithContext: %v", err)
	}
}
