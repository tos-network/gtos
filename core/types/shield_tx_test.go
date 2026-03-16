package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

func sampleShieldTx() *ShieldTx {
	var pubkey, recipient, commitment, handle [32]byte
	var shieldProof [96]byte
	var rangeProof [672]byte
	var sigS, sigE [32]byte

	for i := range pubkey {
		pubkey[i] = byte(i + 1)
	}
	for i := range recipient {
		recipient[i] = byte(i + 101) // distinct from pubkey
	}
	for i := range commitment {
		commitment[i] = byte(i + 33)
	}
	for i := range handle {
		handle[i] = byte(i + 65)
	}
	for i := range shieldProof {
		shieldProof[i] = byte(i%256 + 1)
	}
	for i := range rangeProof {
		rangeProof[i] = byte(i % 256)
	}
	sigS[0] = 0xAA
	sigS[31] = 0xBB
	sigE[0] = 0xCC
	sigE[31] = 0xDD

	return &ShieldTx{
		ChainID:     big.NewInt(42),
		PrivNonce:   7,
		UnoFee:      1,
		Pubkey:      pubkey,
		Recipient:   recipient,
		UnoAmount:   500,
		Commitment:  commitment,
		Handle:      handle,
		ShieldProof: shieldProof,
		RangeProof:  rangeProof,
		S:           sigS,
		E:           sigE,
	}
}

func TestShieldTxType(t *testing.T) {
	inner := sampleShieldTx()

	if got := inner.txType(); got != ShieldTxType {
		t.Fatalf("txType() = %d, want %d (ShieldTxType)", got, ShieldTxType)
	}
	if got := inner.gas(); got != 0 {
		t.Fatalf("gas() = %d, want 0", got)
	}
	if got := inner.value(); got.Sign() != 0 {
		t.Fatalf("value() = %s, want 0", got)
	}
	if got := inner.nonce(); got != inner.PrivNonce {
		t.Fatalf("nonce() = %d, want %d", got, inner.PrivNonce)
	}
	wantPrice := new(big.Int).SetUint64(inner.UnoFee)
	if got := inner.txPrice(); got.Cmp(wantPrice) != 0 {
		t.Fatalf("txPrice() = %s, want %s", got, wantPrice)
	}
}

func TestShieldTxCopy(t *testing.T) {
	orig := sampleShieldTx()
	cpyData := orig.copy()
	cpy, ok := cpyData.(*ShieldTx)
	if !ok {
		t.Fatalf("copy() returned %T, want *ShieldTx", cpyData)
	}

	if cpy.PrivNonce != orig.PrivNonce {
		t.Fatalf("PrivNonce mismatch after copy")
	}
	if cpy.UnoFee != orig.UnoFee {
		t.Fatalf("Fee mismatch after copy")
	}
	if cpy.Pubkey != orig.Pubkey {
		t.Fatalf("Pubkey mismatch after copy")
	}
	if cpy.UnoAmount != orig.UnoAmount {
		t.Fatalf("Amount mismatch after copy")
	}
	if cpy.ShieldProof != orig.ShieldProof {
		t.Fatalf("ShieldProof mismatch after copy")
	}
	if cpy.S != orig.S {
		t.Fatalf("S mismatch after copy")
	}
	if cpy.ChainID.Cmp(orig.ChainID) != 0 {
		t.Fatalf("ChainID mismatch after copy")
	}

	// Mutate original ChainID and verify the copy is independent.
	orig.ChainID.SetInt64(9999)
	if cpy.ChainID.Int64() == 9999 {
		t.Fatalf("copy shares ChainID pointer with original")
	}
}

func TestShieldTxSigningHash(t *testing.T) {
	inner := sampleShieldTx()
	h1 := inner.SigningHash()
	h2 := inner.SigningHash()
	if h1 != h2 {
		t.Fatalf("SigningHash not deterministic")
	}

	// Modifying a field should change the hash.
	inner.UnoAmount = 9999
	h3 := inner.SigningHash()
	if h1 == h3 {
		t.Fatalf("SigningHash did not change after modifying Amount")
	}
}

func TestShieldTxRLPRoundTrip(t *testing.T) {
	inner := sampleShieldTx()
	tx := NewTx(inner)

	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	var decoded Transaction
	if err := decoded.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if decoded.Type() != ShieldTxType {
		t.Fatalf("decoded Type() = %d, want %d", decoded.Type(), ShieldTxType)
	}
	if decoded.Nonce() != inner.PrivNonce {
		t.Fatalf("decoded Nonce() = %d, want %d", decoded.Nonce(), inner.PrivNonce)
	}
	if decoded.ChainId().Cmp(inner.ChainID) != 0 {
		t.Fatalf("decoded ChainId() = %s, want %s", decoded.ChainId(), inner.ChainID)
	}
	if decoded.Hash() != tx.Hash() {
		t.Fatalf("hash mismatch: decoded=%s original=%s", decoded.Hash().Hex(), tx.Hash().Hex())
	}

	stx, ok := decoded.inner.(*ShieldTx)
	if !ok {
		t.Fatalf("decoded inner is %T, want *ShieldTx", decoded.inner)
	}
	if stx.Pubkey != inner.Pubkey {
		t.Fatalf("Pubkey mismatch")
	}
	if stx.UnoAmount != inner.UnoAmount {
		t.Fatalf("Amount mismatch")
	}
	if stx.Commitment != inner.Commitment {
		t.Fatalf("Commitment mismatch")
	}
	if stx.ShieldProof != inner.ShieldProof {
		t.Fatalf("ShieldProof mismatch")
	}
	if stx.RangeProof != inner.RangeProof {
		t.Fatalf("RangeProof mismatch")
	}
}

func TestShieldTxEncodeDecodeTyped(t *testing.T) {
	inner := sampleShieldTx()
	tx := NewTx(inner)

	var buf bytes.Buffer
	if err := tx.EncodeRLP(&buf); err != nil {
		t.Fatalf("EncodeRLP failed: %v", err)
	}

	var decoded Transaction
	if err := rlp.DecodeBytes(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("DecodeRLP failed: %v", err)
	}

	if decoded.Type() != ShieldTxType {
		t.Fatalf("decoded Type() = %d, want %d", decoded.Type(), ShieldTxType)
	}
	if decoded.Hash() != tx.Hash() {
		t.Fatalf("hash mismatch after EncodeRLP/DecodeRLP")
	}
}

func TestShieldTxDerivedAddress(t *testing.T) {
	inner := sampleShieldTx()
	wantSender := common.BytesToAddress(crypto.Keccak256(inner.Pubkey[:]))
	if got := inner.DerivedAddress(); got != wantSender {
		t.Fatalf("DerivedAddress() = %s, want %s", got.Hex(), wantSender.Hex())
	}
	wantRecipient := common.BytesToAddress(crypto.Keccak256(inner.Recipient[:]))
	if got := inner.RecipientAddress(); got != wantRecipient {
		t.Fatalf("RecipientAddress() = %s, want %s", got.Hex(), wantRecipient.Hex())
	}
	// to() should return recipient address, not sender.
	if got := inner.to(); *got != wantRecipient {
		t.Fatalf("to() = %s, want %s (recipient)", got.Hex(), wantRecipient.Hex())
	}
}

func TestShieldFrom(t *testing.T) {
	inner := sampleShieldTx()
	tx := NewTx(inner)

	fromAddr, ok := tx.ShieldFrom()
	if !ok {
		t.Fatalf("ShieldFrom() returned false for ShieldTx")
	}
	wantAddr := common.BytesToAddress(crypto.Keccak256(inner.Pubkey[:]))
	if fromAddr != wantAddr {
		t.Fatalf("ShieldFrom() = %s, want %s", fromAddr.Hex(), wantAddr.Hex())
	}

	// A SignerTx should return (zero, false).
	signerTx := NewTx(&SignerTx{
		ChainID:    big.NewInt(1),
		Nonce:      0,
		To:         &common.Address{},
		Value:      big.NewInt(0),
		Gas:        21000,
		From:       common.Address{},
		SignerType: "secp256k1",
		V:          new(big.Int),
		R:          new(big.Int),
		S:          new(big.Int),
	})
	_, ok2 := signerTx.ShieldFrom()
	if ok2 {
		t.Fatalf("ShieldFrom() returned true for SignerTx")
	}
}

func TestShieldTxMessageInner(t *testing.T) {
	inner := sampleShieldTx()
	tx := NewTx(inner)

	signer := LatestSignerForChainID(big.NewInt(42))
	msg, _ := tx.AsMessage(signer, nil)

	if msg.Type() != ShieldTxType {
		t.Fatalf("msg.Type() = %d, want %d", msg.Type(), ShieldTxType)
	}
	if msg.ShieldInner() == nil {
		t.Fatalf("msg.ShieldInner() is nil, want non-nil")
	}
	if msg.ShieldInner().Pubkey != inner.Pubkey {
		t.Fatalf("msg.ShieldInner().Pubkey mismatch")
	}
	if msg.ShieldInner().UnoAmount != inner.UnoAmount {
		t.Fatalf("msg.ShieldInner().UnoAmount mismatch")
	}
	if msg.PrivTransferInner() != nil {
		t.Fatalf("msg.PrivTransferInner() should be nil for ShieldTx")
	}
	if msg.UnshieldInner() != nil {
		t.Fatalf("msg.UnshieldInner() should be nil for ShieldTx")
	}
}
