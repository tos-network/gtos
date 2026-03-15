package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

// samplePrivTransferTx returns a PrivTransferTx with all fields populated
// using deterministic test values.
func samplePrivTransferTx() *PrivTransferTx {
	var from, to, commitment, senderHandle, receiverHandle [32]byte
	var sourceCommitment, memoSenderHandle, memoReceiverHandle [32]byte
	var sigS, sigE [32]byte

	for i := range from {
		from[i] = byte(i + 1)
	}
	for i := range to {
		to[i] = byte(i + 33)
	}
	for i := range commitment {
		commitment[i] = byte(i + 65)
	}
	for i := range senderHandle {
		senderHandle[i] = byte(i + 97)
	}
	for i := range receiverHandle {
		receiverHandle[i] = byte(i + 129)
	}
	for i := range sourceCommitment {
		sourceCommitment[i] = byte(i + 161)
	}
	for i := range memoSenderHandle {
		memoSenderHandle[i] = byte(i + 193)
	}
	for i := range memoReceiverHandle {
		memoReceiverHandle[i] = byte(i + 225)
	}
	sigS[0] = 0xAA
	sigS[31] = 0xBB
	sigE[0] = 0xCC
	sigE[31] = 0xDD

	return &PrivTransferTx{
		ChainID:            big.NewInt(42),
		PrivNonce:          7,
		Fee:                500,
		FeeLimit:           1000,
		From:               from,
		To:                 to,
		Commitment:         commitment,
		SenderHandle:       senderHandle,
		ReceiverHandle:     receiverHandle,
		SourceCommitment:   sourceCommitment,
		CtValidityProof:    bytes.Repeat([]byte{0x11}, 160),
		CommitmentEqProof:  bytes.Repeat([]byte{0x22}, 192),
		RangeProof:         bytes.Repeat([]byte{0x33}, 672),
		EncryptedMemo:      bytes.Repeat([]byte{0x44}, 64),
		MemoSenderHandle:   memoSenderHandle,
		MemoReceiverHandle: memoReceiverHandle,
		S:                  sigS,
		E:                  sigE,
	}
}

func TestPrivTransferTxType(t *testing.T) {
	inner := samplePrivTransferTx()

	if got := inner.txType(); got != PrivTransferTxType {
		t.Fatalf("txType() = %d, want %d (PrivTransferTxType)", got, PrivTransferTxType)
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
	wantPrice := new(big.Int).SetUint64(inner.Fee)
	if got := inner.txPrice(); got.Cmp(wantPrice) != 0 {
		t.Fatalf("txPrice() = %s, want %s", got, wantPrice)
	}
}

func TestPrivTransferTxRLPRoundTrip(t *testing.T) {
	inner := samplePrivTransferTx()
	tx := NewTx(inner)

	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	var decoded Transaction
	if err := decoded.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if decoded.Type() != PrivTransferTxType {
		t.Fatalf("decoded Type() = %d, want %d", decoded.Type(), PrivTransferTxType)
	}
	if decoded.Nonce() != inner.PrivNonce {
		t.Fatalf("decoded Nonce() = %d, want %d", decoded.Nonce(), inner.PrivNonce)
	}
	if decoded.ChainId().Cmp(inner.ChainID) != 0 {
		t.Fatalf("decoded ChainId() = %s, want %s", decoded.ChainId(), inner.ChainID)
	}
	if decoded.TxPrice().Cmp(new(big.Int).SetUint64(inner.Fee)) != 0 {
		t.Fatalf("decoded TxPrice() = %s, want %d", decoded.TxPrice(), inner.Fee)
	}
	if decoded.Hash() != tx.Hash() {
		t.Fatalf("hash mismatch: decoded=%s original=%s", decoded.Hash().Hex(), tx.Hash().Hex())
	}

	// Verify inner fields survived the round trip.
	ptx, ok := decoded.inner.(*PrivTransferTx)
	if !ok {
		t.Fatalf("decoded inner is %T, want *PrivTransferTx", decoded.inner)
	}
	if ptx.From != inner.From {
		t.Fatalf("From mismatch")
	}
	if ptx.To != inner.To {
		t.Fatalf("To mismatch")
	}
	if ptx.Commitment != inner.Commitment {
		t.Fatalf("Commitment mismatch")
	}
	if !bytes.Equal(ptx.CtValidityProof, inner.CtValidityProof) {
		t.Fatalf("CtValidityProof mismatch")
	}
	if !bytes.Equal(ptx.RangeProof, inner.RangeProof) {
		t.Fatalf("RangeProof mismatch")
	}
	if !bytes.Equal(ptx.EncryptedMemo, inner.EncryptedMemo) {
		t.Fatalf("EncryptedMemo mismatch")
	}
}

func TestPrivTransferTxFromToAddress(t *testing.T) {
	inner := samplePrivTransferTx()

	wantFrom := common.BytesToAddress(crypto.Keccak256(inner.From[:]))
	wantTo := common.BytesToAddress(crypto.Keccak256(inner.To[:]))

	if got := inner.FromAddress(); got != wantFrom {
		t.Fatalf("FromAddress() = %s, want %s", got.Hex(), wantFrom.Hex())
	}
	if got := inner.ToAddress(); got != wantTo {
		t.Fatalf("ToAddress() = %s, want %s", got.Hex(), wantTo.Hex())
	}
	if got := inner.FromPubkey(); got != inner.From {
		t.Fatalf("FromPubkey() mismatch")
	}
	if got := inner.ToPubkey(); got != inner.To {
		t.Fatalf("ToPubkey() mismatch")
	}

	// The to() accessor should also match ToAddress.
	toAddr := inner.to()
	if toAddr == nil {
		t.Fatalf("to() returned nil")
	}
	if *toAddr != wantTo {
		t.Fatalf("to() = %s, want %s", toAddr.Hex(), wantTo.Hex())
	}
}

func TestPrivTransferTxCopy(t *testing.T) {
	orig := samplePrivTransferTx()
	cpyData := orig.copy()
	cpy, ok := cpyData.(*PrivTransferTx)
	if !ok {
		t.Fatalf("copy() returned %T, want *PrivTransferTx", cpyData)
	}

	// Verify all fixed fields match.
	if cpy.PrivNonce != orig.PrivNonce {
		t.Fatalf("PrivNonce mismatch after copy")
	}
	if cpy.Fee != orig.Fee {
		t.Fatalf("Fee mismatch after copy")
	}
	if cpy.From != orig.From {
		t.Fatalf("From mismatch after copy")
	}
	if cpy.S != orig.S {
		t.Fatalf("S mismatch after copy")
	}
	if cpy.ChainID.Cmp(orig.ChainID) != 0 {
		t.Fatalf("ChainID mismatch after copy")
	}

	// Mutate original slices and verify the copy is not affected.
	orig.CtValidityProof[0] = 0xFF
	if cpy.CtValidityProof[0] == 0xFF {
		t.Fatalf("copy shares CtValidityProof slice with original")
	}
	orig.CommitmentEqProof[0] = 0xFF
	if cpy.CommitmentEqProof[0] == 0xFF {
		t.Fatalf("copy shares CommitmentEqProof slice with original")
	}
	orig.RangeProof[0] = 0xFF
	if cpy.RangeProof[0] == 0xFF {
		t.Fatalf("copy shares RangeProof slice with original")
	}
	orig.EncryptedMemo[0] = 0xFF
	if cpy.EncryptedMemo[0] == 0xFF {
		t.Fatalf("copy shares EncryptedMemo slice with original")
	}

	// Mutate original ChainID and verify the copy is independent.
	orig.ChainID.SetInt64(9999)
	if cpy.ChainID.Int64() == 9999 {
		t.Fatalf("copy shares ChainID pointer with original")
	}
}

func TestPrivTransferTxSignatureValues(t *testing.T) {
	inner := samplePrivTransferTx()

	v, r, s := inner.rawSignatureValues()
	if v.Sign() != 0 {
		t.Fatalf("v should be 0 for PrivTransferTx, got %s", v)
	}

	// r should correspond to S field, s to E field.
	wantR := new(big.Int).SetBytes(inner.S[:])
	wantS := new(big.Int).SetBytes(inner.E[:])
	if r.Cmp(wantR) != 0 {
		t.Fatalf("r = %s, want %s", r, wantR)
	}
	if s.Cmp(wantS) != 0 {
		t.Fatalf("s = %s, want %s", s, wantS)
	}

	// Test setSignatureValues: it sets S from r and E from s.
	// Use full 32-byte values since setSignatureValues uses copy() which
	// writes r.Bytes() into the beginning of the [32]byte field.
	var newSBytes, newEBytes [32]byte
	for i := range newSBytes {
		newSBytes[i] = byte(i + 0x50)
	}
	for i := range newEBytes {
		newEBytes[i] = byte(i + 0x80)
	}
	newR := new(big.Int).SetBytes(newSBytes[:])
	newS := new(big.Int).SetBytes(newEBytes[:])
	inner.setSignatureValues(nil, nil, newR, newS)

	if inner.S != newSBytes {
		t.Fatalf("after set, S field mismatch")
	}
	if inner.E != newEBytes {
		t.Fatalf("after set, E field mismatch")
	}
}

func TestPrivTransferFrom(t *testing.T) {
	inner := samplePrivTransferTx()
	tx := NewTx(inner)

	fromAddr, ok := tx.PrivTransferFrom()
	if !ok {
		t.Fatalf("PrivTransferFrom() returned false for PrivTransferTx")
	}
	wantAddr := common.BytesToAddress(crypto.Keccak256(inner.From[:]))
	if fromAddr != wantAddr {
		t.Fatalf("PrivTransferFrom() = %s, want %s", fromAddr.Hex(), wantAddr.Hex())
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
	fromAddr2, ok2 := signerTx.PrivTransferFrom()
	if ok2 {
		t.Fatalf("PrivTransferFrom() returned true for SignerTx")
	}
	if fromAddr2 != (common.Address{}) {
		t.Fatalf("PrivTransferFrom() for SignerTx returned non-zero address %s", fromAddr2.Hex())
	}
}

func TestPrivTransferTxEncodeDecodeTyped(t *testing.T) {
	inner := samplePrivTransferTx()
	tx := NewTx(inner)

	// Encode via EncodeRLP.
	var buf bytes.Buffer
	if err := tx.EncodeRLP(&buf); err != nil {
		t.Fatalf("EncodeRLP failed: %v", err)
	}

	// Decode via DecodeRLP.
	var decoded Transaction
	if err := rlp.DecodeBytes(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("DecodeRLP failed: %v", err)
	}

	if decoded.Type() != PrivTransferTxType {
		t.Fatalf("decoded Type() = %d, want %d", decoded.Type(), PrivTransferTxType)
	}
	if decoded.Hash() != tx.Hash() {
		t.Fatalf("hash mismatch after EncodeRLP/DecodeRLP")
	}

	ptx, ok := decoded.inner.(*PrivTransferTx)
	if !ok {
		t.Fatalf("decoded inner is %T, want *PrivTransferTx", decoded.inner)
	}
	if ptx.From != inner.From {
		t.Fatalf("From mismatch after EncodeRLP/DecodeRLP")
	}
	if ptx.To != inner.To {
		t.Fatalf("To mismatch after EncodeRLP/DecodeRLP")
	}
	if ptx.PrivNonce != inner.PrivNonce {
		t.Fatalf("PrivNonce mismatch after EncodeRLP/DecodeRLP")
	}
	if !bytes.Equal(ptx.RangeProof, inner.RangeProof) {
		t.Fatalf("RangeProof mismatch after EncodeRLP/DecodeRLP")
	}
}

func TestMessageTypeAndPrivTransferInner(t *testing.T) {
	inner := samplePrivTransferTx()
	tx := NewTx(inner)

	// AsMessage requires a Signer. The standard signers don't recognize
	// PrivTransferTxType, so Sender() will fail. We manually construct the
	// Message to test the PrivTransferInner path.
	// First, verify that AsMessage does fail with the standard signer.
	signer := LatestSignerForChainID(big.NewInt(42))
	_, err := tx.AsMessage(signer, nil)
	if err == nil {
		t.Fatalf("expected AsMessage to fail for PrivTransferTx with standard signer")
	}

	// Even though AsMessage returns an error, the Message fields except `from`
	// are still populated. Let's verify the msg returned has the right type and inner.
	msg, _ := tx.AsMessage(signer, nil)
	if msg.Type() != PrivTransferTxType {
		t.Fatalf("msg.Type() = %d, want %d", msg.Type(), PrivTransferTxType)
	}
	if msg.PrivTransferInner() == nil {
		t.Fatalf("msg.PrivTransferInner() is nil, want non-nil")
	}
	if msg.PrivTransferInner().From != inner.From {
		t.Fatalf("msg.PrivTransferInner().From mismatch")
	}
	if msg.PrivTransferInner().To != inner.To {
		t.Fatalf("msg.PrivTransferInner().To mismatch")
	}
	if msg.PrivTransferInner().PrivNonce != inner.PrivNonce {
		t.Fatalf("msg.PrivTransferInner().PrivNonce mismatch")
	}
	if msg.Nonce() != inner.PrivNonce {
		t.Fatalf("msg.Nonce() = %d, want %d", msg.Nonce(), inner.PrivNonce)
	}
	if msg.Gas() != 0 {
		t.Fatalf("msg.Gas() = %d, want 0", msg.Gas())
	}

	// Verify that a SignerTx-based message has nil PrivTransferInner.
	signerTxMsg := NewMessage(
		common.Address{}, &common.Address{}, 0, big.NewInt(0),
		21000, big.NewInt(0), big.NewInt(0), big.NewInt(0),
		nil, nil, false,
	)
	if signerTxMsg.PrivTransferInner() != nil {
		t.Fatalf("SignerTx message PrivTransferInner() should be nil")
	}
}
