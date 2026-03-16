package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
)

func sampleUnshieldTx() *UnshieldTx {
	var pubkey, sourceCommitment [32]byte
	var recipient common.Address
	var commitmentEqProof [192]byte
	var rangeProof [672]byte
	var sigS, sigE [32]byte

	for i := range pubkey {
		pubkey[i] = byte(i + 1)
	}
	for i := range recipient {
		recipient[i] = byte(i + 201) // distinct third-party address
	}
	for i := range sourceCommitment {
		sourceCommitment[i] = byte(i + 33)
	}
	for i := range commitmentEqProof {
		commitmentEqProof[i] = byte(i % 256)
	}
	for i := range rangeProof {
		rangeProof[i] = byte((i + 1) % 256)
	}
	sigS[0] = 0xAA
	sigS[31] = 0xBB
	sigE[0] = 0xCC
	sigE[31] = 0xDD

	return &UnshieldTx{
		ChainID:           big.NewInt(42),
		PrivNonce:         3,
		UnoFee:            1,
		Pubkey:            pubkey,
		Recipient:         recipient,
		UnoAmount:         250,
		SourceCommitment:  sourceCommitment,
		CommitmentEqProof: commitmentEqProof,
		RangeProof:        rangeProof,
		S:                 sigS,
		E:                 sigE,
	}
}

func TestUnshieldTxType(t *testing.T) {
	inner := sampleUnshieldTx()

	if got := inner.txType(); got != UnshieldTxType {
		t.Fatalf("txType() = %d, want %d (UnshieldTxType)", got, UnshieldTxType)
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

func TestUnshieldTxCopy(t *testing.T) {
	orig := sampleUnshieldTx()
	cpyData := orig.copy()
	cpy, ok := cpyData.(*UnshieldTx)
	if !ok {
		t.Fatalf("copy() returned %T, want *UnshieldTx", cpyData)
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
	if cpy.SourceCommitment != orig.SourceCommitment {
		t.Fatalf("SourceCommitment mismatch after copy")
	}
	if cpy.CommitmentEqProof != orig.CommitmentEqProof {
		t.Fatalf("CommitmentEqProof mismatch after copy")
	}
	if cpy.S != orig.S {
		t.Fatalf("S mismatch after copy")
	}
	if cpy.ChainID.Cmp(orig.ChainID) != 0 {
		t.Fatalf("ChainID mismatch after copy")
	}

	orig.ChainID.SetInt64(9999)
	if cpy.ChainID.Int64() == 9999 {
		t.Fatalf("copy shares ChainID pointer with original")
	}
}

func TestUnshieldTxSigningHash(t *testing.T) {
	inner := sampleUnshieldTx()
	h1 := inner.SigningHash()
	h2 := inner.SigningHash()
	if h1 != h2 {
		t.Fatalf("SigningHash not deterministic")
	}

	inner.UnoAmount = 9999
	h3 := inner.SigningHash()
	if h1 == h3 {
		t.Fatalf("SigningHash did not change after modifying Amount")
	}
}

func TestUnshieldTxRLPRoundTrip(t *testing.T) {
	inner := sampleUnshieldTx()
	tx := NewTx(inner)

	data, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	var decoded Transaction
	if err := decoded.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if decoded.Type() != UnshieldTxType {
		t.Fatalf("decoded Type() = %d, want %d", decoded.Type(), UnshieldTxType)
	}
	if decoded.Nonce() != inner.PrivNonce {
		t.Fatalf("decoded Nonce() = %d, want %d", decoded.Nonce(), inner.PrivNonce)
	}
	if decoded.ChainId().Cmp(inner.ChainID) != 0 {
		t.Fatalf("decoded ChainId() = %s, want %s", decoded.ChainId(), inner.ChainID)
	}
	if decoded.Hash() != tx.Hash() {
		t.Fatalf("hash mismatch")
	}

	utx, ok := decoded.inner.(*UnshieldTx)
	if !ok {
		t.Fatalf("decoded inner is %T, want *UnshieldTx", decoded.inner)
	}
	if utx.Pubkey != inner.Pubkey {
		t.Fatalf("Pubkey mismatch")
	}
	if utx.UnoAmount != inner.UnoAmount {
		t.Fatalf("Amount mismatch")
	}
	if utx.SourceCommitment != inner.SourceCommitment {
		t.Fatalf("SourceCommitment mismatch")
	}
	if utx.CommitmentEqProof != inner.CommitmentEqProof {
		t.Fatalf("CommitmentEqProof mismatch")
	}
	if utx.RangeProof != inner.RangeProof {
		t.Fatalf("RangeProof mismatch")
	}
}

func TestUnshieldTxEncodeDecodeTyped(t *testing.T) {
	inner := sampleUnshieldTx()
	tx := NewTx(inner)

	var buf bytes.Buffer
	if err := tx.EncodeRLP(&buf); err != nil {
		t.Fatalf("EncodeRLP failed: %v", err)
	}

	var decoded Transaction
	if err := rlp.DecodeBytes(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("DecodeRLP failed: %v", err)
	}

	if decoded.Type() != UnshieldTxType {
		t.Fatalf("decoded Type() = %d, want %d", decoded.Type(), UnshieldTxType)
	}
	if decoded.Hash() != tx.Hash() {
		t.Fatalf("hash mismatch after EncodeRLP/DecodeRLP")
	}
}

func TestUnshieldTxDerivedAddress(t *testing.T) {
	inner := sampleUnshieldTx()
	wantSender := common.BytesToAddress(crypto.Keccak256(inner.Pubkey[:]))
	if got := inner.DerivedAddress(); got != wantSender {
		t.Fatalf("DerivedAddress() = %s, want %s", got.Hex(), wantSender.Hex())
	}
	// to() should return Recipient address, not sender.
	if got := inner.to(); *got != inner.Recipient {
		t.Fatalf("to() = %s, want %s (recipient)", got.Hex(), inner.Recipient.Hex())
	}
}

func TestUnshieldFrom(t *testing.T) {
	inner := sampleUnshieldTx()
	tx := NewTx(inner)

	fromAddr, ok := tx.UnshieldFrom()
	if !ok {
		t.Fatalf("UnshieldFrom() returned false for UnshieldTx")
	}
	wantAddr := common.BytesToAddress(crypto.Keccak256(inner.Pubkey[:]))
	if fromAddr != wantAddr {
		t.Fatalf("UnshieldFrom() = %s, want %s", fromAddr.Hex(), wantAddr.Hex())
	}

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
	_, ok2 := signerTx.UnshieldFrom()
	if ok2 {
		t.Fatalf("UnshieldFrom() returned true for SignerTx")
	}
}

func TestUnshieldTxMessageInner(t *testing.T) {
	inner := sampleUnshieldTx()
	tx := NewTx(inner)

	signer := LatestSignerForChainID(big.NewInt(42))
	msg, _ := tx.AsMessage(signer, nil)

	if msg.Type() != UnshieldTxType {
		t.Fatalf("msg.Type() = %d, want %d", msg.Type(), UnshieldTxType)
	}
	if msg.UnshieldInner() == nil {
		t.Fatalf("msg.UnshieldInner() is nil, want non-nil")
	}
	if msg.UnshieldInner().Pubkey != inner.Pubkey {
		t.Fatalf("msg.UnshieldInner().Pubkey mismatch")
	}
	if msg.UnshieldInner().UnoAmount != inner.UnoAmount {
		t.Fatalf("msg.UnshieldInner().UnoAmount mismatch")
	}
	if msg.PrivTransferInner() != nil {
		t.Fatalf("msg.PrivTransferInner() should be nil for UnshieldTx")
	}
	if msg.ShieldInner() != nil {
		t.Fatalf("msg.ShieldInner() should be nil for UnshieldTx")
	}
}

func TestPrivTxFrom(t *testing.T) {
	// ShieldTx
	stx := NewTx(sampleShieldTx())
	if addr, ok := stx.PrivTxFrom(); !ok {
		t.Fatal("PrivTxFrom() returned false for ShieldTx")
	} else {
		want := common.BytesToAddress(crypto.Keccak256(sampleShieldTx().Pubkey[:]))
		if addr != want {
			t.Fatalf("PrivTxFrom() for ShieldTx = %s, want %s", addr.Hex(), want.Hex())
		}
	}

	// UnshieldTx
	utx := NewTx(sampleUnshieldTx())
	if _, ok := utx.PrivTxFrom(); !ok {
		t.Fatal("PrivTxFrom() returned false for UnshieldTx")
	}

	// SignerTx
	stxn := NewTx(&SignerTx{
		ChainID: big.NewInt(1), To: &common.Address{}, Value: big.NewInt(0),
		Gas: 21000, SignerType: "secp256k1",
		V: new(big.Int), R: new(big.Int), S: new(big.Int),
	})
	if _, ok := stxn.PrivTxFrom(); ok {
		t.Fatal("PrivTxFrom() returned true for SignerTx")
	}
}
