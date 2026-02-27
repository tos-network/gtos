package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	coreuno "github.com/tos-network/gtos/core/uno"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"github.com/tos-network/gtos/params"
)

func makeValidCiphertext(commitment, handle []byte) coreuno.Ciphertext {
	var ct coreuno.Ciphertext
	copy(ct.Commitment[:], commitment)
	copy(ct.Handle[:], handle)
	return ct
}

func setupElgamalSigner(t *testing.T, st *state.StateDB, account common.Address, pub []byte) {
	t.Helper()
	accountsigner.Set(st, account, accountsigner.SignerTypeElgamal, hexutil.Encode(pub))
}

func TestUNOShieldProofFailureHasNoStateWrite(t *testing.T) {
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")
	from := common.HexToAddress("0x1001")
	to := params.PrivacyRouterAddress
	st.SetBalance(from, big.NewInt(1_000_000))

	pub := ristretto255.NewGeneratorElement().Bytes()
	setupElgamalSigner(t, st, from, pub)

	initialUNO := coreuno.GetAccountState(st, from)
	initialBalance := new(big.Int).Set(st.GetBalance(from))

	payload, err := coreuno.EncodeShieldPayload(coreuno.ShieldPayload{
		Amount:      10,
		NewSender:   makeValidCiphertext(ristretto255.NewGeneratorElement().Bytes(), ristretto255.NewIdentityElement().Bytes()),
		ProofBundle: make([]byte, coreuno.ShieldProofSize),
	})
	if err != nil {
		t.Fatalf("EncodeShieldPayload: %v", err)
	}
	data, err := coreuno.EncodeEnvelope(coreuno.ActionShield, payload)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	msg := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), data, nil, false)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage: %v", err)
	}
	if !errors.Is(res.Err, coreuno.ErrProofNotImplemented) && !errors.Is(res.Err, coreuno.ErrInvalidPayload) {
		t.Fatalf("expected proof error, got %v", res.Err)
	}

	if got := coreuno.GetAccountState(st, from); got != initialUNO {
		t.Fatalf("unexpected UNO state mutation: got=%+v want=%+v", got, initialUNO)
	}
	if st.GetBalance(from).Cmp(initialBalance) != 0 {
		t.Fatalf("unexpected balance mutation: got=%v want=%v", st.GetBalance(from), initialBalance)
	}
}

func TestUNOTransferProofFailureHasNoStateWrite(t *testing.T) {
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")
	from := common.HexToAddress("0x2001")
	recv := common.HexToAddress("0x2002")
	to := params.PrivacyRouterAddress

	pubFrom := ristretto255.NewGeneratorElement().Bytes()
	pubRecv := ristretto255.NewIdentityElement().Add(ristretto255.NewGeneratorElement(), ristretto255.NewGeneratorElement()).Bytes()
	setupElgamalSigner(t, st, from, pubFrom)
	setupElgamalSigner(t, st, recv, pubRecv)

	gen := ristretto255.NewGeneratorElement().Bytes()
	id := ristretto255.NewIdentityElement().Bytes()
	senderInitial := makeValidCiphertext(gen, id)
	receiverInitial := makeValidCiphertext(id, id)
	newSender := makeValidCiphertext(id, id)
	receiverDelta := makeValidCiphertext(gen, id)
	coreuno.SetAccountState(st, from, coreuno.AccountState{Ciphertext: senderInitial, Version: 9})
	coreuno.SetAccountState(st, recv, coreuno.AccountState{Ciphertext: receiverInitial, Version: 3})

	payload, err := coreuno.EncodeTransferPayload(coreuno.TransferPayload{
		To:            recv,
		NewSender:     newSender,
		ReceiverDelta: receiverDelta,
		ProofBundle:   make([]byte, coreuno.CTValidityProofSizeT1+coreuno.BalanceProofSize),
	})
	if err != nil {
		t.Fatalf("EncodeTransferPayload: %v", err)
	}
	data, err := coreuno.EncodeEnvelope(coreuno.ActionTransfer, payload)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	msg := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), data, nil, false)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage: %v", err)
	}
	if !errors.Is(res.Err, coreuno.ErrProofNotImplemented) && !errors.Is(res.Err, coreuno.ErrInvalidPayload) {
		t.Fatalf("expected proof error, got %v", res.Err)
	}

	if got := coreuno.GetAccountState(st, from); got.Ciphertext != senderInitial || got.Version != 9 {
		t.Fatalf("unexpected sender UNO mutation: %+v", got)
	}
	if got := coreuno.GetAccountState(st, recv); got.Ciphertext != receiverInitial || got.Version != 3 {
		t.Fatalf("unexpected receiver UNO mutation: %+v", got)
	}
}

func TestUNOUnshieldProofFailureHasNoStateWrite(t *testing.T) {
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")
	from := common.HexToAddress("0x3001")
	recv := common.HexToAddress("0x3002")
	to := params.PrivacyRouterAddress

	pub := ristretto255.NewGeneratorElement().Bytes()
	setupElgamalSigner(t, st, from, pub)
	gen := ristretto255.NewGeneratorElement().Bytes()
	id := ristretto255.NewIdentityElement().Bytes()
	senderInitial := makeValidCiphertext(gen, id)
	newSender := makeValidCiphertext(id, id)
	coreuno.SetAccountState(st, from, coreuno.AccountState{Ciphertext: senderInitial, Version: 5})
	recvBefore := new(big.Int).Set(st.GetBalance(recv))

	proof := make([]byte, coreuno.BalanceProofSize)
	// BalanceProof carries amount in big-endian first 8 bytes.
	proof[7] = 7
	payload, err := coreuno.EncodeUnshieldPayload(coreuno.UnshieldPayload{
		To:          recv,
		Amount:      7,
		NewSender:   newSender,
		ProofBundle: proof,
	})
	if err != nil {
		t.Fatalf("EncodeUnshieldPayload: %v", err)
	}
	data, err := coreuno.EncodeEnvelope(coreuno.ActionUnshield, payload)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	msg := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), data, nil, false)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage: %v", err)
	}
	if !errors.Is(res.Err, coreuno.ErrProofNotImplemented) && !errors.Is(res.Err, coreuno.ErrInvalidPayload) {
		t.Fatalf("expected proof error, got %v", res.Err)
	}

	if got := coreuno.GetAccountState(st, from); got.Ciphertext != senderInitial || got.Version != 5 {
		t.Fatalf("unexpected sender UNO mutation: %+v", got)
	}
	if st.GetBalance(recv).Cmp(recvBefore) != 0 {
		t.Fatalf("unexpected receiver public balance mutation: got=%v want=%v", st.GetBalance(recv), recvBefore)
	}
}
