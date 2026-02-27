package core

import (
	"errors"
	"math"
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
	// Shield amount=10 TOS; balance must be ≥ 10 TOS (10×1e18 wei) for CanTransfer to pass.
	st.SetBalance(from, new(big.Int).Mul(big.NewInt(11), new(big.Int).SetUint64(params.TOS)))

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

// TestUNOVersionOverflowRejectedInExecution proves that when any involved account
// has uno_version == MaxUint64 the execution path returns ErrVersionOverflow and
// makes no state mutation — ciphertext and version are unchanged for all parties.
func TestUNOVersionOverflowRejectedInExecution(t *testing.T) {
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")
	to := params.PrivacyRouterAddress
	gen := ristretto255.NewGeneratorElement().Bytes()
	id := ristretto255.NewIdentityElement().Bytes()
	gen2 := ristretto255.NewIdentityElement().Add(ristretto255.NewGeneratorElement(), ristretto255.NewGeneratorElement()).Bytes()

	t.Run("shield/sender-version-overflow", func(t *testing.T) {
		t.Parallel()
		st := newTTLDeterminismState(t)
		from := common.HexToAddress("0x6001")
		st.SetBalance(from, new(big.Int).Mul(big.NewInt(10), new(big.Int).SetUint64(params.TOS)))
		setupElgamalSigner(t, st, from, gen)
		initial := coreuno.AccountState{
			Ciphertext: makeValidCiphertext(gen, id),
			Version:    math.MaxUint64,
		}
		coreuno.SetAccountState(st, from, initial)
		body, err := coreuno.EncodeShieldPayload(coreuno.ShieldPayload{
			Amount:      1,
			NewSender:   makeValidCiphertext(gen, id),
			ProofBundle: make([]byte, coreuno.ShieldProofSize),
		})
		if err != nil {
			t.Fatalf("EncodeShieldPayload: %v", err)
		}
		data, err := coreuno.EncodeEnvelope(coreuno.ActionShield, body)
		if err != nil {
			t.Fatalf("EncodeEnvelope: %v", err)
		}
		msg := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), data, nil, false)
		gp := new(GasPool).AddGas(msg.Gas())
		res, err := ApplyMessage(ttlBlockContext(1, coinbase), cfg, msg, gp, st)
		if err != nil {
			t.Fatalf("ApplyMessage: %v", err)
		}
		if !errors.Is(res.Err, coreuno.ErrVersionOverflow) {
			t.Fatalf("expected ErrVersionOverflow, got %v", res.Err)
		}
		if got := coreuno.GetAccountState(st, from); got != initial {
			t.Fatalf("unexpected UNO state mutation: got=%+v want=%+v", got, initial)
		}
	})

	t.Run("transfer/sender-version-overflow", func(t *testing.T) {
		t.Parallel()
		st := newTTLDeterminismState(t)
		from := common.HexToAddress("0x6002")
		recv := common.HexToAddress("0x6003")
		setupElgamalSigner(t, st, from, gen)
		setupElgamalSigner(t, st, recv, gen2)
		initialFrom := coreuno.AccountState{
			Ciphertext: makeValidCiphertext(gen, id),
			Version:    math.MaxUint64,
		}
		initialRecv := coreuno.AccountState{
			Ciphertext: makeValidCiphertext(id, id),
			Version:    0,
		}
		coreuno.SetAccountState(st, from, initialFrom)
		coreuno.SetAccountState(st, recv, initialRecv)
		body, err := coreuno.EncodeTransferPayload(coreuno.TransferPayload{
			To:            recv,
			NewSender:     makeValidCiphertext(id, id),
			ReceiverDelta: makeValidCiphertext(gen, id),
			ProofBundle:   make([]byte, coreuno.CTValidityProofSizeT1+coreuno.BalanceProofSize),
		})
		if err != nil {
			t.Fatalf("EncodeTransferPayload: %v", err)
		}
		data, err := coreuno.EncodeEnvelope(coreuno.ActionTransfer, body)
		if err != nil {
			t.Fatalf("EncodeEnvelope: %v", err)
		}
		msg := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), data, nil, false)
		gp := new(GasPool).AddGas(msg.Gas())
		res, err := ApplyMessage(ttlBlockContext(1, coinbase), cfg, msg, gp, st)
		if err != nil {
			t.Fatalf("ApplyMessage: %v", err)
		}
		if !errors.Is(res.Err, coreuno.ErrVersionOverflow) {
			t.Fatalf("expected ErrVersionOverflow, got %v", res.Err)
		}
		if got := coreuno.GetAccountState(st, from); got != initialFrom {
			t.Fatalf("unexpected sender UNO mutation: got=%+v want=%+v", got, initialFrom)
		}
		if got := coreuno.GetAccountState(st, recv); got != initialRecv {
			t.Fatalf("unexpected receiver UNO mutation: got=%+v want=%+v", got, initialRecv)
		}
	})

	t.Run("transfer/receiver-version-overflow", func(t *testing.T) {
		t.Parallel()
		st := newTTLDeterminismState(t)
		from := common.HexToAddress("0x6004")
		recv := common.HexToAddress("0x6005")
		setupElgamalSigner(t, st, from, gen)
		setupElgamalSigner(t, st, recv, gen2)
		initialFrom := coreuno.AccountState{
			Ciphertext: makeValidCiphertext(gen, id),
			Version:    0,
		}
		initialRecv := coreuno.AccountState{
			Ciphertext: makeValidCiphertext(id, id),
			Version:    math.MaxUint64,
		}
		coreuno.SetAccountState(st, from, initialFrom)
		coreuno.SetAccountState(st, recv, initialRecv)
		body, err := coreuno.EncodeTransferPayload(coreuno.TransferPayload{
			To:            recv,
			NewSender:     makeValidCiphertext(id, id),
			ReceiverDelta: makeValidCiphertext(gen, id),
			ProofBundle:   make([]byte, coreuno.CTValidityProofSizeT1+coreuno.BalanceProofSize),
		})
		if err != nil {
			t.Fatalf("EncodeTransferPayload: %v", err)
		}
		data, err := coreuno.EncodeEnvelope(coreuno.ActionTransfer, body)
		if err != nil {
			t.Fatalf("EncodeEnvelope: %v", err)
		}
		msg := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), data, nil, false)
		gp := new(GasPool).AddGas(msg.Gas())
		res, err := ApplyMessage(ttlBlockContext(1, coinbase), cfg, msg, gp, st)
		if err != nil {
			t.Fatalf("ApplyMessage: %v", err)
		}
		if !errors.Is(res.Err, coreuno.ErrVersionOverflow) {
			t.Fatalf("expected ErrVersionOverflow, got %v", res.Err)
		}
		if got := coreuno.GetAccountState(st, from); got != initialFrom {
			t.Fatalf("unexpected sender UNO mutation: got=%+v want=%+v", got, initialFrom)
		}
		if got := coreuno.GetAccountState(st, recv); got != initialRecv {
			t.Fatalf("unexpected receiver UNO mutation: got=%+v want=%+v", got, initialRecv)
		}
	})

	t.Run("unshield/sender-version-overflow", func(t *testing.T) {
		t.Parallel()
		st := newTTLDeterminismState(t)
		from := common.HexToAddress("0x6006")
		recv := common.HexToAddress("0x6007")
		setupElgamalSigner(t, st, from, gen)
		initial := coreuno.AccountState{
			Ciphertext: makeValidCiphertext(gen, id),
			Version:    math.MaxUint64,
		}
		coreuno.SetAccountState(st, from, initial)
		recvBefore := new(big.Int).Set(st.GetBalance(recv))
		proof := make([]byte, coreuno.BalanceProofSize)
		proof[7] = 1
		body, err := coreuno.EncodeUnshieldPayload(coreuno.UnshieldPayload{
			To:          recv,
			Amount:      1,
			NewSender:   makeValidCiphertext(id, id),
			ProofBundle: proof,
		})
		if err != nil {
			t.Fatalf("EncodeUnshieldPayload: %v", err)
		}
		data, err := coreuno.EncodeEnvelope(coreuno.ActionUnshield, body)
		if err != nil {
			t.Fatalf("EncodeEnvelope: %v", err)
		}
		msg := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), data, nil, false)
		gp := new(GasPool).AddGas(msg.Gas())
		res, err := ApplyMessage(ttlBlockContext(1, coinbase), cfg, msg, gp, st)
		if err != nil {
			t.Fatalf("ApplyMessage: %v", err)
		}
		if !errors.Is(res.Err, coreuno.ErrVersionOverflow) {
			t.Fatalf("expected ErrVersionOverflow, got %v", res.Err)
		}
		if got := coreuno.GetAccountState(st, from); got != initial {
			t.Fatalf("unexpected sender UNO mutation: got=%+v want=%+v", got, initial)
		}
		if st.GetBalance(recv).Cmp(recvBefore) != 0 {
			t.Fatalf("unexpected receiver balance mutation: got=%v want=%v", st.GetBalance(recv), recvBefore)
		}
	})
}

func TestUNONonceReplayRejectedAcrossActions(t *testing.T) {
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")
	from := common.HexToAddress("0x4001")
	recv := common.HexToAddress("0x4002")
	to := params.PrivacyRouterAddress

	makeShieldData := func(t *testing.T) []byte {
		t.Helper()
		body, err := coreuno.EncodeShieldPayload(coreuno.ShieldPayload{
			Amount:      1,
			NewSender:   makeValidCiphertext(ristretto255.NewGeneratorElement().Bytes(), ristretto255.NewIdentityElement().Bytes()),
			ProofBundle: make([]byte, coreuno.ShieldProofSize),
		})
		if err != nil {
			t.Fatalf("EncodeShieldPayload: %v", err)
		}
		data, err := coreuno.EncodeEnvelope(coreuno.ActionShield, body)
		if err != nil {
			t.Fatalf("EncodeEnvelope(shield): %v", err)
		}
		return data
	}
	makeTransferData := func(t *testing.T) []byte {
		t.Helper()
		body, err := coreuno.EncodeTransferPayload(coreuno.TransferPayload{
			To:            recv,
			NewSender:     makeValidCiphertext(ristretto255.NewIdentityElement().Bytes(), ristretto255.NewIdentityElement().Bytes()),
			ReceiverDelta: makeValidCiphertext(ristretto255.NewGeneratorElement().Bytes(), ristretto255.NewIdentityElement().Bytes()),
			ProofBundle:   make([]byte, coreuno.CTValidityProofSizeT1+coreuno.BalanceProofSize),
		})
		if err != nil {
			t.Fatalf("EncodeTransferPayload: %v", err)
		}
		data, err := coreuno.EncodeEnvelope(coreuno.ActionTransfer, body)
		if err != nil {
			t.Fatalf("EncodeEnvelope(transfer): %v", err)
		}
		return data
	}
	makeUnshieldData := func(t *testing.T) []byte {
		t.Helper()
		proof := make([]byte, coreuno.BalanceProofSize)
		proof[7] = 1
		body, err := coreuno.EncodeUnshieldPayload(coreuno.UnshieldPayload{
			To:          recv,
			Amount:      1,
			NewSender:   makeValidCiphertext(ristretto255.NewIdentityElement().Bytes(), ristretto255.NewIdentityElement().Bytes()),
			ProofBundle: proof,
		})
		if err != nil {
			t.Fatalf("EncodeUnshieldPayload: %v", err)
		}
		data, err := coreuno.EncodeEnvelope(coreuno.ActionUnshield, body)
		if err != nil {
			t.Fatalf("EncodeEnvelope(unshield): %v", err)
		}
		return data
	}

	t.Run("same-action replay nonce low", func(t *testing.T) {
		tests := []struct {
			name string
			data func(*testing.T) []byte
		}{
			{name: "shield", data: makeShieldData},
			{name: "transfer", data: makeTransferData},
			{name: "unshield", data: makeUnshieldData},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				st := newTTLDeterminismState(t)
				st.SetBalance(from, new(big.Int).Mul(big.NewInt(2), new(big.Int).SetUint64(params.TOS)))
				setupElgamalSigner(t, st, from, ristretto255.NewGeneratorElement().Bytes())
				setupElgamalSigner(t, st, recv, ristretto255.NewIdentityElement().Add(ristretto255.NewGeneratorElement(), ristretto255.NewGeneratorElement()).Bytes())

				msg := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), tc.data(t), nil, false)

				gp1 := new(GasPool).AddGas(msg.Gas())
				res, err := ApplyMessage(ttlBlockContext(1, coinbase), cfg, msg, gp1, st)
				if err != nil {
					t.Fatalf("first ApplyMessage unexpected precheck error: %v", err)
				}
				if !errors.Is(res.Err, coreuno.ErrProofNotImplemented) && !errors.Is(res.Err, coreuno.ErrInvalidPayload) {
					t.Fatalf("first ApplyMessage expected proof-level failure, got %v", res.Err)
				}

				gp2 := new(GasPool).AddGas(msg.Gas())
				_, err = ApplyMessage(ttlBlockContext(1, coinbase), cfg, msg, gp2, st)
				if !errors.Is(err, ErrNonceTooLow) {
					t.Fatalf("second ApplyMessage expected %v, got %v", ErrNonceTooLow, err)
				}
			})
		}
	})

	t.Run("cross-action replay nonce low", func(t *testing.T) {
		st := newTTLDeterminismState(t)
		st.SetBalance(from, new(big.Int).Mul(big.NewInt(2), new(big.Int).SetUint64(params.TOS)))
		setupElgamalSigner(t, st, from, ristretto255.NewGeneratorElement().Bytes())
		setupElgamalSigner(t, st, recv, ristretto255.NewIdentityElement().Add(ristretto255.NewGeneratorElement(), ristretto255.NewGeneratorElement()).Bytes())

		first := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), makeShieldData(t), nil, false)
		secondDifferentAction := types.NewMessage(from, &to, 0, big.NewInt(0), 2_000_000, big.NewInt(0), big.NewInt(0), big.NewInt(0), makeTransferData(t), nil, false)

		gp1 := new(GasPool).AddGas(first.Gas())
		res, err := ApplyMessage(ttlBlockContext(1, coinbase), cfg, first, gp1, st)
		if err != nil {
			t.Fatalf("first ApplyMessage unexpected precheck error: %v", err)
		}
		if !errors.Is(res.Err, coreuno.ErrProofNotImplemented) && !errors.Is(res.Err, coreuno.ErrInvalidPayload) {
			t.Fatalf("first ApplyMessage expected proof-level failure, got %v", res.Err)
		}

		gp2 := new(GasPool).AddGas(secondDifferentAction.Gas())
		_, err = ApplyMessage(ttlBlockContext(1, coinbase), cfg, secondDifferentAction, gp2, st)
		if !errors.Is(err, ErrNonceTooLow) {
			t.Fatalf("second ApplyMessage expected %v, got %v", ErrNonceTooLow, err)
		}
	})
}
