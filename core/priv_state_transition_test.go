package core

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/priv"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"github.com/tos-network/gtos/params"
)

// makePrivTransferMsg constructs a fake Message containing a PrivTransferTx.
// The message uses isFake=true to skip signature/nonce precheck on the outer
// (public) nonce. The PrivTransferTx inner fields control the priv-layer checks.
func makePrivTransferMsg(fromPub, toPub [32]byte, ptx *types.PrivTransferTx, gasLimit uint64) types.Message {
	fromAddr := common.BytesToAddress(crypto.Keccak256(fromPub[:]))
	toAddr := common.BytesToAddress(crypto.Keccak256(toPub[:]))

	msg := types.NewMessage(
		fromAddr,
		&toAddr,
		ptx.PrivNonce, // outer nonce matches priv nonce to pass preCheck when isFake=false
		big.NewInt(0),
		gasLimit,
		big.NewInt(0), // txPrice=0 so buyGas deducts nothing
		big.NewInt(0),
		big.NewInt(0),
		nil,
		nil,
		true, // isFake: skip public nonce & EOA checks in preCheck
	)
	msg = msg.WithPrivTransferTx(ptx)
	return msg
}

func TestApplyPrivTransfer_NonceMismatch(t *testing.T) {
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")

	// Use generator as the sender pubkey and a different point for receiver.
	fromPub := [32]byte{}
	copy(fromPub[:], ristretto255.NewGeneratorElement().Bytes())
	toPub := [32]byte{}
	copy(toPub[:], ristretto255.NewIdentityElement().Add(
		ristretto255.NewGeneratorElement(),
		ristretto255.NewGeneratorElement(),
	).Bytes())

	fromAddr := common.BytesToAddress(crypto.Keccak256(fromPub[:]))

	// Set PrivNonce to 5 in state.
	priv.SetAccountState(st, fromAddr, priv.AccountState{
		Nonce:   5,
		Version: 0,
	})

	ptx := &types.PrivTransferTx{
		ChainID:   big.NewInt(1337),
		PrivNonce: 3, // wrong — state expects 5
		Fee:       20_000,
		FeeLimit:  20_000,
		From:      fromPub,
		To:        toPub,
	}

	msg := makePrivTransferMsg(fromPub, toPub, ptx, 2_000_000)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(context.Background(), ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage precheck error: %v", err)
	}
	if res.Err == nil {
		t.Fatal("expected execution error for nonce mismatch, got nil")
	}
	if !errors.Is(res.Err, priv.ErrNonceMismatch) {
		t.Fatalf("expected ErrNonceMismatch, got %v", res.Err)
	}

	// Verify PrivNonce unchanged.
	if got := priv.GetPrivNonce(st, fromAddr); got != 5 {
		t.Fatalf("PrivNonce should still be 5, got %d", got)
	}
}

func TestApplyPrivTransfer_InsufficientFee(t *testing.T) {
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")

	fromPub := [32]byte{}
	copy(fromPub[:], ristretto255.NewGeneratorElement().Bytes())
	toPub := [32]byte{}
	copy(toPub[:], ristretto255.NewIdentityElement().Add(
		ristretto255.NewGeneratorElement(),
		ristretto255.NewGeneratorElement(),
	).Bytes())

	fromAddr := common.BytesToAddress(crypto.Keccak256(fromPub[:]))

	// PrivNonce=0 in state (default), set version=0.
	priv.SetAccountState(st, fromAddr, priv.AccountState{
		Nonce:   0,
		Version: 0,
	})

	requiredFee := priv.EstimateRequiredFee(0)

	ptx := &types.PrivTransferTx{
		ChainID:   big.NewInt(1337),
		PrivNonce: 0,
		Fee:       requiredFee - 1,     // below required
		FeeLimit:  requiredFee - 1,     // FeeLimit also below required
		From:      fromPub,
		To:        toPub,
	}

	msg := makePrivTransferMsg(fromPub, toPub, ptx, 2_000_000)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(context.Background(), ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage precheck error: %v", err)
	}
	if res.Err == nil {
		t.Fatal("expected execution error for insufficient fee, got nil")
	}
	if !errors.Is(res.Err, priv.ErrInsufficientFee) {
		t.Fatalf("expected ErrInsufficientFee, got %v", res.Err)
	}

	// Verify PrivNonce unchanged.
	if got := priv.GetPrivNonce(st, fromAddr); got != 0 {
		t.Fatalf("PrivNonce should still be 0, got %d", got)
	}
}

func TestApplyPrivTransfer_FeeLimitGreaterThanFee(t *testing.T) {
	// When Fee < requiredFee but FeeLimit >= requiredFee, the fee/nonce
	// validation should pass. The tx will then fail at Schnorr signature
	// verification (no valid signature on the test tx), proving that the fee
	// logic correctly computed feePaid = requiredFee, refund = FeeLimit - requiredFee.
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")

	fromPub := [32]byte{}
	copy(fromPub[:], ristretto255.NewGeneratorElement().Bytes())
	toPub := [32]byte{}
	copy(toPub[:], ristretto255.NewIdentityElement().Add(
		ristretto255.NewGeneratorElement(),
		ristretto255.NewGeneratorElement(),
	).Bytes())

	fromAddr := common.BytesToAddress(crypto.Keccak256(fromPub[:]))

	// Set up sender state with a valid ciphertext (identity elements).
	id := ristretto255.NewIdentityElement().Bytes()
	var idBytes [32]byte
	copy(idBytes[:], id)
	priv.SetAccountState(st, fromAddr, priv.AccountState{
		Ciphertext: priv.Ciphertext{
			Commitment: idBytes,
			Handle:     idBytes,
		},
		Nonce:   0,
		Version: 0,
	})

	requiredFee := priv.EstimateRequiredFee(0)

	ptx := &types.PrivTransferTx{
		ChainID:          big.NewInt(1337),
		PrivNonce:        0,
		Fee:              requiredFee / 2,     // below required
		FeeLimit:         requiredFee * 2,     // above required — should pass fee check
		From:             fromPub,
		To:               toPub,
		Commitment:       idBytes,
		SenderHandle:     idBytes,
		ReceiverHandle:   idBytes,
		SourceCommitment: idBytes,
		// Empty proofs — will fail at proof verification.
		CtValidityProof:   make([]byte, 0),
		CommitmentEqProof: make([]byte, 0),
		RangeProof:        make([]byte, 0),
	}

	msg := makePrivTransferMsg(fromPub, toPub, ptx, 2_000_000)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(context.Background(), ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage precheck error: %v", err)
	}
	// Should NOT fail with ErrInsufficientFee or ErrNonceMismatch — those
	// checks passed. Should fail at Schnorr signature verification (no valid
	// signature on the test tx).
	if res.Err == nil {
		t.Fatal("expected Schnorr signature error, got nil")
	}
	if errors.Is(res.Err, priv.ErrInsufficientFee) {
		t.Fatal("should not fail with ErrInsufficientFee when FeeLimit >= requiredFee")
	}
	if errors.Is(res.Err, priv.ErrNonceMismatch) {
		t.Fatal("should not fail with ErrNonceMismatch when nonce matches")
	}
	// The error should be a Schnorr signature error.
	if res.Err.Error() != "priv: invalid Schnorr signature" {
		t.Fatalf("expected Schnorr signature error, got %v", res.Err)
	}
}
