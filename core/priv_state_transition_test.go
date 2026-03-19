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
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
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

func makeShieldMsg(pub [32]byte, stx *types.ShieldTx, gasLimit uint64) types.Message {
	addr := common.BytesToAddress(crypto.Keccak256(pub[:]))
	msg := types.NewMessage(
		addr,
		&addr,
		stx.PrivNonce,
		big.NewInt(0),
		gasLimit,
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		nil,
		nil,
		true,
	)
	msg = msg.WithShieldTx(stx)
	return msg
}

func makeUnshieldMsg(pub [32]byte, utx *types.UnshieldTx, gasLimit uint64) types.Message {
	fromAddr := common.BytesToAddress(crypto.Keccak256(pub[:]))
	toAddr := utx.Recipient
	msg := types.NewMessage(
		fromAddr,
		&toAddr,
		utx.PrivNonce,
		big.NewInt(0),
		gasLimit,
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		nil,
		nil,
		true,
	)
	msg = msg.WithUnshieldTx(utx)
	return msg
}

func mustElgamalKeypair(t *testing.T) (pub, privkey [32]byte) {
	t.Helper()

	pubBytes, privBytes, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	copy(pub[:], pubBytes)
	copy(privkey[:], privBytes)
	return pub, privkey
}

func bytesToArray32(in []byte) [32]byte {
	var out [32]byte
	copy(out[:], in)
	return out
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
		UnoFee:      1,
		UnoFeeLimit: 1,
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
		UnoFee:      requiredFee - 1, // below required
		UnoFeeLimit: requiredFee - 1, // UnoFeeLimit also below required
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
		UnoFee:           requiredFee / 2, // below required
		UnoFeeLimit:      requiredFee * 2, // above required — should pass fee check
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

func TestApplyPrivTransfer_FeeExceedsFeeLimit(t *testing.T) {
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
	priv.SetAccountState(st, fromAddr, priv.AccountState{
		Ciphertext: priv.ZeroCiphertext(),
		Nonce:      0,
		Version:    0,
	})

	ptx := &types.PrivTransferTx{
		ChainID:   big.NewInt(1337),
		PrivNonce: 0,
		UnoFee:      2,
		UnoFeeLimit: 1,
		From:      fromPub,
		To:        toPub,
	}

	msg := makePrivTransferMsg(fromPub, toPub, ptx, 2_000_000)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(context.Background(), ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage precheck error: %v", err)
	}
	if !errors.Is(res.Err, priv.ErrFeeLimitExceeded) {
		t.Fatalf("expected ErrFeeLimitExceeded, got %v", res.Err)
	}
	if got := priv.GetPrivNonce(st, fromAddr); got != 0 {
		t.Fatalf("PrivNonce should still be 0, got %d", got)
	}
}

func TestApplyShield_InsufficientFee(t *testing.T) {
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")

	senderPub, _ := mustElgamalKeypair(t)
	addr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	st.AddBalance(addr, new(big.Int).SetUint64(priv.UnomiToTomi(priv.EstimateShieldFee())+1))
	priv.SetAccountState(st, addr, priv.AccountState{
		Ciphertext: priv.ZeroCiphertext(),
		Nonce:      0,
		Version:    0,
	})

	stx := &types.ShieldTx{
		ChainID:   big.NewInt(1337),
		PrivNonce: 0,
		UnoFee:    priv.EstimateShieldFee() - 1,
		Pubkey:    senderPub,
		UnoAmount: 1,
	}

	msg := makeShieldMsg(senderPub, stx, 2_000_000)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(context.Background(), ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage precheck error: %v", err)
	}
	if !errors.Is(res.Err, priv.ErrInsufficientFee) {
		t.Fatalf("expected ErrInsufficientFee, got %v", res.Err)
	}
}

func TestApplyShield_Success(t *testing.T) {
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")

	senderPub, senderPriv := mustElgamalKeypair(t)
	addr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	fee := priv.EstimateShieldFee()              // 1 UNO base unit
	amount := uint64(500)                         // 500 UNO base units = 5 UNO
	totalCostWei := priv.UnomiToTomi(amount + fee) // (amount+fee) * UNOUnit Wei
	feeWei := priv.UnomiToTomi(fee)
	initialPublic := totalCostWei + 12345

	st.AddBalance(addr, new(big.Int).SetUint64(initialPublic))
	priv.SetAccountState(st, addr, priv.AccountState{
		Ciphertext: priv.ZeroCiphertext(),
		Nonce:      0,
		Version:    0,
	})

	opening, err := cryptopriv.GenerateOpening()
	if err != nil {
		t.Fatalf("GenerateOpening: %v", err)
	}
	commitmentBytes, err := cryptopriv.PedersenCommitmentWithOpening(opening, amount)
	if err != nil {
		t.Fatalf("PedersenCommitmentWithOpening: %v", err)
	}
	handleBytes, err := cryptopriv.DecryptHandleWithOpening(senderPub[:], opening)
	if err != nil {
		t.Fatalf("DecryptHandleWithOpening: %v", err)
	}
	commitment := bytesToArray32(commitmentBytes)
	handle := bytesToArray32(handleBytes)
	ctx := priv.BuildShieldTranscriptContext(cfg.ChainID, 0, fee, amount, addr, commitment, handle, [32]byte{})
	shieldProof, _, _, err := cryptopriv.ProveShieldProofWithContext(senderPub[:], amount, opening, ctx)
	if err != nil {
		t.Fatalf("ProveShieldProofWithContext: %v", err)
	}
	rangeProof, err := cryptopriv.ProveRangeProof(commitmentBytes, amount, opening)
	if err != nil {
		t.Fatalf("ProveRangeProof: %v", err)
	}
	if err := priv.VerifyShieldProofWithContext(commitment, handle, senderPub, amount, shieldProof, ctx); err != nil {
		t.Fatalf("VerifyShieldProofWithContext: %v", err)
	}
	if err := priv.VerifySingleRangeProof(commitment, rangeProof); err != nil {
		t.Fatalf("VerifySingleRangeProof: %v", err)
	}

	stx := &types.ShieldTx{
		ChainID:    big.NewInt(1337),
		PrivNonce:  0,
		UnoFee:     fee,
		Pubkey:     senderPub,
		Recipient:  senderPub, // self-directed shield
		UnoAmount:  amount,
		Commitment: commitment,
		Handle:     handle,
	}
	copy(stx.ShieldProof[:], shieldProof)
	copy(stx.RangeProof[:], rangeProof)
	sigHash := stx.SigningHash()
	stx.S, stx.E, err = priv.SignSchnorr(senderPriv, sigHash[:])
	if err != nil {
		t.Fatalf("SignSchnorr: %v", err)
	}

	msg := makeShieldMsg(senderPub, stx, 2_000_000)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(context.Background(), ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage precheck error: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("expected successful shield, got %v", res.Err)
	}

	if got := st.GetBalance(addr).Uint64(); got != initialPublic-totalCostWei {
		t.Fatalf("public balance = %d, want %d", got, initialPublic-totalCostWei)
	}
	if got := st.GetBalance(coinbase).Uint64(); got != feeWei {
		t.Fatalf("coinbase balance = %d, want %d", got, feeWei)
	}
	accountState := priv.GetAccountState(st, addr)
	wantCt := priv.Ciphertext{Commitment: commitment, Handle: handle}
	if accountState.Ciphertext != wantCt {
		t.Fatalf("ciphertext mismatch after shield")
	}
	if accountState.Nonce != 1 {
		t.Fatalf("priv nonce = %d, want 1", accountState.Nonce)
	}
	if accountState.Version != 1 {
		t.Fatalf("version = %d, want 1", accountState.Version)
	}
}

func TestApplyUnshield_InsufficientPublicForFee(t *testing.T) {
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")

	senderPub, _ := mustElgamalKeypair(t)
	fee := priv.EstimateUnshieldFee() // 1 UNO base unit

	senderAddr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	// Amount=0 UNO base units → 0 Wei credit; fee=1 → 1e16 Wei deduction.
	// Recipient has 0 public balance, so available = 0 + 0 < feeWei → should fail.
	utx := &types.UnshieldTx{
		ChainID:   big.NewInt(1337),
		PrivNonce: 0,
		UnoFee:    fee,
		Pubkey:    senderPub,
		Recipient: senderAddr, // self-directed unshield
		UnoAmount: 0,
	}

	msg := makeUnshieldMsg(senderPub, utx, 2_000_000)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(context.Background(), ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage precheck error: %v", err)
	}
	if !errors.Is(res.Err, ErrInsufficientFundsForTransfer) {
		t.Fatalf("expected ErrInsufficientFundsForTransfer, got %v", res.Err)
	}
}

func TestApplyUnshield_InsufficientFee(t *testing.T) {
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")

	senderPub, _ := mustElgamalKeypair(t)

	senderAddr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	utx := &types.UnshieldTx{
		ChainID:   big.NewInt(1337),
		PrivNonce: 0,
		UnoFee:    priv.EstimateUnshieldFee() - 1,
		Pubkey:    senderPub,
		Recipient: senderAddr,
		UnoAmount: 1,
	}

	msg := makeUnshieldMsg(senderPub, utx, 2_000_000)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(context.Background(), ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage precheck error: %v", err)
	}
	if !errors.Is(res.Err, priv.ErrInsufficientFee) {
		t.Fatalf("expected ErrInsufficientFee, got %v", res.Err)
	}
}

func TestApplyUnshield_Success(t *testing.T) {
	st := newTTLDeterminismState(t)
	cfg := &params.ChainConfig{ChainID: big.NewInt(1337)}
	coinbase := common.HexToAddress("0xC0FFEE")

	senderPub, senderPriv := mustElgamalKeypair(t)
	senderAddr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	recipientAddr := common.HexToAddress("0xBEEF")
	fee := priv.EstimateUnshieldFee()       // 1 UNO base unit
	feeWei := priv.UnomiToTomi(fee)         // 1e16 Wei
	senderBalance := uint64(700)             // 700 UNO base units (encrypted balance)
	amount := uint64(500)                    // 500 UNO base units withdrawal
	newBalance := senderBalance - amount     // 200 UNO base units

	opening, err := cryptopriv.GenerateOpening()
	if err != nil {
		t.Fatalf("GenerateOpening: %v", err)
	}
	senderCtBytes, err := cryptopriv.EncryptWithOpening(senderPub[:], senderBalance, opening)
	if err != nil {
		t.Fatalf("EncryptWithOpening: %v", err)
	}
	senderCt := priv.Ciphertext{
		Commitment: bytesToArray32(senderCtBytes[:32]),
		Handle:     bytesToArray32(senderCtBytes[32:]),
	}
	priv.SetAccountState(st, senderAddr, priv.AccountState{
		Ciphertext: senderCt,
		Nonce:      0,
		Version:    0,
	})

	amountCt, err := priv.AddScalarToCiphertext(priv.ZeroCiphertext(), amount)
	if err != nil {
		t.Fatalf("AddScalarToCiphertext: %v", err)
	}
	zeroedCt, err := priv.SubCiphertexts(senderCt, amountCt)
	if err != nil {
		t.Fatalf("SubCiphertexts: %v", err)
	}
	sourceCommitmentBytes, sourceOpening, err := cryptopriv.CommitmentNew(newBalance)
	if err != nil {
		t.Fatalf("CommitmentNew: %v", err)
	}
	sourceCommitment := bytesToArray32(sourceCommitmentBytes)
	ctx := priv.BuildUnshieldTranscriptContext(cfg.ChainID, 0, fee, amount, senderAddr, zeroedCt, sourceCommitment, [32]byte{})
	zeroedCt64 := append(append([]byte{}, zeroedCt.Commitment[:]...), zeroedCt.Handle[:]...)
	commitmentEqProof, err := cryptopriv.ProveCommitmentEqProof(
		senderPriv[:], senderPub[:],
		zeroedCt64,
		sourceCommitmentBytes, sourceOpening,
		newBalance, ctx,
	)
	if err != nil {
		t.Fatalf("ProveCommitmentEqProof: %v", err)
	}
	rangeProof, err := cryptopriv.ProveRangeProof(sourceCommitmentBytes, newBalance, sourceOpening)
	if err != nil {
		t.Fatalf("ProveRangeProof: %v", err)
	}
	if err := priv.VerifyCommitmentEqProofWithContext(senderPub, zeroedCt, sourceCommitment, commitmentEqProof, ctx); err != nil {
		t.Fatalf("VerifyCommitmentEqProofWithContext: %v", err)
	}
	if err := priv.VerifySingleRangeProof(sourceCommitment, rangeProof); err != nil {
		t.Fatalf("VerifySingleRangeProof: %v", err)
	}

	utx := &types.UnshieldTx{
		ChainID:          big.NewInt(1337),
		PrivNonce:        0,
		UnoFee:           fee,
		Pubkey:           senderPub,
		Recipient:        recipientAddr,
		UnoAmount:        amount,
		SourceCommitment: sourceCommitment,
	}
	copy(utx.CommitmentEqProof[:], commitmentEqProof)
	copy(utx.RangeProof[:], rangeProof)
	sigHash := utx.SigningHash()
	utx.S, utx.E, err = priv.SignSchnorr(senderPriv, sigHash[:])
	if err != nil {
		t.Fatalf("SignSchnorr: %v", err)
	}

	msg := makeUnshieldMsg(senderPub, utx, 2_000_000)
	gp := new(GasPool).AddGas(msg.Gas())
	res, err := ApplyMessage(context.Background(), ttlBlockContext(1, coinbase), cfg, msg, gp, st)
	if err != nil {
		t.Fatalf("ApplyMessage precheck error: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("expected successful unshield, got %v", res.Err)
	}

	amountWei := priv.UnomiToTomi(amount)
	if got := st.GetBalance(recipientAddr).Uint64(); got != amountWei-feeWei {
		t.Fatalf("recipient public balance = %d, want %d", got, amountWei-feeWei)
	}
	if got := st.GetBalance(coinbase).Uint64(); got != feeWei {
		t.Fatalf("coinbase balance = %d, want %d", got, feeWei)
	}
	accountState := priv.GetAccountState(st, senderAddr)
	wantCt := priv.Ciphertext{Commitment: sourceCommitment, Handle: zeroedCt.Handle}
	if accountState.Ciphertext != wantCt {
		t.Fatalf("ciphertext mismatch after unshield")
	}
	if accountState.Nonce != 1 {
		t.Fatalf("priv nonce = %d, want 1", accountState.Nonce)
	}
	if accountState.Version != 1 {
		t.Fatalf("version = %d, want 1", accountState.Version)
	}
}
