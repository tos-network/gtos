package core

import (
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/tos-network/gtos/core/priv"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
)

var errInvalidPrivSchnorrSignature = errors.New("priv: invalid Schnorr signature")

func applyPrivacyTxState(chainID *big.Int, statedb vm.StateDB, tx *types.Transaction) (uint64, error) {
	switch tx.Type() {
	case types.PrivTransferTxType:
		ptx := tx.PrivTransferInner()
		if ptx == nil {
			return 0, errors.New("priv: message does not contain PrivTransferTx")
		}
		return applyPrivTransferState(chainID, statedb, ptx)
	case types.ShieldTxType:
		stx := tx.ShieldInner()
		if stx == nil {
			return 0, errors.New("priv: message does not contain ShieldTx")
		}
		return applyShieldState(chainID, statedb, stx)
	case types.UnshieldTxType:
		utx := tx.UnshieldInner()
		if utx == nil {
			return 0, errors.New("priv: message does not contain UnshieldTx")
		}
		return applyUnshieldState(chainID, statedb, utx)
	default:
		return 0, ErrTxTypeNotSupported
	}
}

func applyPrivTransferState(chainID *big.Int, statedb vm.StateDB, ptx *types.PrivTransferTx) (uint64, error) {
	fromAddr := ptx.FromAddress()
	toAddr := ptx.ToAddress()

	if ptx.UnoFee > ptx.UnoFeeLimit {
		return 0, priv.ErrFeeLimitExceeded
	}
	requiredFee := priv.EstimateRequiredFee(0)
	if requiredFee > ptx.UnoFeeLimit {
		return 0, priv.ErrInsufficientFee
	}
	var feePaidGas, feeRefundGas uint64
	if requiredFee > ptx.UnoFee {
		feePaidGas = requiredFee
		feeRefundGas = ptx.UnoFeeLimit - requiredFee
	} else {
		feePaidGas = ptx.UnoFee
		feeRefundGas = ptx.UnoFeeLimit - ptx.UnoFee
	}

	expectedNonce := priv.GetPrivNonce(statedb, fromAddr)
	if ptx.PrivNonce != expectedNonce {
		return 0, priv.ErrNonceMismatch
	}

	sigHash := ptx.SigningHash()
	if !priv.VerifySchnorrSignature(ptx.From, sigHash[:], ptx.S, ptx.E) {
		return 0, errInvalidPrivSchnorrSignature
	}

	senderState := priv.GetAccountState(statedb, fromAddr)
	receiverState := priv.GetAccountState(statedb, toAddr)
	if senderState.Version == math.MaxUint64 || receiverState.Version == math.MaxUint64 {
		return 0, priv.ErrVersionOverflow
	}

	senderCt := priv.Ciphertext{
		Commitment: ptx.Commitment,
		Handle:     ptx.SenderHandle,
	}
	receiverCt := priv.Ciphertext{
		Commitment: ptx.Commitment,
		Handle:     ptx.ReceiverHandle,
	}
	transcriptCtx := priv.BuildPrivTransferTranscriptContext(
		chainID,
		ptx.PrivNonce,
		ptx.UnoFee,
		ptx.UnoFeeLimit,
		fromAddr, toAddr,
		senderCt, receiverCt,
		ptx.SourceCommitment,
	)
	if err := priv.VerifyCiphertextValidityProofWithContext(
		ptx.Commitment, ptx.SenderHandle, ptx.ReceiverHandle,
		ptx.From, ptx.To, ptx.CtValidityProof,
		transcriptCtx,
	); err != nil {
		return 0, err
	}

	// FeeLimit is in UNO base units; ciphertext arithmetic operates in UNO base units directly.
	outputCt, err := priv.AddScalarToCiphertext(senderCt, ptx.UnoFeeLimit)
	if err != nil {
		return 0, err
	}
	newSenderBalanceCt, err := priv.SubCiphertexts(senderState.Ciphertext, outputCt)
	if err != nil {
		return 0, err
	}
	if err := priv.VerifyCommitmentEqProofWithContext(
		ptx.From, newSenderBalanceCt, ptx.SourceCommitment,
		ptx.CommitmentEqProof,
		transcriptCtx,
	); err != nil {
		return 0, err
	}
	if err := priv.VerifyRangeProof(
		ptx.SourceCommitment, ptx.Commitment,
		ptx.RangeProof,
	); err != nil {
		return 0, err
	}

	senderState.Ciphertext = priv.Ciphertext{
		Commitment: ptx.SourceCommitment,
		Handle:     newSenderBalanceCt.Handle,
	}
	if feeRefundGas > 0 {
		refundedCt, err := priv.AddScalarToCiphertext(senderState.Ciphertext, feeRefundGas)
		if err != nil {
			return 0, err
		}
		senderState.Ciphertext = refundedCt
	}
	senderState.Version++
	priv.SetAccountState(statedb, fromAddr, senderState)

	newReceiverCt, err := priv.AddCiphertexts(receiverState.Ciphertext, receiverCt)
	if err != nil {
		return 0, err
	}
	receiverState.Ciphertext = newReceiverCt
	receiverState.Version++
	priv.SetAccountState(statedb, toAddr, receiverState)
	priv.IncrementPrivNonce(statedb, fromAddr)

	return priv.UNOFeeToWei(feePaidGas), nil
}

func applyShieldState(chainID *big.Int, statedb vm.StateDB, stx *types.ShieldTx) (uint64, error) {
	senderAddr := stx.DerivedAddress()
	recipientAddr := stx.RecipientAddress()

	requiredFee := priv.EstimateShieldFee()
	if stx.UnoFee < requiredFee {
		return 0, priv.ErrInsufficientFee
	}

	// Amount and Fee are in UNO base units; convert to Wei for public balance deduction.
	totalCostWei := new(big.Int).SetUint64(priv.UNOFeeToWei(stx.UnoAmount + stx.UnoFee))
	if statedb.GetBalance(senderAddr).Cmp(totalCostWei) < 0 {
		return 0, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, senderAddr.Hex())
	}

	expectedNonce := priv.GetPrivNonce(statedb, senderAddr)
	if stx.PrivNonce != expectedNonce {
		return 0, priv.ErrNonceMismatch
	}

	sigHash := stx.SigningHash()
	if !priv.VerifySchnorrSignature(stx.Pubkey, sigHash[:], stx.S, stx.E) {
		return 0, errInvalidPrivSchnorrSignature
	}

	recipientState := priv.GetAccountState(statedb, recipientAddr)
	if recipientState.Version == math.MaxUint64 {
		return 0, priv.ErrVersionOverflow
	}

	transcriptCtx := priv.BuildShieldTranscriptContext(
		chainID,
		stx.PrivNonce,
		stx.UnoFee,
		stx.UnoAmount,
		senderAddr,
		stx.Commitment,
		stx.Handle,
	)
	if err := priv.VerifyShieldProofWithContext(
		stx.Commitment, stx.Handle, stx.Recipient,
		stx.UnoAmount, stx.ShieldProof[:], transcriptCtx,
	); err != nil {
		return 0, err
	}
	if err := priv.VerifySingleRangeProof(stx.Commitment, stx.RangeProof[:]); err != nil {
		return 0, err
	}

	statedb.SubBalance(senderAddr, totalCostWei)
	depositCt := priv.Ciphertext{
		Commitment: stx.Commitment,
		Handle:     stx.Handle,
	}
	newCt, err := priv.AddCiphertexts(recipientState.Ciphertext, depositCt)
	if err != nil {
		return 0, err
	}
	recipientState.Ciphertext = newCt
	recipientState.Version++
	priv.SetAccountState(statedb, recipientAddr, recipientState)
	priv.IncrementPrivNonce(statedb, senderAddr)

	return priv.UNOFeeToWei(stx.UnoFee), nil
}

func applyUnshieldState(chainID *big.Int, statedb vm.StateDB, utx *types.UnshieldTx) (uint64, error) {
	senderAddr := utx.DerivedAddress()
	recipientAddr := utx.Recipient

	requiredFee := priv.EstimateUnshieldFee()
	if utx.UnoFee < requiredFee {
		return 0, priv.ErrInsufficientFee
	}

	expectedNonce := priv.GetPrivNonce(statedb, senderAddr)
	if utx.PrivNonce != expectedNonce {
		return 0, priv.ErrNonceMismatch
	}

	// Amount and Fee are in UNO base units; convert to Wei for public balance operations.
	amountWei := new(big.Int).SetUint64(priv.UNOFeeToWei(utx.UnoAmount))
	feeWei := priv.UNOFeeToWei(utx.UnoFee)
	availablePublic := new(big.Int).Add(
		new(big.Int).Set(statedb.GetBalance(recipientAddr)),
		amountWei,
	)
	if availablePublic.Cmp(new(big.Int).SetUint64(feeWei)) < 0 {
		return 0, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, recipientAddr.Hex())
	}

	sigHash := utx.SigningHash()
	if !priv.VerifySchnorrSignature(utx.Pubkey, sigHash[:], utx.S, utx.E) {
		return 0, errInvalidPrivSchnorrSignature
	}

	accountState := priv.GetAccountState(statedb, senderAddr)
	if accountState.Version == math.MaxUint64 {
		return 0, priv.ErrVersionOverflow
	}

	amountCt, err := priv.AddScalarToCiphertext(priv.ZeroCiphertext(), utx.UnoAmount)
	if err != nil {
		return 0, err
	}
	zeroedCt, err := priv.SubCiphertexts(accountState.Ciphertext, amountCt)
	if err != nil {
		return 0, err
	}
	transcriptCtx := priv.BuildUnshieldTranscriptContext(
		chainID,
		utx.PrivNonce,
		utx.UnoFee,
		utx.UnoAmount,
		senderAddr,
		zeroedCt,
		utx.SourceCommitment,
	)
	if err := priv.VerifyCommitmentEqProofWithContext(
		utx.Pubkey, zeroedCt, utx.SourceCommitment,
		utx.CommitmentEqProof[:], transcriptCtx,
	); err != nil {
		return 0, err
	}
	if err := priv.VerifySingleRangeProof(utx.SourceCommitment, utx.RangeProof[:]); err != nil {
		return 0, err
	}

	accountState.Ciphertext = priv.Ciphertext{
		Commitment: utx.SourceCommitment,
		Handle:     zeroedCt.Handle,
	}
	accountState.Version++
	priv.SetAccountState(statedb, senderAddr, accountState)
	priv.IncrementPrivNonce(statedb, senderAddr)

	statedb.AddBalance(recipientAddr, amountWei)
	statedb.SubBalance(recipientAddr, new(big.Int).SetUint64(feeWei))

	return feeWei, nil
}
