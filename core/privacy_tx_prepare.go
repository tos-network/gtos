package core

import (
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/priv"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/policywallet"
)

var errPreparedPrivacyStateMismatch = errors.New("priv: prepared state mismatch")

type preparedPrivacyTx interface {
	Transaction() *types.Transaction
	From() common.Address
	AddToBatch(batch *priv.BatchVerifier) error
	VerifyProofs() error
	ApplyState(statedb vm.StateDB) (*big.Int, error)
}

type preparedPrivTransferTx struct {
	tx                 *types.Transaction
	from               common.Address
	to                 common.Address
	inputSenderState   priv.AccountState
	inputReceiverState priv.AccountState
	newSenderBalance   priv.Ciphertext
	feePaidGas         uint64
	feeRefundGas       uint64
	transcriptContext  []byte
}

func (p *preparedPrivTransferTx) Transaction() *types.Transaction {
	return p.tx
}

func (p *preparedPrivTransferTx) From() common.Address {
	return p.from
}

func (p *preparedPrivTransferTx) AddToBatch(batch *priv.BatchVerifier) error {
	ptx := p.tx.PrivTransferInner()
	return addPreparedPrivTransferProofs(batch, ptx, p.newSenderBalance, p.transcriptContext)
}

func (p *preparedPrivTransferTx) VerifyProofs() error {
	ptx := p.tx.PrivTransferInner()
	return verifyPreparedPrivTransferProofs(ptx, p.newSenderBalance, p.transcriptContext)
}

func (p *preparedPrivTransferTx) ApplyState(statedb vm.StateDB) (*big.Int, error) {
	ptx := p.tx.PrivTransferInner()
	if ptx == nil {
		return common.Big0, errors.New("priv: message does not contain PrivTransferTx")
	}
	senderState := priv.GetAccountState(statedb, p.from)
	if !accountStateEqual(senderState, p.inputSenderState) {
		return common.Big0, errPreparedPrivacyStateMismatch
	}
	receiverState := priv.GetAccountState(statedb, p.to)
	if !accountStateEqual(receiverState, p.inputReceiverState) {
		return common.Big0, errPreparedPrivacyStateMismatch
	}

	senderState.Ciphertext = priv.Ciphertext{
		Commitment: ptx.SourceCommitment,
		Handle:     p.newSenderBalance.Handle,
	}
	if p.feeRefundGas > 0 {
		refundedCt, err := priv.AddScalarToCiphertext(senderState.Ciphertext, p.feeRefundGas)
		if err != nil {
			return common.Big0, err
		}
		senderState.Ciphertext = refundedCt
	}
	senderState.Version++
	priv.SetAccountState(statedb, p.from, senderState)

	receiverCt := priv.Ciphertext{
		Commitment: ptx.Commitment,
		Handle:     ptx.ReceiverHandle,
	}
	newReceiverCt, err := priv.AddCiphertexts(receiverState.Ciphertext, receiverCt)
	if err != nil {
		return common.Big0, err
	}
	receiverState.Ciphertext = newReceiverCt
	receiverState.Version++
	priv.SetAccountState(statedb, p.to, receiverState)
	if _, err := priv.IncrementPrivNonce(statedb, p.from); err != nil {
		return common.Big0, err
	}

	return priv.UnomiToTomiBig(p.feePaidGas), nil
}

type preparedShieldTx struct {
	tx                  *types.Transaction
	from                common.Address
	inputSenderBalance  *big.Int
	inputRecipientState priv.AccountState
	transcriptContext   []byte
	totalCostWei        *big.Int
}

func (p *preparedShieldTx) Transaction() *types.Transaction {
	return p.tx
}

func (p *preparedShieldTx) From() common.Address {
	return p.from
}

func (p *preparedShieldTx) AddToBatch(batch *priv.BatchVerifier) error {
	stx := p.tx.ShieldInner()
	return addPreparedShieldProofs(batch, stx, p.transcriptContext)
}

func (p *preparedShieldTx) VerifyProofs() error {
	stx := p.tx.ShieldInner()
	return verifyPreparedShieldProofs(stx, p.transcriptContext)
}

func (p *preparedShieldTx) ApplyState(statedb vm.StateDB) (*big.Int, error) {
	stx := p.tx.ShieldInner()
	if stx == nil {
		return common.Big0, errors.New("priv: message does not contain ShieldTx")
	}
	if statedb.GetBalance(p.from).Cmp(p.inputSenderBalance) != 0 {
		return common.Big0, errPreparedPrivacyStateMismatch
	}
	recipientAddr := stx.RecipientAddress()
	recipientState := priv.GetAccountState(statedb, recipientAddr)
	if !accountStateEqual(recipientState, p.inputRecipientState) {
		return common.Big0, errPreparedPrivacyStateMismatch
	}

	statedb.SubBalance(p.from, new(big.Int).Set(p.totalCostWei))
	depositCt := priv.Ciphertext{
		Commitment: stx.Commitment,
		Handle:     stx.Handle,
	}
	newCt, err := priv.AddCiphertexts(recipientState.Ciphertext, depositCt)
	if err != nil {
		return common.Big0, err
	}
	recipientState.Ciphertext = newCt
	recipientState.Version++
	priv.SetAccountState(statedb, recipientAddr, recipientState)
	if _, err := priv.IncrementPrivNonce(statedb, p.from); err != nil {
		return common.Big0, err
	}

	return priv.UnomiToTomiBig(stx.UnoFee), nil
}

type preparedUnshieldTx struct {
	tx                    *types.Transaction
	from                  common.Address
	inputAccountState     priv.AccountState
	inputRecipientBalance *big.Int
	zeroedCiphertext      priv.Ciphertext
	transcriptContext     []byte
	amountWei             *big.Int
	feeWei                *big.Int
}

func (p *preparedUnshieldTx) Transaction() *types.Transaction {
	return p.tx
}

func (p *preparedUnshieldTx) From() common.Address {
	return p.from
}

func (p *preparedUnshieldTx) AddToBatch(batch *priv.BatchVerifier) error {
	utx := p.tx.UnshieldInner()
	return addPreparedUnshieldProofs(batch, utx, p.zeroedCiphertext, p.transcriptContext)
}

func (p *preparedUnshieldTx) VerifyProofs() error {
	utx := p.tx.UnshieldInner()
	return verifyPreparedUnshieldProofs(utx, p.zeroedCiphertext, p.transcriptContext)
}

func (p *preparedUnshieldTx) ApplyState(statedb vm.StateDB) (*big.Int, error) {
	utx := p.tx.UnshieldInner()
	if utx == nil {
		return common.Big0, errors.New("priv: message does not contain UnshieldTx")
	}
	accountState := priv.GetAccountState(statedb, p.from)
	if !accountStateEqual(accountState, p.inputAccountState) {
		return common.Big0, errPreparedPrivacyStateMismatch
	}
	if statedb.GetBalance(utx.Recipient).Cmp(p.inputRecipientBalance) != 0 {
		return common.Big0, errPreparedPrivacyStateMismatch
	}

	accountState.Ciphertext = priv.Ciphertext{
		Commitment: utx.SourceCommitment,
		Handle:     p.zeroedCiphertext.Handle,
	}
	accountState.Version++
	priv.SetAccountState(statedb, p.from, accountState)
	if _, err := priv.IncrementPrivNonce(statedb, p.from); err != nil {
		return common.Big0, err
	}

	net := new(big.Int).Sub(p.amountWei, p.feeWei)
	if net.Sign() >= 0 {
		statedb.AddBalance(utx.Recipient, net)
	} else {
		statedb.SubBalance(utx.Recipient, new(big.Int).Neg(net))
	}

	return new(big.Int).Set(p.feeWei), nil
}

func verifyPreparedPrivacyBatch(prepared []preparedPrivacyTx) error {
	batch := priv.NewBatchVerifier()
	for _, item := range prepared {
		if err := item.AddToBatch(batch); err != nil {
			return err
		}
	}
	return batch.Verify()
}

func addPreparedPrivTransferProofs(batch *priv.BatchVerifier, ptx *types.PrivTransferTx, newSenderBalanceCt priv.Ciphertext, transcriptCtx []byte) error {
	if err := batch.AddCiphertextValidityProofWithContext(
		ptx.Commitment, ptx.SenderHandle, ptx.ReceiverHandle,
		ptx.From, ptx.To, ptx.CtValidityProof,
		transcriptCtx,
	); err != nil {
		return err
	}
	if err := batch.AddCommitmentEqProofWithContext(
		ptx.From, newSenderBalanceCt, ptx.SourceCommitment,
		ptx.CommitmentEqProof,
		transcriptCtx,
	); err != nil {
		return err
	}
	return batch.AddRangeProof(ptx.SourceCommitment, ptx.Commitment, ptx.RangeProof)
}

func verifyPreparedPrivTransferProofs(ptx *types.PrivTransferTx, newSenderBalanceCt priv.Ciphertext, transcriptCtx []byte) error {
	if err := priv.VerifyCiphertextValidityProofWithContext(
		ptx.Commitment, ptx.SenderHandle, ptx.ReceiverHandle,
		ptx.From, ptx.To, ptx.CtValidityProof,
		transcriptCtx,
	); err != nil {
		return err
	}
	if err := priv.VerifyCommitmentEqProofWithContext(
		ptx.From, newSenderBalanceCt, ptx.SourceCommitment,
		ptx.CommitmentEqProof,
		transcriptCtx,
	); err != nil {
		return err
	}
	return priv.VerifyRangeProof(ptx.SourceCommitment, ptx.Commitment, ptx.RangeProof)
}

func addPreparedShieldProofs(batch *priv.BatchVerifier, stx *types.ShieldTx, transcriptCtx []byte) error {
	if err := batch.AddShieldProofWithContext(
		stx.Commitment, stx.Handle, stx.Recipient,
		stx.UnoAmount, stx.ShieldProof[:], transcriptCtx,
	); err != nil {
		return err
	}
	return batch.AddSingleRangeProof(stx.Commitment, stx.RangeProof[:])
}

func verifyPreparedShieldProofs(stx *types.ShieldTx, transcriptCtx []byte) error {
	if err := priv.VerifyShieldProofWithContext(
		stx.Commitment, stx.Handle, stx.Recipient,
		stx.UnoAmount, stx.ShieldProof[:], transcriptCtx,
	); err != nil {
		return err
	}
	return priv.VerifySingleRangeProof(stx.Commitment, stx.RangeProof[:])
}

func addPreparedUnshieldProofs(batch *priv.BatchVerifier, utx *types.UnshieldTx, zeroedCt priv.Ciphertext, transcriptCtx []byte) error {
	if err := batch.AddCommitmentEqProofWithContext(
		utx.Pubkey, zeroedCt, utx.SourceCommitment,
		utx.CommitmentEqProof[:],
		transcriptCtx,
	); err != nil {
		return err
	}
	return batch.AddSingleRangeProof(utx.SourceCommitment, utx.RangeProof[:])
}

func verifyPreparedUnshieldProofs(utx *types.UnshieldTx, zeroedCt priv.Ciphertext, transcriptCtx []byte) error {
	if err := priv.VerifyCommitmentEqProofWithContext(
		utx.Pubkey, zeroedCt, utx.SourceCommitment,
		utx.CommitmentEqProof[:],
		transcriptCtx,
	); err != nil {
		return err
	}
	return priv.VerifySingleRangeProof(utx.SourceCommitment, utx.RangeProof[:])
}

func preparePrivacyTxState(chainID *big.Int, statedb vm.StateDB, tx *types.Transaction) (preparedPrivacyTx, error) {
	// Privacy terminal access validation: if the sender has privacy terminal
	// policies configured (policy wallet owner is set), enforce terminal rules.
	// Accounts without a policy wallet are unaffected (backward-compatible).
	if err := validatePrivacyTerminalIfConfigured(statedb, tx); err != nil {
		return nil, err
	}

	switch tx.Type() {
	case types.PrivTransferTxType:
		ptx := tx.PrivTransferInner()
		if ptx == nil {
			return nil, errors.New("priv: message does not contain PrivTransferTx")
		}
		return preparePrivTransferState(chainID, statedb, tx, ptx)
	case types.ShieldTxType:
		stx := tx.ShieldInner()
		if stx == nil {
			return nil, errors.New("priv: message does not contain ShieldTx")
		}
		return prepareShieldState(chainID, statedb, tx, stx)
	case types.UnshieldTxType:
		utx := tx.UnshieldInner()
		if utx == nil {
			return nil, errors.New("priv: message does not contain UnshieldTx")
		}
		return prepareUnshieldState(chainID, statedb, tx, utx)
	default:
		return nil, ErrTxTypeNotSupported
	}
}

// validatePrivacyTerminalIfConfigured checks privacy terminal access rules
// when the sender has a policy wallet configured. Returns nil if the sender
// has no policy wallet (owner == zero address), preserving backward compatibility.
func validatePrivacyTerminalIfConfigured(statedb vm.StateDB, tx *types.Transaction) error {
	var senderAddr common.Address
	var actionType string
	var value *big.Int

	switch tx.Type() {
	case types.PrivTransferTxType:
		ptx := tx.PrivTransferInner()
		if ptx == nil {
			return nil // let the caller handle the nil-inner error
		}
		senderAddr = ptx.FromAddress()
		actionType = policywallet.PrivacyActionPrivTransfer
		value = priv.UnomiToTomiBig(ptx.UnoFeeLimit)
	case types.ShieldTxType:
		stx := tx.ShieldInner()
		if stx == nil {
			return nil
		}
		senderAddr = stx.DerivedAddress()
		actionType = policywallet.PrivacyActionShield
		value = priv.UnomiToTomiBig(stx.UnoAmount)
	case types.UnshieldTxType:
		utx := tx.UnshieldInner()
		if utx == nil {
			return nil
		}
		senderAddr = utx.DerivedAddress()
		actionType = policywallet.PrivacyActionUnshield
		value = priv.UnomiToTomiBig(utx.UnoAmount)
	default:
		return nil
	}

	// Only enforce if the account has a policy wallet (owner is set).
	owner := policywallet.ReadOwner(statedb, senderAddr)
	if owner == (common.Address{}) {
		return nil
	}

	terminalClass := uint8(0)
	trustTier := uint8(0)
	if tc, ok := tx.TerminalClass(); ok {
		terminalClass = tc
	}
	if tt, ok := tx.TrustTier(); ok {
		trustTier = tt
	}
	// If both are zero (unset), fall back to permissive defaults
	// for backward compatibility: TerminalApp + TrustFull means
	// "no terminal restriction".
	if terminalClass == 0 && trustTier == 0 {
		terminalClass = policywallet.TerminalApp
		trustTier = policywallet.TrustFull
	}
	return policywallet.ValidatePrivacyTerminalAccess(statedb, senderAddr, terminalClass, trustTier, actionType, value)
}

func preparePrivTransferState(chainID *big.Int, statedb vm.StateDB, tx *types.Transaction, ptx *types.PrivTransferTx) (*preparedPrivTransferTx, error) {
	fromAddr := ptx.FromAddress()
	toAddr := ptx.ToAddress()

	if err := priv.ValidateEncryptedMemoSize(ptx.EncryptedMemo); err != nil {
		return nil, fmt.Errorf("priv: encrypted memo too large: %w", err)
	}
	if ptx.UnoFee > ptx.UnoFeeLimit {
		return nil, priv.ErrFeeLimitExceeded
	}
	requiredFee := priv.EstimateRequiredFee(0)
	if requiredFee > ptx.UnoFeeLimit {
		return nil, priv.ErrInsufficientFee
	}
	feePaidGas := ptx.UnoFee
	if requiredFee > feePaidGas {
		feePaidGas = requiredFee
	}
	feeRefundGas := ptx.UnoFeeLimit - feePaidGas

	expectedNonce := priv.GetPrivNonce(statedb, fromAddr)
	if ptx.PrivNonce != expectedNonce {
		return nil, priv.ErrNonceMismatch
	}

	sigHash := ptx.SigningHash()
	if !priv.VerifySchnorrSignature(ptx.From, sigHash[:], ptx.S, ptx.E) {
		return nil, errInvalidPrivSchnorrSignature
	}

	// Validate auditor handle if auditor key is configured.
	auditorKey := policywallet.ReadAuditorKey(statedb, fromAddr)
	var zeroKey [32]byte
	if auditorKey != zeroKey {
		if ptx.AuditorHandle == zeroKey {
			return nil, fmt.Errorf("priv: auditor key configured but AuditorHandle is zero")
		}
		if len(ptx.AuditorDLEQProof) != 96 {
			return nil, fmt.Errorf("priv: auditor DLEQ proof must be 96 bytes")
		}
	} else {
		// No auditor key: auditor fields must be empty
		if ptx.AuditorHandle != zeroKey {
			return nil, fmt.Errorf("priv: AuditorHandle set but no auditor key configured")
		}
		if len(ptx.AuditorDLEQProof) > 0 {
			return nil, fmt.Errorf("priv: AuditorDLEQProof set but no auditor key configured")
		}
	}

	senderState := priv.GetAccountState(statedb, fromAddr)
	receiverState := priv.GetAccountState(statedb, toAddr)
	if senderState.Version == math.MaxUint64 || receiverState.Version == math.MaxUint64 {
		return nil, priv.ErrVersionOverflow
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
		ptx.AuditorHandle,
	)
	// Verify auditor handle DLEQ if present.
	if auditorKey != zeroKey {
		if err := priv.VerifyAuditorHandleDLEQ(
			ptx.AuditorHandle, ptx.ReceiverHandle,
			auditorKey, ptx.To,
			ptx.AuditorDLEQProof, transcriptCtx,
		); err != nil {
			return nil, fmt.Errorf("priv: auditor handle DLEQ verification failed: %w", err)
		}
	}

	outputCt, err := priv.AddScalarToCiphertext(senderCt, ptx.UnoFeeLimit)
	if err != nil {
		return nil, err
	}
	newSenderBalanceCt, err := priv.SubCiphertexts(senderState.Ciphertext, outputCt)
	if err != nil {
		return nil, err
	}
	return &preparedPrivTransferTx{
		tx:                 tx,
		from:               fromAddr,
		to:                 toAddr,
		inputSenderState:   senderState,
		inputReceiverState: receiverState,
		newSenderBalance:   newSenderBalanceCt,
		feePaidGas:         feePaidGas,
		feeRefundGas:       feeRefundGas,
		transcriptContext:  transcriptCtx,
	}, nil
}

func prepareShieldState(chainID *big.Int, statedb vm.StateDB, tx *types.Transaction, stx *types.ShieldTx) (*preparedShieldTx, error) {
	senderAddr := stx.DerivedAddress()
	recipientAddr := stx.RecipientAddress()

	requiredFee := priv.EstimateShieldFee()
	if stx.UnoFee < requiredFee {
		return nil, priv.ErrInsufficientFee
	}

	totalCostWei := new(big.Int).Add(priv.UnomiToTomiBig(stx.UnoAmount), priv.UnomiToTomiBig(stx.UnoFee))
	senderBalance := new(big.Int).Set(statedb.GetBalance(senderAddr))
	if senderBalance.Cmp(totalCostWei) < 0 {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, senderAddr.Hex())
	}

	expectedNonce := priv.GetPrivNonce(statedb, senderAddr)
	if stx.PrivNonce != expectedNonce {
		return nil, priv.ErrNonceMismatch
	}

	sigHash := stx.SigningHash()
	if !priv.VerifySchnorrSignature(stx.Pubkey, sigHash[:], stx.S, stx.E) {
		return nil, errInvalidPrivSchnorrSignature
	}

	// Validate auditor handle if auditor key is configured.
	shieldAuditorKey := policywallet.ReadAuditorKey(statedb, senderAddr)
	var shieldZeroKey [32]byte
	if shieldAuditorKey != shieldZeroKey {
		if stx.AuditorHandle == shieldZeroKey {
			return nil, fmt.Errorf("priv: auditor key configured but AuditorHandle is zero")
		}
		if len(stx.AuditorDLEQProof) != 96 {
			return nil, fmt.Errorf("priv: auditor DLEQ proof must be 96 bytes")
		}
	} else {
		if stx.AuditorHandle != shieldZeroKey {
			return nil, fmt.Errorf("priv: AuditorHandle set but no auditor key configured")
		}
		if len(stx.AuditorDLEQProof) > 0 {
			return nil, fmt.Errorf("priv: AuditorDLEQProof set but no auditor key configured")
		}
	}

	recipientState := priv.GetAccountState(statedb, recipientAddr)
	if recipientState.Version == math.MaxUint64 {
		return nil, priv.ErrVersionOverflow
	}

	shieldTranscriptCtx := priv.BuildShieldTranscriptContext(
		chainID,
		stx.PrivNonce,
		stx.UnoFee,
		stx.UnoAmount,
		senderAddr,
		stx.Commitment,
		stx.Handle,
		stx.AuditorHandle,
	)

	// Verify auditor handle DLEQ if present.
	if shieldAuditorKey != shieldZeroKey {
		if err := priv.VerifyAuditorHandleDLEQ(
			stx.AuditorHandle, stx.Handle,
			shieldAuditorKey, stx.Recipient,
			stx.AuditorDLEQProof, shieldTranscriptCtx,
		); err != nil {
			return nil, fmt.Errorf("priv: auditor handle DLEQ verification failed: %w", err)
		}
	}

	return &preparedShieldTx{
		tx:                  tx,
		from:                senderAddr,
		inputSenderBalance:  senderBalance,
		inputRecipientState: recipientState,
		transcriptContext:   shieldTranscriptCtx,
		totalCostWei:        totalCostWei,
	}, nil
}

func prepareUnshieldState(chainID *big.Int, statedb vm.StateDB, tx *types.Transaction, utx *types.UnshieldTx) (*preparedUnshieldTx, error) {
	senderAddr := utx.DerivedAddress()
	recipientAddr := utx.Recipient

	requiredFee := priv.EstimateUnshieldFee()
	if utx.UnoFee < requiredFee {
		return nil, priv.ErrInsufficientFee
	}

	expectedNonce := priv.GetPrivNonce(statedb, senderAddr)
	if utx.PrivNonce != expectedNonce {
		return nil, priv.ErrNonceMismatch
	}

	amountWei := priv.UnomiToTomiBig(utx.UnoAmount)
	feeWei := priv.UnomiToTomiBig(utx.UnoFee)
	recipientBalance := new(big.Int).Set(statedb.GetBalance(recipientAddr))
	availablePublic := new(big.Int).Add(new(big.Int).Set(recipientBalance), amountWei)
	if availablePublic.Cmp(feeWei) < 0 {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, recipientAddr.Hex())
	}

	sigHash := utx.SigningHash()
	if !priv.VerifySchnorrSignature(utx.Pubkey, sigHash[:], utx.S, utx.E) {
		return nil, errInvalidPrivSchnorrSignature
	}

	// Validate auditor handle if auditor key is configured.
	unshieldAuditorKey := policywallet.ReadAuditorKey(statedb, senderAddr)
	var unshieldZeroKey [32]byte
	if unshieldAuditorKey != unshieldZeroKey {
		if utx.AuditorHandle == unshieldZeroKey {
			return nil, fmt.Errorf("priv: auditor key configured but AuditorHandle is zero")
		}
		if len(utx.AuditorDLEQProof) != 96 {
			return nil, fmt.Errorf("priv: auditor DLEQ proof must be 96 bytes")
		}
	} else {
		if utx.AuditorHandle != unshieldZeroKey {
			return nil, fmt.Errorf("priv: AuditorHandle set but no auditor key configured")
		}
		if len(utx.AuditorDLEQProof) > 0 {
			return nil, fmt.Errorf("priv: AuditorDLEQProof set but no auditor key configured")
		}
	}

	accountState := priv.GetAccountState(statedb, senderAddr)
	if accountState.Version == math.MaxUint64 {
		return nil, priv.ErrVersionOverflow
	}

	amountCt, err := priv.AddScalarToCiphertext(priv.ZeroCiphertext(), utx.UnoAmount)
	if err != nil {
		return nil, err
	}
	zeroedCt, err := priv.SubCiphertexts(accountState.Ciphertext, amountCt)
	if err != nil {
		return nil, err
	}

	unshieldTranscriptCtx := priv.BuildUnshieldTranscriptContext(
		chainID,
		utx.PrivNonce,
		utx.UnoFee,
		utx.UnoAmount,
		senderAddr,
		zeroedCt,
		utx.SourceCommitment,
		utx.AuditorHandle,
	)

	// Verify auditor handle DLEQ if present.
	if unshieldAuditorKey != unshieldZeroKey {
		if err := priv.VerifyAuditorHandleDLEQ(
			utx.AuditorHandle, accountState.Ciphertext.Handle,
			unshieldAuditorKey, utx.Pubkey,
			utx.AuditorDLEQProof, unshieldTranscriptCtx,
		); err != nil {
			return nil, fmt.Errorf("priv: auditor handle DLEQ verification failed: %w", err)
		}
	}

	return &preparedUnshieldTx{
		tx:                    tx,
		from:                  senderAddr,
		inputAccountState:     accountState,
		inputRecipientBalance: recipientBalance,
		zeroedCiphertext:      zeroedCt,
		transcriptContext:     unshieldTranscriptCtx,
		amountWei:             amountWei,
		feeWei:                feeWei,
	}, nil
}

func accountStateEqual(a, b priv.AccountState) bool {
	return a.Ciphertext == b.Ciphertext && a.Version == b.Version && a.Nonce == b.Nonce
}
