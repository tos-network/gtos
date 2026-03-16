package core

import (
	"fmt"
	"math"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/priv"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
)

type preparedPrivacyTx interface {
	Transaction() *types.Transaction
	From() common.Address
	AddToBatch(batch *priv.BatchVerifier) error
	VerifyProofs() error
}

type preparedPrivTransferTx struct {
	tx                *types.Transaction
	from              common.Address
	newSenderBalance  priv.Ciphertext
	transcriptContext []byte
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

type preparedShieldTx struct {
	tx                *types.Transaction
	from              common.Address
	transcriptContext []byte
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

type preparedUnshieldTx struct {
	tx                *types.Transaction
	from              common.Address
	zeroedCiphertext  priv.Ciphertext
	transcriptContext []byte
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

func verifyPreparedPrivacyBatch(prepared []preparedPrivacyTx) error {
	batch := priv.NewBatchVerifier()
	for _, item := range prepared {
		if err := item.AddToBatch(batch); err != nil {
			return err
		}
	}
	return batch.Verify()
}

func (pool *TxPool) addPreparedPrivacyTx(prepared preparedPrivacyTx, local bool) (bool, error) {
	from := prepared.From()
	isLocal := local || pool.locals.contains(from)
	return pool.addValidatedTx(prepared.Transaction(), prepared.Transaction().Hash(), from, local, isLocal)
}

func (pool *TxPool) addPrivacyTxSequential(tx *types.Transaction, from common.Address, local bool, statedb vm.StateDB) (bool, error) {
	isLocal := local || pool.locals.contains(from)
	prepared, err := pool.preparePrivacyTx(tx, from, isLocal, statedb)
	if err != nil {
		return false, err
	}
	if err := privacyValidationError(prepared.VerifyProofs()); err != nil {
		return false, err
	}
	return pool.addValidatedTx(tx, tx.Hash(), from, local, isLocal)
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

func (pool *TxPool) preparePrivacyTx(tx *types.Transaction, from common.Address, local bool, statedb vm.StateDB) (preparedPrivacyTx, error) {
	switch tx.Type() {
	case types.PrivTransferTxType:
		return pool.preparePrivTransferTx(tx, from, local, statedb)
	case types.ShieldTxType:
		return pool.prepareShieldTx(tx, from, local, statedb)
	case types.UnshieldTxType:
		return pool.prepareUnshieldTx(tx, from, local, statedb)
	default:
		return nil, ErrTxTypeNotSupported
	}
}

func (pool *TxPool) preparePrivTransferTx(tx *types.Transaction, from common.Address, local bool, statedb vm.StateDB) (*preparedPrivTransferTx, error) {
	if uint64(tx.Size()) > txMaxSize {
		return nil, ErrOversizedData
	}
	if tx.ChainId().Cmp(pool.signer.ChainID()) != 0 {
		return nil, types.ErrInvalidChainId
	}
	ptx := tx.PrivTransferInner()
	if ptx == nil {
		return nil, ErrTxTypeNotSupported
	}
	if err := priv.ValidateCTValidityProofShape(ptx.CtValidityProof); err != nil {
		return nil, err
	}
	if err := priv.ValidateCommitmentEqProofShape(ptx.CommitmentEqProof); err != nil {
		return nil, err
	}
	if err := priv.ValidateRangeProofShape(ptx.RangeProof); err != nil {
		return nil, err
	}
	if ptx.UnoFee > ptx.UnoFeeLimit {
		return nil, priv.ErrFeeLimitExceeded
	}
	if ptx.UnoFeeLimit < priv.EstimateRequiredFee(0) {
		return nil, priv.ErrInsufficientFee
	}
	stateNonce := priv.GetPrivNonce(pool.currentState, from)
	if tx.Nonce() < stateNonce {
		return nil, ErrNonceTooLow
	}
	if statedb == nil {
		statedb = pool.currentState
	}
	expectedNonce := priv.GetPrivNonce(statedb, from)
	if tx.Nonce() < expectedNonce {
		return nil, ErrNonceTooLow
	}
	if tx.Nonce() > expectedNonce {
		return nil, ErrNonceTooHigh
	}
	if !local && tx.TxPrice().Cmp(pool.txPrice) < 0 {
		return nil, ErrUnderpriced
	}
	sigHash := ptx.SigningHash()
	if !priv.VerifySchnorrSignature(ptx.From, sigHash[:], ptx.S, ptx.E) {
		return nil, ErrInvalidSender
	}

	senderState := priv.GetAccountState(statedb, from)
	receiverState := priv.GetAccountState(statedb, ptx.ToAddress())
	if senderState.Version == math.MaxUint64 || receiverState.Version == math.MaxUint64 {
		return nil, priv.ErrVersionOverflow
	}

	senderCt := priv.Ciphertext{Commitment: ptx.Commitment, Handle: ptx.SenderHandle}
	receiverCt := priv.Ciphertext{Commitment: ptx.Commitment, Handle: ptx.ReceiverHandle}
	transcriptCtx := priv.BuildPrivTransferTranscriptContext(
		pool.chainconfig.ChainID,
		ptx.PrivNonce,
		ptx.UnoFee,
		ptx.UnoFeeLimit,
		from,
		ptx.ToAddress(),
		senderCt,
		receiverCt,
		ptx.SourceCommitment,
	)
	outputCt, err := priv.AddScalarToCiphertext(senderCt, ptx.UnoFeeLimit)
	if err != nil {
		return nil, err
	}
	newSenderBalanceCt, err := priv.SubCiphertexts(senderState.Ciphertext, outputCt)
	if err != nil {
		return nil, err
	}
	return &preparedPrivTransferTx{
		tx:                tx,
		from:              from,
		newSenderBalance:  newSenderBalanceCt,
		transcriptContext: transcriptCtx,
	}, nil
}

func (pool *TxPool) prepareShieldTx(tx *types.Transaction, from common.Address, local bool, statedb vm.StateDB) (*preparedShieldTx, error) {
	if uint64(tx.Size()) > txMaxSize {
		return nil, ErrOversizedData
	}
	if tx.ChainId().Cmp(pool.signer.ChainID()) != 0 {
		return nil, types.ErrInvalidChainId
	}
	stx := tx.ShieldInner()
	if stx == nil {
		return nil, ErrTxTypeNotSupported
	}
	if err := priv.ValidateShieldProofShape(stx.ShieldProof[:]); err != nil {
		return nil, err
	}
	if err := priv.ValidateRangeProofShape(stx.RangeProof[:]); err != nil {
		return nil, err
	}
	if stx.UnoFee < priv.EstimateShieldFee() {
		return nil, priv.ErrInsufficientFee
	}
	stateNonce := priv.GetPrivNonce(pool.currentState, from)
	if tx.Nonce() < stateNonce {
		return nil, ErrNonceTooLow
	}
	if statedb == nil {
		statedb = pool.currentState
	}
	expectedNonce := priv.GetPrivNonce(statedb, from)
	if tx.Nonce() < expectedNonce {
		return nil, ErrNonceTooLow
	}
	if tx.Nonce() > expectedNonce {
		return nil, ErrNonceTooHigh
	}
	if !local && tx.TxPrice().Cmp(pool.txPrice) < 0 {
		return nil, ErrUnderpriced
	}
	totalCostWei := new(big.Int).SetUint64(priv.UNOFeeToWei(stx.UnoAmount + stx.UnoFee))
	if statedb.GetBalance(from).Cmp(totalCostWei) < 0 {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, from.Hex())
	}
	sigHash := stx.SigningHash()
	if !priv.VerifySchnorrSignature(stx.Pubkey, sigHash[:], stx.S, stx.E) {
		return nil, ErrInvalidSender
	}
	recipientState := priv.GetAccountState(statedb, stx.RecipientAddress())
	if recipientState.Version == math.MaxUint64 {
		return nil, priv.ErrVersionOverflow
	}
	return &preparedShieldTx{
		tx:   tx,
		from: from,
		transcriptContext: priv.BuildShieldTranscriptContext(
			pool.chainconfig.ChainID,
			stx.PrivNonce,
			stx.UnoFee,
			stx.UnoAmount,
			from,
			stx.Commitment,
			stx.Handle,
		),
	}, nil
}

func (pool *TxPool) prepareUnshieldTx(tx *types.Transaction, from common.Address, local bool, statedb vm.StateDB) (*preparedUnshieldTx, error) {
	if uint64(tx.Size()) > txMaxSize {
		return nil, ErrOversizedData
	}
	if tx.ChainId().Cmp(pool.signer.ChainID()) != 0 {
		return nil, types.ErrInvalidChainId
	}
	utx := tx.UnshieldInner()
	if utx == nil {
		return nil, ErrTxTypeNotSupported
	}
	if err := priv.ValidateCommitmentEqProofShape(utx.CommitmentEqProof[:]); err != nil {
		return nil, err
	}
	if err := priv.ValidateRangeProofShape(utx.RangeProof[:]); err != nil {
		return nil, err
	}
	if utx.UnoFee < priv.EstimateUnshieldFee() {
		return nil, priv.ErrInsufficientFee
	}
	stateNonce := priv.GetPrivNonce(pool.currentState, from)
	if tx.Nonce() < stateNonce {
		return nil, ErrNonceTooLow
	}
	if statedb == nil {
		statedb = pool.currentState
	}
	expectedNonce := priv.GetPrivNonce(statedb, from)
	if tx.Nonce() < expectedNonce {
		return nil, ErrNonceTooLow
	}
	if tx.Nonce() > expectedNonce {
		return nil, ErrNonceTooHigh
	}
	if !local && tx.TxPrice().Cmp(pool.txPrice) < 0 {
		return nil, ErrUnderpriced
	}
	amountWei := new(big.Int).SetUint64(priv.UNOFeeToWei(utx.UnoAmount))
	feeWei := priv.UNOFeeToWei(utx.UnoFee)
	availablePublic := new(big.Int).Add(new(big.Int).Set(statedb.GetBalance(utx.Recipient)), amountWei)
	if availablePublic.Cmp(new(big.Int).SetUint64(feeWei)) < 0 {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, utx.Recipient.Hex())
	}
	sigHash := utx.SigningHash()
	if !priv.VerifySchnorrSignature(utx.Pubkey, sigHash[:], utx.S, utx.E) {
		return nil, ErrInvalidSender
	}
	accountState := priv.GetAccountState(statedb, from)
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
	return &preparedUnshieldTx{
		tx:               tx,
		from:             from,
		zeroedCiphertext: zeroedCt,
		transcriptContext: priv.BuildUnshieldTranscriptContext(
			pool.chainconfig.ChainID,
			utx.PrivNonce,
			utx.UnoFee,
			utx.UnoAmount,
			from,
			zeroedCt,
			utx.SourceCommitment,
		),
	}, nil
}
