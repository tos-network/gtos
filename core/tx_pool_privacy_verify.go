package core

import (
	"errors"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/priv"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
)

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
	if err := priv.ValidateEncryptedMemoSize(ptx.EncryptedMemo); err != nil {
		return nil, err
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
	if len(ptx.AuditorDLEQProof) > 0 && len(ptx.AuditorDLEQProof) != 96 {
		return nil, priv.ErrInvalidPayload
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
	prepared, err := preparePrivacyTxState(pool.chainconfig.ChainID, statedb, tx)
	if err != nil {
		return nil, mapPreparedPrivacyError(err)
	}
	pp, ok := prepared.(*preparedPrivTransferTx)
	if !ok {
		return nil, ErrTxTypeNotSupported
	}
	return pp, nil
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
	if len(stx.AuditorDLEQProof) > 0 && len(stx.AuditorDLEQProof) != 96 {
		return nil, priv.ErrInvalidPayload
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
	prepared, err := preparePrivacyTxState(pool.chainconfig.ChainID, statedb, tx)
	if err != nil {
		return nil, mapPreparedPrivacyError(err)
	}
	pp, ok := prepared.(*preparedShieldTx)
	if !ok {
		return nil, ErrTxTypeNotSupported
	}
	return pp, nil
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
	if len(utx.AuditorDLEQProof) > 0 && len(utx.AuditorDLEQProof) != 96 {
		return nil, priv.ErrInvalidPayload
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
	prepared, err := preparePrivacyTxState(pool.chainconfig.ChainID, statedb, tx)
	if err != nil {
		return nil, mapPreparedPrivacyError(err)
	}
	pp, ok := prepared.(*preparedUnshieldTx)
	if !ok {
		return nil, ErrTxTypeNotSupported
	}
	return pp, nil
}

func mapPreparedPrivacyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errInvalidPrivSchnorrSignature) {
		return ErrInvalidSender
	}
	return err
}
