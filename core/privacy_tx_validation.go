package core

import (
	"errors"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
)

var errInvalidPrivSchnorrSignature = errors.New("priv: invalid Schnorr signature")

func applyPrivacyTxState(chainID *big.Int, statedb vm.StateDB, tx *types.Transaction) (*big.Int, error) {
	switch tx.Type() {
	case types.PrivTransferTxType:
		ptx := tx.PrivTransferInner()
		if ptx == nil {
			return common.Big0, errors.New("priv: message does not contain PrivTransferTx")
		}
		return applyPrivTransferState(chainID, statedb, ptx)
	case types.ShieldTxType:
		stx := tx.ShieldInner()
		if stx == nil {
			return common.Big0, errors.New("priv: message does not contain ShieldTx")
		}
		return applyShieldState(chainID, statedb, stx)
	case types.UnshieldTxType:
		utx := tx.UnshieldInner()
		if utx == nil {
			return common.Big0, errors.New("priv: message does not contain UnshieldTx")
		}
		return applyUnshieldState(chainID, statedb, utx)
	default:
		return common.Big0, ErrTxTypeNotSupported
	}
}

func applyPrivTransferState(chainID *big.Int, statedb vm.StateDB, ptx *types.PrivTransferTx) (*big.Int, error) {
	prepared, err := preparePrivTransferState(chainID, statedb, types.NewTx(ptx), ptx)
	if err != nil {
		return common.Big0, err
	}
	if err := prepared.VerifyProofs(); err != nil {
		return common.Big0, err
	}
	return prepared.ApplyState(statedb)
}

func applyShieldState(chainID *big.Int, statedb vm.StateDB, stx *types.ShieldTx) (*big.Int, error) {
	prepared, err := prepareShieldState(chainID, statedb, types.NewTx(stx), stx)
	if err != nil {
		return common.Big0, err
	}
	if err := prepared.VerifyProofs(); err != nil {
		return common.Big0, err
	}
	return prepared.ApplyState(statedb)
}

func applyUnshieldState(chainID *big.Int, statedb vm.StateDB, utx *types.UnshieldTx) (*big.Int, error) {
	prepared, err := prepareUnshieldState(chainID, statedb, types.NewTx(utx), utx)
	if err != nil {
		return common.Big0, err
	}
	if err := prepared.VerifyProofs(); err != nil {
		return common.Big0, err
	}
	return prepared.ApplyState(statedb)
}
