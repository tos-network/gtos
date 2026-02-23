package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
)

var (
	ErrInvalidAccountSignerSignature = errors.New("invalid account signer signature")
	ErrAccountSignerMismatch         = errors.New("account signer metadata mismatch")
	ErrUnsupportedAccountSignerType  = errors.New("account signer type is not supported by current tx signature format")
)

func txRawSig(tx *types.Transaction) (*big.Int, *big.Int, *big.Int) {
	v, r, s := tx.RawSignatureValues()
	return v, r, s
}

// ResolveSender derives tx sender with accountsigner metadata enforcement.
func ResolveSender(tx *types.Transaction, chainSigner types.Signer, statedb vm.StateDB) (common.Address, error) {
	if tx == nil {
		return common.Address{}, errors.New("nil tx")
	}
	if tx.Type() != types.SignerTxType {
		return common.Address{}, types.ErrTxTypeNotSupported
	}
	from, ok := tx.SignerFrom()
	if !ok {
		return common.Address{}, ErrUnsupportedAccountSignerType
	}
	signerType, ok := tx.SignerType()
	if !ok {
		return common.Address{}, ErrUnsupportedAccountSignerType
	}
	normalizedSignerType, err := accountsigner.CanonicalSignerType(signerType)
	if err != nil {
		return common.Address{}, err
	}
	if !accountsigner.SupportsCurrentTxSignatureType(normalizedSignerType) {
		return common.Address{}, ErrUnsupportedAccountSignerType
	}
	hash := chainSigner.Hash(tx)
	_, r, s := txRawSig(tx)

	switch normalizedSignerType {
	case accountsigner.SignerTypeSecp256k1:
		recovered, err := types.Sender(chainSigner, tx)
		if err != nil {
			return common.Address{}, err
		}
		if recovered != from {
			return common.Address{}, fmt.Errorf("%w: expected %s got %s", ErrAccountSignerMismatch, from.Hex(), recovered.Hex())
		}
		cfgType, cfgValue, configured := accountsigner.Get(statedb, from)
		if !configured {
			return from, nil
		}
		normType, normPub, _, err := accountsigner.NormalizeSigner(cfgType, cfgValue)
		if err != nil {
			return common.Address{}, err
		}
		if normType != accountsigner.SignerTypeSecp256k1 {
			return common.Address{}, ErrAccountSignerMismatch
		}
		if !accountsigner.VerifyRawSignature(normType, normPub, hash, r, s) {
			return common.Address{}, ErrInvalidAccountSignerSignature
		}
		addrFromSigner, err := accountsigner.AddressFromSigner(normType, normPub)
		if err != nil {
			return common.Address{}, err
		}
		if addrFromSigner != from {
			return common.Address{}, fmt.Errorf("%w: expected %s got %s", ErrAccountSignerMismatch, addrFromSigner.Hex(), from.Hex())
		}
		return from, nil
	default:
		cfgType, cfgValue, configured := accountsigner.Get(statedb, from)
		if !configured {
			return common.Address{}, ErrAccountSignerMismatch
		}
		normType, normPub, _, err := accountsigner.NormalizeSigner(cfgType, cfgValue)
		if err != nil {
			return common.Address{}, err
		}
		if normType != normalizedSignerType {
			return common.Address{}, ErrAccountSignerMismatch
		}
		if !accountsigner.VerifyRawSignature(normType, normPub, hash, r, s) {
			return common.Address{}, ErrInvalidAccountSignerSignature
		}
		return from, nil
	}
}
