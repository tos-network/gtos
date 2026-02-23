package core

import (
	"bytes"
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
	ErrAccountSignerRequiredMeta     = errors.New("account signer metadata in tx signature is required")
	ErrUnsupportedAccountSignerType  = errors.New("account signer type is not supported by current tx signature format")
)

func txRawSig(tx *types.Transaction) (*big.Int, *big.Int, *big.Int) {
	v, r, s := tx.RawSignatureValues()
	return v, r, s
}

func resolveSenderWithMeta(tx *types.Transaction, chainSigner types.Signer, statedb vm.StateDB, signerType string, signerPub []byte) (common.Address, error) {
	if !accountsigner.SupportsCurrentTxSignatureType(signerType) {
		return common.Address{}, ErrUnsupportedAccountSignerType
	}
	hash := chainSigner.Hash(tx)
	_, r, s := txRawSig(tx)
	if !accountsigner.VerifyRawSignature(signerType, signerPub, hash, r, s) {
		return common.Address{}, ErrInvalidAccountSignerSignature
	}
	from, err := accountsigner.AddressFromSigner(signerType, signerPub)
	if err != nil {
		return common.Address{}, err
	}
	cfgType, cfgValue, ok := accountsigner.Get(statedb, from)
	if !ok {
		return common.Address{}, ErrAccountSignerMismatch
	}
	normType, normPub, _, err := accountsigner.NormalizeSigner(cfgType, cfgValue)
	if err != nil {
		return common.Address{}, err
	}
	if normType != signerType || !bytes.Equal(normPub, signerPub) {
		return common.Address{}, ErrAccountSignerMismatch
	}
	return from, nil
}

// ResolveSender derives tx sender with accountsigner metadata enforcement.
func ResolveSender(tx *types.Transaction, chainSigner types.Signer, statedb vm.StateDB) (common.Address, error) {
	if tx == nil {
		return common.Address{}, errors.New("nil tx")
	}
	v, _, _ := txRawSig(tx)
	if signerType, signerPub, ok, err := accountsigner.DecodeSignatureMeta(v); err != nil {
		return common.Address{}, err
	} else if ok {
		return resolveSenderWithMeta(tx, chainSigner, statedb, signerType, signerPub)
	}

	// Legacy sender derivation path (secp256k1 VRS).
	from, err := types.Sender(chainSigner, tx)
	if err != nil {
		return common.Address{}, err
	}
	cfgType, cfgValue, ok := accountsigner.Get(statedb, from)
	if !ok {
		return from, nil
	}
	normType, normPub, _, err := accountsigner.NormalizeSigner(cfgType, cfgValue)
	if err != nil {
		return common.Address{}, err
	}
	switch normType {
	case accountsigner.SignerTypeSecp256k1:
		hash := chainSigner.Hash(tx)
		_, r, s := txRawSig(tx)
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
	case accountsigner.SignerTypeSecp256r1, accountsigner.SignerTypeEd25519:
		return common.Address{}, ErrAccountSignerRequiredMeta
	default:
		return common.Address{}, ErrUnsupportedAccountSignerType
	}
}
