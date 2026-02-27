package uno

import (
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
)

// RequireElgamalSigner validates that account has configured canonical elgamal signer.
// It returns canonical signer pubkey bytes.
func RequireElgamalSigner(db vm.StateDB, account common.Address) ([]byte, error) {
	signerType, signerValue, ok := accountsigner.Get(db, account)
	if !ok {
		return nil, ErrSignerNotConfigured
	}
	canonicalType, pub, _, err := accountsigner.NormalizeSigner(signerType, signerValue)
	if err != nil {
		return nil, err
	}
	if canonicalType != accountsigner.SignerTypeElgamal {
		return nil, ErrSignerTypeMismatch
	}
	return pub, nil
}
