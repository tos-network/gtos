//go:build !cgo

package accountsigner

import (
	"io"

	"github.com/tos-network/gtos/common"
)

func supportsBLS12381Backend() bool {
	return false
}

func normalizeBLS12381Pubkey(_ []byte) ([]byte, error) {
	return nil, ErrSignerBackendUnavailable
}

func verifyBLS12381Signature(_ []byte, _ []byte, _ common.Hash) bool {
	return false
}

func GenerateBLS12381PrivateKey(_ io.Reader) ([]byte, error) {
	return nil, ErrSignerBackendUnavailable
}

func PublicKeyFromBLS12381Private(_ []byte) ([]byte, error) {
	return nil, ErrSignerBackendUnavailable
}

func SignBLS12381Hash(_ []byte, _ common.Hash) ([]byte, error) {
	return nil, ErrSignerBackendUnavailable
}

func AggregateBLS12381PublicKeys(_ [][]byte) ([]byte, error) {
	return nil, ErrSignerBackendUnavailable
}

func AggregateBLS12381Signatures(_ [][]byte) ([]byte, error) {
	return nil, ErrSignerBackendUnavailable
}

func VerifyBLS12381FastAggregate(_ [][]byte, _ []byte, _ common.Hash) bool {
	return false
}
