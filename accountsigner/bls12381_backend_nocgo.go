//go:build !cgo

package accountsigner

import (
	"io"

	"github.com/tos-network/gtos/common"
)

func supportsBLS12381Backend() bool {
	return pureBLS12381SupportsBackend()
}

func normalizeBLS12381Pubkey(raw []byte) ([]byte, error) {
	return pureBLS12381NormalizePubkey(raw)
}

func verifyBLS12381Signature(pub []byte, sig []byte, txHash common.Hash) bool {
	return pureVerifyBLS12381Signature(pub, sig, txHash)
}

func GenerateBLS12381PrivateKey(r io.Reader) ([]byte, error) {
	return pureGenerateBLS12381PrivateKey(r)
}

func PublicKeyFromBLS12381Private(priv []byte) ([]byte, error) {
	return purePublicKeyFromBLS12381Private(priv)
}

func SignBLS12381Hash(priv []byte, txHash common.Hash) ([]byte, error) {
	return pureSignBLS12381Hash(priv, txHash)
}

func AggregateBLS12381PublicKeys(pubkeys [][]byte) ([]byte, error) {
	return pureAggregateBLS12381PublicKeys(pubkeys)
}

func AggregateBLS12381Signatures(signatures [][]byte) ([]byte, error) {
	return pureAggregateBLS12381Signatures(signatures)
}

func VerifyBLS12381FastAggregate(pubkeys [][]byte, signature []byte, txHash common.Hash) bool {
	return pureVerifyBLS12381FastAggregate(pubkeys, signature, txHash)
}
