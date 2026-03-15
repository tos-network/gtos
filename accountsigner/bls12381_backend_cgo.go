//go:build cgo

package accountsigner

import (
	"io"

	blst "github.com/supranational/blst/bindings/go"
	"github.com/tos-network/gtos/common"
)

func supportsBLS12381Backend() bool {
	return true
}

func normalizeBLS12381Pubkey(raw []byte) ([]byte, error) {
	if len(raw) != bls12381PubkeyLen {
		return nil, ErrInvalidSignerValue
	}
	pk := new(blst.P1Affine).Uncompress(raw)
	if pk == nil || !pk.KeyValidate() {
		return nil, ErrInvalidSignerValue
	}
	return pk.Compress(), nil
}

func bls12381SecretKeyFromBytes(priv []byte) (*blst.SecretKey, error) {
	if len(priv) != bls12381PrivateKeyLen {
		return nil, ErrInvalidSignerKey
	}
	sk := new(blst.SecretKey).Deserialize(priv)
	if sk == nil || !sk.Valid() {
		return nil, ErrInvalidSignerKey
	}
	return sk, nil
}

func verifyBLS12381Signature(pub, sig []byte, txHash common.Hash) bool {
	if len(pub) != bls12381PubkeyLen || len(sig) != bls12381SignatureLen {
		return false
	}
	var dummy blst.P2Affine
	return dummy.VerifyCompressed(sig, true, pub, true, txHash[:], bls12381SignDst)
}

// GenerateBLS12381PrivateKey creates a new BLS12-381 secret key compatible with blst.
func GenerateBLS12381PrivateKey(r io.Reader) ([]byte, error) {
	ikm := make([]byte, bls12381PrivateKeyLen)
	if _, err := io.ReadFull(r, ikm); err != nil {
		return nil, err
	}
	sk := blst.KeyGen(ikm)
	if sk == nil {
		return nil, ErrInvalidSignerKey
	}
	out := append([]byte(nil), sk.Serialize()...)
	sk.Zeroize()
	return out, nil
}

// PublicKeyFromBLS12381Private derives compressed G1 public key bytes from a BLS12-381 secret key.
func PublicKeyFromBLS12381Private(priv []byte) ([]byte, error) {
	sk, err := bls12381SecretKeyFromBytes(priv)
	if err != nil {
		return nil, err
	}
	return new(blst.P1Affine).From(sk).Compress(), nil
}

// SignBLS12381Hash signs tx hash with BLS12-381 and returns compressed G2 signature bytes.
func SignBLS12381Hash(priv []byte, txHash common.Hash) ([]byte, error) {
	sk, err := bls12381SecretKeyFromBytes(priv)
	if err != nil {
		return nil, err
	}
	return new(blst.P2Affine).Sign(sk, txHash[:], bls12381SignDst).Compress(), nil
}

// AggregateBLS12381PublicKeys aggregates compressed BLS12-381 public keys into one compressed public key.
func AggregateBLS12381PublicKeys(pubkeys [][]byte) ([]byte, error) {
	if len(pubkeys) == 0 {
		return nil, ErrInvalidSignerValue
	}
	agg := new(blst.P1Aggregate)
	if !agg.AggregateCompressed(pubkeys, true) {
		return nil, ErrInvalidSignerValue
	}
	out := agg.ToAffine()
	if out == nil || !out.KeyValidate() {
		return nil, ErrInvalidSignerValue
	}
	return out.Compress(), nil
}

// AggregateBLS12381Signatures aggregates compressed BLS12-381 signatures into one compressed signature.
func AggregateBLS12381Signatures(signatures [][]byte) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, ErrInvalidSignerValue
	}
	agg := new(blst.P2Aggregate)
	if !agg.AggregateCompressed(signatures, true) {
		return nil, ErrInvalidSignerValue
	}
	out := agg.ToAffine()
	if out == nil || !out.SigValidate(false) {
		return nil, ErrInvalidSignerValue
	}
	return out.Compress(), nil
}

// VerifyBLS12381FastAggregate verifies an aggregated BLS signature against a list of signers for one message.
func VerifyBLS12381FastAggregate(pubkeys [][]byte, signature []byte, txHash common.Hash) bool {
	aggPub, err := AggregateBLS12381PublicKeys(pubkeys)
	if err != nil {
		return false
	}
	return verifyBLS12381Signature(aggPub, signature, txHash)
}
