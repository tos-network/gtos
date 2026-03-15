package accountsigner

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/tos-network/gtos/common"
	bls "github.com/tos-network/gtos/crypto/bls12381"
)

var (
	bls12381Order        = bls.NewG1().Q()
	bls12381KeygenSaltV4 = []byte("BLS-SIG-KEYGEN-SALT-")
)

func pureBLS12381SupportsBackend() bool {
	return true
}

func pureBLS12381SecretKeyFromBytes(priv []byte) (*big.Int, error) {
	if len(priv) != bls12381PrivateKeyLen {
		return nil, ErrInvalidSignerKey
	}
	sk := new(big.Int).SetBytes(priv)
	if sk.Sign() <= 0 || sk.Cmp(bls12381Order) >= 0 {
		return nil, ErrInvalidSignerKey
	}
	return sk, nil
}

func pureBLS12381NormalizePubkey(raw []byte) ([]byte, error) {
	if len(raw) != bls12381PubkeyLen {
		return nil, ErrInvalidSignerValue
	}
	g1 := bls.NewG1()
	pk, err := g1.FromCompressed(raw)
	if err != nil || g1.IsZero(pk) {
		return nil, ErrInvalidSignerValue
	}
	return g1.ToCompressed(pk), nil
}

func pureBLS12381HKDFExtract(salt []byte, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func pureBLS12381HKDFExpand(prk []byte, info []byte, outLen int) []byte {
	var (
		okm []byte
		t   []byte
	)
	for counter := byte(1); len(okm) < outLen; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:outLen]
}

func pureBLS12381KeyGenFromIKM(ikm []byte, info []byte) ([]byte, error) {
	if len(ikm) < 32 {
		return nil, ErrInvalidSignerKey
	}
	saltDigest := sha256.Sum256(bls12381KeygenSaltV4)
	salt := saltDigest[:]
	infoPrime := append(append([]byte(nil), info...), byte(48>>8), byte(48))
	ikmZero := append(append([]byte(nil), ikm...), 0x00)

	for {
		prk := pureBLS12381HKDFExtract(salt, ikmZero)
		okm := pureBLS12381HKDFExpand(prk, infoPrime, 48)
		sk := new(big.Int).SetBytes(okm)
		sk.Mod(sk, bls12381Order)
		if sk.Sign() != 0 {
			out := make([]byte, bls12381PrivateKeyLen)
			skBytes := sk.Bytes()
			copy(out[len(out)-len(skBytes):], skBytes)
			return out, nil
		}
		nextSalt := sha256.Sum256(salt)
		salt = nextSalt[:]
	}
}

func pureGenerateBLS12381PrivateKey(r io.Reader) ([]byte, error) {
	ikm := make([]byte, bls12381PrivateKeyLen)
	if _, err := io.ReadFull(r, ikm); err != nil {
		return nil, err
	}
	return pureBLS12381KeyGenFromIKM(ikm, nil)
}

func purePublicKeyFromBLS12381Private(priv []byte) ([]byte, error) {
	sk, err := pureBLS12381SecretKeyFromBytes(priv)
	if err != nil {
		return nil, err
	}
	g1 := bls.NewG1()
	pk := g1.New()
	g1.MulScalar(pk, g1.One(), sk)
	if g1.IsZero(pk) {
		return nil, ErrInvalidSignerKey
	}
	return g1.ToCompressed(pk), nil
}

func pureSignBLS12381Hash(priv []byte, txHash common.Hash) ([]byte, error) {
	sk, err := pureBLS12381SecretKeyFromBytes(priv)
	if err != nil {
		return nil, err
	}
	hashPoint, err := bls.HashToG2(txHash[:], bls12381SignDst)
	if err != nil {
		return nil, ErrInvalidSignerValue
	}
	g2 := bls.NewG2()
	sig := g2.New()
	g2.MulScalar(sig, hashPoint, sk)
	if g2.IsZero(sig) {
		return nil, ErrInvalidSignerKey
	}
	return g2.ToCompressed(sig), nil
}

func pureVerifyBLS12381Signature(pub, sig []byte, txHash common.Hash) bool {
	if len(pub) != bls12381PubkeyLen || len(sig) != bls12381SignatureLen {
		return false
	}
	g1 := bls.NewG1()
	pk, err := g1.FromCompressed(pub)
	if err != nil || g1.IsZero(pk) {
		return false
	}
	g2 := bls.NewG2()
	sigPoint, err := g2.FromCompressed(sig)
	if err != nil || g2.IsZero(sigPoint) {
		return false
	}
	hashPoint, err := bls.HashToG2(txHash[:], bls12381SignDst)
	if err != nil {
		return false
	}
	engine := bls.NewPairingEngine()
	engine.AddPair(pk, hashPoint)
	engine.AddPairInv(engine.G1.One(), sigPoint)
	return engine.Check()
}

func pureAggregateBLS12381PublicKeys(pubkeys [][]byte) ([]byte, error) {
	if len(pubkeys) == 0 {
		return nil, ErrInvalidSignerValue
	}
	g1 := bls.NewG1()
	acc := g1.Zero()
	for _, encoded := range pubkeys {
		pk, err := g1.FromCompressed(encoded)
		if err != nil || g1.IsZero(pk) {
			return nil, ErrInvalidSignerValue
		}
		g1.Add(acc, acc, pk)
	}
	if g1.IsZero(acc) {
		return nil, ErrInvalidSignerValue
	}
	return g1.ToCompressed(acc), nil
}

func pureAggregateBLS12381Signatures(signatures [][]byte) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, ErrInvalidSignerValue
	}
	g2 := bls.NewG2()
	acc := g2.Zero()
	for _, encoded := range signatures {
		sig, err := g2.FromCompressed(encoded)
		if err != nil || g2.IsZero(sig) {
			return nil, ErrInvalidSignerValue
		}
		g2.Add(acc, acc, sig)
	}
	if g2.IsZero(acc) {
		return nil, ErrInvalidSignerValue
	}
	return g2.ToCompressed(acc), nil
}

func pureVerifyBLS12381FastAggregate(pubkeys [][]byte, signature []byte, txHash common.Hash) bool {
	aggPub, err := pureAggregateBLS12381PublicKeys(pubkeys)
	if err != nil {
		return false
	}
	return pureVerifyBLS12381Signature(aggPub, signature, txHash)
}
