package tosalign

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/tos-network/gtos/crypto/ristretto255"
	"golang.org/x/crypto/sha3"
)

const (
	CompressedPublicKeySize = 32
	SignatureSize           = 64
	scalarSize              = 32
)

type CompressedPublicKey [CompressedPublicKeySize]byte

type Signature struct {
	s [scalarSize]byte
	e [scalarSize]byte
}

type KeyPair struct {
	private *ristretto255.Scalar
	public  *ristretto255.Element
}

var (
	errInvalidPublicKeyLength  = errors.New("invalid public key length")
	errInvalidPrivateKeyLength = errors.New("invalid private key length")
	errInvalidSignatureLength  = errors.New("invalid signature length")
	errInvalidScalarValue      = errors.New("invalid scalar value")
	errZeroPrivateKey          = errors.New("private key scalar must not be zero")
)

var (
	pedersenBlindingOnce sync.Once
	pedersenBlindingBase *ristretto255.Element
	pedersenBlindingErr  error
)

func NewKeyPair() (*KeyPair, error) {
	private, err := randomScalarNonZero()
	if err != nil {
		return nil, err
	}
	return keyPairFromPrivateScalar(private)
}

func KeyPairFromPrivateKeyBytes(privateKey []byte) (*KeyPair, error) {
	if len(privateKey) != scalarSize {
		return nil, errInvalidPrivateKeyLength
	}
	scalar, err := canonicalScalar(privateKey)
	if err != nil {
		return nil, err
	}
	if isZeroScalar(scalar) {
		return nil, errZeroPrivateKey
	}
	return keyPairFromPrivateScalar(scalar)
}

func (k *KeyPair) PrivateKeyBytes() [scalarSize]byte {
	var out [scalarSize]byte
	copy(out[:], k.private.Bytes())
	return out
}

func (k *KeyPair) PublicKey() CompressedPublicKey {
	var out CompressedPublicKey
	copy(out[:], k.public.Encode(nil))
	return out
}

func (k *KeyPair) Sign(message []byte) (Signature, error) {
	nonce, err := randomScalarNonZero()
	if err != nil {
		return Signature{}, err
	}

	H, err := pedersenBlindingPoint()
	if err != nil {
		return Signature{}, err
	}
	r := ristretto255.NewElement().ScalarMult(nonce, H)
	e, err := hashAndPointToScalar(k.PublicKey(), message, r)
	if err != nil {
		return Signature{}, err
	}

	invPriv := ristretto255.NewScalar().Invert(k.private)
	s := ristretto255.NewScalar().Multiply(invPriv, e)
	s.Add(s, nonce)

	return signatureFromScalars(s, e), nil
}

func (k CompressedPublicKey) Bytes() [CompressedPublicKeySize]byte {
	return k
}

func CompressedPublicKeyFromBytes(raw []byte) (CompressedPublicKey, error) {
	if len(raw) != CompressedPublicKeySize {
		return CompressedPublicKey{}, errInvalidPublicKeyLength
	}
	var key CompressedPublicKey
	copy(key[:], raw)
	return key, nil
}

func (k CompressedPublicKey) Decompress() (*ristretto255.Element, error) {
	point := ristretto255.NewElement()
	if err := point.Decode(k[:]); err != nil {
		return nil, fmt.Errorf("decompress public key: %w", err)
	}
	return point, nil
}

func (k CompressedPublicKey) ToAddress(mainnet bool) Address {
	return NewAddress(mainnet, k)
}

func SignatureFromBytes(raw []byte) (Signature, error) {
	if len(raw) != SignatureSize {
		return Signature{}, errInvalidSignatureLength
	}
	if _, err := canonicalScalar(raw[:scalarSize]); err != nil {
		return Signature{}, err
	}
	if _, err := canonicalScalar(raw[scalarSize:]); err != nil {
		return Signature{}, err
	}

	var sig Signature
	copy(sig.s[:], raw[:scalarSize])
	copy(sig.e[:], raw[scalarSize:])
	return sig, nil
}

func (s Signature) Bytes() [SignatureSize]byte {
	var out [SignatureSize]byte
	copy(out[:scalarSize], s.s[:])
	copy(out[scalarSize:], s.e[:])
	return out
}

func (s Signature) Verify(message []byte, key CompressedPublicKey) bool {
	pub, err := key.Decompress()
	if err != nil {
		return false
	}

	sScalar, err := canonicalScalar(s.s[:])
	if err != nil {
		return false
	}
	eScalar, err := canonicalScalar(s.e[:])
	if err != nil {
		return false
	}

	H, err := pedersenBlindingPoint()
	if err != nil {
		return false
	}

	rFromS := ristretto255.NewElement().ScalarMult(sScalar, H)
	negE := ristretto255.NewScalar().Negate(eScalar)
	rFromE := ristretto255.NewElement().ScalarMult(negE, pub)
	r := ristretto255.NewElement().Add(rFromS, rFromE)

	calc, err := hashAndPointToScalar(key, message, r)
	if err != nil {
		return false
	}
	return calc.Equal(eScalar) == 1
}

func signatureFromScalars(s, e *ristretto255.Scalar) Signature {
	var sig Signature
	copy(sig.s[:], s.Bytes())
	copy(sig.e[:], e.Bytes())
	return sig
}

func canonicalScalar(raw []byte) (*ristretto255.Scalar, error) {
	s := ristretto255.NewScalar()
	if _, err := s.SetCanonicalBytes(raw); err != nil {
		return nil, errInvalidScalarValue
	}
	return s, nil
}

func isZeroScalar(s *ristretto255.Scalar) bool {
	for _, b := range s.Bytes() {
		if b != 0 {
			return false
		}
	}
	return true
}

func randomScalarNonZero() (*ristretto255.Scalar, error) {
	for {
		var seed [64]byte
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, err
		}
		s := ristretto255.NewScalar()
		if _, err := s.SetUniformBytes(seed[:]); err != nil {
			return nil, err
		}
		if !isZeroScalar(s) {
			return s, nil
		}
	}
}

func pedersenBlindingPoint() (*ristretto255.Element, error) {
	pedersenBlindingOnce.Do(func() {
		base := ristretto255.NewGeneratorElement()
		baseCompressed := base.Encode(nil)
		digest := sha3.Sum512(baseCompressed)
		point := ristretto255.NewElement()
		if _, err := point.SetUniformBytes(digest[:]); err != nil {
			pedersenBlindingErr = err
			return
		}
		pedersenBlindingBase = point
	})

	if pedersenBlindingErr != nil {
		return nil, pedersenBlindingErr
	}
	if pedersenBlindingBase == nil {
		return nil, errors.New("pedersen blinding base is nil")
	}
	return ristretto255.NewElement().Set(pedersenBlindingBase), nil
}

func PedersenBlindingPointCompressed() ([CompressedPublicKeySize]byte, error) {
	point, err := pedersenBlindingPoint()
	if err != nil {
		return [CompressedPublicKeySize]byte{}, err
	}
	var out [CompressedPublicKeySize]byte
	copy(out[:], point.Encode(nil))
	return out, nil
}

func keyPairFromPrivateScalar(private *ristretto255.Scalar) (*KeyPair, error) {
	H, err := pedersenBlindingPoint()
	if err != nil {
		return nil, err
	}
	invPriv := ristretto255.NewScalar().Invert(private)
	public := ristretto255.NewElement().ScalarMult(invPriv, H)
	return &KeyPair{private: private, public: public}, nil
}

func hashAndPointToScalar(key CompressedPublicKey, message []byte, point *ristretto255.Element) (*ristretto255.Scalar, error) {
	h := sha3.New512()
	_, _ = h.Write(key[:])
	_, _ = h.Write(message)
	_, _ = h.Write(point.Encode(nil))
	sum := h.Sum(nil)

	s := ristretto255.NewScalar()
	if _, err := s.SetUniformBytes(sum); err != nil {
		return nil, err
	}
	return s, nil
}
