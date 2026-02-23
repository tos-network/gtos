package accountsigner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"

	blst "github.com/supranational/blst/bindings/go"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/crypto/ristretto255"
	"golang.org/x/crypto/sha3"
)

const (
	SignerTypeSecp256k1 = "secp256k1"
	SignerTypeSecp256r1 = "secp256r1"
	SignerTypeEd25519   = "ed25519"
	SignerTypeBLS12381  = "bls12-381"
	SignerTypeElgamal   = "elgamal"

	bls12381PrivateKeyLen = 32
	bls12381PubkeyLen     = 48
	bls12381SignatureLen  = 96
	elgamalPrivateKeyLen  = 32
	elgamalPubkeyLen      = 32
)

var (
	ErrUnknownSignerType      = errors.New("accountsigner: unknown signer type")
	ErrInvalidSignerValue     = errors.New("accountsigner: invalid signer value")
	ErrInvalidSignatureMeta   = errors.New("accountsigner: invalid signature metadata")
	ErrSignerNotSupportedByTx = errors.New("accountsigner: signer type not supported by current tx signature format")
	ErrInvalidSignerKey       = errors.New("accountsigner: invalid signer private key")
	signatureMetaPrefix       = []byte("GTOSSIG1")
	signatureMetaAlgSecp256k1 = byte(1)
	signatureMetaAlgSecp256r1 = byte(2)
	signatureMetaAlgEd25519   = byte(3)
	signatureMetaAlgBLS12381  = byte(4)
	signatureMetaAlgElgamal   = byte(5)
)

var bls12381SignDst = []byte("GTOS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_")

var (
	elgamalHOnce sync.Once
	elgamalH     *ristretto255.Element
	elgamalHErr  error
)

func normalizeSignerType(signerType string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(signerType)) {
	case SignerTypeSecp256k1, "ethereum_secp256k1":
		return SignerTypeSecp256k1, nil
	case SignerTypeSecp256r1:
		return SignerTypeSecp256r1, nil
	case SignerTypeEd25519:
		return SignerTypeEd25519, nil
	case SignerTypeBLS12381, "bls12381":
		return SignerTypeBLS12381, nil
	case SignerTypeElgamal:
		return SignerTypeElgamal, nil
	default:
		return "", ErrUnknownSignerType
	}
}

// CanonicalSignerType normalizes signer type alias to canonical lowercase name.
func CanonicalSignerType(signerType string) (string, error) {
	return normalizeSignerType(signerType)
}

func SupportsCurrentTxSignatureType(signerType string) bool {
	switch signerType {
	case SignerTypeSecp256k1, SignerTypeSecp256r1, SignerTypeEd25519, SignerTypeBLS12381, SignerTypeElgamal:
		return true
	default:
		return false
	}
}

func normalizeSecp256k1Pubkey(raw []byte) ([]byte, error) {
	var (
		pub *ecdsa.PublicKey
		err error
	)
	switch len(raw) {
	case 33:
		pub, err = crypto.DecompressPubkey(raw)
	case 65:
		pub, err = crypto.UnmarshalPubkey(raw)
	default:
		return nil, ErrInvalidSignerValue
	}
	if err != nil {
		return nil, ErrInvalidSignerValue
	}
	return crypto.FromECDSAPub(pub), nil
}

func normalizeSecp256r1Pubkey(raw []byte) ([]byte, error) {
	var x, y *big.Int
	switch len(raw) {
	case 33:
		x, y = elliptic.UnmarshalCompressed(elliptic.P256(), raw)
	case 65:
		x, y = elliptic.Unmarshal(elliptic.P256(), raw)
	default:
		return nil, ErrInvalidSignerValue
	}
	if x == nil || y == nil {
		return nil, ErrInvalidSignerValue
	}
	pub := make([]byte, 65)
	pub[0] = 0x04
	xb := x.Bytes()
	yb := y.Bytes()
	copy(pub[1+32-len(xb):33], xb)
	copy(pub[33+32-len(yb):], yb)
	return pub, nil
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

func normalizeElgamalPubkey(raw []byte) ([]byte, error) {
	if len(raw) != elgamalPubkeyLen {
		return nil, ErrInvalidSignerValue
	}
	point := ristretto255.NewIdentityElement()
	if _, err := point.SetCanonicalBytes(raw); err != nil {
		return nil, ErrInvalidSignerValue
	}
	return point.Bytes(), nil
}

// NormalizeSigner validates signerType/signerValue and returns canonical type, canonical pubkey bytes and canonical value.
func NormalizeSigner(signerType, signerValue string) (string, []byte, string, error) {
	normalizedType, err := normalizeSignerType(signerType)
	if err != nil {
		return "", nil, "", err
	}
	raw, err := hexutil.Decode(strings.TrimSpace(signerValue))
	if err != nil {
		return "", nil, "", ErrInvalidSignerValue
	}
	if len(raw) == 0 || len(raw) > MaxSignerValueLen {
		return "", nil, "", ErrInvalidSignerValue
	}
	var normalizedPub []byte
	switch normalizedType {
	case SignerTypeSecp256k1:
		normalizedPub, err = normalizeSecp256k1Pubkey(raw)
	case SignerTypeSecp256r1:
		normalizedPub, err = normalizeSecp256r1Pubkey(raw)
	case SignerTypeEd25519:
		if len(raw) != ed25519.PublicKeySize {
			err = ErrInvalidSignerValue
		} else {
			normalizedPub = append([]byte(nil), raw...)
		}
	case SignerTypeBLS12381:
		normalizedPub, err = normalizeBLS12381Pubkey(raw)
	case SignerTypeElgamal:
		normalizedPub, err = normalizeElgamalPubkey(raw)
	default:
		err = ErrUnknownSignerType
	}
	if err != nil {
		return "", nil, "", err
	}
	if len(normalizedPub) == 0 {
		return "", nil, "", ErrInvalidSignerValue
	}
	return normalizedType, normalizedPub, hexutil.Encode(normalizedPub), nil
}

// AddressFromSigner derives account address from canonical signer pubkey bytes.
func AddressFromSigner(signerType string, signerPub []byte) (common.Address, error) {
	switch signerType {
	case SignerTypeSecp256k1:
		pub, err := crypto.UnmarshalPubkey(signerPub)
		if err != nil {
			return common.Address{}, ErrInvalidSignerValue
		}
		return crypto.PubkeyToAddress(*pub), nil
	case SignerTypeSecp256r1:
		if len(signerPub) != 65 || signerPub[0] != 0x04 {
			return common.Address{}, ErrInvalidSignerValue
		}
		return common.BytesToAddress(crypto.Keccak256(signerPub[1:])), nil
	case SignerTypeEd25519:
		if len(signerPub) != ed25519.PublicKeySize {
			return common.Address{}, ErrInvalidSignerValue
		}
		return common.BytesToAddress(crypto.Keccak256(signerPub)), nil
	case SignerTypeBLS12381:
		if len(signerPub) == 0 {
			return common.Address{}, ErrInvalidSignerValue
		}
		return common.BytesToAddress(crypto.Keccak256(signerPub)), nil
	case SignerTypeElgamal:
		normalized, err := normalizeElgamalPubkey(signerPub)
		if err != nil {
			return common.Address{}, err
		}
		return common.BytesToAddress(crypto.Keccak256(normalized)), nil
	default:
		return common.Address{}, ErrUnknownSignerType
	}
}

func rsSignatureBytes(r, s *big.Int) ([]byte, error) {
	if r == nil || s == nil {
		return nil, ErrInvalidSignerValue
	}
	if r.Sign() < 0 || s.Sign() < 0 {
		return nil, ErrInvalidSignerValue
	}
	rb := r.Bytes()
	sb := s.Bytes()
	if len(rb) > 32 || len(sb) > 32 {
		return nil, ErrInvalidSignerValue
	}
	sig := make([]byte, 64)
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):], sb)
	return sig, nil
}

func bls12381SignatureFromRS(r, s *big.Int) ([]byte, error) {
	if r == nil || s == nil || r.Sign() < 0 || s.Sign() < 0 {
		return nil, ErrInvalidSignerValue
	}
	if r.BitLen() > bls12381PubkeyLen*8 || s.BitLen() > bls12381PubkeyLen*8 {
		return nil, ErrInvalidSignerValue
	}
	out := make([]byte, bls12381SignatureLen)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[bls12381PubkeyLen-len(rb):bls12381PubkeyLen], rb)
	copy(out[bls12381SignatureLen-len(sb):], sb)
	return out, nil
}

func bls12381SignatureToRS(sig []byte) (*big.Int, *big.Int, error) {
	if len(sig) != bls12381SignatureLen {
		return nil, nil, ErrInvalidSignerValue
	}
	return new(big.Int).SetBytes(sig[:bls12381PubkeyLen]), new(big.Int).SetBytes(sig[bls12381PubkeyLen:]), nil
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

func elgamalGeneratorH() (*ristretto255.Element, error) {
	elgamalHOnce.Do(func() {
		base := ristretto255.NewGeneratorElement().Bytes()
		digest := sha3.Sum512(base)
		h := ristretto255.NewIdentityElement()
		if _, err := h.SetUniformBytes(digest[:]); err != nil {
			elgamalHErr = err
			return
		}
		elgamalH = h
	})
	if elgamalHErr != nil {
		return nil, elgamalHErr
	}
	return ristretto255.NewIdentityElement().Set(elgamalH), nil
}

func elgamalScalarFromCanonicalBytes(raw []byte, keyErr error) (*ristretto255.Scalar, error) {
	if len(raw) != elgamalPrivateKeyLen {
		return nil, keyErr
	}
	scalar := ristretto255.NewScalar()
	if _, err := scalar.SetCanonicalBytes(raw); err != nil {
		return nil, keyErr
	}
	return scalar, nil
}

func elgamalPrivateScalarFromCanonicalBytes(raw []byte) (*ristretto255.Scalar, error) {
	scalar, err := elgamalScalarFromCanonicalBytes(raw, ErrInvalidSignerKey)
	if err != nil {
		return nil, err
	}
	if scalar.Equal(ristretto255.NewScalar()) == 1 {
		return nil, ErrInvalidSignerKey
	}
	return scalar, nil
}

func randomElgamalScalar(r io.Reader) (*ristretto255.Scalar, error) {
	var wide [64]byte
	for {
		if _, err := io.ReadFull(r, wide[:]); err != nil {
			return nil, err
		}
		scalar := ristretto255.NewScalar()
		if _, err := scalar.SetUniformBytes(wide[:]); err != nil {
			return nil, err
		}
		if scalar.Equal(ristretto255.NewScalar()) != 1 {
			return scalar, nil
		}
	}
}

func elgamalHashAndPointToScalar(pub, message []byte, point *ristretto255.Element) (*ristretto255.Scalar, error) {
	hasher := sha3.New512()
	hasher.Write(pub)
	hasher.Write(message)
	hasher.Write(point.Bytes())
	digest := hasher.Sum(nil)
	out := ristretto255.NewScalar()
	if _, err := out.SetUniformBytes(digest); err != nil {
		return nil, err
	}
	return out, nil
}

// GenerateElgamalPrivateKey creates a new ristretto-schnorr private key compatible with TOS elgamal signature flow.
func GenerateElgamalPrivateKey(r io.Reader) ([]byte, error) {
	scalar, err := randomElgamalScalar(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), scalar.Bytes()...), nil
}

// PublicKeyFromElgamalPrivate derives compressed ristretto public key bytes from a private scalar.
func PublicKeyFromElgamalPrivate(priv []byte) ([]byte, error) {
	secret, err := elgamalPrivateScalarFromCanonicalBytes(priv)
	if err != nil {
		return nil, err
	}
	h, err := elgamalGeneratorH()
	if err != nil {
		return nil, err
	}
	inv := ristretto255.NewScalar().Invert(secret)
	pub := ristretto255.NewIdentityElement().ScalarMult(inv, h)
	return pub.Bytes(), nil
}

// SignElgamalHash signs tx hash with the TOS-compatible ristretto Schnorr variant and returns [s || e] bytes.
func SignElgamalHash(priv []byte, txHash common.Hash) ([]byte, error) {
	secret, err := elgamalPrivateScalarFromCanonicalBytes(priv)
	if err != nil {
		return nil, err
	}
	k, err := randomElgamalScalar(rand.Reader)
	if err != nil {
		return nil, err
	}
	h, err := elgamalGeneratorH()
	if err != nil {
		return nil, err
	}
	inv := ristretto255.NewScalar().Invert(secret)
	pub := ristretto255.NewIdentityElement().ScalarMult(inv, h)
	rPoint := ristretto255.NewIdentityElement().ScalarMult(k, h)
	e, err := elgamalHashAndPointToScalar(pub.Bytes(), txHash[:], rPoint)
	if err != nil {
		return nil, err
	}
	s := ristretto255.NewScalar().Add(ristretto255.NewScalar().Multiply(inv, e), k)
	out := make([]byte, 64)
	copy(out[:32], s.Bytes())
	copy(out[32:], e.Bytes())
	return out, nil
}

func verifyElgamalSignature(pub, sig []byte, txHash common.Hash) bool {
	normalizedPub, err := normalizeElgamalPubkey(pub)
	if err != nil || len(sig) != 64 {
		return false
	}
	sScalar, err := elgamalScalarFromCanonicalBytes(sig[:32], ErrInvalidSignerValue)
	if err != nil {
		return false
	}
	eScalar, err := elgamalScalarFromCanonicalBytes(sig[32:], ErrInvalidSignerValue)
	if err != nil {
		return false
	}
	h, err := elgamalGeneratorH()
	if err != nil {
		return false
	}
	pubPoint := ristretto255.NewIdentityElement()
	if _, err := pubPoint.SetCanonicalBytes(normalizedPub); err != nil {
		return false
	}
	hs := ristretto255.NewIdentityElement().ScalarMult(sScalar, h)
	negE := ristretto255.NewScalar().Negate(eScalar)
	pubNegE := ristretto255.NewIdentityElement().ScalarMult(negE, pubPoint)
	rPoint := ristretto255.NewIdentityElement().Add(hs, pubNegE)
	calculatedE, err := elgamalHashAndPointToScalar(normalizedPub, txHash[:], rPoint)
	if err != nil {
		return false
	}
	return eScalar.Equal(calculatedE) == 1
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

// SplitBLS12381Signature splits compressed BLS12-381 signature bytes into tx R/S bigint components.
func SplitBLS12381Signature(sig []byte) (*big.Int, *big.Int, error) {
	return bls12381SignatureToRS(sig)
}

// JoinBLS12381Signature rebuilds compressed BLS12-381 signature bytes from tx R/S bigint components.
func JoinBLS12381Signature(r, s *big.Int) ([]byte, error) {
	return bls12381SignatureFromRS(r, s)
}

// VerifyBLS12381FastAggregate verifies an aggregated BLS signature against a list of signers for one message.
func VerifyBLS12381FastAggregate(pubkeys [][]byte, signature []byte, txHash common.Hash) bool {
	aggPub, err := AggregateBLS12381PublicKeys(pubkeys)
	if err != nil {
		return false
	}
	return verifyBLS12381Signature(aggPub, signature, txHash)
}

type ecdsaASN1Signature struct {
	R, S *big.Int
}

// EncodeSecp256r1Signature encodes r/s values into signer-tx signature bytes [R || S || V].
// For secp256r1, V is always 0 because no recovery id is used.
func EncodeSecp256r1Signature(r, s *big.Int) ([]byte, error) {
	if r == nil || s == nil {
		return nil, ErrInvalidSignerValue
	}
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, ErrInvalidSignerValue
	}
	if r.BitLen() > 256 || s.BitLen() > 256 {
		return nil, ErrInvalidSignerValue
	}
	out := make([]byte, crypto.SignatureLength)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):64], sb)
	out[64] = 0
	return out, nil
}

// EncodeSecp256r1ASN1Signature converts ASN.1 DER ECDSA signature bytes into [R || S || V].
// This is useful when signatures come from standard secp256r1 signers that emit DER format.
func EncodeSecp256r1ASN1Signature(sigDER []byte) ([]byte, error) {
	var parsed ecdsaASN1Signature
	rest, err := asn1.Unmarshal(sigDER, &parsed)
	if err != nil || len(rest) != 0 {
		return nil, ErrInvalidSignerValue
	}
	return EncodeSecp256r1Signature(parsed.R, parsed.S)
}

// SignSecp256r1Hash signs tx hash with a P-256 private key and encodes it as [R || S || V].
func SignSecp256r1Hash(priv *ecdsa.PrivateKey, txHash common.Hash) ([]byte, error) {
	if priv == nil || priv.Curve == nil || priv.Curve != elliptic.P256() {
		return nil, ErrInvalidSignerKey
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, txHash[:])
	if err != nil {
		return nil, err
	}
	return EncodeSecp256r1Signature(r, s)
}

// VerifyRawSignature verifies (R,S)-style tx signature against the signer public key and hash.
func VerifyRawSignature(signerType string, signerPub []byte, txHash common.Hash, r, s *big.Int) bool {
	switch signerType {
	case SignerTypeSecp256k1:
		sig, err := rsSignatureBytes(r, s)
		if err != nil {
			return false
		}
		return crypto.VerifySignature(signerPub, txHash[:], sig)
	case SignerTypeSecp256r1:
		if len(signerPub) != 65 || signerPub[0] != 0x04 {
			return false
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), signerPub)
		if x == nil || y == nil {
			return false
		}
		return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, txHash[:], r, s)
	case SignerTypeEd25519:
		sig, err := rsSignatureBytes(r, s)
		if err != nil {
			return false
		}
		if len(signerPub) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(signerPub), txHash[:], sig)
	case SignerTypeBLS12381:
		sig, err := bls12381SignatureFromRS(r, s)
		if err != nil {
			return false
		}
		return verifyBLS12381Signature(signerPub, sig, txHash)
	case SignerTypeElgamal:
		sig, err := rsSignatureBytes(r, s)
		if err != nil {
			return false
		}
		return verifyElgamalSignature(signerPub, sig, txHash)
	default:
		return false
	}
}

func signatureMetaAlgToType(alg byte) (string, error) {
	switch alg {
	case signatureMetaAlgSecp256k1:
		return SignerTypeSecp256k1, nil
	case signatureMetaAlgSecp256r1:
		return SignerTypeSecp256r1, nil
	case signatureMetaAlgEd25519:
		return SignerTypeEd25519, nil
	case signatureMetaAlgBLS12381:
		return SignerTypeBLS12381, nil
	case signatureMetaAlgElgamal:
		return SignerTypeElgamal, nil
	default:
		return "", ErrInvalidSignatureMeta
	}
}

func signatureTypeToMetaAlg(signerType string) (byte, error) {
	switch signerType {
	case SignerTypeSecp256k1:
		return signatureMetaAlgSecp256k1, nil
	case SignerTypeSecp256r1:
		return signatureMetaAlgSecp256r1, nil
	case SignerTypeEd25519:
		return signatureMetaAlgEd25519, nil
	case SignerTypeBLS12381:
		return signatureMetaAlgBLS12381, nil
	case SignerTypeElgamal:
		return signatureMetaAlgElgamal, nil
	default:
		return 0, ErrUnknownSignerType
	}
}

// EncodeSignatureMeta encodes signer metadata for tx V field.
func EncodeSignatureMeta(signerType string, signerPub []byte) (*big.Int, error) {
	normalizedType, _, _, err := NormalizeSigner(signerType, hexutil.Encode(signerPub))
	if err != nil {
		return nil, err
	}
	alg, err := signatureTypeToMetaAlg(normalizedType)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(signatureMetaPrefix)+1+len(signerPub))
	out = append(out, signatureMetaPrefix...)
	out = append(out, alg)
	out = append(out, signerPub...)
	return new(big.Int).SetBytes(out), nil
}

// DecodeSignatureMeta decodes tx V metadata. ok=false means tx uses legacy V semantics.
func DecodeSignatureMeta(v *big.Int) (signerType string, signerPub []byte, ok bool, err error) {
	if v == nil {
		return "", nil, false, nil
	}
	raw := v.Bytes()
	if len(raw) < len(signatureMetaPrefix)+2 {
		return "", nil, false, nil
	}
	if !bytes.Equal(raw[:len(signatureMetaPrefix)], signatureMetaPrefix) {
		return "", nil, false, nil
	}
	typ, err := signatureMetaAlgToType(raw[len(signatureMetaPrefix)])
	if err != nil {
		return "", nil, false, err
	}
	pub := append([]byte(nil), raw[len(signatureMetaPrefix)+1:]...)
	normalizedType, normalizedPub, _, err := NormalizeSigner(typ, hexutil.Encode(pub))
	if err != nil {
		return "", nil, false, fmt.Errorf("%w: %v", ErrInvalidSignatureMeta, err)
	}
	return normalizedType, normalizedPub, true, nil
}
