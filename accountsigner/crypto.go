package accountsigner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/crypto"
)

const (
	SignerTypeSecp256k1 = "secp256k1"
	SignerTypeSecp256r1 = "secp256r1"
	SignerTypeEd25519   = "ed25519"
	SignerTypeBLS12381  = "bls12-381"
	SignerTypeFROST     = "frost"
	SignerTypePQC       = "pqc"
)

var (
	ErrUnknownSignerType      = errors.New("accountsigner: unknown signer type")
	ErrInvalidSignerValue     = errors.New("accountsigner: invalid signer value")
	ErrInvalidSignatureMeta   = errors.New("accountsigner: invalid signature metadata")
	ErrSignerNotSupportedByTx = errors.New("accountsigner: signer type not supported by current tx signature format")
	signatureMetaPrefix       = []byte("GTOSSIG1")
	signatureMetaAlgSecp256k1 = byte(1)
	signatureMetaAlgSecp256r1 = byte(2)
	signatureMetaAlgEd25519   = byte(3)
	signatureMetaAlgBLS12381  = byte(4)
	signatureMetaAlgFROST     = byte(5)
	signatureMetaAlgPQC       = byte(6)
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
	case SignerTypeFROST:
		return SignerTypeFROST, nil
	case SignerTypePQC:
		return SignerTypePQC, nil
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
	case SignerTypeSecp256k1, SignerTypeSecp256r1, SignerTypeEd25519:
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
		// BLS12-381 public key is expected in compressed G1 form.
		if len(raw) != 48 {
			err = ErrInvalidSignerValue
		} else {
			normalizedPub = append([]byte(nil), raw...)
		}
	case SignerTypeFROST:
		// FROST group key format depends on the underlying curve; keep as opaque key material.
		if len(raw) < 16 || len(raw) > 128 {
			err = ErrInvalidSignerValue
		} else {
			normalizedPub = append([]byte(nil), raw...)
		}
	case SignerTypePQC:
		// PQC key sizes vary by algorithm family; allow opaque bytes within configured bounds.
		if len(raw) < 64 {
			err = ErrInvalidSignerValue
		} else {
			normalizedPub = append([]byte(nil), raw...)
		}
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
		return common.BytesToAddress(crypto.Keccak256(signerPub[1:])[12:]), nil
	case SignerTypeEd25519:
		if len(signerPub) != ed25519.PublicKeySize {
			return common.Address{}, ErrInvalidSignerValue
		}
		return common.BytesToAddress(crypto.Keccak256(signerPub)[12:]), nil
	case SignerTypeBLS12381, SignerTypeFROST, SignerTypePQC:
		if len(signerPub) == 0 {
			return common.Address{}, ErrInvalidSignerValue
		}
		return common.BytesToAddress(crypto.Keccak256(signerPub)[12:]), nil
	default:
		return common.Address{}, ErrUnknownSignerType
	}
}

func rsSignatureBytes(r, s *big.Int) ([]byte, error) {
	if r == nil || s == nil {
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

// VerifyRawSignature verifies (R,S)-style tx signature against the signer public key and hash.
func VerifyRawSignature(signerType string, signerPub []byte, txHash common.Hash, r, s *big.Int) bool {
	sig, err := rsSignatureBytes(r, s)
	if err != nil {
		return false
	}
	switch signerType {
	case SignerTypeSecp256k1:
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
		if len(signerPub) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(signerPub), txHash[:], sig)
	case SignerTypeBLS12381, SignerTypeFROST, SignerTypePQC:
		// These algorithms are tracked as signer types, but not representable via current tx (R,S) signature fields.
		return false
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
	case signatureMetaAlgFROST:
		return SignerTypeFROST, nil
	case signatureMetaAlgPQC:
		return SignerTypePQC, nil
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
	case SignerTypeFROST:
		return signatureMetaAlgFROST, nil
	case SignerTypePQC:
		return signatureMetaAlgPQC, nil
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
