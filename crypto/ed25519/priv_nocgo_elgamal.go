//go:build !cgo || !ed25519c

package ed25519

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/tos-network/gtos/crypto/ristretto255"
	"golang.org/x/crypto/sha3"
)

// ---------------------------------------------------------------------------
// CT (ciphertext) operations
// A ciphertext is 64 bytes: commitment[0:32] || handle[32:64]
// ---------------------------------------------------------------------------

// decodeCT splits a 64-byte ciphertext into two ristretto255 points.
func decodeCT(ct []byte) (commitment, handle *ristretto255.Element, err error) {
	if len(ct) != 64 {
		return nil, nil, ErrPrivInvalidInput
	}
	commitment, err = decodePoint(ct[:32])
	if err != nil {
		return nil, nil, err
	}
	handle, err = decodePoint(ct[32:64])
	if err != nil {
		return nil, nil, err
	}
	return commitment, handle, nil
}

// encodeCT serializes two points into a 64-byte ciphertext.
func encodeCT(commitment, handle *ristretto255.Element) []byte {
	out := make([]byte, 64)
	copy(out[:32], commitment.Bytes())
	copy(out[32:], handle.Bytes())
	return out
}

// ElgamalCTAddCompressed decompresses two 64-byte ciphertexts, adds
// corresponding halves, and returns the recompressed result.
func ElgamalCTAddCompressed(a64, b64 []byte) ([]byte, error) {
	aCom, aHan, err := decodeCT(a64)
	if err != nil {
		return nil, err
	}
	bCom, bHan, err := decodeCT(b64)
	if err != nil {
		return nil, err
	}
	rCom := ristretto255.NewIdentityElement().Add(aCom, bCom)
	rHan := ristretto255.NewIdentityElement().Add(aHan, bHan)
	return encodeCT(rCom, rHan), nil
}

// ElgamalCTSubCompressed decompresses two 64-byte ciphertexts, subtracts
// corresponding halves (a - b), and returns the recompressed result.
func ElgamalCTSubCompressed(a64, b64 []byte) ([]byte, error) {
	aCom, aHan, err := decodeCT(a64)
	if err != nil {
		return nil, err
	}
	bCom, bHan, err := decodeCT(b64)
	if err != nil {
		return nil, err
	}
	rCom := ristretto255.NewIdentityElement().Subtract(aCom, bCom)
	rHan := ristretto255.NewIdentityElement().Subtract(aHan, bHan)
	return encodeCT(rCom, rHan), nil
}

// ElgamalCTAddAmountCompressed adds amount*G to the commitment half of a
// ciphertext. The handle is unchanged.
func ElgamalCTAddAmountCompressed(in64 []byte, amount uint64) ([]byte, error) {
	com, han, err := decodeCT(in64)
	if err != nil {
		return nil, err
	}
	aG := ristretto255.NewIdentityElement().ScalarMult(u64ToLEScalar(amount), getBasepointG())
	rCom := ristretto255.NewIdentityElement().Add(com, aG)
	return encodeCT(rCom, han), nil
}

// ElgamalCTSubAmountCompressed subtracts amount*G from the commitment half of
// a ciphertext. The handle is unchanged.
func ElgamalCTSubAmountCompressed(in64 []byte, amount uint64) ([]byte, error) {
	com, han, err := decodeCT(in64)
	if err != nil {
		return nil, err
	}
	aG := ristretto255.NewIdentityElement().ScalarMult(u64ToLEScalar(amount), getBasepointG())
	rCom := ristretto255.NewIdentityElement().Subtract(com, aG)
	return encodeCT(rCom, han), nil
}

// ElgamalCTNormalizeCompressed decompresses and recompresses a ciphertext
// (canonicalization).
func ElgamalCTNormalizeCompressed(in64 []byte) ([]byte, error) {
	com, han, err := decodeCT(in64)
	if err != nil {
		return nil, err
	}
	return encodeCT(com, han), nil
}

// ElgamalCTZeroCompressed returns a 64-byte ciphertext where both halves are
// the identity element.
func ElgamalCTZeroCompressed() ([]byte, error) {
	id := ristretto255.NewIdentityElement()
	return encodeCT(id, ristretto255.NewIdentityElement().Zero()), nil
}

// ElgamalCTAddScalarCompressed adds scalar*G to the commitment half of a
// ciphertext. The handle is unchanged.
func ElgamalCTAddScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	com, han, err := decodeCT(in64)
	if err != nil {
		return nil, err
	}
	s, err := decodeScalar(scalar32)
	if err != nil {
		return nil, err
	}
	sG := ristretto255.NewIdentityElement().ScalarMult(s, getBasepointG())
	rCom := ristretto255.NewIdentityElement().Add(com, sG)
	return encodeCT(rCom, han), nil
}

// ElgamalCTSubScalarCompressed subtracts scalar*G from the commitment half of
// a ciphertext. The handle is unchanged.
func ElgamalCTSubScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	com, han, err := decodeCT(in64)
	if err != nil {
		return nil, err
	}
	s, err := decodeScalar(scalar32)
	if err != nil {
		return nil, err
	}
	sG := ristretto255.NewIdentityElement().ScalarMult(s, getBasepointG())
	rCom := ristretto255.NewIdentityElement().Subtract(com, sG)
	return encodeCT(rCom, han), nil
}

// ElgamalCTMulScalarCompressed multiplies BOTH halves (commitment and handle)
// of a ciphertext by a scalar.
func ElgamalCTMulScalarCompressed(in64, scalar32 []byte) ([]byte, error) {
	com, han, err := decodeCT(in64)
	if err != nil {
		return nil, err
	}
	s, err := decodeScalar(scalar32)
	if err != nil {
		return nil, err
	}
	rCom := ristretto255.NewIdentityElement().ScalarMult(s, com)
	rHan := ristretto255.NewIdentityElement().ScalarMult(s, han)
	return encodeCT(rCom, rHan), nil
}

// ---------------------------------------------------------------------------
// Key / encrypt / decrypt
// ---------------------------------------------------------------------------

// ElgamalPublicKeyFromPrivate derives PK = priv^(-1) * H.
func ElgamalPublicKeyFromPrivate(priv32 []byte) ([]byte, error) {
	priv, err := decodeScalar(priv32)
	if err != nil {
		return nil, err
	}
	if isScalarZero(priv) {
		return nil, ErrPrivInvalidInput
	}
	inv := ristretto255.NewScalar().Invert(priv)
	pk := ristretto255.NewIdentityElement().ScalarMult(inv, getPedersenH())
	return pk.Bytes(), nil
}

// ElgamalEncrypt encrypts an amount under a public key:
// random r, C = amount*G + r*H, D = r*PK, return C||D.
func ElgamalEncrypt(pub32 []byte, amount uint64) ([]byte, error) {
	pk, err := decodePoint(pub32)
	if err != nil {
		return nil, err
	}
	r, err := randomScalar()
	if err != nil {
		return nil, err
	}
	return elgamalEncryptCore(pk, amount, r)
}

// ElgamalEncryptWithOpening encrypts with a deterministic opening (r).
func ElgamalEncryptWithOpening(pub32 []byte, amount uint64, opening32 []byte) ([]byte, error) {
	pk, err := decodePoint(pub32)
	if err != nil {
		return nil, err
	}
	r, err := decodeScalar(opening32)
	if err != nil {
		return nil, err
	}
	return elgamalEncryptCore(pk, amount, r)
}

// ElgamalEncryptWithGeneratedOpening encrypts and also returns the opening.
func ElgamalEncryptWithGeneratedOpening(pub32 []byte, amount uint64) (ct64 []byte, opening32 []byte, err error) {
	pk, err := decodePoint(pub32)
	if err != nil {
		return nil, nil, err
	}
	r, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}
	ct, err := elgamalEncryptCore(pk, amount, r)
	if err != nil {
		return nil, nil, err
	}
	return ct, r.Bytes(), nil
}

// elgamalEncryptCore is the shared encryption logic.
// C = amount*G + r*H, D = r*PK
func elgamalEncryptCore(pk *ristretto255.Element, amount uint64, r *ristretto255.Scalar) ([]byte, error) {
	G := getBasepointG()
	H := getPedersenH()

	amtScalar := u64ToLEScalar(amount)

	// C = amount*G + r*H
	C := ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{amtScalar, r},
		[]*ristretto255.Element{G, H},
	)

	// D = r * PK
	D := ristretto255.NewIdentityElement().ScalarMult(r, pk)

	return encodeCT(C, D), nil
}

// ElgamalKeypairGenerate generates a random ElGamal keypair.
func ElgamalKeypairGenerate() (pub32 []byte, priv32 []byte, err error) {
	priv, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}
	privBytes := priv.Bytes()
	pubBytes, err := ElgamalPublicKeyFromPrivate(privBytes)
	if err != nil {
		return nil, nil, err
	}
	return pubBytes, privBytes, nil
}

// ElgamalDecryptToPoint decrypts a ciphertext to a point: C - priv * D.
func ElgamalDecryptToPoint(priv32, ct64 []byte) ([]byte, error) {
	priv, err := decodeScalar(priv32)
	if err != nil {
		return nil, err
	}
	if isScalarZero(priv) {
		return nil, ErrPrivInvalidInput
	}
	com, han, err := decodeCT(ct64)
	if err != nil {
		return nil, err
	}
	// M = C - priv * D
	privD := ristretto255.NewIdentityElement().ScalarMult(priv, han)
	M := ristretto255.NewIdentityElement().Subtract(com, privD)
	return M.Bytes(), nil
}

// ElgamalDecryptHandleWithOpening computes opening * PK (the handle for a
// given opening and public key).
func ElgamalDecryptHandleWithOpening(pub32, opening32 []byte) ([]byte, error) {
	pk, err := decodePoint(pub32)
	if err != nil {
		return nil, err
	}
	r, err := decodeScalar(opening32)
	if err != nil {
		return nil, err
	}
	handle := ristretto255.NewIdentityElement().ScalarMult(r, pk)
	return handle.Bytes(), nil
}

// ElgamalPublicKeyToAddress encodes a 32-byte public key as a Bech32 address.
func ElgamalPublicKeyToAddress(pub32 []byte, mainnet bool) (string, error) {
	if len(pub32) != 32 {
		return "", ErrPrivInvalidInput
	}

	// Prepend address type byte (0 = Normal)
	data := make([]byte, 33)
	data[0] = 0x00
	copy(data[1:], pub32)

	// Convert 8-bit groups to 5-bit groups
	converted, err := bech32ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", ErrPrivOperationFailed
	}

	hrp := "tos"
	if !mainnet {
		hrp = "tst"
	}
	encoded, err := bech32Encode(hrp, converted)
	if err != nil {
		return "", ErrPrivOperationFailed
	}
	return encoded, nil
}

// ---------------------------------------------------------------------------
// Pedersen commitments
// ---------------------------------------------------------------------------

// PedersenOpeningGenerate generates a random scalar for use as a Pedersen
// commitment opening.
func PedersenOpeningGenerate() ([]byte, error) {
	s, err := randomScalar()
	if err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

// PedersenCommitmentNew creates a Pedersen commitment with a random opening:
// C = amount*G + r*H.
func PedersenCommitmentNew(amount uint64) (commitment32 []byte, opening32 []byte, err error) {
	r, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}
	C := pedersenCommit(amount, r)
	return C.Bytes(), r.Bytes(), nil
}

// PedersenCommitmentWithOpening creates a Pedersen commitment with a given
// opening: C = amount*G + opening*H.
func PedersenCommitmentWithOpening(opening32 []byte, amount uint64) ([]byte, error) {
	r, err := decodeScalar(opening32)
	if err != nil {
		return nil, err
	}
	C := pedersenCommit(amount, r)
	return C.Bytes(), nil
}

// pedersenCommit computes amount*G + r*H.
func pedersenCommit(amount uint64, r *ristretto255.Scalar) *ristretto255.Element {
	G := getBasepointG()
	H := getPedersenH()
	amtScalar := u64ToLEScalar(amount)
	return ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{amtScalar, r},
		[]*ristretto255.Element{G, H},
	)
}

// ---------------------------------------------------------------------------
// Schnorr signature (SHA3-512 based, NOT Merlin)
// ---------------------------------------------------------------------------

// ElgamalSchnorrSign signs a message with a Schnorr signature over the
// ElGamal keypair. Uses SHA3-512 for the challenge hash.
//
//	PK = priv^(-1) * H
//	k  = random (64 random bytes reduced to scalar)
//	R  = k * H
//	e  = SHA3-512(PK || message || R) reduced mod L
//	s  = priv^(-1) * e + k
func ElgamalSchnorrSign(privkey [32]byte, message []byte) (s [32]byte, e [32]byte, err error) {
	priv, err := decodeScalar(privkey[:])
	if err != nil {
		return s, e, err
	}
	if isScalarZero(priv) {
		return s, e, ErrPrivInvalidInput
	}

	// Derive PK = priv^(-1) * H
	privInv := ristretto255.NewScalar().Invert(priv)
	H := getPedersenH()
	PK := ristretto255.NewIdentityElement().ScalarMult(privInv, H)

	// Generate random k: 64 random bytes reduced to scalar
	var kWide [64]byte
	if _, err := rand.Read(kWide[:]); err != nil {
		return s, e, ErrPrivOperationFailed
	}
	k, err := ristretto255.NewScalar().SetUniformBytes(kWide[:])
	if err != nil {
		return s, e, ErrPrivOperationFailed
	}
	if isScalarZero(k) {
		return s, e, ErrPrivOperationFailed
	}

	// R = k * H
	R := ristretto255.NewIdentityElement().ScalarMult(k, H)

	// e = SHA3-512(PK || message || R) reduced mod L
	hash := sha3.New512()
	hash.Write(PK.Bytes())
	hash.Write(message)
	hash.Write(R.Bytes())
	digest := hash.Sum(nil)

	eScalar, err := ristretto255.NewScalar().SetUniformBytes(digest)
	if err != nil {
		return s, e, ErrPrivOperationFailed
	}

	// s = priv^(-1) * e + k
	sScalar := ristretto255.NewScalar().Add(
		ristretto255.NewScalar().Multiply(privInv, eScalar),
		k,
	)

	copy(s[:], sScalar.Bytes())
	copy(e[:], eScalar.Bytes())
	return s, e, nil
}

// ElgamalSchnorrVerify verifies a Schnorr signature over the ElGamal public key.
//
//	R  = s*H + (-e)*PK
//	e' = SHA3-512(PK || message || R) reduced mod L
//	return e == e'
func ElgamalSchnorrVerify(pubkey [32]byte, message []byte, s [32]byte, e [32]byte) bool {
	sScalar, err := decodeScalar(s[:])
	if err != nil {
		return false
	}
	eScalar, err := decodeScalar(e[:])
	if err != nil {
		return false
	}

	PK, err := decodePoint(pubkey[:])
	if err != nil {
		return false
	}
	H := getPedersenH()

	// R = s*H + (-e)*PK
	negE := ristretto255.NewScalar().Negate(eScalar)
	R := ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{sScalar, negE},
		[]*ristretto255.Element{H, PK},
	)

	// e' = SHA3-512(PK || message || R) reduced mod L
	hash := sha3.New512()
	hash.Write(PK.Bytes())
	hash.Write(message)
	hash.Write(R.Bytes())
	digest := hash.Sum(nil)

	ePrime, err := ristretto255.NewScalar().SetUniformBytes(digest)
	if err != nil {
		return false
	}

	return eScalar.Equal(ePrime) == 1
}

// ---------------------------------------------------------------------------
// Bech32 encoding helpers (BIP-173)
// ---------------------------------------------------------------------------

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32Polymod computes the Bech32 checksum polymod.
func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expands the HRP for checksum computation.
func bech32HRPExpand(hrp string) []byte {
	ret := make([]byte, 0, len(hrp)*2+1)
	for _, c := range hrp {
		ret = append(ret, byte(c>>5))
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, byte(c&31))
	}
	return ret
}

// bech32CreateChecksum creates the 6-byte Bech32 checksum.
func bech32CreateChecksum(hrp string, data []byte) []byte {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	ret := make([]byte, 6)
	for i := 0; i < 6; i++ {
		ret[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}
	return ret
}

// bech32Encode encodes data (already in 5-bit groups) with the given HRP.
func bech32Encode(hrp string, data []byte) (string, error) {
	checksum := bech32CreateChecksum(hrp, data)
	combined := append(data, checksum...)
	var sb strings.Builder
	sb.Grow(len(hrp) + 1 + len(combined))
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, b := range combined {
		if int(b) >= len(bech32Charset) {
			return "", fmt.Errorf("bech32: invalid data byte %d", b)
		}
		sb.WriteByte(bech32Charset[b])
	}
	return sb.String(), nil
}

// bech32ConvertBits converts data between bit groups.
func bech32ConvertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	maxv := uint32((1 << toBits) - 1)
	var ret []byte
	for _, val := range data {
		if uint32(val)>>fromBits != 0 {
			return nil, fmt.Errorf("bech32: invalid data range")
		}
		acc = (acc << fromBits) | uint32(val)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits {
		return nil, fmt.Errorf("bech32: illegal zero padding")
	} else if (acc<<(toBits-bits))&maxv != 0 {
		return nil, fmt.Errorf("bech32: non-zero padding")
	}
	return ret, nil
}
