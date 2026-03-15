package bls12381

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
)

const (
	hashToFieldSecurityBytes = 16
	sha256BlockBytes         = 64
	sha256OutputBytes        = 32
)

var modulusBig = modulus.big()

func oversizedDST(dst []byte) []byte {
	sum := sha256.Sum256(append([]byte("H2C-OVERSIZE-DST-"), dst...))
	return sum[:]
}

func expandMessageXMD(msg []byte, dst []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("invalid output length")
	}
	if len(dst) > 255 {
		dst = oversizedDST(dst)
	}
	if len(dst) > 255 {
		return nil, errors.New("domain separation tag too large")
	}
	ell := (outLen + sha256OutputBytes - 1) / sha256OutputBytes
	if ell > 255 {
		return nil, errors.New("invalid output length")
	}
	dstPrime := make([]byte, 0, len(dst)+1)
	dstPrime = append(dstPrime, dst...)
	dstPrime = append(dstPrime, byte(len(dst)))

	zPad := make([]byte, sha256BlockBytes)
	libStr := []byte{byte(outLen >> 8), byte(outLen)}

	b0Input := make([]byte, 0, len(zPad)+len(msg)+len(libStr)+1+len(dstPrime))
	b0Input = append(b0Input, zPad...)
	b0Input = append(b0Input, msg...)
	b0Input = append(b0Input, libStr...)
	b0Input = append(b0Input, 0x00)
	b0Input = append(b0Input, dstPrime...)
	b0 := sha256.Sum256(b0Input)

	b1Input := make([]byte, 0, len(b0)+1+len(dstPrime))
	b1Input = append(b1Input, b0[:]...)
	b1Input = append(b1Input, 0x01)
	b1Input = append(b1Input, dstPrime...)
	b1 := sha256.Sum256(b1Input)

	out := make([]byte, 0, ell*sha256OutputBytes)
	out = append(out, b1[:]...)

	prev := b1[:]
	for i := 2; i <= ell; i++ {
		xor := make([]byte, sha256OutputBytes)
		for j := 0; j < sha256OutputBytes; j++ {
			xor[j] = b0[j] ^ prev[j]
		}
		biInput := make([]byte, 0, len(xor)+1+len(dstPrime))
		biInput = append(biInput, xor...)
		biInput = append(biInput, byte(i))
		biInput = append(biInput, dstPrime...)
		bi := sha256.Sum256(biInput)
		out = append(out, bi[:]...)
		prev = bi[:]
	}
	return out[:outLen], nil
}

func hashToFieldBase(chunk []byte) (*fe, error) {
	if len(chunk) == 0 {
		return nil, errors.New("empty field input")
	}
	v := new(big.Int).SetBytes(chunk)
	v.Mod(v, modulusBig)
	return fromBig(v)
}

func hashToFieldG1(msg []byte, dst []byte, count int) ([]*fe, error) {
	if count <= 0 {
		return nil, errors.New("invalid count")
	}
	l := (modulusBig.BitLen() + 8*hashToFieldSecurityBytes + 7) / 8
	uniform, err := expandMessageXMD(msg, dst, count*l)
	if err != nil {
		return nil, err
	}
	out := make([]*fe, 0, count)
	for i := 0; i < count; i++ {
		elem, err := hashToFieldBase(uniform[i*l : (i+1)*l])
		if err != nil {
			return nil, err
		}
		out = append(out, elem)
	}
	return out, nil
}

func hashToFieldG2(msg []byte, dst []byte, count int) ([]*fe2, error) {
	if count <= 0 {
		return nil, errors.New("invalid count")
	}
	l := (modulusBig.BitLen() + 8*hashToFieldSecurityBytes + 7) / 8
	uniform, err := expandMessageXMD(msg, dst, count*2*l)
	if err != nil {
		return nil, err
	}
	out := make([]*fe2, 0, count)
	for i := 0; i < count; i++ {
		c0, err := hashToFieldBase(uniform[(i*2)*l : (i*2+1)*l])
		if err != nil {
			return nil, err
		}
		c1, err := hashToFieldBase(uniform[(i*2+1)*l : (i*2+2)*l])
		if err != nil {
			return nil, err
		}
		out = append(out, &fe2{*c0, *c1})
	}
	return out, nil
}

// EncodeToG1 hashes a message to a curve point without random oracle composition.
func EncodeToG1(msg []byte, dst []byte) (*PointG1, error) {
	fieldElems, err := hashToFieldG1(msg, dst, 1)
	if err != nil {
		return nil, err
	}
	uBytes := toBytes(fieldElems[0])
	return NewG1().MapToCurve(uBytes)
}

// HashToG1 hashes a message to a G1 point using the random-oracle construction.
func HashToG1(msg []byte, dst []byte) (*PointG1, error) {
	fieldElems, err := hashToFieldG1(msg, dst, 2)
	if err != nil {
		return nil, err
	}
	g1 := NewG1()
	q0, err := g1.MapToCurve(toBytes(fieldElems[0]))
	if err != nil {
		return nil, err
	}
	q1, err := g1.MapToCurve(toBytes(fieldElems[1]))
	if err != nil {
		return nil, err
	}
	return g1.Affine(g1.Add(g1.New(), q0, q1)), nil
}

// EncodeToG2 hashes a message to a curve point without random oracle composition.
func EncodeToG2(msg []byte, dst []byte) (*PointG2, error) {
	fieldElems, err := hashToFieldG2(msg, dst, 1)
	if err != nil {
		return nil, err
	}
	fp2 := newFp2()
	return NewG2().MapToCurve(fp2.toBytes(fieldElems[0]))
}

// HashToG2 hashes a message to a G2 point using the random-oracle construction.
func HashToG2(msg []byte, dst []byte) (*PointG2, error) {
	fieldElems, err := hashToFieldG2(msg, dst, 2)
	if err != nil {
		return nil, err
	}
	fp2 := newFp2()
	g2 := NewG2()
	q0, err := g2.MapToCurve(fp2.toBytes(fieldElems[0]))
	if err != nil {
		return nil, err
	}
	q1, err := g2.MapToCurve(fp2.toBytes(fieldElems[1]))
	if err != nil {
		return nil, err
	}
	return g2.Affine(g2.Add(g2.New(), q0, q1)), nil
}

func lexicographicallyLargest(y, negY []byte) bool {
	return bytes.Compare(y, negY) > 0
}
