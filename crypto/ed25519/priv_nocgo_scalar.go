//go:build !cgo || !ed25519c

package ed25519

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/tos-network/gtos/crypto/ristretto255"
)

// randomScalar generates a random non-zero scalar.
func randomScalar() (*ristretto255.Scalar, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var wide [64]byte
		if _, err := rand.Read(wide[:]); err != nil {
			return nil, err
		}
		s, err := ristretto255.NewScalar().SetUniformBytes(wide[:])
		if err != nil {
			return nil, err
		}
		if s.Equal(ristretto255.NewScalar().Zero()) == 0 {
			return s, nil
		}
	}
	return nil, ErrPrivOperationFailed
}

// u64ToLEScalar converts a uint64 to a little-endian 32-byte scalar.
func u64ToLEScalar(v uint64) *ristretto255.Scalar {
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[:8], v)
	s, _ := ristretto255.NewScalar().SetCanonicalBytes(buf[:])
	return s
}

// u64ToBE8 converts a uint64 to big-endian 8 bytes.
func u64ToBE8(v uint64) [8]byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return buf
}

// scalarMulAdd computes a*b + c (mod L).
func scalarMulAdd(a, b, c *ristretto255.Scalar) *ristretto255.Scalar {
	return ristretto255.NewScalar().Add(
		ristretto255.NewScalar().Multiply(a, b), c,
	)
}

// decodeScalar decodes a 32-byte canonical scalar, returning an error if invalid.
func decodeScalar(b []byte) (*ristretto255.Scalar, error) {
	if len(b) != 32 {
		return nil, ErrPrivInvalidInput
	}
	s, err := ristretto255.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	return s, nil
}

// decodePoint decodes a 32-byte compressed ristretto255 point, returning an error if invalid.
func decodePoint(b []byte) (*ristretto255.Element, error) {
	if len(b) != 32 {
		return nil, ErrPrivInvalidInput
	}
	p, err := ristretto255.NewElement().SetCanonicalBytes(b)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	return p, nil
}

// isScalarZero checks if a scalar is zero.
func isScalarZero(s *ristretto255.Scalar) bool {
	return s.Equal(ristretto255.NewScalar().Zero()) == 1
}
