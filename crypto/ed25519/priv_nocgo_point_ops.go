//go:build !cgo || !ed25519c

package ed25519

import "github.com/tos-network/gtos/crypto/ristretto255"

// ScalarMultPoint computes scalar32 * point32 and returns the 32-byte
// compressed Ristretto255 result.
func ScalarMultPoint(scalar32, point32 []byte) ([]byte, error) {
	if len(scalar32) != 32 || len(point32) != 32 {
		return nil, ErrPrivInvalidInput
	}
	s, err := decodeScalar(scalar32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	p, err := decodePoint(point32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	result := ristretto255.NewIdentityElement().ScalarMult(s, p)
	return result.Bytes(), nil
}

// PointSubtract computes a32 - b32 (point subtraction) and returns the
// 32-byte compressed Ristretto255 result.
func PointSubtract(a32, b32 []byte) ([]byte, error) {
	if len(a32) != 32 || len(b32) != 32 {
		return nil, ErrPrivInvalidInput
	}
	a, err := decodePoint(a32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	b, err := decodePoint(b32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	result := ristretto255.NewIdentityElement().Subtract(a, b)
	return result.Bytes(), nil
}
