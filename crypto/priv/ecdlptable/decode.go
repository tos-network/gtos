package ecdlptable

import (
	"errors"

	"github.com/tos-network/gtos/crypto/ristretto255"
)

// Decode finds m ∈ [0, maxAmount] such that msgPoint = m*G.
// msgPoint must be a 32-byte compressed Ristretto255 point (the output of
// DecryptToPoint applied to a Twisted ElGamal ciphertext).
//
// Returns (m, true, nil) on success, (0, false, nil) when m > maxAmount,
// or (0, false, err) on invalid input.
func (t *Table) Decode(msgPoint []byte, maxAmount uint64) (uint64, bool, error) {
	if len(msgPoint) != 32 {
		return 0, false, errors.New("ecdlptable: msgPoint must be 32 bytes")
	}

	identity := ristretto255.NewIdentityElement()

	P, err := ristretto255.NewIdentityElement().SetCanonicalBytes(msgPoint)
	if err != nil {
		return 0, false, errors.New("ecdlptable: invalid msgPoint encoding")
	}

	// m == 0 check.
	if P.Equal(identity) == 1 {
		return 0, true, nil
	}

	step := uint64(1) << t.l1
	maxJ := maxAmount/step + 1

	G := ristretto255.NewGeneratorElement()
	current := ristretto255.NewIdentityElement().Set(P)

	for j := uint64(0); j <= maxJ; j++ {
		// Check identity: current == 0 means m = j*step.
		if current.Equal(identity) == 1 {
			candidate := j * step
			if candidate <= maxAmount {
				return candidate, true, nil
			}
		}

		// Positive lookup: candidate = j*step + i.
		if m, ok := t.tryLookup(current, G, P, j, step, maxAmount, false); ok {
			return m, true, nil
		}

		// Negative lookup (negation trick): candidate = j*step - i.
		neg := ristretto255.NewIdentityElement().Negate(current)
		if m, ok := t.tryLookup(neg, G, P, j, step, maxAmount, true); ok {
			return m, true, nil
		}

		// Advance: current = current - stepPoint.
		current = ristretto255.NewIdentityElement().Subtract(current, t.stepPoint)
	}

	return 0, false, nil
}

// tryLookup searches the hash table for the fingerprint of point, then
// verifies each candidate with a full scalar-base multiplication.
func (t *Table) tryLookup(
	point *ristretto255.Element,
	G, P *ristretto255.Element,
	j, step, maxAmount uint64,
	negate bool,
) (uint64, bool) {
	encoded := point.Bytes()
	key := extractKey(encoded)
	// Also check the remapped key (see Generate: key=0 → key=1).
	candidates := t.ht.lookupAll(key)
	if key == 1 {
		// We might also have entries stored under the original key=1.
		// lookupAll already returns them. No extra work needed.
	}

	for _, i := range candidates {
		var candidate uint64
		if negate {
			if j*step < uint64(i) {
				continue
			}
			candidate = j*step - uint64(i)
		} else {
			candidate = j*step + uint64(i)
		}
		if candidate > maxAmount {
			continue
		}
		if verify(G, P, candidate) {
			return candidate, true
		}
	}
	return 0, false
}

// verify checks that candidate*G == P.
func verify(G, P *ristretto255.Element, candidate uint64) bool {
	s := u64ToScalar(candidate)
	check := ristretto255.NewIdentityElement().ScalarMult(s, G)
	return check.Equal(P) == 1
}

// u64ToScalar converts a uint64 to a Ristretto255 scalar (little-endian).
func u64ToScalar(v uint64) *ristretto255.Scalar {
	var buf [32]byte
	buf[0] = byte(v)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
	buf[3] = byte(v >> 24)
	buf[4] = byte(v >> 32)
	buf[5] = byte(v >> 40)
	buf[6] = byte(v >> 48)
	buf[7] = byte(v >> 56)
	s, _ := ristretto255.NewScalar().SetCanonicalBytes(buf[:])
	return s
}
