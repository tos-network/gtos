package uno

import (
	"errors"
	"math"
)

// SolveDiscreteLog finds m ∈ [0, maxAmount] such that m*G equals the message
// point embedded in msgPoint (32-byte compressed Ristretto255 commitment).
// msgPoint is obtained from DecryptToPoint applied to an ElGamal ciphertext.
//
// Uses Baby-Step Giant-Step: O(sqrt(maxAmount)) time and space.
// Returns (m, true, nil) on success, (0, false, nil) if m > maxAmount,
// or (0, false, err) on a cryptographic backend error.
func SolveDiscreteLog(msgPoint []byte, maxAmount uint64) (uint64, bool, error) {
	if len(msgPoint) != 32 {
		return 0, false, errors.New("uno: msgPoint must be 32 bytes")
	}

	zeroCT, err := ZeroCiphertextCompressed()
	if err != nil {
		return 0, false, err
	}

	n := uint64(math.Ceil(math.Sqrt(float64(maxAmount + 1))))

	// Baby steps: build table[commitment_bytes] = i for i*G, i in [0, n].
	// The commitment is the first 32 bytes of the 64-byte compressed ciphertext.
	table := make(map[[32]byte]uint64, n+1)
	babyCT := make([]byte, 64)
	copy(babyCT, zeroCT)
	var key [32]byte
	copy(key[:], babyCT[:32]) // 0*G = identity point
	table[key] = 0
	for i := uint64(1); i <= n; i++ {
		babyCT, err = AddAmountCompressed(babyCT, 1)
		if err != nil {
			return 0, false, err
		}
		copy(key[:], babyCT[:32])
		table[key] = i
	}

	// Giant steps: check (msgPoint - j*n*G) for j in [0, maxAmount/n+1].
	// Build a synthetic ciphertext with commitment=msgPoint and handle=identity.
	giantCT := make([]byte, 64)
	copy(giantCT[:32], msgPoint)
	copy(giantCT[32:], zeroCT[32:]) // handle = identity point
	maxJ := maxAmount/n + 1
	for j := uint64(0); j <= maxJ; j++ {
		copy(key[:], giantCT[:32])
		if babyI, ok := table[key]; ok {
			if result := j*n + babyI; result <= maxAmount {
				return result, true, nil
			}
		}
		if j < maxJ {
			giantCT, err = SubAmountCompressed(giantCT, n)
			if err != nil {
				return 0, false, err
			}
		}
	}
	return 0, false, nil
}
