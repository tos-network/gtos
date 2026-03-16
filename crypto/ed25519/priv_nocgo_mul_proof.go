//go:build !cgo || !ed25519c

package ed25519

import (
	"github.com/tos-network/gtos/crypto/ristretto255"
)

// ---------------------------------------------------------------------------
// Multiplication Proof (160 bytes: R1[32] || R2[32] || z_a[32] || z_ra[32] || z_s[32])
//
// Proves: the value committed in Com_c equals the product of the values
// committed in Com_a and Com_b, i.e., c = a * b, where
//   Com(x) = x*G + r_x*H  (Pedersen commitment).
//
// Key relation: a*Com_b - Com_c = (a*r_b - r_c)*H  (no G component).
//
// Sigma protocol:
//   Public:  Com_a, Com_b, Com_c  (32 bytes each)
//   Witness: a (plaintext of first operand), r_a (its blinding),
//            s = r_c - a*r_b  (blinding difference)
//
//   1. Prover picks random k_a, k_ra, k_s
//   2. R1 = k_a*G + k_ra*H           (opening proof for Com_a)
//      R2 = k_a*Com_b + k_s*H        (multiplication relation proof)
//   3. e = Merlin("gtos-mul-proof", Com_a, Com_b, Com_c, R1, R2).challengeScalar("e")
//   4. z_a  = k_a  + e*a    mod l
//      z_ra = k_ra + e*r_a  mod l
//      z_s  = k_s  + e*s    mod l
//
// Verification:
//   1. Recompute e from transcript
//   2. Check: z_a*G + z_ra*H == R1 + e*Com_a
//   3. Check: z_a*Com_b + z_s*H == R2 + e*Com_c
// ---------------------------------------------------------------------------

const mulProofSize = 160

// provePrivMulProof generates a multiplication Sigma proof.
//
// Inputs:
//   - comA, comB, comC: 32-byte Pedersen commitments
//   - aScalar32: 32-byte LE scalar for plaintext value a
//   - rA32, rB32, rC32: 32-byte LE scalar blindings for Com_a, Com_b, Com_c
//
// Returns a 160-byte proof.
func provePrivMulProof(comA, comB, comC, aScalar32, rA32, rB32, rC32 []byte) ([]byte, error) {
	if len(comA) != 32 || len(comB) != 32 || len(comC) != 32 ||
		len(aScalar32) != 32 || len(rA32) != 32 || len(rB32) != 32 || len(rC32) != 32 {
		return nil, ErrPrivInvalidInput
	}

	// Decode witness scalars.
	a, err := decodeScalar(aScalar32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	rA, err := decodeScalar(rA32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	rB, err := decodeScalar(rB32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	rC, err := decodeScalar(rC32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}

	// Decode public commitments.
	ComB, err := decodePoint(comB)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}

	G := getBasepointG()
	H := getPedersenH()

	// Compute s = r_c - a*r_b  (mod l).
	aRb := ristretto255.NewScalar().Multiply(a, rB)
	s := ristretto255.NewScalar().Subtract(rC, aRb)

	// Random nonces.
	kA, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	kRA, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	kS, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	// R1 = k_a*G + k_ra*H
	R1 := ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{kA, kRA},
		[]*ristretto255.Element{G, H},
	)

	// R2 = k_a*Com_b + k_s*H
	R2 := ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{kA, kS},
		[]*ristretto255.Element{ComB, H},
	)

	// Build transcript.
	t := newMerlinTranscript("gtos-mul-proof")
	t.appendMessage("dom-sep", []byte("mul-proof"))
	t.appendMessage("Com_a", comA)
	t.appendMessage("Com_b", comB)
	t.appendMessage("Com_c", comC)
	t.appendMessage("R1", R1.Bytes())
	t.appendMessage("R2", R2.Bytes())

	e := t.challengeScalar("e")

	// Responses.
	zA := scalarMulAdd(e, a, kA)    // z_a = e*a + k_a
	zRA := scalarMulAdd(e, rA, kRA) // z_ra = e*r_a + k_ra
	zS := scalarMulAdd(e, s, kS)    // z_s = e*s + k_s

	// Pack proof: R1[32] || R2[32] || z_a[32] || z_ra[32] || z_s[32]
	proof := make([]byte, mulProofSize)
	copy(proof[0:32], R1.Bytes())
	copy(proof[32:64], R2.Bytes())
	copy(proof[64:96], zA.Bytes())
	copy(proof[96:128], zRA.Bytes())
	copy(proof[128:160], zS.Bytes())
	return proof, nil
}

// verifyPrivMulProof verifies a multiplication proof.
//
// Inputs:
//   - proof160: 160-byte proof
//   - comA, comB, comC: 32-byte Pedersen commitments
func verifyPrivMulProof(proof160, comA, comB, comC []byte) error {
	if len(proof160) != mulProofSize || len(comA) != 32 || len(comB) != 32 || len(comC) != 32 {
		return ErrPrivInvalidInput
	}

	// Parse proof components.
	R1Bytes := proof160[0:32]
	R2Bytes := proof160[32:64]
	zABytes := proof160[64:96]
	zRABytes := proof160[96:128]
	zSBytes := proof160[128:160]

	R1, err := decodePoint(R1Bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	R2, err := decodePoint(R2Bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	zA, err := decodeScalar(zABytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	zRA, err := decodeScalar(zRABytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	zS, err := decodeScalar(zSBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	ComA, err := decodePoint(comA)
	if err != nil {
		return ErrPrivInvalidProof
	}
	ComB, err := decodePoint(comB)
	if err != nil {
		return ErrPrivInvalidProof
	}
	ComC, err := decodePoint(comC)
	if err != nil {
		return ErrPrivInvalidProof
	}

	G := getBasepointG()
	H := getPedersenH()

	// Rebuild transcript.
	t := newMerlinTranscript("gtos-mul-proof")
	t.appendMessage("dom-sep", []byte("mul-proof"))
	t.appendMessage("Com_a", comA)
	t.appendMessage("Com_b", comB)
	t.appendMessage("Com_c", comC)
	t.appendMessage("R1", R1Bytes)
	t.appendMessage("R2", R2Bytes)

	e := t.challengeScalar("e")
	negE := ristretto255.NewScalar().Negate(e)

	// Check 1: z_a*G + z_ra*H - e*Com_a - R1 == 0
	//   i.e. z_a*G + z_ra*H + (-e)*Com_a + (-1)*R1 == identity
	negOne := ristretto255.NewScalar().Negate(
		ristretto255.NewScalar().Add(ristretto255.NewScalar().Zero(), u64ToLEScalar(1)),
	)
	check1 := ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{zA, zRA, negE, negOne},
		[]*ristretto255.Element{G, H, ComA, R1},
	)
	identity := ristretto255.NewIdentityElement().Zero()
	if check1.Equal(identity) != 1 {
		return ErrPrivInvalidProof
	}

	// Check 2: z_a*Com_b + z_s*H - e*Com_c - R2 == 0
	check2 := ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{zA, zS, negE, negOne},
		[]*ristretto255.Element{ComB, H, ComC, R2},
	)
	if check2.Equal(identity) != 1 {
		return ErrPrivInvalidProof
	}

	return nil
}

// VerifyPrivMulProof is the exported verification function for multiplication proofs.
func VerifyPrivMulProof(proof160, comA, comB, comC []byte) error {
	return verifyPrivMulProof(proof160, comA, comB, comC)
}

// ProvePrivMulProof is the exported proving function for multiplication proofs.
func ProvePrivMulProof(comA, comB, comC, aScalar32, rA32, rB32, rC32 []byte) ([]byte, error) {
	return provePrivMulProof(comA, comB, comC, aScalar32, rA32, rB32, rC32)
}
