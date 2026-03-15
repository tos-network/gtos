//go:build !cgo || !ed25519c

package ed25519

import (
	"encoding/binary"

	"github.com/tos-network/gtos/crypto/ristretto255"
)

// ---------------------------------------------------------------------------
// Shield Proof (96 bytes: Y_H[32] || Y_P[32] || z[32])
// ---------------------------------------------------------------------------

// VerifyPrivShieldProof verifies a shield proof without chain context.
func VerifyPrivShieldProof(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64) error {
	return VerifyPrivShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey, amount, nil)
}

// VerifyPrivShieldProofWithContext verifies a shield proof with optional chain context.
func VerifyPrivShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64, ctx []byte) error {
	if len(proof96) != 96 || len(commitment) != 32 || len(receiverHandle) != 32 || len(receiverPubkey) != 32 {
		return ErrPrivInvalidInput
	}

	// Parse proof components.
	Y_H_bytes := proof96[0:32]
	Y_P_bytes := proof96[32:64]
	z_bytes := proof96[64:96]

	z, err := decodeScalar(z_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	C, err := decodePoint(commitment)
	if err != nil {
		return ErrPrivInvalidProof
	}
	D, err := decodePoint(receiverHandle)
	if err != nil {
		return ErrPrivInvalidProof
	}
	P, err := decodePoint(receiverPubkey)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y_H, err := decodePoint(Y_H_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y_P, err := decodePoint(Y_P_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	G := getBasepointG()
	H := getPedersenH()

	// Build transcript.
	t := newMerlinTranscript("shield-commitment-proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("dom-sep", []byte("shield-commitment-proof"))
	t.appendMessage("Y_H", Y_H_bytes)
	t.appendMessage("Y_P", Y_P_bytes)

	cWide := t.challengeBytes("c", 64)
	_ = t.challengeBytes("w", 64) // finalization, discard

	c, err := ristretto255.NewScalar().SetUniformBytes(cWide)
	if err != nil {
		return ErrPrivInvalidProof
	}

	// C_minus_aG = C - amount*G
	amountScalar := u64ToLEScalar(amount)
	aG := ristretto255.NewIdentityElement().ScalarMult(amountScalar, G)
	CminusAG := ristretto255.NewIdentityElement().Subtract(C, aG)

	// Check 1: z*H == Y_H + c*(C - amount*G)
	lhs1 := ristretto255.NewIdentityElement().ScalarMult(z, H)
	cTimesR := ristretto255.NewIdentityElement().ScalarMult(c, CminusAG)
	rhs1 := ristretto255.NewIdentityElement().Add(Y_H, cTimesR)
	if lhs1.Equal(rhs1) != 1 {
		return ErrPrivInvalidProof
	}

	// Check 2: z*P == Y_P + c*D
	lhs2 := ristretto255.NewIdentityElement().ScalarMult(z, P)
	cTimesD := ristretto255.NewIdentityElement().ScalarMult(c, D)
	rhs2 := ristretto255.NewIdentityElement().Add(Y_P, cTimesD)
	if lhs2.Equal(rhs2) != 1 {
		return ErrPrivInvalidProof
	}

	return nil
}

// ProvePrivShieldProof generates a shield proof without chain context.
func ProvePrivShieldProof(receiverPubkey []byte, amount uint64, opening32 []byte) (proof96 []byte, commitment32 []byte, receiverHandle32 []byte, err error) {
	return ProvePrivShieldProofWithContext(receiverPubkey, amount, opening32, nil)
}

// ProvePrivShieldProofWithContext generates a shield proof with optional chain context.
func ProvePrivShieldProofWithContext(receiverPubkey []byte, amount uint64, opening32 []byte, ctx []byte) (proof96 []byte, commitment32 []byte, receiverHandle32 []byte, err error) {
	if len(receiverPubkey) != 32 || len(opening32) != 32 {
		return nil, nil, nil, ErrPrivInvalidInput
	}
	// Validate opening is canonical.
	if _, err := decodeScalar(opening32); err != nil {
		return nil, nil, nil, ErrPrivInvalidInput
	}

	// Compute commitment and receiver handle.
	commitment32, err = PedersenCommitmentWithOpening(opening32, amount)
	if err != nil {
		return nil, nil, nil, ErrPrivOperationFailed
	}
	receiverHandle32, err = ElgamalDecryptHandleWithOpening(receiverPubkey, opening32)
	if err != nil {
		return nil, nil, nil, ErrPrivOperationFailed
	}

	H := getPedersenH()
	P, err := decodePoint(receiverPubkey)
	if err != nil {
		return nil, nil, nil, ErrPrivOperationFailed
	}

	// Random nonce k.
	k, err := randomScalar()
	if err != nil {
		return nil, nil, nil, ErrPrivOperationFailed
	}

	Y_H := ristretto255.NewIdentityElement().ScalarMult(k, H)
	Y_P := ristretto255.NewIdentityElement().ScalarMult(k, P)

	// Build transcript.
	t := newMerlinTranscript("shield-commitment-proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("dom-sep", []byte("shield-commitment-proof"))
	t.appendMessage("Y_H", Y_H.Bytes())
	t.appendMessage("Y_P", Y_P.Bytes())

	cWide := t.challengeBytes("c", 64)
	_ = t.challengeBytes("w", 64) // finalization, discard

	c, err := ristretto255.NewScalar().SetUniformBytes(cWide)
	if err != nil {
		return nil, nil, nil, ErrPrivOperationFailed
	}

	openingScalar, err := decodeScalar(opening32)
	if err != nil {
		return nil, nil, nil, ErrPrivOperationFailed
	}

	// z = c * opening + k
	z := scalarMulAdd(c, openingScalar, k)

	proof96 = make([]byte, 96)
	copy(proof96[0:32], Y_H.Bytes())
	copy(proof96[32:64], Y_P.Bytes())
	copy(proof96[64:96], z.Bytes())
	return proof96, commitment32, receiverHandle32, nil
}

// ---------------------------------------------------------------------------
// CT Validity Proof
// T0 (128 bytes): Y_0[32] + Y_1[32] + z_r[32] + z_x[32]
// T1 (160 bytes): Y_0[32] + Y_1[32] + Y_2[32] + z_r[32] + z_x[32]
// ---------------------------------------------------------------------------

// VerifyPrivCTValidityProof verifies a CT validity proof without chain context.
func VerifyPrivCTValidityProof(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool) error {
	return VerifyPrivCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey, txVersionT1, nil)
}

// VerifyPrivCTValidityProofWithContext verifies a CT validity proof with optional chain context.
func VerifyPrivCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool, ctx []byte) error {
	wantLen := 128
	if txVersionT1 {
		wantLen = 160
	}
	if len(proof) != wantLen || len(commitment) != 32 || len(senderHandle) != 32 || len(receiverHandle) != 32 || len(senderPubkey) != 32 || len(receiverPubkey) != 32 {
		return ErrPrivInvalidInput
	}

	// Parse proof.
	var Y_0_bytes, Y_1_bytes, Y_2_bytes, z_r_bytes, z_x_bytes []byte
	Y_0_bytes = proof[0:32]
	Y_1_bytes = proof[32:64]
	if txVersionT1 {
		Y_2_bytes = proof[64:96]
		z_r_bytes = proof[96:128]
		z_x_bytes = proof[128:160]
	} else {
		z_r_bytes = proof[64:96]
		z_x_bytes = proof[96:128]
	}

	z_r, err := decodeScalar(z_r_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	z_x, err := decodeScalar(z_x_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	C, err := decodePoint(commitment)
	if err != nil {
		return ErrPrivInvalidProof
	}
	D_receiver, err := decodePoint(receiverHandle)
	if err != nil {
		return ErrPrivInvalidProof
	}
	P_receiver, err := decodePoint(receiverPubkey)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y_0, err := decodePoint(Y_0_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y_1, err := decodePoint(Y_1_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	G := getBasepointG()
	H := getPedersenH()

	var D_sender, P_sender, Y_2 *ristretto255.Element
	if txVersionT1 {
		D_sender, err = decodePoint(senderHandle)
		if err != nil {
			return ErrPrivInvalidProof
		}
		P_sender, err = decodePoint(senderPubkey)
		if err != nil {
			return ErrPrivInvalidProof
		}
		Y_2, err = decodePoint(Y_2_bytes)
		if err != nil {
			return ErrPrivInvalidProof
		}
	}

	// Build transcript.
	t := newMerlinTranscript("validity-proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("dom-sep", []byte("validity-proof"))
	t.appendMessage("Y_0", Y_0_bytes)
	t.appendMessage("Y_1", Y_1_bytes)
	if txVersionT1 {
		t.appendMessage("Y_2", Y_2_bytes)
	}

	cWide := t.challengeBytes("c", 64)
	_ = t.challengeBytes("w", 64) // finalization, discard

	c, err := ristretto255.NewScalar().SetUniformBytes(cWide)
	if err != nil {
		return ErrPrivInvalidProof
	}

	// Check 1: z_x*G + z_r*H == Y_0 + c*C
	lhs1 := ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{z_x, z_r},
		[]*ristretto255.Element{G, H},
	)
	cC := ristretto255.NewIdentityElement().ScalarMult(c, C)
	rhs1 := ristretto255.NewIdentityElement().Add(Y_0, cC)
	if lhs1.Equal(rhs1) != 1 {
		return ErrPrivInvalidProof
	}

	// Check 2: z_r*P_receiver == Y_1 + c*D_receiver
	lhs2 := ristretto255.NewIdentityElement().ScalarMult(z_r, P_receiver)
	cD := ristretto255.NewIdentityElement().ScalarMult(c, D_receiver)
	rhs2 := ristretto255.NewIdentityElement().Add(Y_1, cD)
	if lhs2.Equal(rhs2) != 1 {
		return ErrPrivInvalidProof
	}

	// Check 3 (T1 only): z_r*P_sender == Y_2 + c*D_sender
	if txVersionT1 {
		lhs3 := ristretto255.NewIdentityElement().ScalarMult(z_r, P_sender)
		cDs := ristretto255.NewIdentityElement().ScalarMult(c, D_sender)
		rhs3 := ristretto255.NewIdentityElement().Add(Y_2, cDs)
		if lhs3.Equal(rhs3) != 1 {
			return ErrPrivInvalidProof
		}
	}

	return nil
}

// ProvePrivCTValidityProof generates a CT validity proof without chain context.
func ProvePrivCTValidityProof(senderPubkey, receiverPubkey []byte, amount uint64, opening32 []byte, txVersionT1 bool) (proof []byte, commitment32 []byte, senderHandle32 []byte, receiverHandle32 []byte, err error) {
	return ProvePrivCTValidityProofWithContext(senderPubkey, receiverPubkey, amount, opening32, txVersionT1, nil)
}

// ProvePrivCTValidityProofWithContext generates a CT validity proof with optional chain context.
func ProvePrivCTValidityProofWithContext(senderPubkey, receiverPubkey []byte, amount uint64, opening32 []byte, txVersionT1 bool, ctx []byte) (proof []byte, commitment32 []byte, senderHandle32 []byte, receiverHandle32 []byte, err error) {
	if len(senderPubkey) != 32 || len(receiverPubkey) != 32 || len(opening32) != 32 {
		return nil, nil, nil, nil, ErrPrivInvalidInput
	}
	if _, err := decodeScalar(opening32); err != nil {
		return nil, nil, nil, nil, ErrPrivInvalidInput
	}

	// Compute commitment and handles.
	commitment32, err = PedersenCommitmentWithOpening(opening32, amount)
	if err != nil {
		return nil, nil, nil, nil, ErrPrivOperationFailed
	}
	senderHandle32, err = ElgamalDecryptHandleWithOpening(senderPubkey, opening32)
	if err != nil {
		return nil, nil, nil, nil, ErrPrivOperationFailed
	}
	receiverHandle32, err = ElgamalDecryptHandleWithOpening(receiverPubkey, opening32)
	if err != nil {
		return nil, nil, nil, nil, ErrPrivOperationFailed
	}

	G := getBasepointG()
	H := getPedersenH()
	P_receiver, err := decodePoint(receiverPubkey)
	if err != nil {
		return nil, nil, nil, nil, ErrPrivOperationFailed
	}

	var P_sender *ristretto255.Element
	if txVersionT1 {
		P_sender, err = decodePoint(senderPubkey)
		if err != nil {
			return nil, nil, nil, nil, ErrPrivOperationFailed
		}
	}

	// Random nonces.
	y_r, err := randomScalar()
	if err != nil {
		return nil, nil, nil, nil, ErrPrivOperationFailed
	}
	y_x, err := randomScalar()
	if err != nil {
		return nil, nil, nil, nil, ErrPrivOperationFailed
	}

	// Y_0 = y_x*G + y_r*H
	Y_0 := ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{y_x, y_r},
		[]*ristretto255.Element{G, H},
	)
	// Y_1 = y_r*P_receiver
	Y_1 := ristretto255.NewIdentityElement().ScalarMult(y_r, P_receiver)

	var Y_2 *ristretto255.Element
	if txVersionT1 {
		// Y_2 = y_r*P_sender
		Y_2 = ristretto255.NewIdentityElement().ScalarMult(y_r, P_sender)
	}

	// Build transcript.
	t := newMerlinTranscript("validity-proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("dom-sep", []byte("validity-proof"))
	t.appendMessage("Y_0", Y_0.Bytes())
	t.appendMessage("Y_1", Y_1.Bytes())
	if txVersionT1 {
		t.appendMessage("Y_2", Y_2.Bytes())
	}

	cWide := t.challengeBytes("c", 64)
	_ = t.challengeBytes("w", 64) // finalization, discard

	c, err := ristretto255.NewScalar().SetUniformBytes(cWide)
	if err != nil {
		return nil, nil, nil, nil, ErrPrivOperationFailed
	}

	openingScalar, err := decodeScalar(opening32)
	if err != nil {
		return nil, nil, nil, nil, ErrPrivOperationFailed
	}
	amountScalar := u64ToLEScalar(amount)

	// z_r = c*opening + y_r
	z_r := scalarMulAdd(c, openingScalar, y_r)
	// z_x = c*amount + y_x
	z_x := scalarMulAdd(c, amountScalar, y_x)

	// Pack proof.
	if txVersionT1 {
		proof = make([]byte, 160)
		copy(proof[0:32], Y_0.Bytes())
		copy(proof[32:64], Y_1.Bytes())
		copy(proof[64:96], Y_2.Bytes())
		copy(proof[96:128], z_r.Bytes())
		copy(proof[128:160], z_x.Bytes())
	} else {
		proof = make([]byte, 128)
		copy(proof[0:32], Y_0.Bytes())
		copy(proof[32:64], Y_1.Bytes())
		copy(proof[64:96], z_r.Bytes())
		copy(proof[96:128], z_x.Bytes())
	}

	return proof, commitment32, senderHandle32, receiverHandle32, nil
}

// ---------------------------------------------------------------------------
// Commitment Equality Proof (192 bytes: Y_0[32] || Y_1[32] || Y_2[32] ||
//                                       z_s[32] || z_x[32] || z_r[32])
// ---------------------------------------------------------------------------

// commitmentEqProofVerify is the shared verification logic for commitment
// equality proofs, used by both VerifyPrivCommitmentEqProof and balance proofs.
func commitmentEqProofVerify(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte, t *merlinTranscript) error {
	if len(proof192) != 192 || len(sourcePubkey) != 32 || len(sourceCiphertext64) != 64 || len(destinationCommitment) != 32 {
		return ErrPrivInvalidInput
	}

	// Parse proof.
	Y_0_bytes := proof192[0:32]
	Y_1_bytes := proof192[32:64]
	Y_2_bytes := proof192[64:96]
	z_s_bytes := proof192[96:128]
	z_x_bytes := proof192[128:160]
	z_r_bytes := proof192[160:192]

	z_s, err := decodeScalar(z_s_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	z_x, err := decodeScalar(z_x_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	z_r, err := decodeScalar(z_r_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	P_source, err := decodePoint(sourcePubkey)
	if err != nil {
		return ErrPrivInvalidProof
	}
	C_source, err := decodePoint(sourceCiphertext64[0:32])
	if err != nil {
		return ErrPrivInvalidProof
	}
	D_source, err := decodePoint(sourceCiphertext64[32:64])
	if err != nil {
		return ErrPrivInvalidProof
	}
	C_dest, err := decodePoint(destinationCommitment)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y_0, err := decodePoint(Y_0_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y_1, err := decodePoint(Y_1_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y_2, err := decodePoint(Y_2_bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	G := getBasepointG()
	H := getPedersenH()

	// Transcript: append dom-sep, Y_0, Y_1, Y_2.
	t.appendMessage("dom-sep", []byte("equality-proof"))
	t.appendMessage("Y_0", Y_0_bytes)
	t.appendMessage("Y_1", Y_1_bytes)
	t.appendMessage("Y_2", Y_2_bytes)

	c := t.challengeScalar("c")

	t.appendMessage("z_s", z_s_bytes)
	t.appendMessage("z_x", z_x_bytes)
	t.appendMessage("z_r", z_r_bytes)

	w := t.challengeScalar("w")

	ww := ristretto255.NewScalar().Multiply(w, w)

	// Negate scalars.
	negC := ristretto255.NewScalar().Negate(c)
	negOne := ristretto255.NewScalar().Negate(ristretto255.NewScalar().Add(ristretto255.NewScalar().Zero(), u64ToLEScalar(1)))
	negW := ristretto255.NewScalar().Negate(w)
	negWW := ristretto255.NewScalar().Negate(ww)

	wZx := ristretto255.NewScalar().Multiply(w, z_x)
	wZs := ristretto255.NewScalar().Multiply(w, z_s)
	negWC := ristretto255.NewScalar().Multiply(negW, c)
	wwZx := ristretto255.NewScalar().Multiply(ww, z_x)
	wwZr := ristretto255.NewScalar().Multiply(ww, z_r)
	negWWC := ristretto255.NewScalar().Multiply(negWW, c)

	// 11-point multi-scalar multiplication.
	scalars := []*ristretto255.Scalar{
		z_s,    // 0: z_s * P_source
		negC,   // 1: -c * H
		negOne, // 2: -1 * Y_0
		wZx,    // 3: w*z_x * G
		wZs,    // 4: w*z_s * D_source
		negWC,  // 5: -w*c * C_source
		negW,   // 6: -w * Y_1
		wwZx,   // 7: ww*z_x * G
		wwZr,   // 8: ww*z_r * H
		negWWC, // 9: -ww*c * C_dest
		negWW,  // 10: -ww * Y_2
	}
	points := []*ristretto255.Element{
		P_source, // 0
		H,        // 1
		Y_0,      // 2
		G,        // 3
		D_source, // 4
		C_source, // 5
		Y_1,      // 6
		G,        // 7
		H,        // 8
		C_dest,   // 9
		Y_2,      // 10
	}

	result := ristretto255.NewIdentityElement().MultiScalarMult(scalars, points)
	identity := ristretto255.NewIdentityElement().Zero()
	if result.Equal(identity) != 1 {
		return ErrPrivInvalidProof
	}

	return nil
}

// commitmentEqProofProve is the shared proving logic for commitment equality proofs.
func commitmentEqProofProve(sourcePrivkey, sourcePubkey, sourceCiphertext64, destCommitment32, opening32 []byte, amount uint64, t *merlinTranscript) ([]byte, error) {
	if len(sourcePrivkey) != 32 || len(sourcePubkey) != 32 || len(sourceCiphertext64) != 64 || len(destCommitment32) != 32 || len(opening32) != 32 {
		return nil, ErrPrivInvalidInput
	}

	privkey, err := decodeScalar(sourcePrivkey)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	if isScalarZero(privkey) {
		return nil, ErrPrivInvalidInput
	}
	if _, err := decodeScalar(opening32); err != nil {
		return nil, ErrPrivInvalidInput
	}

	// Verify destination commitment matches.
	expectedCommit, err := PedersenCommitmentWithOpening(opening32, amount)
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	if len(expectedCommit) != 32 {
		return nil, ErrPrivOperationFailed
	}
	match := true
	for i := 0; i < 32; i++ {
		if expectedCommit[i] != destCommitment32[i] {
			match = false
			break
		}
	}
	if !match {
		return nil, ErrPrivInvalidInput
	}

	P_source, err := decodePoint(sourcePubkey)
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	D_source, err := decodePoint(sourceCiphertext64[32:64])
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	G := getBasepointG()
	H := getPedersenH()

	// Random nonces.
	y_s, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	y_x, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	y_r, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	// Y_0 = y_s * P_source
	Y_0 := ristretto255.NewIdentityElement().ScalarMult(y_s, P_source)

	// Y_1 = y_x*G + y_s*D_source
	Y_1 := ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{y_x, y_s},
		[]*ristretto255.Element{G, D_source},
	)

	// Y_2 = y_x*G + y_r*H
	Y_2 := ristretto255.NewIdentityElement().MultiScalarMult(
		[]*ristretto255.Scalar{y_x, y_r},
		[]*ristretto255.Element{G, H},
	)

	// Transcript.
	t.appendMessage("dom-sep", []byte("equality-proof"))
	t.appendMessage("Y_0", Y_0.Bytes())
	t.appendMessage("Y_1", Y_1.Bytes())
	t.appendMessage("Y_2", Y_2.Bytes())

	c := t.challengeScalar("c")

	amountScalar := u64ToLEScalar(amount)
	openingScalar, err := decodeScalar(opening32)
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	// z_s = c*privkey + y_s
	z_s := scalarMulAdd(c, privkey, y_s)
	// z_x = c*amount + y_x
	z_x := scalarMulAdd(c, amountScalar, y_x)
	// z_r = c*opening + y_r
	z_r := scalarMulAdd(c, openingScalar, y_r)

	t.appendMessage("z_s", z_s.Bytes())
	t.appendMessage("z_x", z_x.Bytes())
	t.appendMessage("z_r", z_r.Bytes())

	_ = t.challengeScalar("w") // finalization, discard

	proof := make([]byte, 192)
	copy(proof[0:32], Y_0.Bytes())
	copy(proof[32:64], Y_1.Bytes())
	copy(proof[64:96], Y_2.Bytes())
	copy(proof[96:128], z_s.Bytes())
	copy(proof[128:160], z_x.Bytes())
	copy(proof[160:192], z_r.Bytes())
	return proof, nil
}

// VerifyPrivCommitmentEqProof verifies a commitment equality proof without context.
func VerifyPrivCommitmentEqProof(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte) error {
	if len(proof192) != 192 || len(sourcePubkey) != 32 || len(sourceCiphertext64) != 64 || len(destinationCommitment) != 32 {
		return ErrPrivInvalidInput
	}
	t := newMerlinTranscript("new-commitment-proof")
	return commitmentEqProofVerify(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment, t)
}

// VerifyPrivCommitmentEqProofWithContext verifies a commitment equality proof with context.
func VerifyPrivCommitmentEqProofWithContext(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte, ctx []byte) error {
	if len(proof192) != 192 || len(sourcePubkey) != 32 || len(sourceCiphertext64) != 64 || len(destinationCommitment) != 32 {
		return ErrPrivInvalidInput
	}
	t := newMerlinTranscript("new-commitment-proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	return commitmentEqProofVerify(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment, t)
}

// ProvePrivCommitmentEqProof generates a commitment equality proof.
func ProvePrivCommitmentEqProof(sourcePrivkey, sourcePubkey, sourceCiphertext64, destCommitment32, opening32 []byte, amount uint64, ctx []byte) ([]byte, error) {
	if len(sourcePrivkey) != 32 || len(sourcePubkey) != 32 || len(sourceCiphertext64) != 64 || len(destCommitment32) != 32 || len(opening32) != 32 {
		return nil, ErrPrivInvalidInput
	}
	t := newMerlinTranscript("equality-proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	return commitmentEqProofProve(sourcePrivkey, sourcePubkey, sourceCiphertext64, destCommitment32, opening32, amount, t)
}

// ---------------------------------------------------------------------------
// Balance Proof (200 bytes: amount_BE[8] || eq_proof[192])
// ---------------------------------------------------------------------------

// openingOneBytes returns the scalar 1 as a 32-byte little-endian encoding.
func openingOneBytes() []byte {
	var buf [32]byte
	buf[0] = 1
	return buf[:]
}

// VerifyPrivBalanceProof verifies a balance proof without context.
func VerifyPrivBalanceProof(proof, publicKey, sourceCiphertext64 []byte) error {
	return VerifyPrivBalanceProofWithContext(proof, publicKey, sourceCiphertext64, nil)
}

// VerifyPrivBalanceProofWithContext verifies a balance proof with optional chain context.
func VerifyPrivBalanceProofWithContext(proof, publicKey, sourceCiphertext64 []byte, ctx []byte) error {
	if len(proof) != 200 || len(publicKey) != 32 || len(sourceCiphertext64) != 64 {
		return ErrPrivInvalidInput
	}

	// Parse amount (big-endian) from first 8 bytes.
	amount := binary.BigEndian.Uint64(proof[0:8])
	eqProof := proof[8:200]

	opening1 := openingOneBytes()

	// amount_ct = ElgamalEncryptWithOpening(publicKey, amount, opening_one)
	amountCT, err := ElgamalEncryptWithOpening(publicKey, amount, opening1)
	if err != nil {
		return ErrPrivInvalidProof
	}

	// zeroed = sourceCiphertext64 - amount_ct
	zeroed, err := ElgamalCTSubCompressed(sourceCiphertext64, amountCT)
	if err != nil {
		return ErrPrivInvalidProof
	}

	// dest_commit = PedersenCommitmentWithOpening(opening_one, 0)
	destCommit, err := PedersenCommitmentWithOpening(opening1, 0)
	if err != nil {
		return ErrPrivInvalidProof
	}

	// Transcript.
	t := newMerlinTranscript("balance_proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("dom-sep", []byte("balance-proof"))
	amountBE := u64ToBE8(amount)
	t.appendMessage("amount", amountBE[:])
	t.appendMessage("source_ct", sourceCiphertext64)

	return commitmentEqProofVerify(eqProof, publicKey, zeroed, destCommit, t)
}

// ProvePrivBalanceProof generates a balance proof without context.
func ProvePrivBalanceProof(sourcePrivkey32, sourceCiphertext64 []byte, amount uint64) ([]byte, error) {
	return ProvePrivBalanceProofWithContext(sourcePrivkey32, sourceCiphertext64, amount, nil)
}

// ProvePrivBalanceProofWithContext generates a balance proof with optional chain context.
func ProvePrivBalanceProofWithContext(sourcePrivkey32, sourceCiphertext64 []byte, amount uint64, ctx []byte) ([]byte, error) {
	if len(sourcePrivkey32) != 32 || len(sourceCiphertext64) != 64 {
		return nil, ErrPrivInvalidInput
	}
	privkey, err := decodeScalar(sourcePrivkey32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}
	if isScalarZero(privkey) {
		return nil, ErrPrivInvalidInput
	}

	// Derive public key.
	publicKey, err := ElgamalPublicKeyFromPrivate(sourcePrivkey32)
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	opening1 := openingOneBytes()

	// amount_ct = ElgamalEncryptWithOpening(publicKey, amount, opening_one)
	amountCT, err := ElgamalEncryptWithOpening(publicKey, amount, opening1)
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	// zeroed = sourceCiphertext64 - amount_ct
	zeroed, err := ElgamalCTSubCompressed(sourceCiphertext64, amountCT)
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	// dest_commit = PedersenCommitmentWithOpening(opening_one, 0)
	destCommit, err := PedersenCommitmentWithOpening(opening1, 0)
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	// Transcript.
	t := newMerlinTranscript("balance_proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("dom-sep", []byte("balance-proof"))
	amountBE := u64ToBE8(amount)
	t.appendMessage("amount", amountBE[:])
	t.appendMessage("source_ct", sourceCiphertext64)

	// Run commitment eq proof prove with amount=0, opening=1.
	eqProof, err := commitmentEqProofProve(sourcePrivkey32, publicKey, zeroed, destCommit, opening1, 0, t)
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	// Pack: amount_be[8] || eq_proof[192]
	result := make([]byte, 200)
	copy(result[0:8], amountBE[:])
	copy(result[8:200], eqProof)
	return result, nil
}
