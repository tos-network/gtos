//go:build !cgo || !ed25519c

package ed25519

import (
	"github.com/tos-network/gtos/crypto/ristretto255"
)

// ---------------------------------------------------------------------------
// Bulletproof range proof verification, proving, and aggregated proving
// ---------------------------------------------------------------------------

// validBitLength returns true if n is a valid bit length for batched range proofs.
func validBitLength(n uint64) bool {
	switch n {
	case 1, 2, 4, 8, 16, 32, 64, 128:
		return true
	}
	return false
}

// isPowerOf2 returns true if n > 0 and n is a power of 2.
func isPowerOf2(n uint64) bool {
	return n > 0 && (n&(n-1)) == 0
}

// log2 returns floor(log2(n)) for n > 0.
func log2u(n uint64) int {
	r := 0
	for n >>= 1; n > 0; n >>= 1 {
		r++
	}
	return r
}

// isIdentityBytes returns true if the 32 bytes are all zero (ristretto identity).
func isIdentityBytes(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}

// validateAndAppendPoint checks the point bytes are not identity, then appends to transcript.
func validateAndAppendPoint(t *merlinTranscript, label string, pointBytes []byte) error {
	if isIdentityBytes(pointBytes) {
		return ErrPrivInvalidProof
	}
	t.appendMessage(label, pointBytes)
	return nil
}

// rangeproofsDelta computes the delta term used in bulletproofs verification.
//
//	delta = (z - z^2) * sum_of_powers_y(nm) - sum over batches of (-z^(2+j) * (2^bitLen - 1))
func rangeproofsDelta(nm uint64, y, z, zz *ristretto255.Scalar, bitLengths []byte, batchLen int) *ristretto255.Scalar {
	// Compute sum_of_powers_y = y + y^2 + ... + y^nm using doubling trick.
	// exp_y starts at y, sum starts at y+1.
	expY := ristretto255.NewScalar().Set(y)
	one := u64ToLEScalar(1)
	sumPowY := ristretto255.NewScalar().Add(y, one)
	for i := nm; i > 2; i /= 2 {
		expY = ristretto255.NewScalar().Multiply(expY, expY)
		// sum = exp_y * sum + sum
		sumPowY = ristretto255.NewScalar().Add(
			ristretto255.NewScalar().Multiply(expY, sumPowY),
			sumPowY,
		)
	}

	// delta = (z - zz) * sum_of_powers_y
	delta := ristretto255.NewScalar().Subtract(z, zz)
	delta = ristretto255.NewScalar().Multiply(delta, sumPowY)

	// neg_exp_z starts at -z^2
	negExpZ := ristretto255.NewScalar().Negate(zz)
	for i := 0; i < batchLen; i++ {
		// sum_2 = 2^bitLen - 1: bitLengths[i]/8 bytes of 0xFF in LE
		var sum2Bytes [32]byte
		nBytes := int(bitLengths[i]) / 8
		for j := 0; j < nBytes && j < 32; j++ {
			sum2Bytes[j] = 0xFF
		}
		sum2, _ := ristretto255.NewScalar().SetCanonicalBytes(sum2Bytes[:])

		negExpZ = ristretto255.NewScalar().Multiply(negExpZ, z)
		// delta += neg_exp_z * sum_2
		delta = scalarMulAdd(negExpZ, sum2, delta)
	}

	return delta
}

// VerifyPrivRangeProof verifies a Bulletproof range proof.
func VerifyPrivRangeProof(proof []byte, commitments []byte, bitLengths []byte, batchLen uint8) error {
	if batchLen == 0 {
		return ErrPrivInvalidInput
	}
	bl := int(batchLen)
	if len(commitments) != bl*32 {
		return ErrPrivInvalidInput
	}
	if len(bitLengths) != bl {
		return ErrPrivInvalidInput
	}

	// Compute nm = sum of bit lengths
	var nm uint64
	for i := 0; i < bl; i++ {
		if !validBitLength(uint64(bitLengths[i])) {
			return ErrPrivInvalidInput
		}
		nm += uint64(bitLengths[i])
	}
	if nm == 0 || nm > 256 || !isPowerOf2(nm) {
		return ErrPrivInvalidInput
	}
	logn := log2u(nm)
	if logn > 8 {
		return ErrPrivInvalidInput
	}
	n := int(nm)

	// Expected proof size: 224 + 2*logn*32 + 64
	expectedSize := 224 + 2*logn*32 + 64
	if len(proof) != expectedSize {
		return ErrPrivInvalidInput
	}

	// Parse proof
	aBytes := proof[0:32]
	sBytes := proof[32:64]
	t1Bytes := proof[64:96]
	t2Bytes := proof[96:128]
	txBytes := proof[128:160]
	txbBytes := proof[160:192]
	ebBytes := proof[192:224]

	// L,R pairs
	lrOffset := 224
	lBytes := make([][]byte, logn)
	rBytes := make([][]byte, logn)
	for i := 0; i < logn; i++ {
		lBytes[i] = proof[lrOffset : lrOffset+32]
		lrOffset += 32
		rBytes[i] = proof[lrOffset : lrOffset+32]
		lrOffset += 32
	}
	ippABytes := proof[lrOffset : lrOffset+32]
	ippBBytes := proof[lrOffset+32 : lrOffset+64]

	// Validate scalars
	tx, err := decodeScalar(txBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	txb, err := decodeScalar(txbBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	eb, err := decodeScalar(ebBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	ippA, err := decodeScalar(ippABytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	ippB, err := decodeScalar(ippBBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	// Decompress points
	aRes, err := decodePoint(aBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	// points[0] = G (basepoint), points[1] = H (Pedersen), points[2] = S, points[3] = T1, points[4] = T2
	// then commitments, then L's, then R's, then H generators (n), then G generators (n)
	totalPoints := 5 + bl + 2*logn + 2*n
	points := make([]*ristretto255.Element, totalPoints)
	points[0] = getBasepointG()
	points[1] = getPedersenH()

	sPoint, err := decodePoint(sBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	points[2] = sPoint

	t1Point, err := decodePoint(t1Bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	points[3] = t1Point

	t2Point, err := decodePoint(t2Bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	points[4] = t2Point

	idx := 5
	for i := 0; i < bl; i++ {
		p, err := decodePoint(commitments[i*32 : (i+1)*32])
		if err != nil {
			return ErrPrivInvalidProof
		}
		points[idx] = p
		idx++
	}
	for i := 0; i < logn; i++ {
		p, err := decodePoint(lBytes[i])
		if err != nil {
			return ErrPrivInvalidProof
		}
		points[idx] = p
		idx++
	}
	for i := 0; i < logn; i++ {
		p, err := decodePoint(rBytes[i])
		if err != nil {
			return ErrPrivInvalidProof
		}
		points[idx] = p
		idx++
	}

	// Append H generators, then G generators
	initBPGenerators()
	for i := 0; i < n; i++ {
		points[idx] = bpGenH[i]
		idx++
	}
	for i := 0; i < n; i++ {
		points[idx] = bpGenG[i]
		idx++
	}

	// --- Transcript ---
	transcript := newMerlinTranscript("transaction-proof")
	// Domain separator
	transcript.appendMessage("dom-sep", []byte("rangeproof v1"))
	transcript.appendU64("n", nm)
	transcript.appendU64("m", uint64(batchLen))

	// Append commitments
	for i := 0; i < bl; i++ {
		transcript.appendMessage("V", commitments[i*32:(i+1)*32])
	}

	// Validate and append A, S
	if err := validateAndAppendPoint(transcript, "A", aBytes); err != nil {
		return ErrPrivInvalidProof
	}
	if err := validateAndAppendPoint(transcript, "S", sBytes); err != nil {
		return ErrPrivInvalidProof
	}

	// Challenges y, z
	y := transcript.challengeScalar("y")
	z := transcript.challengeScalar("z")

	// Validate and append T1, T2
	if err := validateAndAppendPoint(transcript, "T_1", t1Bytes); err != nil {
		return ErrPrivInvalidProof
	}
	if err := validateAndAppendPoint(transcript, "T_2", t2Bytes); err != nil {
		return ErrPrivInvalidProof
	}

	// Challenge x
	x := transcript.challengeScalar("x")

	// Append scalars
	transcript.appendMessage("t_x", txBytes)
	transcript.appendMessage("t_x_blinding", txbBytes)
	transcript.appendMessage("e_blinding", ebBytes)

	// Challenge w
	w := transcript.challengeScalar("w")

	// c = 1 for single verification
	c := u64ToLEScalar(1)

	// IPP domain separator
	transcript.appendMessage("dom-sep", []byte("ipp v1"))
	transcript.appendU64("n", nm)

	// IPP challenges
	u := make([]*ristretto255.Scalar, logn)
	for i := 0; i < logn; i++ {
		if err := validateAndAppendPoint(transcript, "L", lBytes[i]); err != nil {
			return ErrPrivInvalidProof
		}
		if err := validateAndAppendPoint(transcript, "R", rBytes[i]); err != nil {
			return ErrPrivInvalidProof
		}
		u[i] = transcript.challengeScalar("u")
	}

	// Batch inversion: compute y_inv, u_inv[i], and allinv
	yInv := ristretto255.NewScalar().Invert(y)
	uInv := make([]*ristretto255.Scalar, logn)
	allinv := ristretto255.NewScalar().Set(yInv)
	for i := 0; i < logn; i++ {
		uInv[i] = ristretto255.NewScalar().Invert(u[i])
		allinv = ristretto255.NewScalar().Multiply(allinv, uInv[i])
	}

	// u_sq[k] = u[k]^2
	uSq := make([]*ristretto255.Scalar, logn)
	for i := 0; i < logn; i++ {
		uSq[i] = ristretto255.NewScalar().Multiply(u[i], u[i])
	}

	// Compute s[i] values
	s := make([]*ristretto255.Scalar, n)
	// s[0] = allinv * y (= product of u_inv)
	s[0] = ristretto255.NewScalar().Multiply(allinv, y)
	for k := 0; k < logn; k++ {
		powk := 1 << uint(k)
		for j := 0; j < powk; j++ {
			i := powk + j
			s[i] = ristretto255.NewScalar().Multiply(s[j], uSq[logn-1-k])
		}
	}

	// --- Build scalar array ---
	scalars := make([]*ristretto255.Scalar, totalPoints)

	// H scalar: -(eb + c * txb)
	scalars[1] = ristretto255.NewScalar().Negate(scalarMulAdd(c, txb, eb))

	// S scalar: x
	scalars[2] = ristretto255.NewScalar().Set(x)

	// T1 scalar: c * x
	cx := ristretto255.NewScalar().Multiply(c, x)
	scalars[3] = ristretto255.NewScalar().Set(cx)

	// T2 scalar: c * x^2
	xx := ristretto255.NewScalar().Multiply(x, x)
	scalars[4] = ristretto255.NewScalar().Multiply(c, xx)

	// Commitment scalars: c*z^2, c*z^3, ...
	zz := ristretto255.NewScalar().Multiply(z, z)
	cz2 := ristretto255.NewScalar().Multiply(zz, c)
	scalars[5] = ristretto255.NewScalar().Set(cz2)
	scIdx := 6
	for i := 1; i < bl; i++ {
		scalars[scIdx] = ristretto255.NewScalar().Multiply(scalars[scIdx-1], z)
		scIdx++
	}

	// L scalars: u[k]^2
	for i := 0; i < logn; i++ {
		scalars[scIdx] = ristretto255.NewScalar().Set(uSq[i])
		scIdx++
	}
	// R scalars: u_inv[k]^2
	uInvSq := make([]*ristretto255.Scalar, logn)
	for i := 0; i < logn; i++ {
		uInvSq[i] = ristretto255.NewScalar().Multiply(uInv[i], uInv[i])
		scalars[scIdx] = ristretto255.NewScalar().Set(uInvSq[i])
		scIdx++
	}

	// H generators scalars
	minusB := ristretto255.NewScalar().Negate(ippB)
	expZ := ristretto255.NewScalar().Set(zz)
	zAnd2 := ristretto255.NewScalar().Set(expZ)
	expYInv := ristretto255.NewScalar().Set(y)

	j := 0
	m := 0
	for i := 0; i < n; i++ {
		if j == int(bitLengths[m]) {
			j = 0
			m++
			expZ = ristretto255.NewScalar().Multiply(expZ, z)
			zAnd2 = ristretto255.NewScalar().Set(expZ)
		}
		if j != 0 {
			zAnd2 = ristretto255.NewScalar().Add(zAnd2, zAnd2)
		}
		expYInv = ristretto255.NewScalar().Multiply(expYInv, yInv)
		// scalar = s[n-1-i] * (-b) + z_and_2
		tmp := scalarMulAdd(s[n-1-i], minusB, zAnd2)
		// scalar = tmp * exp_y_inv + z
		scalars[scIdx] = scalarMulAdd(tmp, expYInv, z)
		scIdx++
		j++
	}

	// G generators scalars
	minusZ := ristretto255.NewScalar().Negate(z)
	minusA := ristretto255.NewScalar().Negate(ippA)
	for i := 0; i < n; i++ {
		scalars[scIdx] = scalarMulAdd(s[i], minusA, minusZ)
		scIdx++
	}

	// G basepoint scalar (index 0)
	delta := rangeproofsDelta(nm, y, z, zz, bitLengths, bl)
	// scalars[0] = (-a)*b + tx
	g0 := scalarMulAdd(minusA, ippB, tx)
	// delta = (delta - tx) * c
	deltaMinusTx := ristretto255.NewScalar().Subtract(delta, tx)
	deltaMinusTx = ristretto255.NewScalar().Multiply(deltaMinusTx, c)
	// scalars[0] = g0 * w + deltaMinusTx
	scalars[0] = scalarMulAdd(g0, w, deltaMinusTx)

	// MSM
	res := ristretto255.NewElement().VarTimeMultiScalarMult(scalars, points)

	// Check res + a_res == identity (i.e., res == -a_res)
	checkPoint := ristretto255.NewElement().Add(res, aRes)
	if checkPoint.Equal(ristretto255.NewIdentityElement()) != 1 {
		return ErrPrivInvalidProof
	}

	return nil
}

// ProvePrivRangeProof generates a Bulletproof range proof for a single 64-bit value.
// Returns 672 bytes of proof data.
func ProvePrivRangeProof(commitment32 []byte, value uint64, blinding32 []byte) ([]byte, error) {
	if len(commitment32) != 32 || len(blinding32) != 32 {
		return nil, ErrPrivInvalidInput
	}
	initBPGenerators()

	const bpN = 64
	const bpLogN = 6

	blinding, err := decodeScalar(blinding32)
	if err != nil {
		return nil, ErrPrivInvalidInput
	}

	proof := make([]byte, 672)

	// Step 1: Bit decompose value
	var aL [bpN]byte
	for i := 0; i < bpN; i++ {
		aL[i] = byte((value >> uint(i)) & 1)
	}

	// Step 2: Generate random blindings
	aBlinding, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	sBlinding, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	sL := make([]*ristretto255.Scalar, bpN)
	sR := make([]*ristretto255.Scalar, bpN)
	for i := 0; i < bpN; i++ {
		sL[i], err = randomScalar()
		if err != nil {
			return nil, ErrPrivOperationFailed
		}
		sR[i], err = randomScalar()
		if err != nil {
			return nil, ErrPrivOperationFailed
		}
	}

	// Step 3: Compute A = aBlinding*H_ped + sum(aL[i]*G[i] + (aL[i]-1)*H[i])
	one := u64ToLEScalar(1)
	{
		msmLen := 1 + 2*bpN
		aScalars := make([]*ristretto255.Scalar, msmLen)
		aPoints := make([]*ristretto255.Element, msmLen)
		aScalars[0] = aBlinding
		aPoints[0] = getPedersenH()
		for i := 0; i < bpN; i++ {
			aScalars[1+2*i] = u64ToLEScalar(uint64(aL[i]))
			aPoints[1+2*i] = bpGenG[i]
			// aR[i] = aL[i] - 1
			aScalars[2+2*i] = ristretto255.NewScalar().Subtract(u64ToLEScalar(uint64(aL[i])), one)
			aPoints[2+2*i] = bpGenH[i]
		}
		aPoint := ristretto255.NewElement().MultiScalarMult(aScalars, aPoints)
		copy(proof[0:32], aPoint.Bytes())
	}

	// Step 4: Compute S = sBlinding*H_ped + sum(sL[i]*G[i] + sR[i]*H[i])
	{
		msmLen := 1 + 2*bpN
		sScalars := make([]*ristretto255.Scalar, msmLen)
		sPoints := make([]*ristretto255.Element, msmLen)
		sScalars[0] = sBlinding
		sPoints[0] = getPedersenH()
		for i := 0; i < bpN; i++ {
			sScalars[1+2*i] = sL[i]
			sPoints[1+2*i] = bpGenG[i]
			sScalars[2+2*i] = sR[i]
			sPoints[2+2*i] = bpGenH[i]
		}
		sPoint := ristretto255.NewElement().MultiScalarMult(sScalars, sPoints)
		copy(proof[32:64], sPoint.Bytes())
	}

	// Step 5: Transcript -> challenges y, z
	transcript := newMerlinTranscript("transaction-proof")
	transcript.appendMessage("dom-sep", []byte("rangeproof v1"))
	transcript.appendU64("n", bpN)
	transcript.appendU64("m", 1)
	transcript.appendMessage("V", commitment32)
	_ = validateAndAppendPoint(transcript, "A", proof[0:32])
	_ = validateAndAppendPoint(transcript, "S", proof[32:64])

	y := transcript.challengeScalar("y")
	z := transcript.challengeScalar("z")

	// Step 6: Build polynomial vectors l(x), r(x)
	zz := ristretto255.NewScalar().Multiply(z, z)
	l0 := make([]*ristretto255.Scalar, bpN)
	l1 := make([]*ristretto255.Scalar, bpN)
	r0 := make([]*ristretto255.Scalar, bpN)
	r1 := make([]*ristretto255.Scalar, bpN)

	expY := ristretto255.NewScalar().Set(one) // y^0 = 1
	exp2 := ristretto255.NewScalar().Set(one) // 2^0 = 1

	for i := 0; i < bpN; i++ {
		aLScalar := u64ToLEScalar(uint64(aL[i]))
		// l0[i] = aL[i] - z
		l0[i] = ristretto255.NewScalar().Subtract(aLScalar, z)
		// l1[i] = sL[i]
		l1[i] = sL[i]

		// aR[i] = aL[i] - 1
		aRScalar := ristretto255.NewScalar().Subtract(aLScalar, one)
		// r0[i] = expY * (aR + z) + zz * exp2
		tmp := ristretto255.NewScalar().Add(aRScalar, z)
		r0[i] = ristretto255.NewScalar().Multiply(expY, tmp)
		r0[i] = scalarMulAdd(zz, exp2, r0[i])

		// r1[i] = expY * sR[i]
		r1[i] = ristretto255.NewScalar().Multiply(expY, sR[i])

		// Advance
		expY = ristretto255.NewScalar().Multiply(expY, y)
		exp2 = ristretto255.NewScalar().Add(exp2, exp2)
	}

	// Step 7: t_0 = <l0, r0>, t_1 = <l0, r1> + <l1, r0>, t_2 = <l1, r1>
	t0 := ristretto255.NewScalar().Zero()
	t1 := ristretto255.NewScalar().Zero()
	t2 := ristretto255.NewScalar().Zero()
	for i := 0; i < bpN; i++ {
		t0 = scalarMulAdd(l0[i], r0[i], t0)
		tmp1 := ristretto255.NewScalar().Multiply(l0[i], r1[i])
		t1 = scalarMulAdd(l1[i], r0[i], t1)
		t1 = ristretto255.NewScalar().Add(t1, tmp1)
		t2 = scalarMulAdd(l1[i], r1[i], t2)
	}

	// Step 8: Commit T1 = t1*G + t1Blinding*H, T2 = t2*G + t2Blinding*H
	t1Blinding, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	t2Blinding, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}

	{
		tScalars := []*ristretto255.Scalar{t1, t1Blinding}
		tPoints := []*ristretto255.Element{getBasepointG(), getPedersenH()}
		t1Point := ristretto255.NewElement().MultiScalarMult(tScalars, tPoints)
		copy(proof[64:96], t1Point.Bytes())

		tScalars[0] = t2
		tScalars[1] = t2Blinding
		t2Point := ristretto255.NewElement().MultiScalarMult(tScalars, tPoints)
		copy(proof[96:128], t2Point.Bytes())
	}

	// Step 9: Transcript -> challenge x
	_ = validateAndAppendPoint(transcript, "T_1", proof[64:96])
	_ = validateAndAppendPoint(transcript, "T_2", proof[96:128])
	x := transcript.challengeScalar("x")

	// Step 10: Evaluate at x
	xx := ristretto255.NewScalar().Multiply(x, x)
	// tx = t0 + t1*x + t2*x^2
	txVal := scalarMulAdd(t1, x, t0)
	txVal = scalarMulAdd(t2, xx, txVal)
	// txb = zz*blinding + t1Blinding*x + t2Blinding*x^2
	txbVal := ristretto255.NewScalar().Multiply(zz, blinding)
	txbVal = scalarMulAdd(t1Blinding, x, txbVal)
	txbVal = scalarMulAdd(t2Blinding, xx, txbVal)
	// eb = aBlinding + sBlinding*x
	ebVal := scalarMulAdd(sBlinding, x, aBlinding)

	copy(proof[128:160], txVal.Bytes())
	copy(proof[160:192], txbVal.Bytes())
	copy(proof[192:224], ebVal.Bytes())

	// Step 11: Transcript -> challenge w
	transcript.appendMessage("t_x", proof[128:160])
	transcript.appendMessage("t_x_blinding", proof[160:192])
	transcript.appendMessage("e_blinding", proof[192:224])
	w := transcript.challengeScalar("w")

	// Step 12: Evaluate l and r at x
	lVec := make([]*ristretto255.Scalar, bpN)
	rVec := make([]*ristretto255.Scalar, bpN)
	for i := 0; i < bpN; i++ {
		lVec[i] = scalarMulAdd(l1[i], x, l0[i])
		rVec[i] = scalarMulAdd(r1[i], x, r0[i])
	}

	// Step 13: Inner Product Proof
	transcript.appendMessage("dom-sep", []byte("ipp v1"))
	transcript.appendU64("n", bpN)

	// Compute y_inv
	yInv := ristretto255.NewScalar().Invert(y)

	// Build working generators: H'[i] = y^(-i) * H[i], G'[i] = G[i]
	gWork := make([]*ristretto255.Element, bpN)
	hWork := make([]*ristretto255.Element, bpN)
	{
		expYInv := ristretto255.NewScalar().Set(one) // start at 1
		for i := 0; i < bpN; i++ {
			gWork[i] = ristretto255.NewElement().Set(bpGenG[i])
			hWork[i] = ristretto255.NewElement().ScalarMult(expYInv, bpGenH[i])
			expYInv = ristretto255.NewScalar().Multiply(expYInv, yInv)
		}
	}

	// Q = w * basepoint_G
	qPoint := ristretto255.NewElement().ScalarMult(w, getBasepointG())

	// Working vectors
	aVec := make([]*ristretto255.Scalar, bpN)
	bVec := make([]*ristretto255.Scalar, bpN)
	copy(aVec, lVec)
	copy(bVec, rVec)

	half := bpN
	ippOff := 224

	for round := 0; round < bpLogN; round++ {
		half >>= 1

		// cL = <a[0..half], b[half..n]>
		cL := ristretto255.NewScalar().Zero()
		cR := ristretto255.NewScalar().Zero()
		for j := 0; j < half; j++ {
			cL = scalarMulAdd(aVec[j], bVec[half+j], cL)
			cR = scalarMulAdd(aVec[half+j], bVec[j], cR)
		}

		// L = <a[0..half], G[half..]> + <b[half..], H[0..half]> + cL*Q
		{
			msmLen := 2*half + 1
			lScalars := make([]*ristretto255.Scalar, msmLen)
			lPoints := make([]*ristretto255.Element, msmLen)
			for j := 0; j < half; j++ {
				lScalars[j] = aVec[j]
				lPoints[j] = gWork[half+j]
			}
			for j := 0; j < half; j++ {
				lScalars[half+j] = bVec[half+j]
				lPoints[half+j] = hWork[j]
			}
			lScalars[2*half] = cL
			lPoints[2*half] = qPoint
			lPoint := ristretto255.NewElement().MultiScalarMult(lScalars, lPoints)
			copy(proof[ippOff:ippOff+32], lPoint.Bytes())
		}

		// R = <a[half..], G[0..half]> + <b[0..half], H[half..]> + cR*Q
		{
			msmLen := 2*half + 1
			rScalars := make([]*ristretto255.Scalar, msmLen)
			rPoints := make([]*ristretto255.Element, msmLen)
			for j := 0; j < half; j++ {
				rScalars[j] = aVec[half+j]
				rPoints[j] = gWork[j]
			}
			for j := 0; j < half; j++ {
				rScalars[half+j] = bVec[j]
				rPoints[half+j] = hWork[half+j]
			}
			rScalars[2*half] = cR
			rPoints[2*half] = qPoint
			rPoint := ristretto255.NewElement().MultiScalarMult(rScalars, rPoints)
			copy(proof[ippOff+32:ippOff+64], rPoint.Bytes())
		}

		// Transcript: L, R -> challenge u
		_ = validateAndAppendPoint(transcript, "L", proof[ippOff:ippOff+32])
		_ = validateAndAppendPoint(transcript, "R", proof[ippOff+32:ippOff+64])
		uChal := transcript.challengeScalar("u")
		uInv := ristretto255.NewScalar().Invert(uChal)

		ippOff += 64

		// Fold vectors
		for j := 0; j < half; j++ {
			// a_new = u*a[j] + u_inv*a[half+j]
			aNew := scalarMulAdd(uInv, aVec[half+j], ristretto255.NewScalar().Multiply(uChal, aVec[j]))
			// b_new = u_inv*b[j] + u*b[half+j]
			bNew := scalarMulAdd(uChal, bVec[half+j], ristretto255.NewScalar().Multiply(uInv, bVec[j]))
			aVec[j] = aNew
			bVec[j] = bNew

			// G_new = u_inv*G[j] + u*G[half+j]
			gTmp1 := ristretto255.NewElement().ScalarMult(uInv, gWork[j])
			gTmp2 := ristretto255.NewElement().ScalarMult(uChal, gWork[half+j])
			gWork[j] = ristretto255.NewElement().Add(gTmp1, gTmp2)

			// H_new = u*H[j] + u_inv*H[half+j]
			hTmp1 := ristretto255.NewElement().ScalarMult(uChal, hWork[j])
			hTmp2 := ristretto255.NewElement().ScalarMult(uInv, hWork[half+j])
			hWork[j] = ristretto255.NewElement().Add(hTmp1, hTmp2)
		}
	}

	// Write final IPP scalars a, b
	copy(proof[ippOff:ippOff+32], aVec[0].Bytes())
	copy(proof[ippOff+32:ippOff+64], bVec[0].Bytes())

	_ = w // used in Q computation above

	return proof, nil
}

func ProvePrivAggregatedRangeProof(commitments [][]byte, values []uint64, blindings [][]byte) ([]byte, error) {
	return provePrivAggregatedRangeProofGo(commitments, values, blindings)
}
