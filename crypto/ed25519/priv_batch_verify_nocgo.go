//go:build !cgo || !ed25519c

package ed25519

import (
	"crypto/rand"

	"github.com/tos-network/gtos/crypto/ristretto255"
)

type PrivBatchVerifier struct {
	sigmaScalars []*ristretto255.Scalar
	sigmaPoints  []*ristretto255.Element
	rangeScalars []*ristretto255.Scalar
	rangePoints  []*ristretto255.Element
}

func NewPrivBatchVerifier() *PrivBatchVerifier {
	return &PrivBatchVerifier{}
}

func randomBatchScalar() (*ristretto255.Scalar, error) {
	var wide [64]byte
	zero := ristretto255.NewScalar().Zero()
	for {
		if _, err := rand.Read(wide[:]); err != nil {
			return nil, ErrPrivOperationFailed
		}
		scalar, err := ristretto255.NewScalar().SetUniformBytes(wide[:])
		if err != nil {
			return nil, ErrPrivOperationFailed
		}
		if scalar.Equal(zero) != 1 {
			return scalar, nil
		}
	}
}

func appendWeightedTerms(dstScalars *[]*ristretto255.Scalar, dstPoints *[]*ristretto255.Element, weight *ristretto255.Scalar, scalars []*ristretto255.Scalar, points []*ristretto255.Element) {
	for i := range scalars {
		*dstScalars = append(*dstScalars, ristretto255.NewScalar().Multiply(weight, scalars[i]))
		*dstPoints = append(*dstPoints, points[i])
	}
}

func (b *PrivBatchVerifier) appendRangeProofTerms(scalars []*ristretto255.Scalar, points []*ristretto255.Element) {
	b.rangeScalars = append(b.rangeScalars, scalars...)
	b.rangePoints = append(b.rangePoints, points...)
}

func (b *PrivBatchVerifier) AddPrivShieldProofWithContext(proof96, commitment, receiverHandle, receiverPubkey []byte, amount uint64, ctx []byte) error {
	if len(proof96) != 96 || len(commitment) != 32 || len(receiverHandle) != 32 || len(receiverPubkey) != 32 {
		return ErrPrivInvalidInput
	}

	YHBytes := proof96[0:32]
	YPBytes := proof96[32:64]
	zBytes := proof96[64:96]

	z, err := decodeScalar(zBytes)
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
	YH, err := decodePoint(YHBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	YP, err := decodePoint(YPBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	t := newMerlinTranscript("shield-commitment-proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("dom-sep", []byte("shield-commitment-proof"))
	t.appendMessage("Y_H", YHBytes)
	t.appendMessage("Y_P", YPBytes)

	cWide := t.challengeBytes("c", 64)
	_ = t.challengeBytes("w", 64)
	c, err := ristretto255.NewScalar().SetUniformBytes(cWide)
	if err != nil {
		return ErrPrivInvalidProof
	}

	amountScalar := u64ToLEScalar(amount)
	aG := ristretto255.NewIdentityElement().ScalarMult(amountScalar, getBasepointG())
	CMinusAG := ristretto255.NewIdentityElement().Subtract(C, aG)
	weight1, err := randomBatchScalar()
	if err != nil {
		return err
	}
	appendWeightedTerms(
		&b.sigmaScalars,
		&b.sigmaPoints,
		weight1,
		[]*ristretto255.Scalar{
			z,
			ristretto255.NewScalar().Negate(c),
			ristretto255.NewScalar().Negate(u64ToLEScalar(1)),
		},
		[]*ristretto255.Element{
			getPedersenH(),
			CMinusAG,
			YH,
		},
	)
	weight2, err := randomBatchScalar()
	if err != nil {
		return err
	}
	appendWeightedTerms(
		&b.sigmaScalars,
		&b.sigmaPoints,
		weight2,
		[]*ristretto255.Scalar{
			z,
			ristretto255.NewScalar().Negate(c),
			ristretto255.NewScalar().Negate(u64ToLEScalar(1)),
		},
		[]*ristretto255.Element{
			P,
			D,
			YP,
		},
	)
	return nil
}

func (b *PrivBatchVerifier) AddPrivCTValidityProofWithContext(proof, commitment, senderHandle, receiverHandle, senderPubkey, receiverPubkey []byte, txVersionT1 bool, ctx []byte) error {
	wantLen := 128
	if txVersionT1 {
		wantLen = 160
	}
	if len(proof) != wantLen || len(commitment) != 32 || len(senderHandle) != 32 || len(receiverHandle) != 32 || len(senderPubkey) != 32 || len(receiverPubkey) != 32 {
		return ErrPrivInvalidInput
	}

	Y0Bytes := proof[0:32]
	Y1Bytes := proof[32:64]
	var Y2Bytes []byte
	var zrBytes, zxBytes []byte
	if txVersionT1 {
		Y2Bytes = proof[64:96]
		zrBytes = proof[96:128]
		zxBytes = proof[128:160]
	} else {
		zrBytes = proof[64:96]
		zxBytes = proof[96:128]
	}

	zr, err := decodeScalar(zrBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	zx, err := decodeScalar(zxBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	C, err := decodePoint(commitment)
	if err != nil {
		return ErrPrivInvalidProof
	}
	DReceiver, err := decodePoint(receiverHandle)
	if err != nil {
		return ErrPrivInvalidProof
	}
	PReceiver, err := decodePoint(receiverPubkey)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y0, err := decodePoint(Y0Bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y1, err := decodePoint(Y1Bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	var DSender, PSender, Y2 *ristretto255.Element
	if txVersionT1 {
		DSender, err = decodePoint(senderHandle)
		if err != nil {
			return ErrPrivInvalidProof
		}
		PSender, err = decodePoint(senderPubkey)
		if err != nil {
			return ErrPrivInvalidProof
		}
		Y2, err = decodePoint(Y2Bytes)
		if err != nil {
			return ErrPrivInvalidProof
		}
	}

	t := newMerlinTranscript("validity-proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("dom-sep", []byte("validity-proof"))
	t.appendMessage("Y_0", Y0Bytes)
	t.appendMessage("Y_1", Y1Bytes)
	if txVersionT1 {
		t.appendMessage("Y_2", Y2Bytes)
	}

	cWide := t.challengeBytes("c", 64)
	_ = t.challengeBytes("w", 64)
	c, err := ristretto255.NewScalar().SetUniformBytes(cWide)
	if err != nil {
		return ErrPrivInvalidProof
	}

	weight0, err := randomBatchScalar()
	if err != nil {
		return err
	}
	appendWeightedTerms(
		&b.sigmaScalars,
		&b.sigmaPoints,
		weight0,
		[]*ristretto255.Scalar{
			zx,
			zr,
			ristretto255.NewScalar().Negate(c),
			ristretto255.NewScalar().Negate(u64ToLEScalar(1)),
		},
		[]*ristretto255.Element{
			getBasepointG(),
			getPedersenH(),
			C,
			Y0,
		},
	)
	weight1, err := randomBatchScalar()
	if err != nil {
		return err
	}
	appendWeightedTerms(
		&b.sigmaScalars,
		&b.sigmaPoints,
		weight1,
		[]*ristretto255.Scalar{
			zr,
			ristretto255.NewScalar().Negate(c),
			ristretto255.NewScalar().Negate(u64ToLEScalar(1)),
		},
		[]*ristretto255.Element{
			PReceiver,
			DReceiver,
			Y1,
		},
	)
	if txVersionT1 {
		weight2, err := randomBatchScalar()
		if err != nil {
			return err
		}
		appendWeightedTerms(
			&b.sigmaScalars,
			&b.sigmaPoints,
			weight2,
			[]*ristretto255.Scalar{
				zr,
				ristretto255.NewScalar().Negate(c),
				ristretto255.NewScalar().Negate(u64ToLEScalar(1)),
			},
			[]*ristretto255.Element{
				PSender,
				DSender,
				Y2,
			},
		)
	}
	return nil
}

func (b *PrivBatchVerifier) AddPrivCommitmentEqProofWithContext(proof192, sourcePubkey, sourceCiphertext64, destinationCommitment []byte, ctx []byte) error {
	if len(proof192) != 192 || len(sourcePubkey) != 32 || len(sourceCiphertext64) != 64 || len(destinationCommitment) != 32 {
		return ErrPrivInvalidInput
	}

	Y0Bytes := proof192[0:32]
	Y1Bytes := proof192[32:64]
	Y2Bytes := proof192[64:96]
	zsBytes := proof192[96:128]
	zxBytes := proof192[128:160]
	zrBytes := proof192[160:192]

	zs, err := decodeScalar(zsBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	zx, err := decodeScalar(zxBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	zr, err := decodeScalar(zrBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	PSource, err := decodePoint(sourcePubkey)
	if err != nil {
		return ErrPrivInvalidProof
	}
	CSource, err := decodePoint(sourceCiphertext64[0:32])
	if err != nil {
		return ErrPrivInvalidProof
	}
	DSource, err := decodePoint(sourceCiphertext64[32:64])
	if err != nil {
		return ErrPrivInvalidProof
	}
	CDest, err := decodePoint(destinationCommitment)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y0, err := decodePoint(Y0Bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y1, err := decodePoint(Y1Bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}
	Y2, err := decodePoint(Y2Bytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	t := newMerlinTranscript("new-commitment-proof")
	if len(ctx) > 0 {
		t.appendMessage("chain-ctx", ctx)
	}
	t.appendMessage("dom-sep", []byte("equality-proof"))
	t.appendMessage("Y_0", Y0Bytes)
	t.appendMessage("Y_1", Y1Bytes)
	t.appendMessage("Y_2", Y2Bytes)
	c := t.challengeScalar("c")
	t.appendMessage("z_s", zsBytes)
	t.appendMessage("z_x", zxBytes)
	t.appendMessage("z_r", zrBytes)
	w := t.challengeScalar("w")

	ww := ristretto255.NewScalar().Multiply(w, w)
	negOne := ristretto255.NewScalar().Negate(u64ToLEScalar(1))
	scalars := []*ristretto255.Scalar{
		zs,
		ristretto255.NewScalar().Negate(c),
		negOne,
		ristretto255.NewScalar().Multiply(w, zx),
		ristretto255.NewScalar().Multiply(w, zs),
		ristretto255.NewScalar().Negate(ristretto255.NewScalar().Multiply(w, c)),
		ristretto255.NewScalar().Negate(w),
		ristretto255.NewScalar().Multiply(ww, zx),
		ristretto255.NewScalar().Multiply(ww, zr),
		ristretto255.NewScalar().Negate(ristretto255.NewScalar().Multiply(ww, c)),
		ristretto255.NewScalar().Negate(ww),
	}
	points := []*ristretto255.Element{
		PSource,
		getPedersenH(),
		Y0,
		getBasepointG(),
		DSource,
		CSource,
		Y1,
		getBasepointG(),
		getPedersenH(),
		CDest,
		Y2,
	}
	weight, err := randomBatchScalar()
	if err != nil {
		return err
	}
	appendWeightedTerms(&b.sigmaScalars, &b.sigmaPoints, weight, scalars, points)
	return nil
}

func (b *PrivBatchVerifier) AddPrivRangeProof(proof []byte, commitments []byte, bitLengths []byte, batchLen uint8) error {
	if batchLen == 0 {
		return ErrPrivInvalidInput
	}
	bl := int(batchLen)
	if len(commitments) != bl*32 || len(bitLengths) != bl {
		return ErrPrivInvalidInput
	}

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
	expectedSize := 224 + 2*logn*32 + 64
	if len(proof) != expectedSize {
		return ErrPrivInvalidInput
	}

	aBytes := proof[0:32]
	sBytes := proof[32:64]
	t1Bytes := proof[64:96]
	t2Bytes := proof[96:128]
	txBytes := proof[128:160]
	txbBytes := proof[160:192]
	ebBytes := proof[192:224]

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

	txScalar, err := decodeScalar(txBytes)
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

	aRes, err := decodePoint(aBytes)
	if err != nil {
		return ErrPrivInvalidProof
	}

	totalPoints := 5 + bl + 2*logn + 2*n
	points := make([]*ristretto255.Element, totalPoints+1)
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
	initBPGenerators()
	for i := 0; i < n; i++ {
		points[idx] = bpGenH[i]
		idx++
	}
	for i := 0; i < n; i++ {
		points[idx] = bpGenG[i]
		idx++
	}

	transcript := newMerlinTranscript("transaction-proof")
	transcript.appendMessage("dom-sep", []byte("rangeproof v1"))
	transcript.appendU64("n", nm)
	transcript.appendU64("m", uint64(batchLen))
	for i := 0; i < bl; i++ {
		transcript.appendMessage("V", commitments[i*32:(i+1)*32])
	}
	if err := validateAndAppendPoint(transcript, "A", aBytes); err != nil {
		return ErrPrivInvalidProof
	}
	if err := validateAndAppendPoint(transcript, "S", sBytes); err != nil {
		return ErrPrivInvalidProof
	}

	y := transcript.challengeScalar("y")
	z := transcript.challengeScalar("z")
	if err := validateAndAppendPoint(transcript, "T_1", t1Bytes); err != nil {
		return ErrPrivInvalidProof
	}
	if err := validateAndAppendPoint(transcript, "T_2", t2Bytes); err != nil {
		return ErrPrivInvalidProof
	}
	x := transcript.challengeScalar("x")
	transcript.appendMessage("t_x", txBytes)
	transcript.appendMessage("t_x_blinding", txbBytes)
	transcript.appendMessage("e_blinding", ebBytes)
	w := transcript.challengeScalar("w")
	c, err := randomBatchScalar()
	if err != nil {
		return err
	}

	transcript.appendMessage("dom-sep", []byte("ipp v1"))
	transcript.appendU64("n", nm)
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

	yInv := ristretto255.NewScalar().Invert(y)
	uInv := make([]*ristretto255.Scalar, logn)
	allinv := ristretto255.NewScalar().Set(yInv)
	for i := 0; i < logn; i++ {
		uInv[i] = ristretto255.NewScalar().Invert(u[i])
		allinv = ristretto255.NewScalar().Multiply(allinv, uInv[i])
	}
	uSq := make([]*ristretto255.Scalar, logn)
	for i := 0; i < logn; i++ {
		uSq[i] = ristretto255.NewScalar().Multiply(u[i], u[i])
	}

	s := make([]*ristretto255.Scalar, n)
	s[0] = ristretto255.NewScalar().Multiply(allinv, y)
	for k := 0; k < logn; k++ {
		powk := 1 << uint(k)
		for j := 0; j < powk; j++ {
			i := powk + j
			s[i] = ristretto255.NewScalar().Multiply(s[j], uSq[logn-1-k])
		}
	}

	scalars := make([]*ristretto255.Scalar, totalPoints+1)
	scalars[1] = ristretto255.NewScalar().Negate(scalarMulAdd(c, txb, eb))
	scalars[2] = ristretto255.NewScalar().Set(x)
	cx := ristretto255.NewScalar().Multiply(c, x)
	scalars[3] = ristretto255.NewScalar().Set(cx)
	xx := ristretto255.NewScalar().Multiply(x, x)
	scalars[4] = ristretto255.NewScalar().Multiply(c, xx)

	zz := ristretto255.NewScalar().Multiply(z, z)
	cz2 := ristretto255.NewScalar().Multiply(zz, c)
	scalars[5] = ristretto255.NewScalar().Set(cz2)
	scIdx := 6
	for i := 1; i < bl; i++ {
		scalars[scIdx] = ristretto255.NewScalar().Multiply(scalars[scIdx-1], z)
		scIdx++
	}
	for i := 0; i < logn; i++ {
		scalars[scIdx] = ristretto255.NewScalar().Set(uSq[i])
		scIdx++
	}
	for i := 0; i < logn; i++ {
		uInvSq := ristretto255.NewScalar().Multiply(uInv[i], uInv[i])
		scalars[scIdx] = uInvSq
		scIdx++
	}

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
		tmp := scalarMulAdd(s[n-1-i], minusB, zAnd2)
		scalars[scIdx] = scalarMulAdd(tmp, expYInv, z)
		scIdx++
		j++
	}

	minusZ := ristretto255.NewScalar().Negate(z)
	minusA := ristretto255.NewScalar().Negate(ippA)
	for i := 0; i < n; i++ {
		scalars[scIdx] = scalarMulAdd(s[i], minusA, minusZ)
		scIdx++
	}

	delta := rangeproofsDelta(nm, y, z, zz, bitLengths, bl)
	g0 := scalarMulAdd(minusA, ippB, txScalar)
	deltaMinusTx := ristretto255.NewScalar().Subtract(delta, txScalar)
	deltaMinusTx = ristretto255.NewScalar().Multiply(deltaMinusTx, c)
	scalars[0] = scalarMulAdd(g0, w, deltaMinusTx)

	points[totalPoints] = aRes
	scalars[totalPoints] = u64ToLEScalar(1)
	b.appendRangeProofTerms(scalars, points)
	return nil
}

func (b *PrivBatchVerifier) Verify() error {
	identity := ristretto255.NewIdentityElement()
	if len(b.sigmaScalars) > 0 {
		sigmaResult := ristretto255.NewElement().VarTimeMultiScalarMult(b.sigmaScalars, b.sigmaPoints)
		if sigmaResult.Equal(identity) != 1 {
			return ErrPrivInvalidProof
		}
	}
	if len(b.rangeScalars) > 0 {
		rangeResult := ristretto255.NewElement().VarTimeMultiScalarMult(b.rangeScalars, b.rangePoints)
		if rangeResult.Equal(identity) != 1 {
			return ErrPrivInvalidProof
		}
	}
	return nil
}
