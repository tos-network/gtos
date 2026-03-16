package ed25519

import "github.com/tos-network/gtos/crypto/ristretto255"

func aggregatedIsPowerOf2(n uint64) bool {
	return n > 0 && (n&(n-1)) == 0
}

func aggregatedLog2u(n uint64) int {
	r := 0
	for n >>= 1; n > 0; n >>= 1 {
		r++
	}
	return r
}

func aggregatedIsIdentityBytes(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}

func aggregatedValidateAndAppendPoint(t *merlinTranscript, label string, pointBytes []byte) error {
	if aggregatedIsIdentityBytes(pointBytes) {
		return ErrPrivInvalidProof
	}
	t.appendMessage(label, pointBytes)
	return nil
}

func aggregatedRangeProofSize(batchLen int) (int, error) {
	if batchLen <= 0 {
		return 0, ErrPrivInvalidInput
	}
	nm := uint64(64 * batchLen)
	if nm == 0 || nm > 256 || !aggregatedIsPowerOf2(nm) {
		return 0, ErrPrivInvalidInput
	}
	logn := aggregatedLog2u(nm)
	return 224 + 2*logn*32 + 64, nil
}

func provePrivAggregatedRangeProofGo(commitments [][]byte, values []uint64, blindings [][]byte) ([]byte, error) {
	if len(commitments) != len(values) || len(commitments) != len(blindings) {
		return nil, ErrPrivInvalidInput
	}
	if len(commitments) == 0 {
		return nil, ErrPrivInvalidInput
	}
	if len(commitments) == 1 {
		return ProvePrivRangeProof(commitments[0], values[0], blindings[0])
	}
	nm := uint64(64 * len(commitments))
	if nm == 0 || nm > 256 || !aggregatedIsPowerOf2(nm) {
		return nil, ErrPrivInvalidInput
	}
	for i := range commitments {
		if len(commitments[i]) != 32 || len(blindings[i]) != 32 {
			return nil, ErrPrivInvalidInput
		}
		if _, err := decodeScalar(blindings[i]); err != nil {
			return nil, ErrPrivInvalidInput
		}
	}

	initBPGenerators()

	logn := aggregatedLog2u(nm)
	n := int(nm)
	proofSize, err := aggregatedRangeProofSize(len(commitments))
	if err != nil {
		return nil, err
	}
	proof := make([]byte, proofSize)

	// Bit-decompose all values in commitment order.
	aLBits := make([]byte, n)
	for batch := range values {
		base := 64 * batch
		for bit := 0; bit < 64; bit++ {
			aLBits[base+bit] = byte((values[batch] >> uint(bit)) & 1)
		}
	}

	aBlinding, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	sBlinding, err := randomScalar()
	if err != nil {
		return nil, ErrPrivOperationFailed
	}
	sL := make([]*ristretto255.Scalar, n)
	sR := make([]*ristretto255.Scalar, n)
	for i := 0; i < n; i++ {
		sL[i], err = randomScalar()
		if err != nil {
			return nil, ErrPrivOperationFailed
		}
		sR[i], err = randomScalar()
		if err != nil {
			return nil, ErrPrivOperationFailed
		}
	}

	one := u64ToLEScalar(1)
	{
		msmLen := 1 + 2*n
		aScalars := make([]*ristretto255.Scalar, msmLen)
		aPoints := make([]*ristretto255.Element, msmLen)
		aScalars[0] = aBlinding
		aPoints[0] = getPedersenH()
		for i := 0; i < n; i++ {
			aLScalar := u64ToLEScalar(uint64(aLBits[i]))
			aScalars[1+2*i] = aLScalar
			aPoints[1+2*i] = bpGenG[i]
			aScalars[2+2*i] = ristretto255.NewScalar().Subtract(aLScalar, one)
			aPoints[2+2*i] = bpGenH[i]
		}
		copy(proof[0:32], ristretto255.NewElement().MultiScalarMult(aScalars, aPoints).Bytes())
	}

	{
		msmLen := 1 + 2*n
		sScalars := make([]*ristretto255.Scalar, msmLen)
		sPoints := make([]*ristretto255.Element, msmLen)
		sScalars[0] = sBlinding
		sPoints[0] = getPedersenH()
		for i := 0; i < n; i++ {
			sScalars[1+2*i] = sL[i]
			sPoints[1+2*i] = bpGenG[i]
			sScalars[2+2*i] = sR[i]
			sPoints[2+2*i] = bpGenH[i]
		}
		copy(proof[32:64], ristretto255.NewElement().MultiScalarMult(sScalars, sPoints).Bytes())
	}

	transcript := newMerlinTranscript("transaction-proof")
	transcript.appendMessage("dom-sep", []byte("rangeproof v1"))
	transcript.appendU64("n", nm)
	transcript.appendU64("m", uint64(len(commitments)))
	for _, commitment := range commitments {
		transcript.appendMessage("V", commitment)
	}
	if err := aggregatedValidateAndAppendPoint(transcript, "A", proof[0:32]); err != nil {
		return nil, ErrPrivInvalidProof
	}
	if err := aggregatedValidateAndAppendPoint(transcript, "S", proof[32:64]); err != nil {
		return nil, ErrPrivInvalidProof
	}

	y := transcript.challengeScalar("y")
	z := transcript.challengeScalar("z")
	zz := ristretto255.NewScalar().Multiply(z, z)

	l0 := make([]*ristretto255.Scalar, n)
	l1 := make([]*ristretto255.Scalar, n)
	r0 := make([]*ristretto255.Scalar, n)
	r1 := make([]*ristretto255.Scalar, n)

	expY := ristretto255.NewScalar().Set(one)
	expZ := ristretto255.NewScalar().Set(zz)
	for batch := range values {
		exp2 := ristretto255.NewScalar().Set(one)
		base := 64 * batch
		for bit := 0; bit < 64; bit++ {
			i := base + bit
			aLScalar := u64ToLEScalar(uint64(aLBits[i]))
			l0[i] = ristretto255.NewScalar().Subtract(aLScalar, z)
			l1[i] = sL[i]

			aRScalar := ristretto255.NewScalar().Subtract(aLScalar, one)
			tmp := ristretto255.NewScalar().Add(aRScalar, z)
			r0[i] = ristretto255.NewScalar().Multiply(expY, tmp)
			r0[i] = scalarMulAdd(expZ, exp2, r0[i])
			r1[i] = ristretto255.NewScalar().Multiply(expY, sR[i])

			expY = ristretto255.NewScalar().Multiply(expY, y)
			exp2 = ristretto255.NewScalar().Add(exp2, exp2)
		}
		expZ = ristretto255.NewScalar().Multiply(expZ, z)
	}

	t0 := ristretto255.NewScalar().Zero()
	t1 := ristretto255.NewScalar().Zero()
	t2 := ristretto255.NewScalar().Zero()
	for i := 0; i < n; i++ {
		t0 = scalarMulAdd(l0[i], r0[i], t0)
		tmp1 := ristretto255.NewScalar().Multiply(l0[i], r1[i])
		t1 = scalarMulAdd(l1[i], r0[i], t1)
		t1 = ristretto255.NewScalar().Add(t1, tmp1)
		t2 = scalarMulAdd(l1[i], r1[i], t2)
	}

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
		copy(proof[64:96], ristretto255.NewElement().MultiScalarMult(tScalars, tPoints).Bytes())
		tScalars[0] = t2
		tScalars[1] = t2Blinding
		copy(proof[96:128], ristretto255.NewElement().MultiScalarMult(tScalars, tPoints).Bytes())
	}

	if err := aggregatedValidateAndAppendPoint(transcript, "T_1", proof[64:96]); err != nil {
		return nil, ErrPrivInvalidProof
	}
	if err := aggregatedValidateAndAppendPoint(transcript, "T_2", proof[96:128]); err != nil {
		return nil, ErrPrivInvalidProof
	}
	x := transcript.challengeScalar("x")
	xx := ristretto255.NewScalar().Multiply(x, x)

	txVal := scalarMulAdd(t1, x, t0)
	txVal = scalarMulAdd(t2, xx, txVal)

	txbVal := ristretto255.NewScalar().Zero()
	expZ = ristretto255.NewScalar().Set(zz)
	for _, blindingBytes := range blindings {
		blinding, err := decodeScalar(blindingBytes)
		if err != nil {
			return nil, ErrPrivInvalidInput
		}
		txbVal = scalarMulAdd(expZ, blinding, txbVal)
		expZ = ristretto255.NewScalar().Multiply(expZ, z)
	}
	txbVal = scalarMulAdd(t1Blinding, x, txbVal)
	txbVal = scalarMulAdd(t2Blinding, xx, txbVal)

	ebVal := scalarMulAdd(sBlinding, x, aBlinding)

	copy(proof[128:160], txVal.Bytes())
	copy(proof[160:192], txbVal.Bytes())
	copy(proof[192:224], ebVal.Bytes())

	transcript.appendMessage("t_x", proof[128:160])
	transcript.appendMessage("t_x_blinding", proof[160:192])
	transcript.appendMessage("e_blinding", proof[192:224])
	w := transcript.challengeScalar("w")

	lVec := make([]*ristretto255.Scalar, n)
	rVec := make([]*ristretto255.Scalar, n)
	for i := 0; i < n; i++ {
		lVec[i] = scalarMulAdd(l1[i], x, l0[i])
		rVec[i] = scalarMulAdd(r1[i], x, r0[i])
	}

	transcript.appendMessage("dom-sep", []byte("ipp v1"))
	transcript.appendU64("n", nm)

	yInv := ristretto255.NewScalar().Invert(y)
	gWork := make([]*ristretto255.Element, n)
	hWork := make([]*ristretto255.Element, n)
	expYInv := ristretto255.NewScalar().Set(one)
	for i := 0; i < n; i++ {
		gWork[i] = ristretto255.NewElement().Set(bpGenG[i])
		hWork[i] = ristretto255.NewElement().ScalarMult(expYInv, bpGenH[i])
		expYInv = ristretto255.NewScalar().Multiply(expYInv, yInv)
	}

	qPoint := ristretto255.NewElement().ScalarMult(w, getBasepointG())
	aVec := make([]*ristretto255.Scalar, n)
	bVec := make([]*ristretto255.Scalar, n)
	copy(aVec, lVec)
	copy(bVec, rVec)

	half := n
	ippOff := 224
	for round := 0; round < logn; round++ {
		half >>= 1
		cL := ristretto255.NewScalar().Zero()
		cR := ristretto255.NewScalar().Zero()
		for j := 0; j < half; j++ {
			cL = scalarMulAdd(aVec[j], bVec[half+j], cL)
			cR = scalarMulAdd(aVec[half+j], bVec[j], cR)
		}

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
			copy(proof[ippOff:ippOff+32], ristretto255.NewElement().MultiScalarMult(lScalars, lPoints).Bytes())
		}

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
			copy(proof[ippOff+32:ippOff+64], ristretto255.NewElement().MultiScalarMult(rScalars, rPoints).Bytes())
		}

		if err := aggregatedValidateAndAppendPoint(transcript, "L", proof[ippOff:ippOff+32]); err != nil {
			return nil, ErrPrivInvalidProof
		}
		if err := aggregatedValidateAndAppendPoint(transcript, "R", proof[ippOff+32:ippOff+64]); err != nil {
			return nil, ErrPrivInvalidProof
		}
		uChal := transcript.challengeScalar("u")
		uInv := ristretto255.NewScalar().Invert(uChal)
		ippOff += 64

		for j := 0; j < half; j++ {
			aVec[j] = scalarMulAdd(uInv, aVec[half+j], ristretto255.NewScalar().Multiply(uChal, aVec[j]))
			bVec[j] = scalarMulAdd(uChal, bVec[half+j], ristretto255.NewScalar().Multiply(uInv, bVec[j]))

			gTmp1 := ristretto255.NewElement().ScalarMult(uInv, gWork[j])
			gTmp2 := ristretto255.NewElement().ScalarMult(uChal, gWork[half+j])
			gWork[j] = ristretto255.NewElement().Add(gTmp1, gTmp2)

			hTmp1 := ristretto255.NewElement().ScalarMult(uChal, hWork[j])
			hTmp2 := ristretto255.NewElement().ScalarMult(uInv, hWork[half+j])
			hWork[j] = ristretto255.NewElement().Add(hTmp1, hTmp2)
		}
	}

	copy(proof[ippOff:ippOff+32], aVec[0].Bytes())
	copy(proof[ippOff+32:ippOff+64], bVec[0].Bytes())
	return proof, nil
}
