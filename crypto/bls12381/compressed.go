package bls12381

import "errors"

const (
	compressedFlag = byte(0x80)
	infinityFlag   = byte(0x40)
	sortFlag       = byte(0x20)
	flagMask       = compressedFlag | infinityFlag | sortFlag
)

func (g *G1) ToCompressed(p *PointG1) []byte {
	out := make([]byte, 48)
	if g.IsZero(p) {
		out[0] = compressedFlag | infinityFlag
		return out
	}
	g.Affine(p)
	copy(out, toBytes(&p[0]))
	yBytes := toBytes(&p[1])
	negY := new(fe)
	neg(negY, &p[1])
	if lexicographicallyLargest(yBytes, toBytes(negY)) {
		out[0] |= sortFlag
	}
	out[0] |= compressedFlag
	return out
}

func (g *G1) FromCompressed(in []byte) (*PointG1, error) {
	if len(in) != 48 {
		return nil, errors.New("invalid g1 compressed point length")
	}
	if in[0]&compressedFlag == 0 {
		return nil, errors.New("g1 point is not compressed")
	}
	if in[0]&infinityFlag != 0 {
		if in[0] != compressedFlag|infinityFlag {
			return nil, errors.New("invalid g1 infinity encoding")
		}
		for _, b := range in[1:] {
			if b != 0 {
				return nil, errors.New("invalid g1 infinity encoding")
			}
		}
		return g.Zero(), nil
	}
	sort := in[0]&sortFlag != 0
	raw := append([]byte(nil), in...)
	raw[0] &= ^flagMask

	x, err := fromBytes(raw)
	if err != nil {
		return nil, err
	}
	rhs := new(fe)
	square(rhs, x)
	mul(rhs, rhs, x)
	add(rhs, rhs, b)
	y := new(fe)
	if !sqrt(y, rhs) {
		return nil, errors.New("g1 point is not on curve")
	}
	negY := new(fe)
	neg(negY, y)
	if lexicographicallyLargest(toBytes(y), toBytes(negY)) != sort {
		y = negY
	}
	p := &PointG1{*x, *y, *new(fe).one()}
	if !g.IsOnCurve(p) || !g.InCorrectSubgroup(p) {
		return nil, errors.New("g1 point is not in correct subgroup")
	}
	return g.Affine(p), nil
}

func (g *G2) ToCompressed(p *PointG2) []byte {
	out := make([]byte, 96)
	if g.IsZero(p) {
		out[0] = compressedFlag | infinityFlag
		return out
	}
	g.Affine(p)
	fp2 := g.f
	copy(out, fp2.toBytes(&p[0]))
	yBytes := fp2.toBytes(&p[1])
	negY := new(fe2)
	fp2.neg(negY, &p[1])
	if lexicographicallyLargest(yBytes, fp2.toBytes(negY)) {
		out[0] |= sortFlag
	}
	out[0] |= compressedFlag
	return out
}

func (g *G2) FromCompressed(in []byte) (*PointG2, error) {
	if len(in) != 96 {
		return nil, errors.New("invalid g2 compressed point length")
	}
	if in[0]&compressedFlag == 0 {
		return nil, errors.New("g2 point is not compressed")
	}
	if in[0]&infinityFlag != 0 {
		if in[0] != compressedFlag|infinityFlag {
			return nil, errors.New("invalid g2 infinity encoding")
		}
		for _, b := range in[1:] {
			if b != 0 {
				return nil, errors.New("invalid g2 infinity encoding")
			}
		}
		return g.Zero(), nil
	}
	sort := in[0]&sortFlag != 0
	raw := append([]byte(nil), in...)
	raw[0] &= ^flagMask

	x, err := g.f.fromBytes(raw)
	if err != nil {
		return nil, err
	}
	rhs := new(fe2)
	g.f.square(rhs, x)
	g.f.mul(rhs, rhs, x)
	g.f.add(rhs, rhs, b2)
	y := new(fe2)
	if !g.f.sqrt(y, rhs) {
		return nil, errors.New("g2 point is not on curve")
	}
	negY := new(fe2)
	g.f.neg(negY, y)
	if lexicographicallyLargest(g.f.toBytes(y), g.f.toBytes(negY)) != sort {
		y = negY
	}
	p := &PointG2{*x, *y, *new(fe2).one()}
	if !g.IsOnCurve(p) || !g.InCorrectSubgroup(p) {
		return nil, errors.New("g2 point is not in correct subgroup")
	}
	return g.Affine(p), nil
}
