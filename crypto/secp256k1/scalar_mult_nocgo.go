//go:build gofuzz || !cgo
// +build gofuzz !cgo

package secp256k1

import "math/big"

func (BitCurve *BitCurve) ScalarMult(Bx, By *big.Int, scalar []byte) (*big.Int, *big.Int) {
	panic("ScalarMult is not available when secp256k1 is built without cgo")
}
