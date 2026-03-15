//go:build !cgo

package types

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

func supportsBLS12381GoldenVerify() bool {
	return false
}

func verifyBLS12381GoldenRaw(_ []byte, _ common.Hash, _ *big.Int, _ *big.Int) bool {
	return false
}
