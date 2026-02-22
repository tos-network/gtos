package misc

import (
	"math/big"

	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
)

// CalcBaseFee returns a fixed zero base fee.
// GTOS does not use dynamic-fee style base fee adjustment.
func CalcBaseFee(_ *params.ChainConfig, _ *types.Header) *big.Int {
	return new(big.Int)
}
