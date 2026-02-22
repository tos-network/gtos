package vm

import (
	"github.com/holiman/uint256"
)

// Gas costs
const (
	GasQuickStep   uint64 = 2
	GasFastestStep uint64 = 3
	GasFastStep    uint64 = 5
	GasMidStep     uint64 = 8
	GasSlowStep    uint64 = 10
	GasExtStep     uint64 = 20
)

// callGas returns the actual gas cost of the call.
//
// When the 63/64 rule is enabled, the returned gas is gas - base * 63 / 64.
func callGas(apply63Over64Rule bool, availableGas, base uint64, callCost *uint256.Int) (uint64, error) {
	if apply63Over64Rule {
		availableGas = availableGas - base
		gas := availableGas - availableGas/64
		// If the bit length exceeds 64 bits, the requested call gas is larger than
		// the capped amount, so return the capped value instead of an overflow error.
		if !callCost.IsUint64() || gas < callCost.Uint64() {
			return gas, nil
		}
	}
	if !callCost.IsUint64() {
		return 0, ErrGasUintOverflow
	}

	return callCost.Uint64(), nil
}
