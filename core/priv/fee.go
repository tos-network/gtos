package priv

import (
	"errors"
	"math"
	"math/big"

	"github.com/tos-network/gtos/params"
)

// MaxSafeUnomi is the largest unomi value that can be converted to tomi
// without overflowing uint64. Values above this MUST use UnomiToTomiBig.
var MaxSafeUnomi = math.MaxUint64 / params.Unomi

// ErrUnomiOverflow indicates a UNO base-unit value exceeds the safe uint64 range.
var ErrUnomiOverflow = errors.New("priv: unomi value exceeds safe uint64 range")

// Fee fields in PrivTransferTx / ShieldTx / UnshieldTx are denominated in
// UNO base units (unomi). 1 unomi = 0.01 UNO = 0.01 TOS = 10^16 tomi.
//
// The actual tomi cost charged on-chain is:
//
//     fee_tomi = Fee * params.Unomi
//
// Because params.Unomi = 10^16, a uint64 multiplication overflows at just
// 1845 unomi (~18.44 TOS). All conversions therefore use big.Int.

var bigUnomi = new(big.Int).SetUint64(params.Unomi)

// UnomiToTomiBig converts unomi to tomi as *big.Int (no overflow).
func UnomiToTomiBig(unomi uint64) *big.Int {
	return new(big.Int).Mul(new(big.Int).SetUint64(unomi), bigUnomi)
}

// UnomiToTomi converts unomi to tomi, returning a uint64.
// Panics if the result overflows uint64 (> ~18.44 TOS).
// Callers handling user-supplied amounts should use UnomiToTomiBig instead.
func UnomiToTomi(unomi uint64) uint64 {
	result := UnomiToTomiBig(unomi)
	if !result.IsUint64() {
		panic("priv: UnomiToTomi overflow")
	}
	return result.Uint64()
}

// TomiToUnomi converts tomi to UNO base units (truncating).
func TomiToUnomi(tomi uint64) uint64 {
	return tomi / params.Unomi
}

// TomiToUnomiRemainder returns the tomi remainder after UNO conversion.
func TomiToUnomiRemainder(tomi uint64) uint64 {
	return tomi % params.Unomi
}

// EstimateRequiredFee returns the minimum fee (in UNO base units) for a PrivTransferTx.
func EstimateRequiredFee(txSize int) uint64 {
	return params.UNOBaseFee
}

// EstimateShieldFee returns the minimum fee (in UNO base units) for a ShieldTx.
func EstimateShieldFee() uint64 {
	return params.UNOBaseFee
}

// EstimateUnshieldFee returns the minimum fee (in UNO base units) for an UnshieldTx.
func EstimateUnshieldFee() uint64 {
	return params.UNOBaseFee
}
