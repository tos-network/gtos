package priv

import "github.com/tos-network/gtos/params"

// Fee fields in PrivTransferTx / ShieldTx / UnshieldTx are denominated in
// UNO base units. 1 UNO base unit = 0.01 UNO = 10^16 tomi.
//
// The actual tomi cost charged on-chain is:
//
//     fee_tomi = Fee * params.Unomi

// UnomiToTomi converts a fee in UNO base units to tomi.
func UnomiToTomi(feeUNO uint64) uint64 {
	return feeUNO * params.Unomi
}

// Backward-compatible alias.
var UNOFeeToWei = UnomiToTomi

// TomiToUnomi converts tomi to UNO base units (truncating).
func TomiToUnomi(tomi uint64) uint64 {
	return tomi / params.Unomi
}

// Backward-compatible alias.
var WeiToUNO = TomiToUnomi

// TomiToUnomiRemainder returns the tomi remainder after UNO conversion.
func TomiToUnomiRemainder(tomi uint64) uint64 {
	return tomi % params.Unomi
}

// Backward-compatible alias.
var WeiToUNORemainder = TomiToUnomiRemainder

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
