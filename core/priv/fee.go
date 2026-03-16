package priv

import "github.com/tos-network/gtos/params"

// Fee fields in PrivTransferTx / ShieldTx / UnshieldTx are denominated in
// UNO base units. 1 UNO base unit = 0.01 UNO = 10^16 Wei.
//
// The actual Wei cost charged on-chain is:
//
//     fee_wei = Fee * params.UNOUnit

// UNOFeeToWei converts a fee in UNO base units to Wei.
func UNOFeeToWei(feeUNO uint64) uint64 {
	return feeUNO * params.UNOUnit
}

// WeiToUNO converts Wei to UNO base units (truncating).
func WeiToUNO(wei uint64) uint64 {
	return wei / params.UNOUnit
}

// WeiToUNORemainder returns the Wei remainder after UNO conversion.
func WeiToUNORemainder(wei uint64) uint64 {
	return wei % params.UNOUnit
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
