package priv

import "github.com/tos-network/gtos/params"

// Fee fields in PrivTransferTx / ShieldTx / UnshieldTx are denominated in
// *gas units*, not Wei.  The actual Wei cost charged on-chain is:
//
//     fee_wei = Fee * params.TxPriceWei          (protocol-fixed gas price)
//
// This keeps the Fee field small and human-readable (e.g. 10 000) while the
// on-chain deduction follows the same gas-price model as regular transactions.

// FeeToWei converts a fee in gas units to Wei using the protocol-fixed gas price.
func FeeToWei(feeGasUnits uint64) uint64 {
	return feeGasUnits * uint64(params.TxPriceWei)
}

// EstimateRequiredFee returns the minimum fee (in gas units) for a PrivTransferTx.
func EstimateRequiredFee(txSize int) uint64 {
	return 42_000 // PrivBaseFee from params
}

// EstimateShieldFee returns the minimum fee (in gas units) for a ShieldTx.
func EstimateShieldFee() uint64 {
	return 42_000
}

// EstimateUnshieldFee returns the minimum fee (in gas units) for an UnshieldTx.
func EstimateUnshieldFee() uint64 {
	return 42_000
}
