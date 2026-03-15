package priv

// EstimateRequiredFee computes the minimum fee for a PrivTransferTx.
// For now, returns a fixed base fee. Can be made dynamic later.
func EstimateRequiredFee(txSize int) uint64 {
	// Base fee per private transfer
	return 10_000 // PrivBaseFee from params
}
