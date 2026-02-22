package params

// These are the multipliers for tos denominations.
// Example: To get the wei value of an amount in 'gwei', use
//
//	new(big.Int).Mul(value, big.NewInt(params.GWei))
const (
	Wei  = 1
	GWei = 1e9
	TOS  = 1e18
)
