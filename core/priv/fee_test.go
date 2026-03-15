package priv

import "testing"

func TestEstimateRequiredFee(t *testing.T) {
	fee := EstimateRequiredFee(0)
	if fee != 10_000 {
		t.Fatalf("EstimateRequiredFee: got %d want 10000", fee)
	}

	// Fee should be the same regardless of txSize for now.
	fee2 := EstimateRequiredFee(9999)
	if fee2 != fee {
		t.Fatalf("fee should be constant: got %d and %d", fee, fee2)
	}
}
