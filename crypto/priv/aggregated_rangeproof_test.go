package priv

import "testing"

func testAggregatedRangeProof(tb testing.TB) {
	tb.Helper()

	values := []uint64{91, 17}
	commitments := make([][]byte, 2)
	blindings := make([][]byte, 2)
	for i, value := range values {
		commitment, opening, err := CommitmentNew(value)
		if err != nil {
			tb.Fatalf("CommitmentNew[%d]: %v", i, err)
		}
		commitments[i] = commitment
		blindings[i] = opening
	}

	proof, err := ProveAggregatedRangeProof(commitments, values, blindings)
	if err != nil {
		tb.Fatalf("ProveAggregatedRangeProof: %v", err)
	}
	if len(proof) != 736 {
		tb.Fatalf("unexpected aggregated proof size: %d", len(proof))
	}

	flatCommitments := make([]byte, 64)
	copy(flatCommitments[:32], commitments[0])
	copy(flatCommitments[32:], commitments[1])
	if err := VerifyRangeProof(proof, flatCommitments, []byte{64, 64}, 2); err != nil {
		tb.Fatalf("VerifyRangeProof(aggregated): %v", err)
	}
}
