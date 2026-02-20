package tos

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/core/types"
)

func TestShouldAdvanceFinality(t *testing.T) {
	block := func(number uint64) *types.Block {
		return types.NewBlockWithHeader(&types.Header{Number: new(big.Int).SetUint64(number)})
	}
	tests := []struct {
		name      string
		current   *types.Block
		candidate *types.Block
		want      bool
	}{
		{
			name:      "nil candidate",
			current:   block(10),
			candidate: nil,
			want:      false,
		},
		{
			name:      "first finalized",
			current:   nil,
			candidate: block(1),
			want:      true,
		},
		{
			name:      "same height",
			current:   block(12),
			candidate: block(12),
			want:      false,
		},
		{
			name:      "lower height",
			current:   block(12),
			candidate: block(11),
			want:      false,
		},
		{
			name:      "higher height",
			current:   block(12),
			candidate: block(13),
			want:      true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldAdvanceFinality(tc.current, tc.candidate); got != tc.want {
				t.Fatalf("shouldAdvanceFinality() = %v, want %v", got, tc.want)
			}
		})
	}
}
