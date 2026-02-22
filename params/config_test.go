package params

import (
	"math/big"
	"reflect"
	"testing"
)

func TestCheckCompatible(t *testing.T) {
	type test struct {
		stored, new *ChainConfig
		head        uint64
		wantErr     *ConfigCompatError
	}
	tests := []test{
		{stored: AllDPoSProtocolChanges, new: AllDPoSProtocolChanges, head: 0, wantErr: nil},
		{stored: AllDPoSProtocolChanges, new: AllDPoSProtocolChanges, head: 100, wantErr: nil},
		{
			stored: &ChainConfig{
				ChainID:                 big.NewInt(1),
				TerminalTotalDifficulty: big.NewInt(100),
			},
			new: &ChainConfig{
				ChainID:                 big.NewInt(1),
				TerminalTotalDifficulty: big.NewInt(200),
			},
			head:    150,
			wantErr: nil,
		},
		{
			stored: &ChainConfig{ChainID: big.NewInt(1)},
			new:    &ChainConfig{ChainID: big.NewInt(2)},
			head:   10,
			wantErr: &ConfigCompatError{
				What:         "chain ID",
				StoredConfig: big.NewInt(1),
				NewConfig:    big.NewInt(2),
				RewindTo:     0,
			},
		},
	}

	for _, test := range tests {
		err := test.stored.CheckCompatible(test.new, test.head)
		if !reflect.DeepEqual(err, test.wantErr) {
			t.Errorf("error mismatch:\nstored: %v\nnew: %v\nhead: %v\nerr: %v\nwant: %v", test.stored, test.new, test.head, err, test.wantErr)
		}
	}
}
