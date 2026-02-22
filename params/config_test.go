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
			stored:  &ChainConfig{GrayGlacierBlock: big.NewInt(10)},
			new:     &ChainConfig{GrayGlacierBlock: big.NewInt(20)},
			head:    9,
			wantErr: nil,
		},
		{
			stored: &ChainConfig{GrayGlacierBlock: big.NewInt(10)},
			new:    &ChainConfig{GrayGlacierBlock: big.NewInt(20)},
			head:   25,
			wantErr: &ConfigCompatError{
				What:         "Gray Glacier fork block",
				StoredConfig: big.NewInt(10),
				NewConfig:    big.NewInt(20),
				RewindTo:     9,
			},
		},
		{
			stored: &ChainConfig{
				GrayGlacierBlock:   big.NewInt(0),
				MergeNetsplitBlock: big.NewInt(100),
			},
			new: &ChainConfig{
				GrayGlacierBlock:   big.NewInt(0),
				MergeNetsplitBlock: big.NewInt(120),
			},
			head:    80,
			wantErr: nil,
		},
		{
			stored: &ChainConfig{
				GrayGlacierBlock:   big.NewInt(0),
				MergeNetsplitBlock: big.NewInt(100),
			},
			new: &ChainConfig{
				GrayGlacierBlock:   big.NewInt(0),
				MergeNetsplitBlock: big.NewInt(120),
			},
			head: 150,
			wantErr: &ConfigCompatError{
				What:         "Merge netsplit fork block",
				StoredConfig: big.NewInt(100),
				NewConfig:    big.NewInt(120),
				RewindTo:     99,
			},
		},
		{
			stored: &ChainConfig{ChainID: big.NewInt(1), GrayGlacierBlock: big.NewInt(0)},
			new:    &ChainConfig{ChainID: big.NewInt(2), GrayGlacierBlock: big.NewInt(0)},
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
