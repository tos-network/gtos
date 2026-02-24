// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

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
