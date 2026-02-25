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
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
)

func TestNormalizeDPoSSealSignerType(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: DPoSSealSignerTypeEd25519},
		{in: "ed25519", want: DPoSSealSignerTypeEd25519},
		{in: "secp256k1", want: DPoSSealSignerTypeSecp256k1},
		{in: " ethereum_secp256k1 ", want: DPoSSealSignerTypeSecp256k1},
		{in: "bls12-381", wantErr: true},
	}
	for _, tc := range tests {
		got, err := NormalizeDPoSSealSignerType(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeDPoSSealSignerType(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeDPoSSealSignerType(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeDPoSSealSignerType(%q): have %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestDPoSConfigTargetBlockPeriodMs(t *testing.T) {
	tests := []struct {
		name string
		cfg  *DPoSConfig
		want uint64
	}{
		{name: "nil", cfg: nil, want: 0},
		{name: "periodMs only", cfg: &DPoSConfig{PeriodMs: 500}, want: 500},
		{name: "legacy period only", cfg: &DPoSConfig{Period: 2}, want: 2000},
		{name: "periodMs precedence", cfg: &DPoSConfig{Period: 2, PeriodMs: 750}, want: 750},
	}
	for _, tc := range tests {
		if got := tc.cfg.TargetBlockPeriodMs(); got != tc.want {
			t.Fatalf("%s: have %d want %d", tc.name, got, tc.want)
		}
	}
}

func TestDPoSConfigNormalizePeriod(t *testing.T) {
	cfg := &DPoSConfig{Period: 3}
	cfg.NormalizePeriod()
	if cfg.PeriodMs != 3000 {
		t.Fatalf("legacy period mapping failed: have %d want %d", cfg.PeriodMs, 3000)
	}

	cfg = &DPoSConfig{Period: 3, PeriodMs: 450}
	cfg.NormalizePeriod()
	if cfg.PeriodMs != 450 {
		t.Fatalf("periodMs should take precedence: have %d want %d", cfg.PeriodMs, 450)
	}
}

func TestChainConfigJSONPeriodMsAndLegacyPeriod(t *testing.T) {
	periodMsJSON := []byte(`{"chainId":1,"dpos":{"periodMs":500,"epoch":1000,"maxValidators":21,"sealSignerType":"ed25519"}}`)
	var cfg ChainConfig
	if err := json.Unmarshal(periodMsJSON, &cfg); err != nil {
		t.Fatalf("unmarshal periodMs config: %v", err)
	}
	if cfg.DPoS == nil {
		t.Fatalf("dpos config missing")
	}
	if cfg.DPoS.TargetBlockPeriodMs() != 500 {
		t.Fatalf("periodMs parse mismatch: have %d want %d", cfg.DPoS.TargetBlockPeriodMs(), 500)
	}

	legacyPeriodJSON := []byte(`{"chainId":1,"dpos":{"period":1,"epoch":1000,"maxValidators":21,"sealSignerType":"ed25519"}}`)
	var legacy ChainConfig
	if err := json.Unmarshal(legacyPeriodJSON, &legacy); err != nil {
		t.Fatalf("unmarshal legacy period config: %v", err)
	}
	if legacy.DPoS == nil {
		t.Fatalf("legacy dpos config missing")
	}
	if legacy.DPoS.TargetBlockPeriodMs() != 1000 {
		t.Fatalf("legacy period mapping mismatch: have %d want %d", legacy.DPoS.TargetBlockPeriodMs(), 1000)
	}
}

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
