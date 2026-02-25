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
		{name: "periodMs only", cfg: &DPoSConfig{PeriodMs: 360}, want: 360},
	}
	for _, tc := range tests {
		if got := tc.cfg.TargetBlockPeriodMs(); got != tc.want {
			t.Fatalf("%s: have %d want %d", tc.name, got, tc.want)
		}
	}
}

func TestDPoSConfigRecentSignerWindowSize(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *DPoSConfig
		validators int
		want       uint64
	}{
		{name: "auto default", cfg: &DPoSConfig{}, validators: 15, want: 6},
		{name: "auto small set", cfg: &DPoSConfig{}, validators: 3, want: 2},
		{name: "explicit override", cfg: &DPoSConfig{RecentSignerWindow: 9}, validators: 21, want: 9},
		{name: "override capped by validators", cfg: &DPoSConfig{RecentSignerWindow: 100}, validators: 15, want: 15},
		{name: "zero validators guard", cfg: &DPoSConfig{}, validators: 0, want: 1},
		{name: "nil config uses auto", cfg: nil, validators: 21, want: 8},
	}
	for _, tc := range tests {
		if got := tc.cfg.RecentSignerWindowSize(tc.validators); got != tc.want {
			t.Fatalf("%s: have %d want %d", tc.name, got, tc.want)
		}
	}
}

func TestChainConfigJSONPeriodMs(t *testing.T) {
	periodMsJSON := []byte(`{"chainId":1,"dpos":{"periodMs":360,"epoch":1667,"maxValidators":15,"recentSignerWindow":9,"sealSignerType":"ed25519"}}`)
	var cfg ChainConfig
	if err := json.Unmarshal(periodMsJSON, &cfg); err != nil {
		t.Fatalf("unmarshal periodMs config: %v", err)
	}
	if cfg.DPoS == nil {
		t.Fatalf("dpos config missing")
	}
	if cfg.DPoS.TargetBlockPeriodMs() != 360 {
		t.Fatalf("periodMs parse mismatch: have %d want %d", cfg.DPoS.TargetBlockPeriodMs(), 360)
	}
	if cfg.DPoS.RecentSignerWindow != 9 {
		t.Fatalf("recentSignerWindow parse mismatch: have %d want %d", cfg.DPoS.RecentSignerWindow, 9)
	}

}

func TestChainConfigJSONRejectsLegacyPeriod(t *testing.T) {
	legacyPeriodJSON := []byte(`{"chainId":1,"dpos":{"period":1,"epoch":1667,"maxValidators":15,"sealSignerType":"ed25519"}}`)
	var cfg ChainConfig
	if err := json.Unmarshal(legacyPeriodJSON, &cfg); err == nil {
		t.Fatalf("expected legacy period config to be rejected")
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
