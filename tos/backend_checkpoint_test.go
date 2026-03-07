package tos

import (
	"math/big"
	"strings"
	"testing"

	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/tos/tosconfig"
)

func TestValidateCheckpointRetention(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *tosconfig.Config
		chainCfg  *params.ChainConfig
		wantError string
	}{
		{
			name: "inactive",
			cfg:  &tosconfig.Config{},
			chainCfg: &params.ChainConfig{ChainID: big.NewInt(1), DPoS: &params.DPoSConfig{
				PeriodMs:       360,
				Epoch:          208,
				MaxValidators:  21,
				TurnLength:     params.DPoSTurnLength,
				SealSignerType: params.DPoSSealSignerTypeEd25519,
			}},
		},
		{
			name: "archive bypasses retention limit",
			cfg:  &tosconfig.Config{NoPruning: true},
			chainCfg: &params.ChainConfig{ChainID: big.NewInt(1), DPoS: &params.DPoSConfig{
				PeriodMs:                360,
				Epoch:                   208,
				MaxValidators:           21,
				TurnLength:              params.DPoSTurnLength,
				SealSignerType:          params.DPoSSealSignerTypeEd25519,
				CheckpointInterval:      200,
				CheckpointFinalityBlock: big.NewInt(1000),
			}},
		},
		{
			name: "small interval fits full-node retention",
			cfg:  &tosconfig.Config{},
			chainCfg: &params.ChainConfig{ChainID: big.NewInt(1), DPoS: &params.DPoSConfig{
				PeriodMs:                360,
				Epoch:                   208,
				MaxValidators:           21,
				TurnLength:              params.DPoSTurnLength,
				SealSignerType:          params.DPoSSealSignerTypeEd25519,
				CheckpointInterval:      core.TriesInMemory / 2,
				CheckpointFinalityBlock: big.NewInt(1000),
			}},
		},
		{
			name: "default interval requires archive mode",
			cfg:  &tosconfig.Config{},
			chainCfg: &params.ChainConfig{ChainID: big.NewInt(1), DPoS: &params.DPoSConfig{
				PeriodMs:                360,
				Epoch:                   208,
				MaxValidators:           21,
				TurnLength:              params.DPoSTurnLength,
				SealSignerType:          params.DPoSSealSignerTypeEd25519,
				CheckpointFinalityBlock: big.NewInt(1000),
			}},
			wantError: "checkpoint finality requires state retention",
		},
	}

	for _, tc := range tests {
		err := validateCheckpointRetention(tc.cfg, tc.chainCfg)
		if tc.wantError == "" {
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantError) {
			t.Fatalf("%s: have error %v want substring %q", tc.name, err, tc.wantError)
		}
	}
}
