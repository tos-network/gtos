// Copyright 2020 The go-ethereum Authors
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

// Package checkpointoracle is a stub after the removal of the on-chain
// checkpoint oracle contract (which depended on accounts/abi/bind and
// contracts/checkpointoracle, both removed in GTOS).
package checkpointoracle

import (
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
)

// CheckpointOracle is a no-op stub. The on-chain checkpoint oracle has been
// removed together with the EVM and ABI toolchain.
type CheckpointOracle struct {
	config   *params.CheckpointOracleConfig
	getLocal func(uint64) params.TrustedCheckpoint
}

// New creates a no-op checkpoint oracle stub.
func New(config *params.CheckpointOracleConfig, getLocal func(uint64) params.TrustedCheckpoint) *CheckpointOracle {
	return &CheckpointOracle{
		config:   config,
		getLocal: getLocal,
	}
}

// Start is a no-op in the stub (no contract backend needed).
func (oracle *CheckpointOracle) Start(backend interface{}) {}

// IsRunning always returns false in the stub.
func (oracle *CheckpointOracle) IsRunning() bool { return false }

// StableCheckpoint always returns nil in the stub (no on-chain data).
func (oracle *CheckpointOracle) StableCheckpoint() (*params.TrustedCheckpoint, uint64) {
	return nil, 0
}

// VerifySigners always returns false in the stub.
func (oracle *CheckpointOracle) VerifySigners(index uint64, hash [32]byte, signatures [][]byte) (bool, []common.Address) {
	return false, nil
}

// ContractAddr returns the configured contract address.
func (oracle *CheckpointOracle) ContractAddr() common.Address {
	if oracle.config != nil {
		return oracle.config.Address
	}
	return common.Address{}
}
