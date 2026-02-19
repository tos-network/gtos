// Copyright 2024 The gtos Authors
// This file is part of the gtos library.
//
// The gtos library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The gtos library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the gtos library. If not, see <http://www.gnu.org/licenses/>.

package params

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

// TOS system addresses — fixed, well-known addresses used by the protocol.
var (
	// SystemActionAddress is the sentinel To-address for system action transactions.
	// Transactions sent to this address carry a JSON-encoded SysAction in tx.Data
	// and are executed outside the EVM by the state processor.
	SystemActionAddress = common.HexToAddress("0x0000000000000000000000000000000054534F31") // "TOS1"

	// AgentRegistryAddress stores on-chain agent registry state via storage slots.
	AgentRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000054534F32") // "TOS2"

	// StakingAddress stores on-chain staking / delegation state via storage slots.
	StakingAddress = common.HexToAddress("0x0000000000000000000000000000000054534F33") // "TOS3"
)

// TOS staking parameters.
var (
	// MinNodeStake is the minimum self-stake (in wei) required for a node to be
	// considered active and eligible for block rewards.
	// Default: 10,000 TOS  (10000 * 1e18 wei)
	MinNodeStake = new(big.Int).Mul(big.NewInt(10_000), big.NewInt(1e18))

	// BlockReward is the total TOS minted per block and distributed to active
	// nodes (and their delegators) by the consensus Finalize() hook.
	// Default: 2 TOS per block
	BlockReward = new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18))

	// BaseBlockReward is an alias for BlockReward, used by the staking reward distributor.
	BaseBlockReward = BlockReward

	// UnstakeLockBlocks is the number of blocks a node must wait after calling
	// NODE_UNSTAKE before the stake is actually withdrawable.
	UnstakeLockBlocks = uint64(50_400) // ~7 days at 12 s/block

	// UndelegateLockBlocks is the lock period for delegators after UNDELEGATE.
	UndelegateLockBlocks = uint64(25_200) // ~3.5 days

	// MaxCommissionBPS is the maximum commission a node may charge, in basis points.
	MaxCommissionBPS = uint64(5_000) // 50%
)

// SysActionGas is the fixed gas cost charged for any system action transaction,
// on top of the intrinsic gas.
const SysActionGas uint64 = 100_000
