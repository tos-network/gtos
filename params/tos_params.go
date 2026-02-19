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
)

// SysActionGas is the fixed gas cost charged for any system action transaction,
// on top of the intrinsic gas.
const SysActionGas uint64 = 100_000
