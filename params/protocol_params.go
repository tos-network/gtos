// Copyright 2015 The go-ehtereum Authors
// Copyright 2023 Terminos Network
// This file is part of the tos library.
//
// The tos library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The tos library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the tos library. If not, see <http://www.gnu.org/licenses/>.

package params

import "math/big"

const (
	GasLimitBoundDivisor uint64 = 1024    // The bound divisor of the gas limit, used in update calculations.
	MinGasLimit          uint64 = 5000    // Minimum the gas limit may ever be.
	GenesisGasLimit      uint64 = 4712388 // Gas limit of the Genesis block.
	MaximumExtraDataSize uint64 = 32      // Maximum size extra data may be after Genesis.
	QuadCoeffDiv         uint64 = 512     // Divisor for the quadratic particle of the memory cost equation.
	EpochDuration        uint64 = 30000   // Duration between proof-of-work epochs.
	CallCreateDepth      uint64 = 1024    // Maximum depth of call/create stack.
	StackLimit           uint64 = 1024    // Maximum size of VM stack allowed.
	MaxCodeSize                 = 24576   // Maximum bytecode to permit for a contract

	// Gas costs
	TxGas uint64 = 21000
)

var (
	DifficultyBoundDivisor = big.NewInt(2048)   // The bound divisor of the difficulty, used in the update calculations.
	GenesisDifficulty      = big.NewInt(131072) // Difficulty of the Genesis block.
	MinimumDifficulty      = big.NewInt(131072) // The minimum that the difficulty may ever be.
	DurationLimit          = big.NewInt(13)     // The decision boundary on the blocktime duration used to determine whether difficulty should go up or not.
)
