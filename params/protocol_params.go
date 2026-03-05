// Copyright 2015 The go-ethereum Authors
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

import "math/big"

const (
	GasLimitBoundDivisor uint64 = 1024               // The bound divisor of the gas limit, used in update calculations.
	MinGasLimit          uint64 = 5000               // Minimum the gas limit may ever be.
	MaxGasLimit          uint64 = 0x7fffffffffffffff // Maximum the gas limit (2^63-1).
	GenesisGasLimit      uint64 = 4712388            // Gas limit of the Genesis block.

	MaximumExtraDataSize      uint64 = 32    // Maximum size extra data may be after Genesis.
	TxGas                     uint64 = 3000  // Per transaction not creating a contract.
	TxGasContractCreation     uint64 = 53000 // Per transaction that creates a contract.
	TxDataZeroGas             uint64 = 4     // Per byte of transaction data that equals zero.
	TxDataNonZeroGasFrontier  uint64 = 68    // Per byte of data attached to a transaction that is not equal to zero. NOTE: Not payable on data of calls between transactions.
	TxDataNonZeroGasReduced   uint64 = 16    // Per byte of non-zero data attached to a transaction (reduced rate)
	TxAccessListAddressGas    uint64 = 2400  // Per address specified in a transaction access list
	TxAccessListStorageKeyGas uint64 = 1900  // Per storage key specified in a transaction access list

	InitialBaseFee = 1000000000 // Initial base fee for dynamic-fee blocks.
	MaxCodeSize    = 64 * 1024   // Maximum bytecode size permitted for raw code storage writes (EIP-170 compatible).
	MaxPackageSize = 512 * 1024  // Maximum .tor package size permitted for TOL contract deployment.
	// Additional gas charged per ttl block for KV record retention.
	KVTTLBlockGas uint64 = 1

	// RefundQuotient caps how much used gas can be refunded after a transaction.
	// The legacy cap was gasUsed/2; the stricter cap is gasUsed/5 to prevent
	// gas-refund griefing. GTOS uses the stricter value unconditionally.
	RefundQuotient       uint64 = 2 // legacy cap: gasUsed/2 (kept for reference)
	RefundQuotientStrict uint64 = 5 // strict cap: gasUsed/5 — GTOS default
)

var (
	GenesisDifficulty = big.NewInt(131072) // Difficulty of the Genesis block.
)
