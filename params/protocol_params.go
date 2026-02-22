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
	TxDataNonZeroGasReduced   uint64 = 16    // Per byte of non-zero data attached to a transaction after the Istanbul update
	TxAccessListAddressGas    uint64 = 2400  // Per address specified in a transaction access list
	TxAccessListStorageKeyGas uint64 = 1900  // Per storage key specified in a transaction access list

	InitialBaseFee = 1000000000 // Initial base fee for dynamic-fee blocks.

	// The Refund Quotient is the cap on how much of the used gas can be refunded. Before refund-limit rules,
	// up to half the consumed gas could be refunded. Redefined as 1/5th in refund-limit rules
	RefundQuotient uint64 = 2
)

var (
	GenesisDifficulty = big.NewInt(131072) // Difficulty of the Genesis block.
)
