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

	// ValidatorRegistryAddress stores on-chain DPoS validator state via storage slots.
	ValidatorRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000054534F33") // "TOS3"
)

// DPoS validator stake and reward parameters.
var (
	DPoSMinValidatorStake = new(big.Int).Mul(big.NewInt(10_000), big.NewInt(1e18)) // 10,000 TOS
	DPoSBlockReward       = new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18))      // 2 TOS/block
)

// SysActionGas is the fixed gas cost charged for any system action transaction,
// on top of the intrinsic gas.
const SysActionGas uint64 = 100_000

// DPoS consensus parameters.
const (
	DPoSEpochLength   uint64 = 200
	DPoSMaxValidators uint64 = 21
	DPoSBlockPeriod   uint64 = 3 // target seconds per block
)
