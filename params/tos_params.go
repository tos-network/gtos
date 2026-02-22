package params

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

// Protocol system addresses — fixed, well-known addresses used by GTOS.
var (
	// SystemActionAddress is the sentinel To-address for system action transactions.
	// Transactions sent to this address carry a JSON-encoded SysAction in tx.Data
	// and are executed outside the EVM by the state processor.
	SystemActionAddress = common.HexToAddress("0x53595354454D5F414354494F4E5F43454E544552") // "SYSTEM_ACTION_CENTER"

	// ValidatorRegistryAddress stores on-chain DPoS validator state via storage slots.
	ValidatorRegistryAddress = common.HexToAddress("0x56414C494441544F525F535441544553544F5245") // "VALIDATOR_STATESTORE"
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
