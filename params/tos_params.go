package params

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

// Protocol system addresses — fixed, well-known addresses used by GTOS.
var (
	// SystemActionAddress is the sentinel To-address for system action transactions.
	// Transactions sent to this address carry a JSON-encoded SysAction in tx.Data
	// and are executed outside the TVM by the state processor.
	SystemActionAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000001")

	// ValidatorRegistryAddress stores on-chain DPoS validator state via storage slots.
	ValidatorRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000003")

	// PrivacyRouterAddress is the dedicated recipient for UNO private-balance transactions.
	PrivacyRouterAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000004")

	// LVMSerialAddress is a sentinel write-address injected by AnalyzeTx for
	// any transaction whose destination is a code-bearing address (LVM call).
	// Because LVM contracts can perform arbitrary cross-contract storage writes
	// that cannot be predicted statically, all such transactions share this
	// address in their write set, forcing them into serial execution levels.
	LVMSerialAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000005")

	// Agent-Native system contract addresses (Agent-Native infrastructure).
	AgentRegistryAddress      = common.HexToAddress("0x0000000000000000000000000000000000000101")
	CapabilityRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000102")
	DelegationRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000103")
	ReputationHubAddress      = common.HexToAddress("0x0000000000000000000000000000000000000104")
)

// DPoS validator stake and reward parameters.
var (
	DPoSMinValidatorStake = new(big.Int).Mul(big.NewInt(10_000_000), big.NewInt(1e18)) // 10,000,000 TOS
	DPoSBlockReward       = new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18))          // 2 TOS/block

	// AgentMinStake is the minimum stake required for AGENT_REGISTER.
	AgentMinStake = new(big.Int).Mul(big.NewInt(1_000), big.NewInt(1e18)) // 1,000 TOS
)

// Account Abstraction constants.
const (
	// ValidationGasCap is the hard gas cap for account.validate() calls.
	ValidationGasCap uint64 = 50_000
	// AgentLoadGas is the gas cost of tos.agentload() — equivalent to 1 SLOAD.
	AgentLoadGas uint64 = 100
)

// SysActionGas is the fixed gas cost charged for any system action transaction,
// on top of the intrinsic gas.
const SysActionGas uint64 = 100_000

// UNO private-balance gas and payload bounds (MVP).
const (
	UNOBaseGas         uint64 = 150_000
	UNOShieldGas       uint64 = 300_000
	UNOTransferGas     uint64 = 500_000
	UNOUnshieldGas     uint64 = 300_000
	UNOMaxPayloadBytes        = 128 * 1024
	UNOMaxProofBytes          = 96 * 1024
)

// GTOSPriceWei is the protocol-fixed tx price for GTOS transactions.
// 10 gwei = 10,000,000,000 wei.
const GTOSPriceWei int64 = 10_000_000_000

// GTOSPrice returns the protocol-fixed tx price as a new big.Int.
func GTOSPrice() *big.Int {
	return big.NewInt(GTOSPriceWei)
}

// DPoS consensus parameters.
const (
	DPoSEpochLength   uint64 = 1667 // ~10 minutes at 360ms block interval
	DPoSMaxValidators uint64 = 15
	DPoSBlockPeriodMs uint64 = 360 // target milliseconds per block
)
