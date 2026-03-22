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

	// PrivacyRouterAddress is the dedicated recipient for private-balance transactions.
	PrivacyRouterAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000004")

	// LVMSerialAddress is a sentinel write-address injected by AnalyzeTx for
	// any transaction whose destination is a code-bearing address (LVM call).
	// Because LVM contracts can perform arbitrary cross-contract storage writes
	// that cannot be predicted statically, all such transactions share this
	// address in their write set, forcing them into serial execution levels.
	LVMSerialAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000005")

	// Agent-Native system contract addresses (Agent-Native infrastructure).
	AgentRegistryAddress      = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000101")
	CapabilityRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000102")
	DelegationRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000103")
	ReputationHubAddress      = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000104")

	// KYC / TNS / Referral system contract addresses.
	KYCRegistryAddress      = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000105")
	TNSRegistryAddress      = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000106")
	ReferralRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000107")

	// TaskSchedulerAddress stores on-chain scheduled-task state via storage slots.
	TaskSchedulerAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000108")

	// CheckpointSlashIndicatorAddress is the native system-contract style address
	// that accepts malicious-vote evidence submissions for checkpoint finality.
	CheckpointSlashIndicatorAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000109")

	// SponsorRegistryAddress stores protocol-level sponsor nonce state for
	// native sponsored transactions.
	SponsorRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000110")

	// GroupRegistryAddress stores on-chain Group registration and state commitment data.
	GroupRegistryAddress = common.HexToAddress("0x000000000000000000000000000000000000000000000000000000000000010A")

	// LeaseRegistryAddress stores protocol-native lease metadata, expiry indexes,
	// and tombstones for lease contracts.
	LeaseRegistryAddress = common.HexToAddress("0x000000000000000000000000000000000000000000000000000000000000010B")

	// PolicyWalletRegistryAddress stores on-chain policy wallet state (spend caps,
	// allowlists, terminal policies, delegate auth, guardian/recovery).
	PolicyWalletRegistryAddress = common.HexToAddress("0x000000000000000000000000000000000000000000000000000000000000010C")

	// AuditReceiptRegistryAddress stores audit receipt metadata for
	// intent-to-receipt traceability and proof references.
	AuditReceiptRegistryAddress = common.HexToAddress("0x000000000000000000000000000000000000000000000000000000000000010D")

	// GatewayRegistryAddress stores on-chain gateway relay configuration for
	// agents with the GatewayRelay capability.
	GatewayRegistryAddress = common.HexToAddress("0x000000000000000000000000000000000000000000000000000000000000010E")

	// SettlementRegistryAddress stores settlement callbacks and async
	// fulfillment records composable with account policy and receipts.
	SettlementRegistryAddress = common.HexToAddress("0x000000000000000000000000000000000000000000000000000000000000010F")

	// PackageRegistryAddress stores on-chain package publishing registry state
	// (publisher records, package records, hash lookups).
	PackageRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000200")

	// VerificationRegistryAddress stores verifier definitions and subject-proof
	// verification attestations for protocol-backed `tos.isverified(...)`.
	VerificationRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000201")

	// PayPolicyRegistryAddress stores settlement/pay policy records used by
	// protocol-backed `tos.canpay(...)`.
	PayPolicyRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000000000000000000000000000202")
)

// DPoS validator stake and reward parameters.
var (
	DPoSMinValidatorStake = new(big.Int).Mul(big.NewInt(10_000_000), big.NewInt(1e18)) // 10,000,000 TOS
	DPoSBlockReward       = new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18))          // 2 TOS/block

	// AgentMinStake is the minimum stake required for AGENT_REGISTER.
	AgentMinStake = new(big.Int).Mul(big.NewInt(1_000), big.NewInt(1e18)) // 1,000 TOS

	// TNSRegistrationFee is the fee required for TNS_REGISTER (0.1 TOS).
	TNSRegistrationFee = new(big.Int).Mul(big.NewInt(1e17), big.NewInt(1)) // 0.1 TOS (1e17 tomi)
)

// Account Abstraction constants.
const (
	// ValidationGasCap is the hard gas cap for account.validate() calls.
	ValidationGasCap uint64 = 50_000
	// AgentLoadGas is the gas cost of tos.agentload() — equivalent to 1 SLOAD.
	AgentLoadGas uint64 = 100
)

// Scheduled task constants.
const (
	TaskScheduleGas       uint64 = 200
	TaskCancelGas         uint64 = 100
	TaskInfoGas           uint64 = 100
	TaskMinGasLimit       uint64 = 10_000
	TaskMaxGasLimit       uint64 = 500_000
	TaskMaxPerBlock       uint64 = 50
	TaskMaxPerContract    uint64 = 100
	TaskMinIntervalBlocks uint64 = 10
	TaskMaxHorizonBlocks  uint64 = 1_000_000
)

// TNS / KYC / Referral constants.
const (
	TNSMinNameLen           = 3
	TNSMaxNameLen           = 64
	MaxReferralDepth uint8  = 20
	ReferralBindGas  uint64 = 500
	KYCLoadGas       uint64 = 100
	TNSLoadGas       uint64 = 200
	ReferralLoadGas  uint64 = 100
	KYCCommitteeBit  uint8  = 1
)

// SysActionGas is the fixed gas cost charged for any system action transaction,
// on top of the intrinsic gas.
const SysActionGas uint64 = 100_000

// Lease-contract constants.
const (
	// Separate gas schedule for native lease deployment via LEASE_DEPLOY.
	LeaseDeployBaseGas uint64 = 0
	LeaseDeployByteGas uint64 = 100

	// Separate gas schedules for in-contract lease deployment. These keep the
	// same CREATE/CREATE2 base shape as the permanent VM primitives while using
	// a discounted lease-specific code-install price.
	LeaseCreateXBaseGas  uint64 = 32_000
	LeaseCreateXByteGas  uint64 = 100
	LeaseCreate2XBaseGas uint64 = 32_000
	LeaseCreate2XByteGas uint64 = 100

	// Deposit / lifecycle policy defaults.
	LeaseDepositReferenceByteGas uint64 = 200
	LeaseReferenceBlocks         uint64 = 87_600_000
	LeaseMinBlocks               uint64 = 1
	LeaseMaxBlocks               uint64 = LeaseReferenceBlocks
	LeaseRefundNumerator         uint64 = 80
	LeaseRefundDenominator       uint64 = 100
	LeasePruneBudgetPerSweep     uint64 = 4096
)

// UNO (Untraceable Native cOin) unit system.
// 1 TOS = 1 UNO; UNO has 2 decimal places.
const (
	UNODecimals        = 2
	Unomi       uint64 = 1e16 // 1 UNO base unit = 0.01 TOS = 10^16 tomi
	UNOBaseFee  uint64 = 1    // base fee per priv tx in UNO base units (0.01 UNO)

)

// Privacy proof size limits.
const (
	PrivMaxProofBytes = 96 * 1024
)

// TxPriceTomi is the protocol-fixed tx price for GTOS transactions.
// 10 gtomi = 10,000,000,000 tomi.
const TxPriceTomi int64 = 10_000_000_000

// TxPrice returns the protocol-fixed tx price as a new big.Int.
func TxPrice() *big.Int {
	return big.NewInt(TxPriceTomi)
}

// DPoS consensus parameters.
const (
	DPoSEpochLength   uint64 = 1664 // ~10 minutes at 360ms block interval; divisible by turnLength=16
	DPoSMaxValidators uint64 = 15
	DPoSBlockPeriodMs uint64 = 360 // target milliseconds per block
	DPoSTurnLength    uint64 = 16
	// 24 hours at the default 360ms block interval.
	DPoSMaintenanceMaxBlocks uint64 = 240000
	// Lease contracts freeze for one epoch by default before becoming expired.
	LeaseGraceBlocks uint64 = DPoSEpochLength
)
