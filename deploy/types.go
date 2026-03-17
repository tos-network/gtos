package deploy

import (
	"math/big"

	"github.com/tos-network/gtos/common"
)

// ContractDeployment tracks the state of a single contract deployment.
type ContractDeployment struct {
	Name            string         `json:"name"`
	SourcePath      string         `json:"source_path"`
	TorBytes        []byte         `json:"-"`
	ConstructorArgs []interface{}  `json:"constructor_args"`
	DeployerAddress common.Address `json:"deployer_address"`
	ContractAddress common.Address `json:"contract_address,omitempty"`
	TxHash          common.Hash    `json:"tx_hash,omitempty"`
	BlockNumber     uint64         `json:"block_number,omitempty"`
	GasUsed         uint64         `json:"gas_used,omitempty"`
	Status          string         `json:"status"` // "pending", "deployed", "failed"
	DeployedAt      uint64         `json:"deployed_at,omitempty"`
}

// DeploymentManifest records a full deployment session across one or more contracts.
type DeploymentManifest struct {
	SchemaVersion string               `json:"schema_version"`
	Network       string               `json:"network"` // "testnet", "mainnet"
	Contracts     []ContractDeployment `json:"contracts"`
	DeployedAt    string               `json:"deployed_at"`
}

// PolicyWalletDeployParams holds the constructor arguments for a PolicyWallet deployment.
type PolicyWalletDeployParams struct {
	Owner            common.Address `json:"owner"`
	Guardian         common.Address `json:"guardian"`
	DailyLimit       *big.Int       `json:"daily_limit"`
	SingleTxLimit    *big.Int       `json:"single_tx_limit"`
	RecoveryTimelock uint64         `json:"recovery_timelock"` // seconds
}
