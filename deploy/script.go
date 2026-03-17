package deploy

import (
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/common"
)

// DeployTestnetPolicyWallet is a helper that compiles and prepares a full
// policy wallet deployment for the testnet. It returns a manifest with all
// policy wallet contracts compiled and ready for on-chain deployment.
func DeployTestnetPolicyWallet(owner, guardian common.Address) (*DeploymentManifest, error) {
	compiled, err := CompileAllPolicyWallet()
	if err != nil {
		return nil, fmt.Errorf("compile policy wallet: %w", err)
	}

	d := NewDeployer()

	// Register all policy wallet contracts with appropriate constructor args.
	for name, tor := range compiled {
		var args []interface{}
		if name == "PolicyWallet" {
			args = []interface{}{
				owner,
				guardian,
				defaultDailyLimit(),
				defaultSingleTxLimit(),
				uint64(86400), // 24h recovery timelock
			}
		}
		d.AddContract(name, tor, args)
	}

	manifest, err := d.DeployAll(owner)
	if err != nil {
		return nil, fmt.Errorf("deploy policy wallet: %w", err)
	}
	return manifest, nil
}

// DeployTestnetAgentEconomy prepares all agent economy contracts for
// testnet deployment. It returns a manifest with all contracts compiled
// and ready for on-chain deployment.
func DeployTestnetAgentEconomy(deployer common.Address) (*DeploymentManifest, error) {
	compiled, err := CompileAllAgentEconomy()
	if err != nil {
		return nil, fmt.Errorf("compile agent economy: %w", err)
	}

	d := NewDeployer()

	// Register all agent economy contracts.
	for name, tor := range compiled {
		d.AddContract(name, tor, nil)
	}

	manifest, err := d.DeployAll(deployer)
	if err != nil {
		return nil, fmt.Errorf("deploy agent economy: %w", err)
	}
	return manifest, nil
}

// DeployTestnetAll compiles and prepares both policy wallet and agent economy
// contracts for testnet deployment, returning a single combined manifest.
func DeployTestnetAll(owner, guardian common.Address) (*DeploymentManifest, error) {
	d := NewDeployer()

	// Compile and register policy wallet contracts.
	pwContracts, err := CompileAllPolicyWallet()
	if err != nil {
		return nil, fmt.Errorf("compile policy wallet: %w", err)
	}
	for name, tor := range pwContracts {
		var args []interface{}
		if name == "PolicyWallet" {
			args = []interface{}{
				owner,
				guardian,
				defaultDailyLimit(),
				defaultSingleTxLimit(),
				uint64(86400),
			}
		}
		d.AddContract(name, tor, args)
	}

	// Compile and register agent economy contracts.
	aeContracts, err := CompileAllAgentEconomy()
	if err != nil {
		return nil, fmt.Errorf("compile agent economy: %w", err)
	}
	for name, tor := range aeContracts {
		d.AddContract(name, tor, nil)
	}

	manifest, err := d.DeployAll(owner)
	if err != nil {
		return nil, fmt.Errorf("deploy all: %w", err)
	}
	return manifest, nil
}

// NewDefaultPolicyWalletParams creates default policy wallet deploy parameters.
func NewDefaultPolicyWalletParams(owner, guardian common.Address) PolicyWalletDeployParams {
	return PolicyWalletDeployParams{
		Owner:            owner,
		Guardian:         guardian,
		DailyLimit:       defaultDailyLimit(),
		SingleTxLimit:    defaultSingleTxLimit(),
		RecoveryTimelock: 86400,
	}
}

// ensure big.Int is used (it is used via defaultDailyLimit/defaultSingleTxLimit)
var _ = (*big.Int)(nil)
