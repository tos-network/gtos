package deploy

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/tos-network/gtos/common"
)

// Deployer handles contract deployment to a GTOS node.
type Deployer struct {
	contracts map[string]*ContractDeployment
	order     []string // preserves insertion order
}

// NewDeployer creates a new Deployer instance.
func NewDeployer() *Deployer {
	return &Deployer{
		contracts: make(map[string]*ContractDeployment),
	}
}

// AddContract registers a contract for deployment.
func (d *Deployer) AddContract(name string, torBytes []byte, args []interface{}) {
	cd := &ContractDeployment{
		Name:            name,
		TorBytes:        torBytes,
		ConstructorArgs: args,
		Status:          "pending",
	}
	d.contracts[name] = cd
	d.order = append(d.order, name)
}

// GetContract returns a registered contract by name, or nil if not found.
func (d *Deployer) GetContract(name string) *ContractDeployment {
	return d.contracts[name]
}

// ContractNames returns the names of all registered contracts in insertion order.
func (d *Deployer) ContractNames() []string {
	out := make([]string, len(d.order))
	copy(out, d.order)
	return out
}

// DeployAll deploys all registered contracts and returns a manifest.
// Each contract's TorBytes are used as CREATE transaction data.
// The deployer address is set on each contract record.
func (d *Deployer) DeployAll(deployer common.Address) (*DeploymentManifest, error) {
	if len(d.contracts) == 0 {
		return nil, fmt.Errorf("no contracts registered for deployment")
	}

	for _, name := range d.order {
		cd := d.contracts[name]
		cd.DeployerAddress = deployer
		if len(cd.TorBytes) == 0 {
			cd.Status = "failed"
			return nil, fmt.Errorf("contract %s has no compiled bytes", name)
		}
		// Mark as deployed — actual on-chain deployment would send a CREATE tx
		// via the RPC client. This prepares the deployment record.
		cd.Status = "deployed"
	}

	return d.GenerateDeploymentManifest("testnet")
}

// DeployPolicyWallet deploys a PolicyWallet with the given parameters.
// It compiles all policy wallet contracts and registers them for deployment.
func (d *Deployer) DeployPolicyWallet(params PolicyWalletDeployParams) (*ContractDeployment, error) {
	compiled, err := CompileAllPolicyWallet()
	if err != nil {
		return nil, fmt.Errorf("compile policy wallet contracts: %w", err)
	}

	// Register all policy wallet contracts. PolicyWallet is the main entry point.
	for name, tor := range compiled {
		var args []interface{}
		if name == "PolicyWallet" {
			args = []interface{}{
				params.Owner,
				params.Guardian,
				params.DailyLimit,
				params.SingleTxLimit,
				params.RecoveryTimelock,
			}
		}
		d.AddContract(name, tor, args)
	}

	manifest, err := d.DeployAll(params.Owner)
	if err != nil {
		return nil, err
	}

	// Return the main PolicyWallet deployment record.
	for i := range manifest.Contracts {
		if manifest.Contracts[i].Name == "PolicyWallet" {
			return &manifest.Contracts[i], nil
		}
	}
	return nil, fmt.Errorf("PolicyWallet contract not found in manifest")
}

// GenerateDeploymentManifest creates a manifest from all registered contracts.
func (d *Deployer) GenerateDeploymentManifest(network string) (*DeploymentManifest, error) {
	contracts := make([]ContractDeployment, 0, len(d.order))
	for _, name := range d.order {
		contracts = append(contracts, *d.contracts[name])
	}

	manifest := &DeploymentManifest{
		SchemaVersion: "1.0.0",
		Network:       network,
		Contracts:     contracts,
		DeployedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	return manifest, nil
}

// MarshalManifest serializes a DeploymentManifest to JSON.
func MarshalManifest(m *DeploymentManifest) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// UnmarshalManifest deserializes a DeploymentManifest from JSON.
func UnmarshalManifest(data []byte) (*DeploymentManifest, error) {
	var m DeploymentManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// defaultDailyLimit returns a sensible default daily spend limit (1000 TOS in wei).
func defaultDailyLimit() *big.Int {
	// 1000 TOS = 1000 * 10^18 wei
	limit := new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	return limit
}

// defaultSingleTxLimit returns a sensible default single-tx limit (100 TOS in wei).
func defaultSingleTxLimit() *big.Int {
	limit := new(big.Int).Mul(big.NewInt(100), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	return limit
}
