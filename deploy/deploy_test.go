package deploy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tos-network/gtos/common"
)

// tolangRoot returns the absolute path to the tolang repository.
// It checks TOLANG_PATH first, then falls back to ../tolang relative to gtos root.
func tolangRoot(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("TOLANG_PATH"); p != "" {
		return p
	}
	// Walk up from the test file location to find the gtos root, then go to ../tolang.
	// In typical CI/dev layout: ~/gtos/deploy/ -> ~/tolang
	candidates := []string{
		filepath.Join("..", "..", "tolang"),           // from deploy/ in gtos
		filepath.Join("..", "tolang"),                 // from gtos root
		filepath.Join(os.Getenv("HOME"), "tolang"),   // absolute fallback
	}
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(abs, "tol_api.go")); err == nil {
			return abs
		}
	}
	t.Skip("tolang repository not found; set TOLANG_PATH or ensure ~/tolang exists")
	return ""
}

func policyWalletDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(tolangRoot(t), "examples", "policy_wallet")
}

func agentEconomyDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(tolangRoot(t), "examples", "agent_economy")
}

func TestCompileContract(t *testing.T) {
	dir := policyWalletDir(t)
	src := filepath.Join(dir, "PolicyWallet.tol")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		t.Skipf("policy wallet source not found at %s", src)
	}

	tor, err := CompileContract(src)
	if err != nil {
		t.Fatalf("CompileContract failed: %v", err)
	}
	if len(tor) == 0 {
		t.Fatal("CompileContract returned empty bytes")
	}
	// .tor files start with ZIP magic (PK\x03\x04)
	if len(tor) < 4 || tor[0] != 'P' || tor[1] != 'K' {
		t.Fatalf("compiled output does not look like a .tor package (first bytes: %x)", tor[:4])
	}
}

func TestCompileAllPolicyWallet(t *testing.T) {
	// Set TOLANG_PATH so the compiler can find the examples.
	root := tolangRoot(t)
	t.Setenv("TOLANG_PATH", root)

	contracts, err := CompileAllPolicyWallet()
	if err != nil {
		t.Fatalf("CompileAllPolicyWallet failed: %v", err)
	}

	expected := []string{"PolicyWallet", "SpendGuard", "GuardianRecovery", "DelegatedAgent", "TerminalAuthority"}
	if len(contracts) != len(expected) {
		t.Fatalf("expected %d contracts, got %d", len(expected), len(contracts))
	}
	for _, name := range expected {
		tor, ok := contracts[name]
		if !ok {
			t.Errorf("missing contract: %s", name)
			continue
		}
		if len(tor) == 0 {
			t.Errorf("contract %s has empty bytes", name)
		}
	}
}

func TestCompileAllAgentEconomy(t *testing.T) {
	root := tolangRoot(t)
	t.Setenv("TOLANG_PATH", root)

	contracts, err := CompileAllAgentEconomy()
	if err != nil {
		t.Fatalf("CompileAllAgentEconomy failed: %v", err)
	}

	expected := []string{"TaskEscrow", "SponsorRelay", "RecurringPayment", "MerchantPayment", "OracleResolver"}
	if len(contracts) != len(expected) {
		t.Fatalf("expected %d contracts, got %d", len(expected), len(contracts))
	}
	for _, name := range expected {
		tor, ok := contracts[name]
		if !ok {
			t.Errorf("missing contract: %s", name)
			continue
		}
		if len(tor) == 0 {
			t.Errorf("contract %s has empty bytes", name)
		}
	}
}

func TestDeployerRegisterAndTrack(t *testing.T) {
	d := NewDeployer()

	// Add some mock contracts.
	d.AddContract("Alpha", []byte("fake-tor-alpha"), []interface{}{"arg1"})
	d.AddContract("Beta", []byte("fake-tor-beta"), nil)

	names := d.ContractNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 contracts, got %d", len(names))
	}
	if names[0] != "Alpha" || names[1] != "Beta" {
		t.Fatalf("unexpected contract order: %v", names)
	}

	alpha := d.GetContract("Alpha")
	if alpha == nil {
		t.Fatal("GetContract(Alpha) returned nil")
	}
	if alpha.Status != "pending" {
		t.Fatalf("expected pending status, got %s", alpha.Status)
	}
	if len(alpha.ConstructorArgs) != 1 {
		t.Fatalf("expected 1 constructor arg, got %d", len(alpha.ConstructorArgs))
	}
}

func TestDeployAll(t *testing.T) {
	d := NewDeployer()
	d.AddContract("TestContract", []byte("fake-tor-data"), nil)

	deployer := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	manifest, err := d.DeployAll(deployer)
	if err != nil {
		t.Fatalf("DeployAll failed: %v", err)
	}

	if manifest.SchemaVersion != "1.0.0" {
		t.Fatalf("expected schema version 1.0.0, got %s", manifest.SchemaVersion)
	}
	if manifest.Network != "testnet" {
		t.Fatalf("expected network testnet, got %s", manifest.Network)
	}
	if len(manifest.Contracts) != 1 {
		t.Fatalf("expected 1 contract, got %d", len(manifest.Contracts))
	}
	if manifest.Contracts[0].Status != "deployed" {
		t.Fatalf("expected deployed status, got %s", manifest.Contracts[0].Status)
	}
	if manifest.Contracts[0].DeployerAddress != deployer {
		t.Fatalf("deployer address mismatch")
	}
}

func TestDeployAllNoContracts(t *testing.T) {
	d := NewDeployer()
	_, err := d.DeployAll(common.Address{})
	if err == nil {
		t.Fatal("expected error for empty deployer")
	}
}

func TestDeploymentManifestSerialization(t *testing.T) {
	manifest := &DeploymentManifest{
		SchemaVersion: "1.0.0",
		Network:       "testnet",
		Contracts: []ContractDeployment{
			{
				Name:            "PolicyWallet",
				SourcePath:      "examples/policy_wallet/PolicyWallet.tol",
				Status:          "deployed",
				DeployerAddress: common.HexToAddress("0xaaaa"),
				BlockNumber:     42,
				GasUsed:         100000,
			},
		},
		DeployedAt: "2026-01-01T00:00:00Z",
	}

	data, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalManifest failed: %v", err)
	}

	// Verify it's valid JSON.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("manifest JSON is invalid: %v", err)
	}

	// Round-trip.
	restored, err := UnmarshalManifest(data)
	if err != nil {
		t.Fatalf("UnmarshalManifest failed: %v", err)
	}
	if restored.SchemaVersion != manifest.SchemaVersion {
		t.Fatalf("schema version mismatch: %s != %s", restored.SchemaVersion, manifest.SchemaVersion)
	}
	if restored.Network != manifest.Network {
		t.Fatalf("network mismatch")
	}
	if len(restored.Contracts) != 1 {
		t.Fatalf("expected 1 contract, got %d", len(restored.Contracts))
	}
	if restored.Contracts[0].Name != "PolicyWallet" {
		t.Fatalf("contract name mismatch")
	}
	if restored.Contracts[0].BlockNumber != 42 {
		t.Fatalf("block number mismatch")
	}
}
