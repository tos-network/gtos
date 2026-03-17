package deploy

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/tos-network/gtos/common"
)

// testOwner and testGuardian are deterministic addresses used across integration tests.
var (
	testOwner    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	testGuardian = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
)

func TestDeployTestnetPolicyWallet(t *testing.T) {
	root := tolangRoot(t)
	t.Setenv("TOLANG_PATH", root)

	manifest, err := DeployTestnetPolicyWallet(testOwner, testGuardian)
	if err != nil {
		t.Fatalf("DeployTestnetPolicyWallet failed: %v", err)
	}

	// Verify manifest metadata.
	if manifest.Network != "testnet" {
		t.Fatalf("expected network testnet, got %s", manifest.Network)
	}
	if manifest.SchemaVersion != "1.0.0" {
		t.Fatalf("expected schema version 1.0.0, got %s", manifest.SchemaVersion)
	}
	if manifest.DeployedAt == "" {
		t.Fatal("DeployedAt should be set")
	}

	// Verify contract count.
	if len(manifest.Contracts) != 5 {
		t.Fatalf("expected 5 contracts, got %d", len(manifest.Contracts))
	}

	// Verify all expected contract names are present.
	expected := map[string]bool{
		"PolicyWallet":      false,
		"SpendGuard":        false,
		"GuardianRecovery":  false,
		"DelegatedAgent":    false,
		"TerminalAuthority": false,
	}
	for _, c := range manifest.Contracts {
		if _, ok := expected[c.Name]; !ok {
			t.Errorf("unexpected contract name: %s", c.Name)
			continue
		}
		expected[c.Name] = true

		if c.Status != "deployed" {
			t.Errorf("contract %s status = %s, want deployed", c.Name, c.Status)
		}
		if c.DeployerAddress != testOwner {
			t.Errorf("contract %s deployer address mismatch", c.Name)
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("missing expected contract: %s", name)
		}
	}
}

func TestDeployTestnetAgentEconomy(t *testing.T) {
	root := tolangRoot(t)
	t.Setenv("TOLANG_PATH", root)

	deployer := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
	manifest, err := DeployTestnetAgentEconomy(deployer)
	if err != nil {
		t.Fatalf("DeployTestnetAgentEconomy failed: %v", err)
	}

	if len(manifest.Contracts) != 5 {
		t.Fatalf("expected 5 contracts, got %d", len(manifest.Contracts))
	}

	expected := map[string]bool{
		"TaskEscrow":       false,
		"SponsorRelay":     false,
		"RecurringPayment": false,
		"MerchantPayment":  false,
		"OracleResolver":   false,
	}
	for _, c := range manifest.Contracts {
		if _, ok := expected[c.Name]; !ok {
			t.Errorf("unexpected contract name: %s", c.Name)
			continue
		}
		expected[c.Name] = true
	}
	for name, found := range expected {
		if !found {
			t.Errorf("missing expected contract: %s", name)
		}
	}
}

func TestDeployTestnetAll(t *testing.T) {
	root := tolangRoot(t)
	t.Setenv("TOLANG_PATH", root)

	manifest, err := DeployTestnetAll(testOwner, testGuardian)
	if err != nil {
		t.Fatalf("DeployTestnetAll failed: %v", err)
	}

	// Should have all 10 contracts combined.
	if len(manifest.Contracts) != 10 {
		t.Fatalf("expected 10 contracts, got %d", len(manifest.Contracts))
	}

	// Verify no duplicate names.
	seen := make(map[string]bool)
	for _, c := range manifest.Contracts {
		if seen[c.Name] {
			t.Errorf("duplicate contract name: %s", c.Name)
		}
		seen[c.Name] = true
	}

	// Verify all 10 expected names.
	allExpected := []string{
		"PolicyWallet", "SpendGuard", "GuardianRecovery", "DelegatedAgent", "TerminalAuthority",
		"TaskEscrow", "SponsorRelay", "RecurringPayment", "MerchantPayment", "OracleResolver",
	}
	for _, name := range allExpected {
		if !seen[name] {
			t.Errorf("missing expected contract: %s", name)
		}
	}
}

func TestManifestJSONRoundTrip(t *testing.T) {
	root := tolangRoot(t)
	t.Setenv("TOLANG_PATH", root)

	manifest, err := DeployTestnetAll(testOwner, testGuardian)
	if err != nil {
		t.Fatalf("DeployTestnetAll failed: %v", err)
	}

	// Marshal to JSON.
	data, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("MarshalManifest failed: %v", err)
	}

	// Verify it is valid JSON.
	if !json.Valid(data) {
		t.Fatal("marshaled manifest is not valid JSON")
	}

	// Unmarshal back.
	restored, err := UnmarshalManifest(data)
	if err != nil {
		t.Fatalf("UnmarshalManifest failed: %v", err)
	}

	// Verify top-level fields.
	if restored.SchemaVersion != manifest.SchemaVersion {
		t.Errorf("SchemaVersion: got %s, want %s", restored.SchemaVersion, manifest.SchemaVersion)
	}
	if restored.Network != manifest.Network {
		t.Errorf("Network: got %s, want %s", restored.Network, manifest.Network)
	}
	if restored.DeployedAt != manifest.DeployedAt {
		t.Errorf("DeployedAt: got %s, want %s", restored.DeployedAt, manifest.DeployedAt)
	}

	// Verify contracts round-trip (TorBytes is json:"-" so it won't survive).
	if len(restored.Contracts) != len(manifest.Contracts) {
		t.Fatalf("contract count: got %d, want %d", len(restored.Contracts), len(manifest.Contracts))
	}
	for i, orig := range manifest.Contracts {
		got := restored.Contracts[i]
		if got.Name != orig.Name {
			t.Errorf("contract[%d] Name: got %s, want %s", i, got.Name, orig.Name)
		}
		if got.Status != orig.Status {
			t.Errorf("contract[%d] Status: got %s, want %s", i, got.Status, orig.Status)
		}
		if got.DeployerAddress != orig.DeployerAddress {
			t.Errorf("contract[%d] DeployerAddress mismatch", i)
		}
	}
}

func TestContractBytecodeNonEmpty(t *testing.T) {
	root := tolangRoot(t)
	t.Setenv("TOLANG_PATH", root)

	pwContracts, err := CompileAllPolicyWallet()
	if err != nil {
		t.Fatalf("CompileAllPolicyWallet failed: %v", err)
	}
	aeContracts, err := CompileAllAgentEconomy()
	if err != nil {
		t.Fatalf("CompileAllAgentEconomy failed: %v", err)
	}

	// Merge both maps for unified checking.
	all := make(map[string][]byte)
	for k, v := range pwContracts {
		all[k] = v
	}
	for k, v := range aeContracts {
		all[k] = v
	}

	for name, tor := range all {
		// Verify bytecode exceeds a reasonable minimum size for a real contract.
		if len(tor) < 100 {
			t.Errorf("contract %s: bytecode too small (%d bytes), expected > 100", name, len(tor))
		}

		// .tor packages are ZIP archives starting with PK\x03\x04 magic bytes.
		if len(tor) < 4 {
			t.Errorf("contract %s: bytecode shorter than 4 bytes", name)
			continue
		}
		if tor[0] != 'P' || tor[1] != 'K' || tor[2] != 0x03 || tor[3] != 0x04 {
			t.Errorf("contract %s: expected ZIP magic PK\\x03\\x04, got %x", name, tor[:4])
		}
	}
}

func TestDeployerIdempotency(t *testing.T) {
	root := tolangRoot(t)
	t.Setenv("TOLANG_PATH", root)

	// Deploy the same set twice and verify structural equivalence.
	manifest1, err := DeployTestnetAll(testOwner, testGuardian)
	if err != nil {
		t.Fatalf("first DeployTestnetAll failed: %v", err)
	}
	manifest2, err := DeployTestnetAll(testOwner, testGuardian)
	if err != nil {
		t.Fatalf("second DeployTestnetAll failed: %v", err)
	}

	// Same network and schema version.
	if manifest1.Network != manifest2.Network {
		t.Errorf("network mismatch: %s vs %s", manifest1.Network, manifest2.Network)
	}
	if manifest1.SchemaVersion != manifest2.SchemaVersion {
		t.Errorf("schema version mismatch: %s vs %s", manifest1.SchemaVersion, manifest2.SchemaVersion)
	}

	// Same number of contracts.
	if len(manifest1.Contracts) != len(manifest2.Contracts) {
		t.Fatalf("contract count mismatch: %d vs %d", len(manifest1.Contracts), len(manifest2.Contracts))
	}

	// Same set of contract names (order may differ due to map iteration in compile).
	names1 := contractNamesSorted(manifest1)
	names2 := contractNamesSorted(manifest2)
	for i := range names1 {
		if names1[i] != names2[i] {
			t.Errorf("contract name mismatch at index %d: %s vs %s", i, names1[i], names2[i])
		}
	}

	// Same status for each contract.
	byName1 := contractsByName(manifest1)
	byName2 := contractsByName(manifest2)
	for name, c1 := range byName1 {
		c2, ok := byName2[name]
		if !ok {
			t.Errorf("contract %s missing from second manifest", name)
			continue
		}
		if c1.Status != c2.Status {
			t.Errorf("contract %s status mismatch: %s vs %s", name, c1.Status, c2.Status)
		}
		if c1.DeployerAddress != c2.DeployerAddress {
			t.Errorf("contract %s deployer address mismatch", name)
		}
	}
}

// contractNamesSorted returns the sorted list of contract names from a manifest.
func contractNamesSorted(m *DeploymentManifest) []string {
	names := make([]string, len(m.Contracts))
	for i, c := range m.Contracts {
		names[i] = c.Name
	}
	sort.Strings(names)
	return names
}

// contractsByName returns a map from contract name to deployment record.
func contractsByName(m *DeploymentManifest) map[string]ContractDeployment {
	out := make(map[string]ContractDeployment, len(m.Contracts))
	for _, c := range m.Contracts {
		out[c.Name] = c
	}
	return out
}
