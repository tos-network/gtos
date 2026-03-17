package deploy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	lua "github.com/tos-network/tolang"
)

// policyWalletContracts lists the contract source files in the policy_wallet example directory.
var policyWalletContracts = []string{
	"PolicyWallet.tol",
	"SpendGuard.tol",
	"GuardianRecovery.tol",
	"DelegatedAgent.tol",
	"TerminalAuthority.tol",
}

// agentEconomyContracts lists the contract source files in the agent_economy example directory.
var agentEconomyContracts = []string{
	"TaskEscrow.tol",
	"SponsorRelay.tol",
	"RecurringPayment.tol",
	"MerchantPayment.tol",
	"OracleResolver.tol",
}

// tolangExamplesDir returns the absolute path to the tolang examples directory.
// It resolves relative to the tolang module which is expected at ../tolang
// relative to the gtos repository root. If the TOLANG_PATH environment variable
// is set, that path is used instead.
func tolangExamplesDir() string {
	if p := os.Getenv("TOLANG_PATH"); p != "" {
		return filepath.Join(p, "examples")
	}
	// Resolve relative to this source file's expected repository layout.
	// gtos/deploy/ -> gtos/ -> ../tolang/examples
	return filepath.Join("..", "tolang", "examples")
}

// CompileContract compiles a .tol source file to .tor package bytes using the TOL compiler.
func CompileContract(sourcePath string) ([]byte, error) {
	src, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("read source %s: %w", sourcePath, err)
	}
	torBytes, err := lua.CompilePackage(src, sourcePath, nil)
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", sourcePath, err)
	}
	return torBytes, nil
}

// CompileAllPolicyWallet compiles all policy wallet contracts and returns a map
// of contract name (without extension) to .tor bytes.
func CompileAllPolicyWallet() (map[string][]byte, error) {
	dir := filepath.Join(tolangExamplesDir(), "policy_wallet")
	return compileContractSet(dir, policyWalletContracts)
}

// CompileAllAgentEconomy compiles all agent economy contracts and returns a map
// of contract name (without extension) to .tor bytes.
func CompileAllAgentEconomy() (map[string][]byte, error) {
	dir := filepath.Join(tolangExamplesDir(), "agent_economy")
	return compileContractSet(dir, agentEconomyContracts)
}

// compileContractSet compiles a list of .tol files from a directory.
func compileContractSet(dir string, files []string) (map[string][]byte, error) {
	result := make(map[string][]byte, len(files))
	for _, f := range files {
		path := filepath.Join(dir, f)
		tor, err := CompileContract(path)
		if err != nil {
			return nil, fmt.Errorf("compile %s: %w", f, err)
		}
		name := strings.TrimSuffix(f, ".tol")
		result[name] = tor
	}
	return result, nil
}
