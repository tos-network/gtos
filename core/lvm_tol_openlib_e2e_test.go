package core

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/tos-network/gtos/accounts/abi"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	lua "github.com/tos-network/tolang"
)

const policyAccountValueReceiverTolSource = `pragma tolang 0.4.0;

contract ValueReceiver {
  event ValueSeen(agent indexed caller, u256 value)

  u256 last_value;

  function record() public payable returns (bool ok) {
    set last_value = msg.value;
    emit ValueSeen(msg.sender, msg.value);
    return true;
  }

  function lastValue() public view returns (u256 value) {
    return last_value;
  }
}
`

func tolangRootCore(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("TOLANG_PATH"); p != "" {
		return p
	}
	candidates := []string{
		filepath.Join("..", "tolang"),
		filepath.Join("..", "..", "tolang"),
		filepath.Join(os.Getenv("HOME"), "tolang"),
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

func mustBuildStdlibReleaseTor(t *testing.T, contract string) []byte {
	t.Helper()
	root := tolangRootCore(t)
	var entry lua.StdlibReleaseEntry
	found := false
	for _, candidate := range lua.StdlibReleaseCatalog() {
		if candidate.Contract == contract {
			entry = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("openlib release entry not found for %s", contract)
	}
	sourcePath := filepath.Join(root, entry.SourcePath)
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	built, err := lua.BuildStdlibReleaseArtifacts(source, sourcePath, entry)
	if err != nil {
		t.Fatalf("build openlib release artifacts for %s: %v", contract, err)
	}
	return built.PackageTOR
}

func mustCompileTorPackage(t *testing.T, source []byte, name, packageName string) []byte {
	t.Helper()
	torBytes, err := lua.CompilePackage(source, name, &lua.PackageOptions{PackageName: packageName})
	if err != nil {
		t.Fatalf("CompilePackage %s: %v", name, err)
	}
	return torBytes
}

func TestTolStdlibPolicyAccountExecuteForwardsValueEndToEnd(t *testing.T) {
	policyTor := mustBuildStdlibReleaseTor(t, "PolicyAccount")
	targetTor := mustCompileTorPackage(t, []byte(policyAccountValueReceiverTolSource), "<ValueReceiver.tol>", "ValueReceiver")

	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	owner := crypto.PubkeyToAddress(key1.PublicKey)
	guardian := common.HexToAddress("0x000000000000000000000000000000000000000000000000000000000000b0b0")

	targetPredicted := crypto.CreateAddress(owner, 0)
	accountPredicted := crypto.CreateAddress(owner, 1)

	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 208, MaxValidators: 21, TurnLength: params.DPoSTurnLength},
	}
	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config:    config,
		GasLimit:  100_000_000,
		ExtraData: testDPoSGenesisExtra(),
		Alloc: GenesisAlloc{
			owner:            {Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.TOS))},
			accountPredicted: {Balance: big.NewInt(500)},
		},
	}
	gspec.MustCommit(db)
	bc, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Stop()

	targetAddr, targetDeployReceipt := deployTorTx(t, bc, targetTor, nil)
	if (targetDeployReceipt.ContractAddress != common.Address{}) {
		targetAddr = targetDeployReceipt.ContractAddress
	}
	if targetAddr != targetPredicted {
		t.Fatalf("target deploy address mismatch: got=%s want=%s", targetAddr.Hex(), targetPredicted.Hex())
	}

	agentType, err := abi.NewType("agent", "", nil)
	if err != nil {
		t.Fatalf("abi.NewType(agent): %v", err)
	}
	u256Type, err := abi.NewType("u256", "", nil)
	if err != nil {
		t.Fatalf("abi.NewType(u256): %v", err)
	}
	policyCtorArgs, err := abi.Arguments{
		{Type: agentType},
		{Type: agentType},
		{Type: u256Type},
		{Type: u256Type},
	}.Pack(owner, guardian, big.NewInt(1000), big.NewInt(400))
	if err != nil {
		t.Fatalf("pack PolicyAccount ctor args: %v", err)
	}

	accountAddr, accountDeployReceipt := deployTorTx(t, bc, policyTor, policyCtorArgs)
	if (accountDeployReceipt.ContractAddress != common.Address{}) {
		accountAddr = accountDeployReceipt.ContractAddress
	}
	if accountAddr != accountPredicted {
		t.Fatalf("policy account deploy address mismatch: got=%s want=%s", accountAddr.Hex(), accountPredicted.Hex())
	}

	innerCallData := torCalldata(t, "ValueReceiver", "record()")
	executeData := torCalldata(
		t,
		"PolicyAccount",
		"execute(agent,bytes,u256)",
		"agent", targetAddr,
		"bytes", innerCallData,
		"u256", big.NewInt(200),
	)
	executeReceipt := runLvmCallTor(t, bc, key1, accountAddr, big.NewInt(0), executeData)

	state, err := bc.State()
	if err != nil {
		t.Fatalf("bc.State: %v", err)
	}
	if got := state.GetBalance(targetAddr); got.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("target balance after execute: got=%s want=200", got.String())
	}
	if got := state.GetBalance(accountAddr); got.Cmp(big.NewInt(300)) != 0 {
		t.Fatalf("policy account balance after execute: got=%s want=300", got.String())
	}

	wantValueSeen := crypto.Keccak256Hash([]byte("ValueSeen(agent,u256)"))
	foundValueSeen := false
	for _, l := range executeReceipt.Logs {
		if len(l.Topics) == 0 || l.Topics[0] != wantValueSeen {
			continue
		}
		foundValueSeen = true
		if len(l.Topics) < 2 {
			t.Fatalf("ValueSeen event missing indexed caller topic")
		}
		if gotCaller := common.BytesToAddress(l.Topics[1][:]); gotCaller != accountAddr {
			t.Fatalf("ValueSeen caller: got=%s want=%s", gotCaller.Hex(), accountAddr.Hex())
		}
		if len(l.Data) < 32 || new(big.Int).SetBytes(l.Data).Cmp(big.NewInt(200)) != 0 {
			t.Fatalf("ValueSeen amount: got=%x want=200", l.Data)
		}
	}
	if !foundValueSeen {
		t.Fatalf("ValueSeen event not found in execute receipt logs=%d", len(executeReceipt.Logs))
	}
}
