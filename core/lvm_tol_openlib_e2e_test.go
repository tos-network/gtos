package core

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/tos-network/gtos/accounts/abi"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/paypolicy"
	"github.com/tos-network/gtos/trie"
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

func payPolicyGenesisStorage(t *testing.T, owner common.Address, asset string, maxAmount int64) map[common.Hash]common.Hash {
	t.Helper()
	db := state.NewDatabaseWithConfig(rawdb.NewMemoryDatabase(), &trie.Config{Preimages: true})
	st, err := state.New(common.Hash{}, db, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	policyHash := crypto.Keccak256Hash([]byte("paypolicy:" + owner.Hex() + ":" + asset))
	var policyID [32]byte
	copy(policyID[:], policyHash[:])
	paypolicy.WritePolicy(st, paypolicy.PolicyRecord{
		PolicyID:  policyID,
		Owner:     owner,
		Asset:     asset,
		MaxAmount: big.NewInt(maxAmount),
		Status:    paypolicy.PolicyActive,
	})
	root, err := st.Commit(false)
	if err != nil {
		t.Fatalf("commit paypolicy temp state: %v", err)
	}
	if err := st.Database().TrieDB().Commit(root, true, nil); err != nil {
		t.Fatalf("persist paypolicy temp trie: %v", err)
	}
	st, err = state.New(root, db, nil)
	if err != nil {
		t.Fatalf("reload paypolicy temp state: %v", err)
	}
	storage := make(map[common.Hash]common.Hash)
	if err := st.ForEachStorage(params.PayPolicyRegistryAddress, func(key, value common.Hash) bool {
		storage[key] = value
		return true
	}); err != nil {
		t.Fatalf("ForEachStorage: %v", err)
	}
	return storage
}

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

func mustBuildOpenlibReleaseTor(t *testing.T, contract string) []byte {
	t.Helper()
	root := tolangRootCore(t)
	var entry lua.OpenlibReleaseEntry
	found := false
	for _, candidate := range lua.OpenlibReleaseCatalog() {
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
	built, err := lua.BuildOpenlibReleaseArtifacts(source, sourcePath, entry)
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
	policyTor := mustBuildOpenlibReleaseTor(t, "PolicyAccount")
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

func TestTolPayAnnotationHonorsProtocolPolicyEndToEnd(t *testing.T) {
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	owner := crypto.PubkeyToAddress(key1.PublicKey)
	treasury := common.HexToAddress("0x000000000000000000000000000000000000000000000000000000000000f00d")
	source := []byte(fmt.Sprintf(`pragma tolang 0.4.0;

contract PayProbe {
  /// @pay(10, recipient: "%s")
  function payMe() public payable returns (bool ok) {
    return true;
  }
}
`, treasury.Hex()))
	payTor := mustCompileTorPackage(t, source, "<PayProbe.tol>", "PayProbe")
	calldata := torCalldata(t, "PayProbe", "payMe()")

	makeChain := func(maxAmount int64) *BlockChain {
		config := &params.ChainConfig{
			ChainID: big.NewInt(1),
			DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 208, MaxValidators: 21, TurnLength: params.DPoSTurnLength},
		}
		db := rawdb.NewMemoryDatabase()
		policyStorage := payPolicyGenesisStorage(t, owner, "TOS", maxAmount)
		gspec := &Genesis{
			Config:    config,
			GasLimit:  100_000_000,
			ExtraData: testDPoSGenesisExtra(),
			Alloc: GenesisAlloc{
				owner:                           {Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.TOS))},
				params.PayPolicyRegistryAddress: {Balance: big.NewInt(0), Storage: policyStorage},
			},
		}
		gspec.MustCommit(db)
		bc, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return bc
	}

	t.Run("policy_denied", func(t *testing.T) {
		bc := makeChain(5)
		defer bc.Stop()

		contractAddr, receipt := deployTorTx(t, bc, payTor, nil)
		if receipt.ContractAddress != (common.Address{}) {
			contractAddr = receipt.ContractAddress
		}
		callReceipt := runLvmCallTorWithStatus(t, bc, key1, contractAddr, big.NewInt(10), calldata)
		if callReceipt.Status != 0 {
			t.Fatalf("expected denied @pay call to fail, got status=%d", callReceipt.Status)
		}
		state, err := bc.State()
		if err != nil {
			t.Fatalf("bc.State: %v", err)
		}
		if got := state.GetBalance(treasury); got.Sign() != 0 {
			t.Fatalf("treasury balance on denied path: got=%s want=0", got.String())
		}
		if got := state.GetBalance(contractAddr); got.Sign() != 0 {
			t.Fatalf("contract balance on denied path: got=%s want=0", got.String())
		}
	})

	t.Run("policy_allowed", func(t *testing.T) {
		bc := makeChain(10)
		defer bc.Stop()

		contractAddr, receipt := deployTorTx(t, bc, payTor, nil)
		if receipt.ContractAddress != (common.Address{}) {
			contractAddr = receipt.ContractAddress
		}
		callReceipt := runLvmCallTorWithStatus(t, bc, key1, contractAddr, big.NewInt(10), calldata)
		if callReceipt.Status != 1 {
			t.Fatalf("expected allowed @pay call to succeed, got status=%d", callReceipt.Status)
		}
		state, err := bc.State()
		if err != nil {
			t.Fatalf("bc.State: %v", err)
		}
		if got := state.GetBalance(treasury); got.Cmp(big.NewInt(10)) != 0 {
			t.Fatalf("treasury balance on allowed path: got=%s want=10", got.String())
		}
		if got := state.GetBalance(contractAddr); got.Sign() != 0 {
			t.Fatalf("contract balance on allowed path: got=%s want=0", got.String())
		}
	})
}
