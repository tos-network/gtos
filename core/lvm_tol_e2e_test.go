package core

// End-to-end test for the full TOL contract lifecycle:
//
//  write (.tol) → compile+package (.tor) → deploy (CREATE tx) → call (CALL tx)
//
// This test exercises the exact path that a real on-chain TRC20 deployment
// would follow, including:
//  - lua.CompilePackage: produces a .tor ZIP from TOL source
//  - SplitDeployDataAndConstructorArgs: splits the zip from ctor ABI args
//  - lvm.Create: runs init_code, stores .tor as contract code
//  - executePackage: routes CALL calldata via dispatch tag + selector
//  - __tol_emit / tos.emit: events with alternating (type,val) pairs

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/accounts/abi"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/types"
	lvm "github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	lua "github.com/tos-network/tolang"
)

// trc20TolSource is a minimal TRC20 token in TOL.
// Uses agent (32-byte TOS identity) and u256 types.
const trc20TolSource = `pragma tolang 0.2.0;

contract TRC20 {
  u256 total_supply;
  mapping(agent => u256) balances;

  constant NOBODY: agent = "0x0000000000000000000000000000000000000000000000000000000000000000";

  event Transfer(agent from indexed, agent to indexed, u256 value)

  constructor(u256 initialSupply) {
    set total_supply = initialSupply;
    set balances[msg.sender] = initialSupply;
    emit Transfer(NOBODY, msg.sender, initialSupply);
    return;
  }

  function totalSupply() public view returns (u256 s) {
    return total_supply;
  }

  function balanceOf(agent account) public view returns (u256 balance) {
    return balances[account];
  }

  function transfer(agent to, u256 value) public returns (bool ok) {
    require(balances[msg.sender] >= value, "INSUFFICIENT");
    require(to != NOBODY, "NOBODY");
    set balances[msg.sender] -= value;
    set balances[to] += value;
    emit Transfer(msg.sender, to, value);
    return true;
  }
}
`

const counterPackageTolSource = `pragma tolang 0.4.0;

contract Counter {
  error CounterWriteFailed(u256 attempted);
  u256 current;

  function store(u256 next) public {
    set current = next;
    return;
  }

  function get() public view returns (u256 value) {
    return current;
  }

  function failAfterWrite(u256 next) public {
    set current = next;
    revert CounterWriteFailed(next);
  }
}
`

// deployTorTx sends a contract-creation transaction (To = nil) with
// data = torBytes ++ abiEncodedCtorArgs and returns the receipt.
// The contract address is derived from (sender, nonce).
// runLvmCallTor sends a CALL transaction from key's account to contractAddr,
// building the block on top of bc.CurrentBlock() (not genesis).
// It fatals if the tx fails or the receipt status is not successful.
func runLvmCallTor(t *testing.T, bc *BlockChain, key *ecdsa.PrivateKey, contractAddr common.Address, value *big.Int, data []byte) *types.Receipt {
	t.Helper()
	signer := types.LatestSigner(bc.Config())
	state, _ := bc.State()
	from := crypto.PubkeyToAddress(key.PublicKey)
	nonce := state.GetNonce(from)

	tx := types.NewTx(&types.SignerTx{
		ChainID:    signer.ChainID(),
		Nonce:      nonce,
		To:         &contractAddr,
		Value:      value,
		Gas:        20_000_000,
		Data:       data,
		From:       from,
		SignerType: accountsigner.SignerTypeSecp256k1,
	})
	tx, err := types.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("runLvmCallTor: SignTx: %v", err)
	}

	parent := bc.CurrentBlock()
	blocks, _ := GenerateChain(bc.Config(), parent, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("runLvmCallTor: InsertChain: %v", err)
	}
	block := blocks[0]
	receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
	if len(receipts) == 0 {
		t.Fatal("runLvmCallTor: no receipts found")
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("runLvmCallTor: tx failed (status=%d, gasUsed=%d)", receipts[0].Status, receipts[0].GasUsed)
	}
	return receipts[0]
}

func deployTorTx(t *testing.T, bc *BlockChain, torBytes []byte, ctorArgs []byte) (contractAddr common.Address, receipt *types.Receipt) {
	t.Helper()
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)
	signer := types.LatestSigner(bc.Config())
	state, _ := bc.State()
	nonce := state.GetNonce(addr1)

	// Contract address = crypto.CreateAddress(from, nonce)
	contractAddr = crypto.CreateAddress(addr1, nonce)

	data := append(append([]byte(nil), torBytes...), ctorArgs...)

	tx := types.NewTx(&types.SignerTx{
		ChainID:    signer.ChainID(),
		Nonce:      nonce,
		To:         nil, // CREATE
		Value:      new(big.Int),
		Gas:        50_000_000, // large .tor: intrinsic + code storage + constructor
		Data:       data,
		From:       addr1,
		SignerType: accountsigner.SignerTypeSecp256k1,
	})
	tx, err := types.SignTx(tx, signer, key1)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	parent := bc.CurrentBlock()
	blocks, _ := GenerateChain(bc.Config(), parent, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain (deploy): %v", err)
	}
	block := blocks[0]
	receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
	if len(receipts) == 0 {
		t.Fatal("deploy: no receipts")
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("deploy failed (status=%d)", receipts[0].Status)
	}
	return contractAddr, receipts[0]
}

// torCalldata builds calldata for a .tor package call:
//
//	[4-byte dispatch tag] ++ [4-byte function selector] ++ [ABI-encoded args]
//
// contractName: the contract name in the .tor manifest (e.g. "TRC20")
// sig: TOL ABI function signature (e.g. "transfer(agent,u256)")
// typeVals: alternating ("type", value) pairs
func torCalldata(t *testing.T, contractName, sig string, typeVals ...interface{}) []byte {
	t.Helper()
	dispatchTag := crypto.Keccak256([]byte("pkg:" + contractName))[:4]
	selector := crypto.Keccak256([]byte(sig))[:4]

	var encoded []byte
	if len(typeVals) > 0 {
		if len(typeVals)%2 != 0 {
			t.Fatal("torCalldata: typeVals must be (type,value) pairs")
		}
		n := len(typeVals) / 2
		abiArgs := make(abi.Arguments, n)
		vals := make([]interface{}, n)
		for i := 0; i < n; i++ {
			typStr, ok := typeVals[i*2].(string)
			if !ok {
				t.Fatalf("torCalldata: arg %d type must be string", i)
			}
			typ, err := abi.NewType(typStr, "", nil)
			if err != nil {
				t.Fatalf("torCalldata: NewType %q: %v", typStr, err)
			}
			abiArgs[i] = abi.Argument{Type: typ}
			vals[i] = typeVals[i*2+1]
		}
		packed, err := abiArgs.Pack(vals...)
		if err != nil {
			t.Fatalf("torCalldata: Pack: %v", err)
		}
		encoded = packed
	}

	var result []byte
	result = append(result, dispatchTag...)
	result = append(result, selector...)
	result = append(result, encoded...)
	return result
}

func readStringSlot(state interface {
	GetState(common.Address, common.Hash) common.Hash
}, addr common.Address, key string) string {
	lenSlot := state.GetState(addr, lvm.StrLenSlot(key))
	if lenSlot == (common.Hash{}) {
		return ""
	}
	length := int(binary.BigEndian.Uint64(lenSlot[24:]) - 1)
	if length <= 0 {
		return ""
	}
	data := make([]byte, length)
	base := lvm.StrLenSlot(key)
	for i := 0; i < length; i += 32 {
		chunk := state.GetState(addr, lvm.StrChunkSlot(base, i/32))
		end := i + 32
		if end > length {
			end = length
		}
		copy(data[i:end], chunk[:end-i])
	}
	return string(data)
}

func TestTolTRC20EndToEnd(t *testing.T) {
	// Step 1: Compile TRC20 TOL source into a .tor package.
	torBytes, err := lua.CompilePackage([]byte(trc20TolSource), "<TRC20.tol>", &lua.PackageOptions{
		PackageName: "TRC20",
	})
	if err != nil {
		t.Fatalf("CompilePackage: %v", err)
	}

	// Step 2: Set up a minimal genesis blockchain.
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)
	bob := common.HexToAddress("0x000000000000000000000000000000000000000000000000000000000000BBBB")

	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 208, MaxValidators: 21, TurnLength: params.DPoSTurnLength},
	}
	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config:    config,
		GasLimit:  100_000_000, // high limit: .tor code storage = 200 gas/byte × ~120KB = ~24M gas
		ExtraData: testDPoSGenesisExtra(),
		Alloc: GenesisAlloc{
			addr1: {Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.TOS))},
		},
	}
	gspec.MustCommit(db)
	bc, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Stop()

	// Step 3: Deploy TRC20.tor with initialSupply = 1_000_000.
	//
	// Constructor ABI args: abi.encode("u256", 1000000)
	// ("u256" maps to UintTy via our TOL alias support in accounts/abi)
	const supply = int64(1_000_000)
	ctorType, _ := abi.NewType("u256", "", nil)
	ctorArgs, err := abi.Arguments{{Type: ctorType}}.Pack(big.NewInt(supply))
	if err != nil {
		t.Fatalf("abi.Pack ctor args: %v", err)
	}

	contractAddr, deployReceipt := deployTorTx(t, bc, torBytes, ctorArgs)
	// Use the receipt's ContractAddress if set (authoritative), fall back to pre-computed.
	if (deployReceipt.ContractAddress != common.Address{}) {
		contractAddr = deployReceipt.ContractAddress
	}
	t.Logf("TRC20 deployed at %s", contractAddr.Hex())

	// Step 4: Constructor emits Transfer(NOBODY, addr1, 1000000).
	// Verify the mint event in the deploy receipt.
	nobody := common.Address{} // 32-byte zeros
	wantMintSig := crypto.Keccak256Hash([]byte("Transfer(agent,agent,u256)"))
	foundMint := false
	for _, l := range deployReceipt.Logs {
		if len(l.Topics) > 0 && l.Topics[0] == wantMintSig {
			foundMint = true
			t.Logf("Mint Transfer event: topics=%d data=%d bytes", len(l.Topics), len(l.Data))
			// topics[1] = from (NOBODY) indexed, topics[2] = to (addr1) indexed
			if len(l.Topics) >= 2 {
				gotFrom := common.BytesToAddress(l.Topics[1][:])
				if gotFrom != nobody {
					t.Errorf("mint from: want NOBODY, got %s", gotFrom.Hex())
				}
			}
			break
		}
	}
	if !foundMint {
		t.Errorf("constructor Transfer(NOBODY,addr1,supply) event not found; logs=%d", len(deployReceipt.Logs))
	}

	// Step 5: Call transfer(bob, 100) from addr1.
	// Use runLvmCallTor which builds from the current chain head (not genesis).
	transferData := torCalldata(t, "TRC20", "transfer(agent,u256)",
		"agent", bob,
		"u256", big.NewInt(100),
	)
	transferReceipt := runLvmCallTor(t, bc, key1, contractAddr, big.NewInt(0), transferData)

	// Step 6: Verify Transfer(addr1, bob, 100) event.
	wantTransferSig := crypto.Keccak256Hash([]byte("Transfer(agent,agent,u256)"))
	foundTransfer := false
	for _, l := range transferReceipt.Logs {
		if len(l.Topics) > 0 && l.Topics[0] == wantTransferSig {
			foundTransfer = true
			t.Logf("Transfer event: topics=%d data=%d bytes", len(l.Topics), len(l.Data))
			// topics[2] = to (bob) indexed
			if len(l.Topics) >= 3 {
				gotTo := common.BytesToAddress(l.Topics[2][:])
				if gotTo != bob {
					t.Errorf("transfer to: want %s, got %s", bob.Hex(), gotTo.Hex())
				}
			}
			// data = abi.encode(uint256(100)) = 32 bytes, last byte = 100
			if len(l.Data) >= 32 && l.Data[31] != 100 {
				t.Errorf("transfer value: want 100, got %d", l.Data[31])
			}
			break
		}
	}
	if !foundTransfer {
		t.Errorf("transfer Transfer(addr1,bob,100) event not found; logs=%d", len(transferReceipt.Logs))
	}

	// Step 7: Verify revert on insufficient balance.
	// bob has 100, try to transfer 200 — should fail.
	key2, _ := crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	addr2 := crypto.PubkeyToAddress(key2.PublicKey) // use addr2 as stand-in for bob (bob has no key)
	_ = addr2

	// Call transfer(bob, 101) again to deplete bob's balance—
	// bob has 100, so transferring 101 from addr1's remaining 999900 is fine.
	// Instead verify that a second transfer from addr1 of 999901 fails.
	bigTransferData := torCalldata(t, "TRC20", "transfer(agent,u256)",
		"agent", bob,
		"u256", new(big.Int).SetInt64(999901),
	)
	// This should fail since addr1 only has 999900 left.
	{
		signer := types.LatestSigner(bc.Config())
		state, _ := bc.State()
		nonce := state.GetNonce(addr1)
		tx := types.NewTx(&types.SignerTx{
			ChainID:    signer.ChainID(),
			Nonce:      nonce,
			To:         &contractAddr,
			Value:      new(big.Int),
			Gas:        500_000,
			Data:       bigTransferData,
			From:       addr1,
			SignerType: accountsigner.SignerTypeSecp256k1,
		})
		tx, _ = types.SignTx(tx, signer, key1)
		parent := bc.CurrentBlock()
		blocks, _ := GenerateChain(bc.Config(), parent, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
			b.AddTx(tx)
		})
		if _, err := bc.InsertChain(blocks); err != nil {
			t.Fatalf("InsertChain (revert test): %v", err)
		}
		block := blocks[0]
		receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
		if len(receipts) == 0 {
			t.Fatal("revert test: no receipts")
		}
		if receipts[0].Status != types.ReceiptStatusFailed {
			t.Errorf("expected revert (status=0) for insufficient balance, got status=%d", receipts[0].Status)
		}
		t.Log("insufficient balance correctly reverted")
	}
}

func TestTolPackageCallRollbackAndRevertDataEndToEnd(t *testing.T) {
	targetTor, err := lua.CompilePackage([]byte(counterPackageTolSource), "<Counter.tol>", &lua.PackageOptions{
		PackageName: "CounterPkg",
	})
	if err != nil {
		t.Fatalf("CompilePackage Counter: %v", err)
	}

	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	owner := crypto.PubkeyToAddress(key1.PublicKey)
	callerAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	targetPredicted := crypto.CreateAddress(owner, 0)
	callerCode := fmt.Sprintf(`
		local ok, ret = tos.package_call(%q, "Counter", msg.data, 5000000)
		tos.sstore("ok", ok and 1 or 0)
		if ret == nil then
			tos.setStr("ret", "")
		else
			tos.setStr("ret", ret)
		end
	`, targetPredicted.Hex())

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
			owner:      {Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.TOS))},
			callerAddr: {Balance: big.NewInt(0), Code: []byte(callerCode)},
		},
	}
	gspec.MustCommit(db)
	bc, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Stop()

	targetAddr, deployReceipt := deployTorTx(t, bc, targetTor, nil)
	if (deployReceipt.ContractAddress != common.Address{}) {
		targetAddr = deployReceipt.ContractAddress
	}
	if targetAddr != targetPredicted {
		t.Fatalf("target deploy address mismatch: got=%s want=%s", targetAddr.Hex(), targetPredicted.Hex())
	}

	u256Type, err := abi.NewType("u256", "", nil)
	if err != nil {
		t.Fatalf("abi.NewType(u256): %v", err)
	}
	failArg := big.NewInt(77)
	failPayload := torCalldata(t, "Counter", "failAfterWrite(u256)", "u256", failArg)[4:]
	runLvmCallTor(t, bc, key1, callerAddr, big.NewInt(0), failPayload)

	state, err := bc.State()
	if err != nil {
		t.Fatalf("bc.State after fail: %v", err)
	}
	okSlot := state.GetState(callerAddr, lvm.StorageSlot("ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 0 {
		t.Fatalf("caller ok after revert: got=%d want=0", got)
	}
	gotRet := readStringSlot(state, callerAddr, "ret")
	wantRetPayload, err := abi.Arguments{{Type: u256Type}}.Pack(failArg)
	if err != nil {
		t.Fatalf("pack expected revert payload: %v", err)
	}
	wantRetBytes := append(crypto.Keccak256([]byte("CounterWriteFailed(u256)"))[:4], wantRetPayload...)
	wantRet := "0x" + common.Bytes2Hex(wantRetBytes)
	if gotRet != wantRet {
		t.Fatalf("package_call revert data mismatch:\n got=%s\nwant=%s", gotRet, wantRet)
	}

	getPayload := torCalldata(t, "Counter", "get()")[4:]
	runLvmCallTor(t, bc, key1, callerAddr, big.NewInt(0), getPayload)

	state, err = bc.State()
	if err != nil {
		t.Fatalf("bc.State after get-zero: %v", err)
	}
	okSlot = state.GetState(callerAddr, lvm.StorageSlot("ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 1 {
		t.Fatalf("caller ok after get(): got=%d want=1", got)
	}
	if got := new(big.Int).SetBytes(common.FromHex(readStringSlot(state, callerAddr, "ret"))); got.Sign() != 0 {
		t.Fatalf("counter value after reverted package call: got=%s want=0", got.String())
	}

	setArg := big.NewInt(11)
	setPayload := torCalldata(t, "Counter", "store(u256)", "u256", setArg)[4:]
	runLvmCallTor(t, bc, key1, callerAddr, big.NewInt(0), setPayload)
	runLvmCallTor(t, bc, key1, callerAddr, big.NewInt(0), getPayload)

	state, err = bc.State()
	if err != nil {
		t.Fatalf("bc.State after set/get: %v", err)
	}
	if got := new(big.Int).SetBytes(common.FromHex(readStringSlot(state, callerAddr, "ret"))); got.Cmp(setArg) != 0 {
		t.Fatalf("counter value after successful package call: got=%s want=%s", got.String(), setArg.String())
	}
}
