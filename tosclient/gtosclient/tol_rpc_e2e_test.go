package gtosclient

// RPC end-to-end test for TOL smart contract execution via tos_call.
//
// Flow:
//  1. Compile TRC20.tol → .tor bytes (in-process via tolang)
//  2. Deploy TRC20.tor via direct InsertChain (node blockchain)
//  3. Connect via embedded RPC (backend.Attach)
//  4. tos_call → balanceOf(addr1) → expect initialSupply
//  5. Send transfer(bob, 100) via InsertChain
//  6. tos_call → balanceOf(bob) → expect 100

import (
	"context"
	"math/big"
	"testing"

	lua "github.com/tos-network/tolang"
	gtos "github.com/tos-network/gtos"
	"github.com/tos-network/gtos/accounts/abi"
	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/node"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/tos"
	"github.com/tos-network/gtos/tos/filters"
	"github.com/tos-network/gtos/tos/tosconfig"
	"github.com/tos-network/gtos/tosclient"
)

const trc20TolSrc = `pragma tolang 0.2.0;

contract TRC20 {
  u256 total_supply;
  mapping(agent => u256) balances;

  constant NOBODY: agent = "0x0000000000000000000000000000000000000000000000000000000000000000";

  event Transfer(agent from indexed, agent to indexed, u256 value)

  constructor(u256 initialSupply) {
    total_supply = initialSupply;
    balances[msg.sender] = initialSupply;
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
    balances[msg.sender] -= value;
    balances[to] += value;
    emit Transfer(msg.sender, to, value);
    return true;
  }
}
`

var (
	e2eKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	e2eAddr    = crypto.PubkeyToAddress(e2eKey.PublicKey)
	e2eBob     = common.HexToAddress("0x000000000000000000000000000000000000000000000000000000000000BBBB")
	e2eSupply  = int64(1_000_000)
)

// newE2EBackend creates an embedded node with a funded genesis for e2eAddr.
// Returns the node and the live tos service (for direct chain manipulation).
func newE2EBackend(t *testing.T) (*node.Node, *tos.TOS) {
	t.Helper()
	config := params.AllDPoSProtocolChanges
	genesis := &core.Genesis{
		Config:    config,
		GasLimit:  100_000_000,
		ExtraData: testDPoSGenesisExtra(e2eAddr),
		Alloc: core.GenesisAlloc{
			e2eAddr: {Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.TOS))},
		},
	}
	n, err := node.New(&node.Config{})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	tosService, err := tos.New(n, &tosconfig.Config{
		Genesis: genesis,
		Engine:  dpos.NewFaker(),
	})
	if err != nil {
		t.Fatalf("tos.New: %v", err)
	}
	filterSystem := filters.NewFilterSystem(tosService.APIBackend, filters.Config{})
	n.RegisterAPIs([]rpc.API{{
		Namespace: "tos",
		Service:   filters.NewFilterAPI(filterSystem, false),
	}})
	if err := n.Start(); err != nil {
		t.Fatalf("node.Start: %v", err)
	}
	return n, tosService
}

// torCalldata builds [dispatchTag(4)] ++ [selector(4)] ++ [abi-encoded args].
func rpcTorCalldata(t *testing.T, contractName, sig string, typeVals ...interface{}) []byte {
	t.Helper()
	dispatchTag := crypto.Keccak256([]byte("pkg:" + contractName))[:4]
	selector := crypto.Keccak256([]byte(sig))[:4]
	var encoded []byte
	if len(typeVals) > 0 {
		if len(typeVals)%2 != 0 {
			t.Fatal("rpcTorCalldata: typeVals must be (type, value) pairs")
		}
		n := len(typeVals) / 2
		abiArgs := make(abi.Arguments, n)
		vals := make([]interface{}, n)
		for i := 0; i < n; i++ {
			typStr := typeVals[i*2].(string)
			typ, err := abi.NewType(typStr, "", nil)
			if err != nil {
				t.Fatalf("rpcTorCalldata: NewType %q: %v", typStr, err)
			}
			abiArgs[i] = abi.Argument{Type: typ}
			vals[i] = typeVals[i*2+1]
		}
		packed, err := abiArgs.Pack(vals...)
		if err != nil {
			t.Fatalf("rpcTorCalldata: Pack: %v", err)
		}
		encoded = packed
	}
	result := make([]byte, 0, 8+len(encoded))
	result = append(result, dispatchTag...)
	result = append(result, selector...)
	result = append(result, encoded...)
	return result
}

// insertBlock builds and inserts a single block with one tx on top of chain head.
// chainDb must be tosService.ChainDb() since BlockChain.db is unexported.
func insertBlock(t *testing.T, svc *tos.TOS, tx *types.Transaction) *types.Receipt {
	t.Helper()
	bc := svc.BlockChain()
	parent := bc.CurrentBlock()
	blocks, _ := core.GenerateChain(bc.Config(), parent, dpos.NewFaker(), svc.ChainDb(), 1, func(i int, b *core.BlockGen) {
		b.AddTx(tx)
	})
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
	block := blocks[0]
	receipts := bc.GetReceiptsByHash(block.Hash())
	if len(receipts) == 0 {
		t.Fatal("insertBlock: no receipts")
	}
	return receipts[0]
}

func TestTolRPCEndToEnd(t *testing.T) {
	// Step 1: Compile TRC20.tol → .tor
	torBytes, err := lua.CompilePackage([]byte(trc20TolSrc), "<TRC20.tol>", &lua.PackageOptions{
		PackageName: "TRC20",
	})
	if err != nil {
		t.Fatalf("CompilePackage: %v", err)
	}

	// Step 2: Start embedded node
	n, tosService := newE2EBackend(t)
	defer n.Close()

	bc := tosService.BlockChain()
	signer := types.LatestSigner(bc.Config())

	// Step 3: Deploy TRC20 with initialSupply = 1_000_000
	ctorType, _ := abi.NewType("u256", "", nil)
	ctorArgs, _ := abi.Arguments{{Type: ctorType}}.Pack(big.NewInt(e2eSupply))

	state, _ := bc.State()
	deployNonce := state.GetNonce(e2eAddr)
	contractAddr := crypto.CreateAddress(e2eAddr, deployNonce)

	deployData := append(append([]byte(nil), torBytes...), ctorArgs...)
	deployTx, err := types.SignNewTx(e2eKey, signer, &types.SignerTx{
		ChainID:    signer.ChainID(),
		Nonce:      deployNonce,
		To:         nil, // CREATE
		Value:      new(big.Int),
		Gas:        50_000_000,
		Data:       deployData,
		From:       e2eAddr,
		SignerType: accountsigner.SignerTypeSecp256k1,
	})
	if err != nil {
		t.Fatalf("SignNewTx deploy: %v", err)
	}

	deployReceipt := insertBlock(t, tosService, deployTx)
	if deployReceipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("deploy failed (status=%d)", deployReceipt.Status)
	}
	if (deployReceipt.ContractAddress != common.Address{}) {
		contractAddr = deployReceipt.ContractAddress
	}
	t.Logf("TRC20 deployed at %s (block %d)", contractAddr.Hex(), deployReceipt.BlockNumber)

	// Step 4: Connect via embedded RPC
	rpcClient, err := n.Attach()
	if err != nil {
		t.Fatalf("node.Attach: %v", err)
	}
	defer rpcClient.Close()
	client := tosclient.NewClient(rpcClient)

	ctx := context.Background()

	// Step 5: tos_call → balanceOf(addr1) — must equal initialSupply
	balanceOfData := rpcTorCalldata(t, "TRC20", "balanceOf(agent)",
		"agent", e2eAddr,
	)
	result, err := client.CallContract(ctx, gtos.CallMsg{
		From: e2eAddr,
		To:   &contractAddr,
		Gas:  5_000_000,
		Data: balanceOfData,
	}, nil) // nil = latest block
	if err != nil {
		t.Fatalf("tos_call balanceOf(addr1): %v", err)
	}
	// Decode uint256 return value (32 bytes, big-endian)
	if len(result) < 32 {
		t.Fatalf("balanceOf result too short: %d bytes", len(result))
	}
	gotBalance := new(big.Int).SetBytes(result[len(result)-32:])
	if gotBalance.Int64() != e2eSupply {
		t.Errorf("balanceOf(addr1): want %d, got %d", e2eSupply, gotBalance)
	} else {
		t.Logf("balanceOf(addr1) = %d ✓", gotBalance)
	}

	// Step 6: Send transfer(bob, 100) via InsertChain
	state, _ = bc.State()
	transferNonce := state.GetNonce(e2eAddr)
	transferData := rpcTorCalldata(t, "TRC20", "transfer(agent,u256)",
		"agent", e2eBob,
		"u256", big.NewInt(100),
	)
	transferTx, err := types.SignNewTx(e2eKey, signer, &types.SignerTx{
		ChainID:    signer.ChainID(),
		Nonce:      transferNonce,
		To:         &contractAddr,
		Value:      new(big.Int),
		Gas:        5_000_000,
		Data:       transferData,
		From:       e2eAddr,
		SignerType: accountsigner.SignerTypeSecp256k1,
	})
	if err != nil {
		t.Fatalf("SignNewTx transfer: %v", err)
	}
	transferReceipt := insertBlock(t, tosService, transferTx)
	if transferReceipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("transfer failed (status=%d)", transferReceipt.Status)
	}
	t.Logf("transfer(bob, 100) mined in block %d", transferReceipt.BlockNumber)

	// Step 7: tos_call → balanceOf(bob) — must equal 100
	balanceOfBobData := rpcTorCalldata(t, "TRC20", "balanceOf(agent)",
		"agent", e2eBob,
	)
	resultBob, err := client.CallContract(ctx, gtos.CallMsg{
		From: e2eAddr,
		To:   &contractAddr,
		Gas:  5_000_000,
		Data: balanceOfBobData,
	}, nil)
	if err != nil {
		t.Fatalf("tos_call balanceOf(bob): %v", err)
	}
	if len(resultBob) < 32 {
		t.Fatalf("balanceOf(bob) result too short: %d bytes", len(resultBob))
	}
	gotBobBalance := new(big.Int).SetBytes(resultBob[len(resultBob)-32:])
	if gotBobBalance.Int64() != 100 {
		t.Errorf("balanceOf(bob): want 100, got %d", gotBobBalance)
	} else {
		t.Logf("balanceOf(bob) = %d ✓", gotBobBalance)
	}

	// Step 8: Verify receipt retrieval via RPC
	receipt, err := client.TransactionReceipt(ctx, transferTx.Hash())
	if err != nil {
		t.Fatalf("TransactionReceipt: %v", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Errorf("TransactionReceipt: want status=1, got status=%d", receipt.Status)
	}
	t.Logf("TransactionReceipt OK: %d logs", len(receipt.Logs))
}
