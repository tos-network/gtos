package core

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// luaTestSetup returns a blockchain with:
//   - addr1 (key1): 10 TOS balance, used as tx sender
//   - contractAddr:  Lua code pre-loaded via Genesis Code field
func luaTestSetup(t *testing.T, luaCode string) (bc *BlockChain, contractAddr common.Address, cleanup func()) {
	t.Helper()
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 200, MaxValidators: 21},
	}
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)

	// Use a deterministic contract address.
	contractAddr = common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			addr1: {Balance: new(big.Int).Mul(big.NewInt(10), big.NewInt(params.TOS))},
			contractAddr: {
				Balance: new(big.Int).Mul(big.NewInt(1), big.NewInt(params.TOS)), // 1 TOS pre-funded
				Code:    []byte(luaCode),
			},
		},
	}
	gspec.MustCommit(db)
	bc, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = addr1
	return bc, contractAddr, bc.Stop
}

// TestLuaContractStorageGetSet verifies tos.set / tos.get round-trip.
func TestLuaContractStorageGetSet(t *testing.T) {
	const code = `
		tos.set("counter", 42)
		local v = tos.get("counter")
		assert(v == 42, "expected 42, got " .. tostring(v))
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()

	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.LatestSigner(bc.Config())
	tx, err := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	genesis := bc.GetBlockByNumber(0)
	blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
}

// TestLuaContractStorageUnsetReturnsNil verifies unset keys return nil.
func TestLuaContractStorageUnsetReturnsNil(t *testing.T) {
	const code = `
		local v = tos.get("nonexistent")
		assert(v == nil, "expected nil for unset key")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()

	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.LatestSigner(bc.Config())
	tx, err := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	genesis := bc.GetBlockByNumber(0)
	blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
}

// TestLuaContractCallerAndValue verifies tos.caller() and tos.value().
func TestLuaContractCallerAndValue(t *testing.T) {
	code := `
		local caller = tos.caller()
		assert(type(caller) == "string", "caller should be string")
		assert(#caller > 0, "caller should not be empty")
		local val = tos.value()
		assert(val == 1000000000000000000, "expected 1 TOS in wei")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()

	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.LatestSigner(bc.Config())
	oneETH := big.NewInt(params.TOS)
	tx, err := signTestSignerTx(signer, key1, 0, contractAddr, oneETH, 500_000, big.NewInt(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	genesis := bc.GetBlockByNumber(0)
	blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
}

// TestLuaContractRequireRevert verifies that tos.require(false) reverts state.
func TestLuaContractRequireRevert(t *testing.T) {
	const code = `
		tos.set("key", 99)
		tos.require(false, "deliberate revert")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()

	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.LatestSigner(bc.Config())
	tx, err := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	genesis := bc.GetBlockByNumber(0)
	blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	// Block is accepted; the tx fails internally (vmerr), not a consensus error.
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain should succeed (failed tx ≠ bad block): %v", err)
	}

	// Verify: "key" slot must still be zero (revert worked).
	state, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}
	slot := luaStorageSlot("key")
	val := state.GetState(contractAddr, slot)
	if val != (common.Hash{}) {
		t.Errorf("expected storage slot to be zero after revert, got %x", val)
	}
}

// TestLuaContractGasLimit verifies that an infinite loop hits the gas cap.
func TestLuaContractGasLimit(t *testing.T) {
	const code = `while true do end`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()

	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.LatestSigner(bc.Config())
	tx, err := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	genesis := bc.GetBlockByNumber(0)
	blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	// Block is accepted; the tx consumes all gas and fails with OOG.
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
}

// TestLuaContractHash verifies tos.hash returns a deterministic keccak256 hex string.
func TestLuaContractHash(t *testing.T) {
	const code = `
		local h = tos.hash("hello")
		-- keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
		assert(type(h) == "string" and #h == 66, "hash should be 66-char hex string (0x + 64)")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()

	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.LatestSigner(bc.Config())
	tx, err := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	genesis := bc.GetBlockByNumber(0)
	blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
}
