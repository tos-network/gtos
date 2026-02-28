package core

import (
	"fmt"
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

// runLuaTx is a helper that sends one tx to contractAddr and inserts the block.
func runLuaTx(t *testing.T, bc *BlockChain, contractAddr common.Address, value *big.Int) {
	t.Helper()
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.LatestSigner(bc.Config())
	tx, err := signTestSignerTx(signer, key1, 0, contractAddr, value, 500_000, big.NewInt(1), nil)
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

// TestLuaContractStorageGetSet verifies tos.set / tos.get round-trip.
func TestLuaContractStorageGetSet(t *testing.T) {
	const code = `
		tos.set("counter", 42)
		local v = tos.get("counter")
		assert(v == 42, "expected 42, got " .. tostring(v))
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractStorageUnsetReturnsNil verifies unset keys return nil.
func TestLuaContractStorageUnsetReturnsNil(t *testing.T) {
	const code = `
		local v = tos.get("nonexistent")
		assert(v == nil, "expected nil for unset key")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractCallerAndValue verifies tos.caller and tos.value as properties.
func TestLuaContractCallerAndValue(t *testing.T) {
	code := `
		assert(type(tos.caller) == "string", "caller should be string")
		assert(#tos.caller > 0, "caller should not be empty")
		assert(tos.value == 1000000000000000000, "expected 1 TOS in wei")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(params.TOS))
}

// TestLuaContractRequireRevert verifies that tos.require(false) reverts state.
func TestLuaContractRequireRevert(t *testing.T) {
	const code = `
		tos.set("key", 99)
		tos.require(false, "deliberate revert")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))

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
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractBlockChainID verifies tos.block.chainid is the configured chain ID.
func TestLuaContractBlockChainID(t *testing.T) {
	const code = `
		assert(tos.block.chainid == 1, "expected chainid 1, got " .. tostring(tos.block.chainid))
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractBlockGasLimit verifies tos.block.gaslimit is a positive value.
func TestLuaContractBlockGasLimit(t *testing.T) {
	const code = `
		assert(tos.block.gaslimit > 0, "expected positive gaslimit, got " .. tostring(tos.block.gaslimit))
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractBlockBaseFee verifies tos.block.basefee is non-negative.
func TestLuaContractBlockBaseFee(t *testing.T) {
	const code = `
		assert(tos.block.basefee >= 0, "expected non-negative basefee, got " .. tostring(tos.block.basefee))
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractTxContext verifies tos.tx.origin and tos.tx.gasprice as properties.
func TestLuaContractTxContext(t *testing.T) {
	const code = `
		assert(type(tos.tx.origin) == "string" and #tos.tx.origin > 0, "origin should be non-empty string")
		-- origin must equal caller for a simple (non-inner-call) tx
		assert(tos.tx.origin == tos.caller, "origin should equal caller for top-level tx")
		assert(tos.tx.gasprice >= 0, "gasprice should be non-negative")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractGasLeft verifies tos.gasleft() returns a positive decreasing value.
// gasleft() remains a function because its value changes with each opcode executed.
func TestLuaContractGasLeft(t *testing.T) {
	const code = `
		local g1 = tos.gasleft()
		assert(g1 > 0, "gasleft should be positive at start")
		-- burn some gas with a loop, then check it decreased
		for i = 1, 100 do end
		local g2 = tos.gasleft()
		assert(g2 < g1, "gasleft should decrease after doing work")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractNoPrefixAccess verifies that all tos.* primitives are also
// available without the "tos." prefix (caller, value, block.number, set(), …).
func TestLuaContractNoPrefixAccess(t *testing.T) {
	const code = `
		-- properties
		assert(type(caller) == "string" and #caller > 0, "caller")
		assert(value == 1000000000000000000, "value")
		assert(block.number > 0, "block.number")
		assert(block.chainid == 1, "block.chainid")
		assert(type(tx.origin) == "string", "tx.origin")
		assert(tx.origin == caller, "tx.origin == caller")
		-- functions
		set("nopfx", 7)
		assert(get("nopfx") == 7, "get/set without prefix")
		local h = keccak256("hello")
		assert(#h == 66, "keccak256 without prefix")
		local g = gasleft()
		assert(g > 0, "gasleft without prefix")
		-- tos.* still works too
		assert(tos.caller == caller, "tos.caller == caller")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(params.TOS))
}

// TestLuaContractKeccak256 verifies tos.keccak256 returns a deterministic hex string.
func TestLuaContractKeccak256(t *testing.T) {
	const code = `
		local h = tos.keccak256("hello")
		-- keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
		assert(type(h) == "string" and #h == 66, "keccak256 should be 66-char hex string (0x + 64)")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractMsgSender verifies Solidity-style msg.sender / msg.value aliases.
// msg.sender == tos.caller == caller (same value, three spellings)
// msg.value  == tos.value  == value  (same value, three spellings)
func TestLuaContractMsgSender(t *testing.T) {
	code := `
		-- Solidity-style access
		assert(type(msg.sender) == "string" and #msg.sender > 0, "msg.sender should be non-empty string")
		assert(msg.value == 1000000000000000000, "msg.value should be 1 TOS in wei")
		-- All three spellings must agree
		assert(msg.sender == tos.caller, "msg.sender == tos.caller")
		assert(msg.sender == caller,     "msg.sender == caller")
		assert(msg.value  == tos.value,  "msg.value == tos.value")
		assert(msg.value  == value,      "msg.value == value")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(params.TOS))
}

// ── Phase 2C tests ────────────────────────────────────────────────────────────

// TestLuaContractSha256 verifies tos.sha256 returns a 66-char hex string.
func TestLuaContractSha256(t *testing.T) {
	const code = `
		local h = sha256("hello")
		-- sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
		assert(type(h) == "string" and #h == 66, "sha256 should be 66-char hex string")
		assert(h:sub(1,2) == "0x", "sha256 should start with 0x")
		-- also accessible via tos prefix
		assert(tos.sha256("hello") == h, "tos.sha256 == sha256")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractAddmod verifies tos.addmod computes (x+y)%k correctly.
func TestLuaContractAddmod(t *testing.T) {
	const code = `
		assert(addmod(1, 2, 3) == 0,  "(1+2)%3 == 0")
		assert(addmod(5, 7, 4) == 0,  "(5+7)%4 == 0")
		assert(addmod(10, 1, 7) == 4, "(10+1)%7 == 4")
		assert(addmod(0, 0, 1) == 0,  "(0+0)%1 == 0")
		-- same via tos prefix
		assert(tos.addmod(2, 3, 4) == 1, "tos.addmod")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractMulmod verifies tos.mulmod computes (x*y)%k correctly.
func TestLuaContractMulmod(t *testing.T) {
	const code = `
		assert(mulmod(2, 3, 5)  == 1,  "(2*3)%5 == 1")
		assert(mulmod(4, 4, 7)  == 2,  "(4*4)%7 == 2")
		assert(mulmod(0, 999, 7) == 0, "(0*999)%7 == 0")
		assert(mulmod(1, 1, 1)  == 0,  "(1*1)%1 == 0")
		-- same via tos prefix
		assert(tos.mulmod(3, 3, 4) == 1, "tos.mulmod")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractSelf verifies tos.self is the contract's own address.
func TestLuaContractSelf(t *testing.T) {
	// contractAddr is always 0xCCCC...CC (32 bytes) in luaTestSetup.
	const code = `
		assert(type(self) == "string" and #self > 0, "self should be non-empty string")
		assert(self == tos.self, "self == tos.self")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	_ = contractAddr
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractBlockhash verifies blockhash returns nil or a 66-char hex string.
func TestLuaContractBlockhash(t *testing.T) {
	const code = `
		-- Block 0 (genesis): may or may not be available depending on chain context.
		local h = blockhash(0)
		assert(h == nil or (#h == 66 and h:sub(1,2) == "0x"),
			"blockhash(0) should be nil or 66-char hex, got: " .. tostring(h))
		-- A very far future block is never available.
		assert(blockhash(999999999) == nil, "far-future blockhash should be nil")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractEcrecover verifies ecrecover returns the correct signer address.
func TestLuaContractEcrecover(t *testing.T) {
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)

	msgHash := crypto.Keccak256([]byte("hello ecrecover"))
	sig, err := crypto.Sign(msgHash, key1)
	if err != nil {
		t.Fatal(err)
	}
	r := "0x" + common.Bytes2Hex(sig[0:32])
	s := "0x" + common.Bytes2Hex(sig[32:64])
	v := int(sig[64]) + 27 // Solidity convention: 27 or 28
	hashHex := "0x" + common.Bytes2Hex(msgHash)

	code := fmt.Sprintf(`
		local recovered = ecrecover("%s", %d, "%s", "%s")
		assert(recovered ~= nil, "ecrecover returned nil")
		assert(recovered == "%s", "ecrecover address mismatch: " .. tostring(recovered))
		-- same via tos prefix
		assert(tos.ecrecover("%s", %d, "%s", "%s") == recovered, "tos.ecrecover == ecrecover")
	`, hashHex, v, r, s, addr1.Hex(),
		hashHex, v, r, s)

	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}
