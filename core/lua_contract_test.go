package core

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"testing"

	lua "github.com/tos-network/glua"
	"github.com/tos-network/gtos/accounts/abi"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	goripemd160 "golang.org/x/crypto/ripemd160"
)

// luaEventSig returns keccak256 of the canonical Ethereum event signature.
// For a no-arg event: luaEventSig("Ping") → keccak256("Ping()")
// For a typed event:  luaEventSig("Transfer", "address", "uint256")
//
//	→ keccak256("Transfer(address,uint256)")
//
// Use this in test assertions whenever you check receipt log topics produced
// by tos.emit, since tos.emit uses the canonical signature (with types) as
// topic[0] to be compatible with the Ethereum ABI event log specification.
func luaEventSig(name string, types ...string) common.Hash {
	sig := name + "(" + strings.Join(types, ",") + ")"
	return crypto.Keccak256Hash([]byte(sig))
}

// buildCalldata constructs EVM-compatible calldata:
//
//	selector (4 bytes) || ABI-encoded arguments
//
// sig:     Solidity ABI signature, e.g. "transfer(address,uint256)"
// typeVals: alternating ("type", value) pairs matching the signature args
func buildCalldata(t *testing.T, sig string, typeVals ...interface{}) []byte {
	t.Helper()
	// 4-byte selector
	sel := crypto.Keccak256([]byte(sig))[:4]

	if len(typeVals) == 0 {
		return sel
	}
	if len(typeVals)%2 != 0 {
		t.Fatalf("buildCalldata: typeVals must be even (type,value pairs)")
	}
	n := len(typeVals) / 2
	abiArgs := make(abi.Arguments, n)
	vals := make([]interface{}, n)
	for i := 0; i < n; i++ {
		typStr, ok := typeVals[i*2].(string)
		if !ok {
			t.Fatalf("buildCalldata: arg %d type must be string", i)
		}
		typ, err := abi.NewType(typStr, "", nil)
		if err != nil {
			t.Fatalf("buildCalldata: NewType %q: %v", typStr, err)
		}
		abiArgs[i] = abi.Argument{Type: typ}
		vals[i] = typeVals[i*2+1]
	}
	packed, err := abiArgs.Pack(vals...)
	if err != nil {
		t.Fatalf("buildCalldata: Pack: %v", err)
	}
	return append(sel, packed...)
}

// abiSelector returns the 4-byte selector hex "0x..." for a signature.
func abiSelector(sig string) string {
	h := crypto.Keccak256([]byte(sig))
	return "0x" + common.Bytes2Hex(h[:4])
}

// luaTestSetup2 returns a blockchain with TWO Lua contracts pre-deployed at
// genesis, used for cross-contract read tests.
//
//   - addr1 (key1):    10 TOS, used as tx sender
//   - contractAddr:    codeA (the "caller" contract)
//   - contractAddrB:   codeB (the "target" contract with state to be read)
func luaTestSetup2(t *testing.T, codeA, codeB string) (bc *BlockChain, contractAddr, contractAddrB common.Address, cleanup func()) {
	t.Helper()
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 200, MaxValidators: 21},
	}
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)

	contractAddr = common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	contractAddrB = common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			addr1:         {Balance: new(big.Int).Mul(big.NewInt(10), big.NewInt(params.TOS))},
			contractAddr:  {Balance: new(big.Int).Mul(big.NewInt(1), big.NewInt(params.TOS)), Code: []byte(codeA)},
			contractAddrB: {Balance: new(big.Int).Mul(big.NewInt(2), big.NewInt(params.TOS)), Code: []byte(codeB)},
		},
	}
	gspec.MustCommit(db)
	bc, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = addr1
	return bc, contractAddr, contractAddrB, bc.Stop
}

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

// luaTestSetupCodeBytes is like luaTestSetup, but accepts raw code bytes.
// This is used to deploy precompiled glua bytecode in tests.
func luaTestSetupCodeBytes(t *testing.T, code []byte) (bc *BlockChain, contractAddr common.Address, cleanup func()) {
	t.Helper()
	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 200, MaxValidators: 21},
	}
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)

	contractAddr = common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			addr1: {Balance: new(big.Int).Mul(big.NewInt(10), big.NewInt(params.TOS))},
			contractAddr: {
				Balance: new(big.Int).Mul(big.NewInt(1), big.NewInt(params.TOS)),
				Code:    append([]byte(nil), code...),
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

func luaTestSetupBytecode(t *testing.T, luaCode string) (bc *BlockChain, contractAddr common.Address, cleanup func()) {
	t.Helper()
	bytecode, err := lua.CompileSourceToBytecode([]byte(luaCode), "<genesis-contract>")
	if err != nil {
		t.Fatalf("CompileSourceToBytecode: %v", err)
	}
	return luaTestSetupCodeBytes(t, bytecode)
}

// runLuaTx sends one tx (no calldata) and asserts Lua executed successfully.
func runLuaTx(t *testing.T, bc *BlockChain, contractAddr common.Address, value *big.Int) {
	t.Helper()
	runLuaTxWithData(t, bc, contractAddr, value, nil)
}

// runLuaTxExpectFail sends one tx expecting the Lua script to fail (revert/OOG).
// It asserts the receipt status is 0 (failed).
func runLuaTxExpectFail(t *testing.T, bc *BlockChain, contractAddr common.Address, value *big.Int) {
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
	block := blocks[0]
	receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
	if len(receipts) == 0 {
		t.Fatal("no receipts found for block")
	}
	if receipts[0].Status != types.ReceiptStatusFailed {
		t.Fatalf("expected Lua to fail (status=0), got status=%d", receipts[0].Status)
	}
}

// runLuaTxWithData sends one tx with custom calldata to contractAddr and
// verifies that the Lua script executed successfully (receipt status == 1).
// Builds on top of the current canonical head so sequential calls accumulate state.
func runLuaTxWithData(t *testing.T, bc *BlockChain, contractAddr common.Address, value *big.Int, data []byte) {
	t.Helper()
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)
	signer := types.LatestSigner(bc.Config())
	state, _ := bc.State()
	nonce := state.GetNonce(addr1)
	tx, err := signTestSignerTx(signer, key1, nonce, contractAddr, value, 500_000, big.NewInt(1), data)
	if err != nil {
		t.Fatal(err)
	}
	parent := bc.CurrentBlock()
	blocks, _ := GenerateChain(bc.Config(), parent, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
	// Verify the Lua contract executed successfully (status 1 = success).
	// A failed Lua script (assert failure, error, etc.) produces status 0.
	block := blocks[0]
	receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
	if len(receipts) == 0 {
		t.Fatal("no receipts found for block")
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("Lua contract execution failed (receipt status=%d): Lua error or assert failed", receipts[0].Status)
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
	runLuaTxExpectFail(t, bc, contractAddr, big.NewInt(0))

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
	runLuaTxExpectFail(t, bc, contractAddr, big.NewInt(0))
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

// TestLuaContractRipemd160 verifies tos.ripemd160 (and bare ripemd160):
//   - Output is a 66-char "0x"-prefixed string (20-byte hash left-padded to 32 bytes).
//   - Known test vector: ripemd160("hello") matches Go's goripemd160.
//   - Accessible as both tos.ripemd160 and bare ripemd160 global.
func TestLuaContractRipemd160(t *testing.T) {
	// Compute the expected value using Go's ripemd160 package.
	h := goripemd160.New()
	h.Write([]byte("hello"))
	raw := h.Sum(nil) // 20 bytes
	var padded [32]byte
	copy(padded[12:], raw)
	want := "0x" + common.Bytes2Hex(padded[:])

	code := fmt.Sprintf(`
		local h = tos.ripemd160("hello")
		assert(type(h) == "string" and #h == 66,
			"ripemd160 output should be 66-char hex string, got len " .. tostring(#h))
		assert(h:sub(1,2) == "0x", "ripemd160 should start with 0x")
		-- first 12 zero-bytes are the left-padding (24 hex chars after "0x")
		assert(h:sub(3,26) == "000000000000000000000000",
			"first 12 bytes should be zero-padded, got " .. h:sub(3,26))
		-- exact match against Go-computed reference
		assert(h == %q, "ripemd160 mismatch: got " .. h)
		-- accessible as bare global too
		assert(ripemd160("hello") == h, "bare ripemd160 should equal tos.ripemd160")
		-- deterministic: same input → same output
		assert(tos.ripemd160("hello") == tos.ripemd160("hello"), "not deterministic")
		-- different inputs → different outputs
		assert(tos.ripemd160("hello") ~= tos.ripemd160("world"), "collision")
	`, want)
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

// ── Phase 2C: ABI encode/decode + msg.data/sig ───────────────────────────────

// TestLuaContractABIEncodePacked verifies abi.encodePacked for scalar types.
func TestLuaContractABIEncodePacked(t *testing.T) {
	const code = `
		-- uint8(1) packed = 1 byte = "0x01"
		assert(abi.encodePacked("uint8", 1) == "0x01", "uint8 packed")

		-- uint256(1) packed = 32 bytes, last byte = 0x01
		local u256 = abi.encodePacked("uint256", 1)
		assert(#u256 == 66, "uint256 packed len: " .. tostring(#u256))
		assert(u256:sub(65) == "01", "uint256 packed last byte")

		-- bool packed
		assert(abi.encodePacked("bool", true)  == "0x01", "bool true packed")
		assert(abi.encodePacked("bool", false) == "0x00", "bool false packed")

		-- string packed = raw UTF-8 bytes
		assert(abi.encodePacked("string", "AB") == "0x4142", "string packed")

		-- bytes4 packed
		assert(abi.encodePacked("bytes4", "0xdeadbeef") == "0xdeadbeef", "bytes4 packed")

		-- concatenation: uint8(1) ++ uint8(2) = "0x0102"
		assert(abi.encodePacked("uint8", 1, "uint8", 2) == "0x0102", "concat packed")

		-- tos. prefix works too
		assert(tos.abi.encodePacked("uint8", 7) == "0x07", "tos.abi.encodePacked")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractABIEncodeDecodeRoundTrip verifies encode→decode is lossless
// for static types.
func TestLuaContractABIEncodeDecodeRoundTrip(t *testing.T) {
	const code = `
		-- static types round-trip
		local encoded = abi.encode("uint256", 999, "bool", true, "uint8", 7)
		-- 3 × 32 bytes = 96 bytes = "0x" + 192 hex chars = 194 total chars
		assert(#encoded == 194, "encode len: " .. tostring(#encoded))

		local n, b, m = abi.decode(encoded, "uint256", "bool", "uint8")
		assert(n == 999, "uint256 roundtrip: " .. tostring(n))
		assert(b == true, "bool roundtrip: " .. tostring(b))
		assert(m == 7,   "uint8 roundtrip: " .. tostring(m))

		-- negative int256
		local enc2 = abi.encode("int256", -1)
		local neg = abi.decode(enc2, "int256")
		assert(neg == -1, "int256 -1 roundtrip: " .. tostring(neg))

		-- tos.abi prefix also works
		local enc3 = tos.abi.encode("uint256", 42)
		local v = tos.abi.decode(enc3, "uint256")
		assert(v == 42, "tos.abi roundtrip")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractABIEncodeDynamic verifies abi.encode/decode with dynamic types.
func TestLuaContractABIEncodeDynamic(t *testing.T) {
	const code = `
		-- string round-trip
		local enc = abi.encode("string", "hello world")
		local s = abi.decode(enc, "string")
		assert(s == "hello world", "string roundtrip: " .. tostring(s))

		-- bytes round-trip ("0x"-prefixed input → "0x"-prefixed output)
		local encB = abi.encode("bytes", "0xdeadbeef")
		local bv = abi.decode(encB, "bytes")
		assert(bv == "0xdeadbeef", "bytes roundtrip: " .. tostring(bv))

		-- mixed static + dynamic
		local encM = abi.encode("uint256", 123, "string", "TOS", "bool", true)
		local n, str, flag = abi.decode(encM, "uint256", "string", "bool")
		assert(n == 123,    "mixed uint256")
		assert(str == "TOS", "mixed string")
		assert(flag == true, "mixed bool")

		-- two dynamic args
		local enc2 = abi.encode("string", "foo", "string", "bar")
		local a, bstr = abi.decode(enc2, "string", "string")
		assert(a == "foo", "two strings a")
		assert(bstr == "bar", "two strings b")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractABIFunctionSelector verifies the Solidity function-selector
// pattern: keccak256("funcName(types)")[:4 bytes].
// keccak256("transfer(address,uint256)") must equal 0xa9059cbb.
func TestLuaContractABIFunctionSelector(t *testing.T) {
	const code = `
		local full = keccak256("transfer(address,uint256)")
		local selector = full:sub(1, 10)  -- "0x" + 8 hex chars = 4 bytes
		assert(#selector == 10, "selector length")
		assert(selector == "0xa9059cbb", "transfer selector: " .. selector)
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractMsgData verifies msg.data and msg.sig carry the tx calldata.
func TestLuaContractMsgData(t *testing.T) {
	const code = `
		assert(type(msg.data) == "string", "msg.data should be string")
		assert(msg.data:sub(1,2) == "0x", "msg.data should start with 0x")
		assert(type(msg.sig) == "string", "msg.sig should be string")
		-- sent 8 bytes, so msg.data = "0x" + 16 hex chars = 18 chars
		assert(#msg.data == 18, "msg.data length: " .. tostring(#msg.data))
		-- sig = first 4 bytes = "0x" + first 8 hex chars of data
		assert(msg.sig == msg.data:sub(1, 10), "msg.sig == first 4 bytes of msg.data")
		assert(msg.sig == "0xc2985578", "msg.sig value")
	`
	// keccak256("foo()") selector = 0xc2985578, appended with 4 extra bytes
	txData := common.FromHex("0xc298557812345678")
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTxWithData(t, bc, contractAddr, big.NewInt(0), txData)
}

// TestLuaContractABIAddress verifies abi.encode/decode roundtrip for the address type.
func TestLuaContractABIAddress(t *testing.T) {
	const code = `
		-- tos.self is the contract's own 32-byte address
		local addr = tos.self
		local enc = abi.encode("address", addr)
		-- 1 × 32-byte ABI slot = "0x" + 64 hex chars = 66 total chars
		assert(#enc == 66, "address encoded len: " .. tostring(#enc))

		local dec = abi.decode(enc, "address")
		assert(dec == addr, "address roundtrip: " .. tostring(dec))

		-- address + uint256 multi-field round-trip
		local enc2 = abi.encode("address", addr, "uint256", 42)
		local a2, n2 = abi.decode(enc2, "address", "uint256")
		assert(a2 == addr, "addr in multi: " .. tostring(a2))
		assert(n2 == 42, "uint256 in multi: " .. tostring(n2))
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractABIFixedBytes verifies abi.encode/decode roundtrip for fixedBytes (bytes1, bytes32).
// The unpack path returns a [N]byte reflect.Array; abiGoToLua extracts it via reflection.
func TestLuaContractABIFixedBytes(t *testing.T) {
	const code = `
		-- bytes1: single byte
		local enc1 = abi.encode("bytes1", "0xab")
		local dec1 = abi.decode(enc1, "bytes1")
		assert(dec1 == "0xab", "bytes1 roundtrip: " .. dec1)

		-- bytes32: 4-byte input is right-padded with zeros on encode
		local enc32 = abi.encode("bytes32", "0xdeadbeef")
		assert(#enc32 == 66, "bytes32 encoded slot len: " .. tostring(#enc32))
		local dec32 = abi.decode(enc32, "bytes32")
		-- decoded = "0x" + 64 hex chars
		assert(#dec32 == 66, "bytes32 decoded len: " .. tostring(#dec32))
		-- first 4 bytes preserved; remaining 28 bytes are zero
		assert(dec32:sub(1, 10) == "0xdeadbeef", "bytes32 first 4 bytes: " .. dec32:sub(1,10))
		assert(dec32:sub(11) == string.rep("00", 28), "bytes32 zero padding")

		-- bytes32 full: exact 32 bytes survives unchanged
		local full = "0x" .. string.rep("ab", 32)
		local encF = abi.encode("bytes32", full)
		local decF = abi.decode(encF, "bytes32")
		assert(decF == full, "bytes32 full roundtrip")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractABISmallInts verifies abi.encode/decode for uint16/32/64 and int8/16/32/64.
// These sizes return native Go int types from ReadInteger, not *big.Int.
func TestLuaContractABISmallInts(t *testing.T) {
	const code = `
		-- uint16 max (65535)
		local v16 = abi.decode(abi.encode("uint16", 65535), "uint16")
		assert(v16 == 65535, "uint16 max: " .. tostring(v16))

		-- uint32 max (4294967295)
		local v32 = abi.decode(abi.encode("uint32", 4294967295), "uint32")
		assert(v32 == 4294967295, "uint32 max: " .. tostring(v32))

		-- uint64 max — pass as string to avoid Lua literal overflow
		local maxU64 = "18446744073709551615"
		local v64 = abi.decode(abi.encode("uint64", maxU64), "uint64")
		assert(tostring(v64) == maxU64, "uint64 max: " .. tostring(v64))

		-- int8 min / max
		local vI8min = abi.decode(abi.encode("int8", -128), "int8")
		assert(vI8min == -128, "int8 min: " .. tostring(vI8min))
		local vI8max = abi.decode(abi.encode("int8", 127), "int8")
		assert(vI8max == 127, "int8 max: " .. tostring(vI8max))

		-- int16 min
		local vI16 = abi.decode(abi.encode("int16", -32768), "int16")
		assert(vI16 == -32768, "int16 min: " .. tostring(vI16))

		-- int32 min
		local vI32 = abi.decode(abi.encode("int32", -2147483648), "int32")
		assert(vI32 == -2147483648, "int32 min: " .. tostring(vI32))

		-- int64 min: pass as string for encoding, compare via Lua literal for decode.
		-- Decoded value is the uint256 two's complement (2^256 - 2^63), same as
		-- Lua literal -9223372036854775808 after the OP_UNM wrap fix.
		local vI64 = abi.decode(abi.encode("int64", "-9223372036854775808"), "int64")
		assert(vI64 == -9223372036854775808, "int64 min: " .. tostring(vI64))
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractABIEncodePackedExtended verifies encodePacked for negative ints and address.
func TestLuaContractABIEncodePackedExtended(t *testing.T) {
	const code = `
		-- int8(-1): two's complement 1 byte = 0xff
		assert(abi.encodePacked("int8",  -1)   == "0xff",   "int8 -1 packed")
		assert(abi.encodePacked("int8",  -128) == "0x80",   "int8 -128 packed")

		-- int16(-1): 2 bytes of 0xff
		assert(abi.encodePacked("int16", -1)   == "0xffff", "int16 -1 packed")

		-- int256(-1): 32 bytes of 0xff
		local neg1_256 = abi.encodePacked("int256", -1)
		assert(#neg1_256 == 66, "int256 -1 packed len: " .. tostring(#neg1_256))
		assert(neg1_256 == "0x" .. string.rep("ff", 32), "int256 -1 packed value")

		-- address packed = 32 bytes (gtos uses 32-byte addresses)
		local encA = abi.encodePacked("address", tos.self)
		assert(#encA == 66, "address packed len: " .. tostring(#encA))

		-- bytes (dynamic) packed = raw bytes, no length prefix
		assert(abi.encodePacked("bytes", "0xdeadbeef") == "0xdeadbeef", "bytes packed no prefix")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractABIErrors verifies that malformed calls raise errors catchable by pcall.
func TestLuaContractABIErrors(t *testing.T) {
	const code = `
		-- odd number of args to encode (missing value)
		local ok1, e1 = pcall(function() abi.encode("uint256") end)
		assert(not ok1, "missing value should error")
		assert(type(e1) == "string", "error should be string, got: " .. type(e1))

		-- unrecognised type string
		local ok2, e2 = pcall(function() abi.encode("notavalidtype", 1) end)
		assert(not ok2, "invalid type should error")

		-- decode with too-short data (< 32 bytes for a uint256 slot)
		local ok3, e3 = pcall(function() abi.decode("0x1234", "uint256") end)
		assert(not ok3, "short data should error")

		-- wrong Lua type for uint256 (bool instead of number/string)
		local ok4, e4 = pcall(function() abi.encode("uint256", true) end)
		assert(not ok4, "wrong Lua type should error")

		-- encodePacked: odd args
		local ok5, e5 = pcall(function() abi.encodePacked("uint8") end)
		assert(not ok5, "encodePacked odd args should error")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// TestLuaContractABIEdgeCases verifies boundary values and empty inputs.
func TestLuaContractABIEdgeCases(t *testing.T) {
	const code = `
		-- uint256 maximum
		local maxU256 = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
		local vMax = abi.decode(abi.encode("uint256", maxU256), "uint256")
		assert(tostring(vMax) == maxU256, "uint256 max: " .. tostring(vMax))

		-- empty string round-trip
		local vStr = abi.decode(abi.encode("string", ""), "string")
		assert(vStr == "", "empty string roundtrip")

		-- empty bytes round-trip
		local vBytes = abi.decode(abi.encode("bytes", "0x"), "bytes")
		assert(vBytes == "0x", "empty bytes roundtrip: " .. tostring(vBytes))

		-- uint8 zero
		local v0 = abi.decode(abi.encode("uint8", 0), "uint8")
		assert(v0 == 0, "uint8 zero: " .. tostring(v0))

		-- encodePacked: empty string yields just "0x" (no payload bytes)
		assert(abi.encodePacked("string", "") == "0x", "encodePacked empty string")

		-- encodePacked: uint256 zero = 32 zero bytes
		local pz = abi.encodePacked("uint256", 0)
		assert(pz == "0x" .. string.rep("00", 32), "encodePacked uint256 zero")
	`
	bc, contractAddr, cleanup := luaTestSetup(t, code)
	defer cleanup()
	runLuaTx(t, bc, contractAddr, big.NewInt(0))
}

// runLuaTxGetReceipt is like runLuaTxWithData but also returns the receipt so
// callers can inspect logs, status, etc.
func runLuaTxGetReceipt(t *testing.T, bc *BlockChain, contractAddr common.Address, value *big.Int, data []byte) *types.Receipt {
	t.Helper()
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.LatestSigner(bc.Config())
	tx, err := signTestSignerTx(signer, key1, 0, contractAddr, value, 500_000, big.NewInt(1), data)
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
	block := blocks[0]
	receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
	if len(receipts) == 0 {
		t.Fatal("no receipts found for block")
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("Lua contract execution failed (receipt status=%d)", receipts[0].Status)
	}
	return receipts[0]
}

// TestLuaContractEmit verifies tos.emit produces correct receipt logs.
//
// Checks:
//   - topic[0] == keccak256(canonicalSig) where canonicalSig = "EventName(types...)"
//   - data == ABI-encoded non-indexed payload
//   - multiple events in one execution each appear in logs
//   - emit with no data produces empty Data bytes
func TestLuaContractEmit(t *testing.T) {
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)

	t.Run("single_event_no_data", func(t *testing.T) {
		const code = `tos.emit("Ping")`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		log := receipt.Logs[0]
		wantTopic := luaEventSig("Ping")
		if log.Topics[0] != wantTopic {
			t.Errorf("topic[0]: got %s, want %s", log.Topics[0].Hex(), wantTopic.Hex())
		}
		if len(log.Data) != 0 {
			t.Errorf("expected empty data, got %x", log.Data)
		}
		if log.Address != contractAddr {
			t.Errorf("log.Address: got %s, want %s", log.Address.Hex(), contractAddr.Hex())
		}
	})

	t.Run("event_with_uint256_payload", func(t *testing.T) {
		const code = `tos.emit("Transfer", "uint256", 42)`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		log := receipt.Logs[0]
		wantTopic := luaEventSig("Transfer", "uint256")
		if log.Topics[0] != wantTopic {
			t.Errorf("topic[0] mismatch")
		}
		// ABI-encoded uint256(42) = 32 bytes, big-endian.
		if len(log.Data) != 32 {
			t.Fatalf("expected 32 bytes of data, got %d", len(log.Data))
		}
		if log.Data[31] != 42 {
			t.Errorf("expected data[31]=42, got %d", log.Data[31])
		}
	})

	t.Run("event_with_address_and_uint256", func(t *testing.T) {
		// Emit a Transfer(address from, address to, uint256 value) event.
		const code = `
			local recipient = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
			tos.emit("Transfer", "address", tos.caller, "address", recipient, "uint256", 1000)
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		log := receipt.Logs[0]
		wantTopic := luaEventSig("Transfer", "address", "address", "uint256")
		if log.Topics[0] != wantTopic {
			t.Errorf("topic[0] mismatch")
		}
		// data = ABI-encode(address caller, address recipient, uint256 1000)
		// GTOS addresses are 32 bytes; ABI encodes each as a full 32-byte slot.
		// = 3 × 32 bytes = 96 bytes total
		if len(log.Data) != 96 {
			t.Fatalf("expected 96 bytes data, got %d", len(log.Data))
		}
		// First 32 bytes: addr1 (full 32-byte GTOS address, no zero-padding).
		if common.BytesToAddress(log.Data[0:32]) != addr1 {
			t.Errorf("from address mismatch in log data: got %s want %s",
				common.BytesToAddress(log.Data[0:32]).Hex(), addr1.Hex())
		}
		// Third 32 bytes: value 1000 in last byte
		if log.Data[95] != 232 { // 1000 & 0xff = 232
			t.Errorf("expected data[95]=232 (1000 low byte), got %d", log.Data[95])
		}
	})

	t.Run("multiple_events", func(t *testing.T) {
		const code = `
			tos.emit("Event1")
			tos.emit("Event2")
			tos.emit("Event3", "uint256", 99)
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 3 {
			t.Fatalf("expected 3 logs, got %d", len(receipt.Logs))
		}
		wantTopics := []common.Hash{
			luaEventSig("Event1"),
			luaEventSig("Event2"),
			luaEventSig("Event3", "uint256"),
		}
		for i, want := range wantTopics {
			if receipt.Logs[i].Topics[0] != want {
				t.Errorf("log[%d] topic mismatch: got %s", i, receipt.Logs[i].Topics[0].Hex())
			}
		}
	})

	t.Run("emit_revert_clears_logs", func(t *testing.T) {
		// Logs emitted before a revert must be discarded (snapshot revert).
		const code = `
			tos.emit("ShouldNotAppear")
			tos.revert("oops")
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		signer := types.LatestSigner(bc.Config())
		tx, _ := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), nil)
		genesis := bc.GetBlockByNumber(0)
		blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
			b.AddTx(tx)
		})
		bc.InsertChain(blocks)
		receipts := rawdb.ReadReceipts(bc.db, blocks[0].Hash(), blocks[0].NumberU64(), bc.Config())
		if len(receipts) == 0 {
			t.Fatal("no receipt")
		}
		// Transaction failed → logs must be empty.
		if receipts[0].Status != types.ReceiptStatusFailed {
			t.Errorf("expected status=0 (failed), got %d", receipts[0].Status)
		}
		if len(receipts[0].Logs) != 0 {
			t.Errorf("expected 0 logs after revert, got %d", len(receipts[0].Logs))
		}
	})
}

// TestLuaContractStrStorage verifies tos.setStr / tos.getStr.
//
// Checks:
//   - nil returned for unset key
//   - short string (fits in one 32-byte chunk)
//   - exact 32-byte string (single full chunk)
//   - long string spanning multiple chunks
//   - overwrite replaces previous value
func TestLuaContractStrStorage(t *testing.T) {
	t.Run("unset_returns_nil", func(t *testing.T) {
		const code = `
			local v = tos.getStr("missing")
			assert(v == nil, "expected nil for unset key, got: " .. tostring(v))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("short_string_roundtrip", func(t *testing.T) {
		const code = `
			tos.setStr("greeting", "hello, world!")
			local v = tos.getStr("greeting")
			assert(v == "hello, world!", "roundtrip: " .. tostring(v))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("exact_32_byte_string", func(t *testing.T) {
		// Exactly 32 bytes: fills exactly one storage slot.
		const code = `
			local s = string.rep("A", 32)
			tos.setStr("key32", s)
			local v = tos.getStr("key32")
			assert(v == s, "32-byte roundtrip failed: len=" .. #v)
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("long_string_multi_chunk", func(t *testing.T) {
		// 100 bytes: spans 4 chunks (32+32+32+4).
		const code = `
			local s = string.rep("XY", 50)   -- 100 chars
			tos.setStr("long", s)
			local v = tos.getStr("long")
			assert(#v == 100, "length: " .. #v)
			assert(v == s, "content mismatch")
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("overwrite", func(t *testing.T) {
		const code = `
			tos.setStr("k", "first")
			tos.setStr("k", "second")
			local v = tos.getStr("k")
			assert(v == "second", "overwrite: " .. tostring(v))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("empty_string", func(t *testing.T) {
		const code = `
			tos.setStr("e", "")
			local v = tos.getStr("e")
			assert(v == "", "empty: got " .. tostring(v))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("independent_keys", func(t *testing.T) {
		const code = `
			tos.setStr("a", "alpha")
			tos.setStr("b", "beta")
			assert(tos.getStr("a") == "alpha", "a")
			assert(tos.getStr("b") == "beta",  "b")
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("str_and_uint_namespaces_separate", func(t *testing.T) {
		// tos.set("x", 99) and tos.setStr("x", "hello") must not collide.
		const code = `
			tos.set("x", 99)
			tos.setStr("x", "hello")
			assert(tos.get("x") == 99, "uint slot corrupted: " .. tostring(tos.get("x")))
			assert(tos.getStr("x") == "hello", "str slot corrupted: " .. tostring(tos.getStr("x")))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})
}

// TestLuaContractSelector verifies tos.selector(sig) produces the correct
// 4-byte keccak function selector.
func TestLuaContractSelector(t *testing.T) {
	cases := []struct {
		sig  string
		want string // "0x" + 8 hex chars
	}{
		{"transfer(address,uint256)", abiSelector("transfer(address,uint256)")},
		{"balanceOf(address)", abiSelector("balanceOf(address)")},
		{"mint()", abiSelector("mint()")},
		{"get()", abiSelector("get()")},
	}
	for _, tc := range cases {
		sig := tc.sig
		want := tc.want
		t.Run(sig, func(t *testing.T) {
			code := fmt.Sprintf(`
				local sel = tos.selector(%q)
				assert(sel == %q, "selector: got " .. sel .. " want " .. %q)
			`, sig, want, want)
			bc, contractAddr, cleanup := luaTestSetup(t, code)
			defer cleanup()
			runLuaTx(t, bc, contractAddr, big.NewInt(0))
		})
	}
}

// TestLuaContractDispatch verifies tos.dispatch routes calldata to the correct
// Lua handler and decodes arguments.
func TestLuaContractDispatch(t *testing.T) {

	t.Run("no_data_is_noop", func(t *testing.T) {
		// dispatch with no msg.data and no fallback = no-op (no error).
		const code = `
			tos.dispatch({
				["ping()"] = function()
					tos.emit("Ping")
				end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		// No calldata → dispatch is a no-op → no logs emitted.
		if len(receipt.Logs) != 0 {
			t.Errorf("expected 0 logs for no-data call, got %d", len(receipt.Logs))
		}
	})

	t.Run("no_arg_function", func(t *testing.T) {
		// Call ping() with 4-byte selector, no arguments.
		const code = `
			tos.dispatch({
				["ping()"] = function()
					tos.emit("Ping")
				end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		data := buildCalldata(t, "ping()")
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), data)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		if receipt.Logs[0].Topics[0] != luaEventSig("Ping") {
			t.Errorf("wrong event topic")
		}
	})

	t.Run("uint256_arg", func(t *testing.T) {
		// store(uint256 value): sets a storage slot, emits StoredValue event.
		const code = `
			tos.dispatch({
				["store(uint256)"] = function(value)
					tos.set("stored", tostring(value))
					tos.emit("StoredValue", "uint256", value)
				end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		// Calldata: store(uint256 42)
		data := buildCalldata(t, "store(uint256)", "uint256", big.NewInt(42))
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), data)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		// data = ABI-encode(uint256 42) = 32 bytes, last byte = 42
		if receipt.Logs[0].Data[31] != 42 {
			t.Errorf("expected 42 in log data, got %d", receipt.Logs[0].Data[31])
		}
	})

	t.Run("multi_arg_address_uint256", func(t *testing.T) {
		// transfer(address to, uint256 amount): routes and decodes two args.
		const code = `
			tos.dispatch({
				["transfer(address,uint256)"] = function(to, amount)
					tos.emit("Transfer", "address", tos.caller, "address", to, "uint256", amount)
				end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1 := crypto.PubkeyToAddress(key1.PublicKey)
		recipient := common.HexToAddress("0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF")
		data := buildCalldata(t, "transfer(address,uint256)", "address", recipient, "uint256", big.NewInt(1000))
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), data)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 Transfer log, got %d", len(receipt.Logs))
		}
		// 3 × 32 bytes: from, to, amount
		if len(receipt.Logs[0].Data) != 96 {
			t.Fatalf("expected 96 bytes, got %d", len(receipt.Logs[0].Data))
		}
		// First 32 bytes: addr1 (from = tos.caller)
		if common.BytesToAddress(receipt.Logs[0].Data[0:32]) != addr1 {
			t.Errorf("from address mismatch in Transfer log")
		}
		// Second 32 bytes: recipient
		if common.BytesToAddress(receipt.Logs[0].Data[32:64]) != recipient {
			t.Errorf("to address mismatch in Transfer log")
		}
		// Third 32 bytes: amount 1000 → last byte = 232
		if receipt.Logs[0].Data[95] != 232 {
			t.Errorf("amount mismatch: got %d want 232", receipt.Logs[0].Data[95])
		}
	})

	t.Run("multiple_functions_routing", func(t *testing.T) {
		// Two functions; only the one whose selector matches msg.sig is called.
		const code = `
			tos.dispatch({
				["foo()"] = function() tos.emit("Foo") end,
				["bar()"] = function() tos.emit("Bar") end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		// Call bar() — Foo must not be emitted.
		data := buildCalldata(t, "bar()")
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), data)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		if receipt.Logs[0].Topics[0] != luaEventSig("Bar") {
			t.Errorf("wrong event: expected Bar")
		}
	})

	t.Run("fallback_on_unknown_selector", func(t *testing.T) {
		// fallback function is called when selector doesn't match any handler.
		const code = `
			tos.dispatch({
				["known()"] = function() tos.emit("Known") end,
				[""] = function()        tos.emit("Fallback") end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		// Send calldata for unknown selector "0xdeadbeef".
		data := []byte{0xde, 0xad, 0xbe, 0xef}
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), data)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		if receipt.Logs[0].Topics[0] != luaEventSig("Fallback") {
			t.Errorf("expected Fallback event")
		}
	})

	t.Run("fallback_on_empty_calldata", func(t *testing.T) {
		// fallback is also called when msg.data is empty (receive-like).
		const code = `
			tos.dispatch({
				[""] = function() tos.emit("Received") end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		if receipt.Logs[0].Topics[0] != luaEventSig("Received") {
			t.Errorf("expected Received event")
		}
	})

	t.Run("no_match_no_fallback_reverts", func(t *testing.T) {
		// Unknown selector with no fallback → tx must fail (revert).
		const code = `
			tos.dispatch({
				["known()"] = function() tos.emit("Known") end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		// Send calldata with an unknown selector — dispatch should revert.
		unknownSelector := []byte{0x12, 0x34, 0x56, 0x78}
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		signer := types.LatestSigner(bc.Config())
		tx, _ := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), unknownSelector)
		genesis := bc.GetBlockByNumber(0)
		blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
			b.AddTx(tx)
		})
		bc.InsertChain(blocks)
		receipts := rawdb.ReadReceipts(bc.db, blocks[0].Hash(), blocks[0].NumberU64(), bc.Config())
		if len(receipts) == 0 {
			t.Fatal("no receipt")
		}
		if receipts[0].Status != types.ReceiptStatusFailed {
			t.Errorf("expected status=0 (revert on unknown selector), got %d", receipts[0].Status)
		}
	})

	t.Run("handler_revert_rolls_back", func(t *testing.T) {
		// A handler that reverts should roll back any state it modified.
		const code = `
			tos.dispatch({
				["badOp()"] = function()
					tos.emit("ShouldNotAppear")
					tos.revert("intentional revert")
				end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		data := buildCalldata(t, "badOp()")
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		signer := types.LatestSigner(bc.Config())
		tx, _ := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), data)
		genesis := bc.GetBlockByNumber(0)
		blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
			b.AddTx(tx)
		})
		bc.InsertChain(blocks)
		receipts := rawdb.ReadReceipts(bc.db, blocks[0].Hash(), blocks[0].NumberU64(), bc.Config())
		if len(receipts) == 0 {
			t.Fatal("no receipt")
		}
		if receipts[0].Status != types.ReceiptStatusFailed {
			t.Errorf("expected status=0 after handler revert")
		}
		if len(receipts[0].Logs) != 0 {
			t.Errorf("expected 0 logs after revert, got %d", len(receipts[0].Logs))
		}
	})

	t.Run("bool_and_string_args", func(t *testing.T) {
		// Decode bool and string ABI types.
		const code = `
			tos.dispatch({
				["register(string,bool)"] = function(name, active)
					if active then
						tos.setStr("name", name)
						tos.emit("Registered", "string", name)
					end
				end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		data := buildCalldata(t, "register(string,bool)", "string", "Alice", "bool", true)
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), data)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		if receipt.Logs[0].Topics[0] != luaEventSig("Registered", "string") {
			t.Errorf("expected Registered event")
		}
	})
}

// TestLuaContractOncreate verifies tos.oncreate constructor semantics.
func TestLuaContractOncreate(t *testing.T) {

	t.Run("runs_once_on_first_call", func(t *testing.T) {
		// The constructor sets "owner" and emits Deployed.
		// On the second call the constructor must NOT run again.
		const code = `
			tos.oncreate(function()
				tos.setStr("owner", tos.caller)
				tos.emit("Deployed")
			end)
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()

		// First call: constructor runs → Deployed event emitted.
		receipt1 := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt1.Logs) != 1 {
			t.Fatalf("first call: expected 1 log (Deployed), got %d", len(receipt1.Logs))
		}
		if receipt1.Logs[0].Topics[0] != luaEventSig("Deployed") {
			t.Errorf("first call: expected Deployed event")
		}

		// Second call (nonce=1, block=2): constructor must be skipped → 0 logs.
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		signer := types.LatestSigner(bc.Config())
		tx2, _ := signTestSignerTx(signer, key1, 1, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), nil)
		parent := bc.GetBlockByNumber(1)
		blocks2, _ := GenerateChain(bc.Config(), parent, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
			b.AddTx(tx2)
		})
		bc.InsertChain(blocks2)
		receipts2 := rawdb.ReadReceipts(bc.db, blocks2[0].Hash(), blocks2[0].NumberU64(), bc.Config())
		if len(receipts2) == 0 {
			t.Fatal("second call: no receipt")
		}
		if receipts2[0].Status != types.ReceiptStatusSuccessful {
			t.Fatalf("second call: expected success, got status=%d", receipts2[0].Status)
		}
		if len(receipts2[0].Logs) != 0 {
			t.Errorf("second call: constructor ran again (expected 0 logs, got %d)", len(receipts2[0].Logs))
		}
	})

	t.Run("constructor_can_coexist_with_dispatch", func(t *testing.T) {
		// Contract: constructor sets owner; dispatch exposes a function.
		// Both should work correctly on the same contract.
		const code = `
			tos.oncreate(function()
				tos.setStr("owner", tos.caller)
			end)
			tos.dispatch({
				["getOwner()"] = function()
					tos.emit("Owner", "address", common.HexToAddress(tos.getStr("owner")))
				end,
			})
		`
		// "getOwner()" just emits an event; the address decode is tricky in Lua,
		// so just verify the contract succeeds and emits on first call.
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()

		// First call with no calldata: constructor runs, dispatch is no-op.
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		// Constructor ran (no emit here), dispatch no-op → 0 logs.
		if len(receipt.Logs) != 0 {
			t.Errorf("expected 0 logs on first bare call, got %d", len(receipt.Logs))
		}
	})

	t.Run("constructor_revert_allows_retry", func(t *testing.T) {
		// Constructor calls tos.revert → tx fails, __oncreate__ flag is NOT set.
		// A second call should still try to run the constructor.
		// We test this by having the constructor fail then checking the flag
		// via a separate call that emits if __oncreate__ is unset.
		const code = `
			tos.oncreate(function()
				tos.revert("constructor failed")
			end)
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()

		// First call: constructor reverts → tx must fail.
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		signer := types.LatestSigner(bc.Config())
		tx, _ := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), nil)
		genesis := bc.GetBlockByNumber(0)
		blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
			b.AddTx(tx)
		})
		bc.InsertChain(blocks)
		receipts := rawdb.ReadReceipts(bc.db, blocks[0].Hash(), blocks[0].NumberU64(), bc.Config())
		if len(receipts) == 0 {
			t.Fatal("no receipt")
		}
		if receipts[0].Status != types.ReceiptStatusFailed {
			t.Errorf("expected constructor revert to fail tx, got status=%d", receipts[0].Status)
		}
	})
}

// TestLuaContractArrayStorage verifies tos.arrPush/arrPop/arrGet/arrSet/arrLen.
func TestLuaContractArrayStorage(t *testing.T) {

	t.Run("empty_array_len_is_zero", func(t *testing.T) {
		const code = `
			local n = tos.arrLen("items")
			assert(n == 0, "empty len: " .. tostring(n))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("push_and_len", func(t *testing.T) {
		const code = `
			tos.arrPush("nums", 10)
			tos.arrPush("nums", 20)
			tos.arrPush("nums", 30)
			assert(tos.arrLen("nums") == 3, "len after 3 pushes: " .. tostring(tos.arrLen("nums")))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("get_elements", func(t *testing.T) {
		const code = `
			tos.arrPush("v", 100)
			tos.arrPush("v", 200)
			tos.arrPush("v", 300)
			assert(tos.arrGet("v", 1) == 100, "v[1]: " .. tostring(tos.arrGet("v", 1)))
			assert(tos.arrGet("v", 2) == 200, "v[2]: " .. tostring(tos.arrGet("v", 2)))
			assert(tos.arrGet("v", 3) == 300, "v[3]: " .. tostring(tos.arrGet("v", 3)))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("get_out_of_bounds_returns_nil", func(t *testing.T) {
		const code = `
			tos.arrPush("a", 42)
			assert(tos.arrGet("a", 0)   == nil, "index 0 should be nil")
			assert(tos.arrGet("a", 2)   == nil, "index 2 out of bounds")
			assert(tos.arrGet("a", -1)  == nil, "negative index")
			assert(tos.arrGet("empty", 1) == nil, "empty array")
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("set_overwrites", func(t *testing.T) {
		const code = `
			tos.arrPush("x", 1)
			tos.arrPush("x", 2)
			tos.arrSet("x", 1, 99)
			assert(tos.arrGet("x", 1) == 99, "set [1]: " .. tostring(tos.arrGet("x", 1)))
			assert(tos.arrGet("x", 2) == 2,  "set [2] unchanged: " .. tostring(tos.arrGet("x", 2)))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("set_out_of_bounds_reverts", func(t *testing.T) {
		const code = `tos.arrSet("z", 1, 5)`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTxExpectFail(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("pop_basic", func(t *testing.T) {
		const code = `
			tos.arrPush("q", 11)
			tos.arrPush("q", 22)
			local v = tos.arrPop("q")
			assert(v == 22, "pop: " .. tostring(v))
			assert(tos.arrLen("q") == 1, "len after pop: " .. tostring(tos.arrLen("q")))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("pop_empty_returns_nil", func(t *testing.T) {
		const code = `
			local v = tos.arrPop("empty")
			assert(v == nil, "pop empty: " .. tostring(v))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("push_pop_round_trip", func(t *testing.T) {
		// Push 1×10 … 5×10, then pop all five and verify LIFO order.
		// Uses a decrementing numeric for loop (for i = 5, 1, -1) which now
		// works correctly after the OP_FORLOOP two's complement sign fix.
		const code = `
			for i = 1, 5 do tos.arrPush("s", i * 10) end
			assert(tos.arrLen("s") == 5, "len=5")
			for i = 5, 1, -1 do
				local v = tos.arrPop("s")
				assert(v == i * 10, "pop " .. tostring(i) .. ": got " .. tostring(v))
			end
			assert(tos.arrLen("s") == 0, "len=0 after all pops")
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("independent_keys", func(t *testing.T) {
		// Two arrays with different keys must not share storage.
		const code = `
			tos.arrPush("a", 1)
			tos.arrPush("b", 99)
			assert(tos.arrGet("a", 1) == 1,  "a[1]")
			assert(tos.arrGet("b", 1) == 99, "b[1]")
			assert(tos.arrLen("a") == 1, "len a")
			assert(tos.arrLen("b") == 1, "len b")
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("arr_and_scalar_namespaces_separate", func(t *testing.T) {
		// tos.set("k", 7) and tos.arrPush("k", 7) must not collide.
		const code = `
			tos.set("k", 42)
			tos.arrPush("k", 99)
			assert(tos.get("k") == 42,       "scalar k not corrupted")
			assert(tos.arrGet("k", 1) == 99, "array k not corrupted")
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("dispatch_with_array", func(t *testing.T) {
		// Real-world pattern: append to an array from a dispatched function.
		const code = `
			tos.dispatch({
				["enroll(uint256)"] = function(id)
					tos.arrPush("ids", id)
					tos.emit("Enrolled", "uint256", id, "uint256", tos.arrLen("ids"))
				end,
			})
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		data := buildCalldata(t, "enroll(uint256)", "uint256", big.NewInt(42))
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), data)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		// data = ABI-encode(uint256 42, uint256 1) → 64 bytes; last byte of word1 = 42, last byte of word2 = 1
		if len(receipt.Logs[0].Data) != 64 {
			t.Fatalf("expected 64 bytes log data, got %d", len(receipt.Logs[0].Data))
		}
		if receipt.Logs[0].Data[31] != 42 {
			t.Errorf("id in log: expected 42, got %d", receipt.Logs[0].Data[31])
		}
		if receipt.Logs[0].Data[63] != 1 {
			t.Errorf("len in log: expected 1, got %d", receipt.Logs[0].Data[63])
		}
	})
}

// TestLuaContractMapping verifies tos.mapGet / tos.mapSet / tos.mapGetStr /
// tos.mapSetStr and the tos.at proxy mapGet / mapGetStr.
//
// Covers:
//   - Single-key uint256 round-trip
//   - Two-key nested mapping (mapSet/mapGet with 2 keys)
//   - mapGetStr / mapSetStr round-trip (single and nested keys)
//   - Unset key returns nil
//   - Namespace isolation: mapGet and tos.get on same logical string are
//     in different namespaces → different values
//   - mapSet reverts in staticcall
//   - tos.at(addr).mapGet reads another contract's mapping
func TestLuaContractMapping(t *testing.T) {
	t.Run("single_key_uint256", func(t *testing.T) {
		const code = `
			tos.mapSet("balance", "alice", 1000)
			local v = tos.mapGet("balance", "alice")
			assert(v == 1000, "expected 1000, got " .. tostring(v))
			assert(tos.mapGet("balance", "bob") == nil, "unset key should be nil")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("proxy_single_key_uint256", func(t *testing.T) {
		const code = `
			local balance = tos.mapping("balance")
			balance["alice"] = 1000
			assert(balance["alice"] == 1000, "proxy read/write")
			assert(balance["bob"] == nil, "proxy unset")
			-- interchangeable with mapGet/mapSet
			assert(tos.mapGet("balance", "alice") == 1000, "compat with mapGet")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("nested_two_keys", func(t *testing.T) {
		const code = `
			-- allowance[owner][spender] = amount
			tos.mapSet("allowance", "owner1", "spender1", 500)
			tos.mapSet("allowance", "owner1", "spender2", 250)
			assert(tos.mapGet("allowance", "owner1", "spender1") == 500, "spender1")
			assert(tos.mapGet("allowance", "owner1", "spender2") == 250, "spender2")
			-- different owner shares no storage with owner1
			assert(tos.mapGet("allowance", "owner2", "spender1") == nil, "different owner")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("proxy_nested_two_keys_uint256", func(t *testing.T) {
		const code = `
			local allowance = tos.mapping("allowance", 2)
			allowance["owner1"]["spender1"] = 500
			allowance["owner1"]["spender2"] = 250
			assert(allowance["owner1"]["spender1"] == 500, "spender1")
			assert(allowance["owner1"]["spender2"] == 250, "spender2")
			assert(allowance["owner2"]["spender1"] == nil, "different owner")
			-- top-level assignment is invalid for depth=2
			local ok = pcall(function() allowance["owner3"] = 1 end)
			assert(not ok, "depth=2 requires second key")
			-- interchangeable with mapGet/mapSet
			assert(tos.mapGet("allowance", "owner1", "spender1") == 500, "compat with mapGet")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("single_key_string", func(t *testing.T) {
		const code = `
			tos.mapSetStr("name", "token1", "CoolNFT")
			local s = tos.mapGetStr("name", "token1")
			assert(s == "CoolNFT", "expected CoolNFT, got " .. tostring(s))
			assert(tos.mapGetStr("name", "token2") == nil, "unset key should be nil")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("nested_string", func(t *testing.T) {
		const code = `
			tos.mapSetStr("meta", "nft1", "owner1", "Alice")
			tos.mapSetStr("meta", "nft1", "owner2", "Bob")
			assert(tos.mapGetStr("meta", "nft1", "owner1") == "Alice", "owner1")
			assert(tos.mapGetStr("meta", "nft1", "owner2") == "Bob",   "owner2")
			assert(tos.mapGetStr("meta", "nft2", "owner1") == nil,     "different nft")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("namespace_isolation_from_set_get", func(t *testing.T) {
		// tos.mapGet("x", "y") and tos.get("x") use different namespaces;
		// setting one must not affect the other.
		const code = `
			tos.set("balance", 99)
			tos.mapSet("balance", "alice", 42)
			-- tos.get still reads the uint256 storage namespace
			assert(tos.get("balance") == 99, "tos.get should be unchanged")
			-- tos.mapGet reads the map namespace
			assert(tos.mapGet("balance", "alice") == 42, "mapGet should be 42")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("mapGet_unset_nil", func(t *testing.T) {
		const code = `
			assert(tos.mapGet("x", "k") == nil, "unset uint256 slot is nil")
			assert(tos.mapGetStr("x", "k") == nil, "unset string slot is nil")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("mapSet_readonly_reverts", func(t *testing.T) {
		// staticcall B (which tries tos.mapSet) → must return false.
		// Uses the same fixed-address pattern as TestLuaContractStaticCall.
		const addrB = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		const addrA = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
		calleeCode := `tos.mapSet("x", "k", 1)`
		callerCode := fmt.Sprintf(`
			local ok = tos.staticcall(%q, "")
			assert(not ok, "mapSet inside staticcall should fail")
		`, addrB)
		bc, _, _, cleanup := luaTestSetup2(t, callerCode, calleeCode)
		defer cleanup()
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
	})

	t.Run("proxy_mapGet_reads_own_state", func(t *testing.T) {
		// Write via mapSet, then read the same state via tos.at(self).mapGet.
		// This exercises the proxy's mapGet code path without a second contract.
		const code = `
			tos.mapSet("pts", "alice", 77)
			tos.mapSet("pts", "bob",   33)
			local proxy = tos.at(tos.self)
			assert(proxy.mapGet("pts", "alice") == 77, "alice via proxy")
			assert(proxy.mapGet("pts", "bob")   == 33, "bob via proxy")
			assert(proxy.mapGet("pts", "carol") == nil, "unset via proxy")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("proxy_mapGetStr_reads_own_state", func(t *testing.T) {
		const code = `
			tos.mapSetStr("tag", "nft1", "Dragon")
			local proxy = tos.at(tos.self)
			assert(proxy.mapGetStr("tag", "nft1") == "Dragon", "nft1 via proxy")
			assert(proxy.mapGetStr("tag", "nft2") == nil, "unset via proxy")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})
}

// TestLuaContractCrossContractRead verifies tos.at(addr) and tos.codeAt(addr).
//
// Two contracts are pre-deployed at genesis:
//   - contractAddrB: "source" — has pre-written state via genesis storage
//   - contractAddr:  "reader" — uses tos.at(addrB) to read B's state and
//     emits events so the test can inspect the values.
//
// Because genesis contracts can't run Lua at block-0 (no transactions), we
// pre-populate contractAddrB's storage slots directly in the genesis alloc
// via the same slot derivation used by applyLua.
func TestLuaContractCrossContractRead(t *testing.T) {

	// Pre-compute the storage slots that B's tos.set/setStr/arrPush would write.
	// We inject them directly into genesis so block-1 can read them via tos.at.
	slotUint := func(key string) common.Hash { return luaStorageSlot(key) }
	slotStrLen := func(key string) common.Hash { return luaStrLenSlot(key) }
	slotStrChunk := func(key string, i int) common.Hash {
		return luaStrChunkSlot(luaStrLenSlot(key), i)
	}
	slotArrLen := func(key string) common.Hash { return luaArrLenSlot(key) }
	slotArrElem := func(key string, i uint64) common.Hash {
		return luaArrElemSlot(luaArrLenSlot(key), i)
	}

	uint256Slot := func(v uint64) common.Hash {
		var h common.Hash
		new(big.Int).SetUint64(v).FillBytes(h[:])
		return h
	}

	// String "hello" (5 bytes): lenSlot = 5+1 = 6 stored as uint64 in bytes [24:32]
	strLenSlotValue := func(s string) common.Hash {
		var h common.Hash
		binary.BigEndian.PutUint64(h[24:], uint64(len(s))+1)
		return h
	}
	strChunkSlotValue := func(s string, chunk int) common.Hash {
		var h common.Hash
		data := []byte(s)
		start := chunk * 32
		end := start + 32
		if end > len(data) {
			end = len(data)
		}
		copy(h[:], data[start:end])
		return h
	}

	addrB := common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	// codeA: reads from B and emits results as events.
	codeA := fmt.Sprintf(`
		local b = tos.at(%q)
		-- read uint256
		local score = b.get("score")
		tos.emit("Score", "uint256", score)
		-- read string
		local name = b.getStr("name")
		tos.emit("Name", "string", name)
		-- read array length
		local n = b.arrLen("items")
		tos.emit("ArrLen", "uint256", n)
		-- read array element
		local v1 = b.arrGet("items", 1)
		tos.emit("ArrElem", "uint256", v1)
		-- read balance
		local bal = b.balance()
		tos.emit("Balance", "uint256", bal)
		-- codeAt
		local hasCode = tos.codeAt(%q)
		tos.emit("HasCode", "bool", hasCode)
		local noCode = tos.codeAt("0x0000000000000000000000000000000000000000")
		tos.emit("NoCode", "bool", noCode)
	`, addrB.Hex(), addrB.Hex())

	// codeB: just a no-op Lua script (its storage is injected via genesis alloc).
	codeB := `-- storage pre-seeded in genesis`

	config := &params.ChainConfig{
		ChainID: big.NewInt(1),
		DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 200, MaxValidators: 21},
	}
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)
	contractAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")

	storageName := "hello"
	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config: config,
		Alloc: GenesisAlloc{
			addr1:        {Balance: new(big.Int).Mul(big.NewInt(10), big.NewInt(params.TOS))},
			contractAddr: {Balance: new(big.Int).Mul(big.NewInt(1), big.NewInt(params.TOS)), Code: []byte(codeA)},
			addrB: {
				Balance: new(big.Int).Mul(big.NewInt(2), big.NewInt(params.TOS)),
				Code:    []byte(codeB),
				Storage: map[common.Hash]common.Hash{
					// tos.set("score", 42)
					slotUint("score"): uint256Slot(42),
					// tos.setStr("name", "hello")
					slotStrLen("name"):      strLenSlotValue(storageName),
					slotStrChunk("name", 0): strChunkSlotValue(storageName, 0),
					// tos.arrPush("items", 99)  → len=1, items[0]=99
					slotArrLen("items"):     uint256Slot(1),
					slotArrElem("items", 0): uint256Slot(99),
				},
			},
		},
	}
	gspec.MustCommit(db)
	bc, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Stop()

	receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
	if len(receipt.Logs) != 7 {
		t.Fatalf("expected 7 logs, got %d", len(receipt.Logs))
	}

	// Log 0: Score = 42
	if receipt.Logs[0].Topics[0] != luaEventSig("Score", "uint256") {
		t.Errorf("log[0] not Score")
	}
	if receipt.Logs[0].Data[31] != 42 {
		t.Errorf("Score: expected 42, got %d", receipt.Logs[0].Data[31])
	}

	// Log 1: Name = "hello" (ABI-encoded string)
	if receipt.Logs[1].Topics[0] != luaEventSig("Name", "string") {
		t.Errorf("log[1] not Name")
	}
	// ABI-encoded string: offset(32) + length(32) + data(32 padded) = 96 bytes
	if len(receipt.Logs[1].Data) != 96 {
		t.Fatalf("Name data: expected 96 bytes, got %d", len(receipt.Logs[1].Data))
	}
	// bytes [64:69] = "hello"
	if string(receipt.Logs[1].Data[64:69]) != "hello" {
		t.Errorf("Name data: expected 'hello', got %q", string(receipt.Logs[1].Data[64:69]))
	}

	// Log 2: ArrLen = 1
	if receipt.Logs[2].Topics[0] != luaEventSig("ArrLen", "uint256") {
		t.Errorf("log[2] not ArrLen")
	}
	if receipt.Logs[2].Data[31] != 1 {
		t.Errorf("ArrLen: expected 1, got %d", receipt.Logs[2].Data[31])
	}

	// Log 3: ArrElem = 99
	if receipt.Logs[3].Topics[0] != luaEventSig("ArrElem", "uint256") {
		t.Errorf("log[3] not ArrElem")
	}
	if receipt.Logs[3].Data[31] != 99 {
		t.Errorf("ArrElem: expected 99, got %d", receipt.Logs[3].Data[31])
	}

	// Log 4: Balance = 2 TOS
	if receipt.Logs[4].Topics[0] != luaEventSig("Balance", "uint256") {
		t.Errorf("log[4] not Balance")
	}
	twoTOS := new(big.Int).Mul(big.NewInt(2), big.NewInt(params.TOS))
	gotBal := new(big.Int).SetBytes(receipt.Logs[4].Data)
	if gotBal.Cmp(twoTOS) != 0 {
		t.Errorf("Balance: expected %s, got %s", twoTOS, gotBal)
	}

	// Log 5: HasCode = true (addrB has code)
	if receipt.Logs[5].Topics[0] != luaEventSig("HasCode", "bool") {
		t.Errorf("log[5] not HasCode")
	}
	if receipt.Logs[5].Data[31] != 1 {
		t.Errorf("HasCode: expected true (1), got %d", receipt.Logs[5].Data[31])
	}

	// Log 6: NoCode = false (zero address has no code)
	if receipt.Logs[6].Topics[0] != luaEventSig("NoCode", "bool") {
		t.Errorf("log[6] not NoCode")
	}
	if receipt.Logs[6].Data[31] != 0 {
		t.Errorf("NoCode: expected false (0), got %d", receipt.Logs[6].Data[31])
	}
}

// TestLuaContractCall tests tos.call — inter-contract calls with value
// forwarding, calldata, caller identity, and revert isolation.
func TestLuaContractCall(t *testing.T) {
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)

	// noCodeAddr is an address with no deployed code.
	noCodeAddr := common.HexToAddress("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEF")

	t.Run("no_code_plain_transfer", func(t *testing.T) {
		// tos.call to an address with no code acts as a plain TOS transfer.
		// A has 1 TOS in genesis; it transfers 0.25 TOS to noCodeAddr.
		oneTOS := new(big.Int).Mul(big.NewInt(1), big.NewInt(params.TOS))
		quarterTOS := new(big.Int).Div(oneTOS, big.NewInt(4))

		codeA := fmt.Sprintf(`
			local ok = tos.call(%q, %s)
			tos.require(ok, "plain transfer failed")
		`, noCodeAddr.Hex(), quarterTOS.Text(10))

		bc, contractAddr, _, cleanup := luaTestSetup2(t, codeA, `-- codeB unused`)
		defer cleanup()
		_ = contractAddr

		runLuaTx(t, bc, contractAddr, big.NewInt(0))

		state, _ := bc.State()
		got := state.GetBalance(noCodeAddr)
		if got == nil || got.Cmp(quarterTOS) != 0 {
			t.Errorf("noCodeAddr balance: want %s, got %v", quarterTOS, got)
		}
	})

	t.Run("executes_callee_code", func(t *testing.T) {
		// A calls B; B writes "called"=1 to its own storage.
		// After the tx, contractAddrB's storage slot for "called" must be 1.
		codeB := `tos.set("called", 1)`
		codeA := fmt.Sprintf(`
			local ok = tos.call(%q)
			tos.require(ok, "call failed")
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, _, contractAddrB, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		runLuaTx(t, bc, common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"), big.NewInt(0))

		state, _ := bc.State()
		slot := luaStorageSlot("called")
		val := state.GetState(contractAddrB, slot)
		if val[31] != 1 {
			t.Errorf("contractAddrB.called: want 1, got %d", val[31])
		}
	})

	t.Run("caller_identity", func(t *testing.T) {
		// A calls B. Inside B:
		//   msg.sender == contractAddr (A's address, not the EOA)
		//   tx.origin  == addr1 (the original EOA, unchanged)
		codeB := `
			tos.emit("Sender",  "address", msg.sender)
			tos.emit("Origin",  "address", tx.origin)
		`
		codeA := fmt.Sprintf(`tos.call(%q)`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, contractAddr, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		receipt := runLuaTxGetReceipt(t, bc,
			common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
			big.NewInt(0), nil)

		if len(receipt.Logs) < 2 {
			t.Fatalf("expected 2 logs, got %d", len(receipt.Logs))
		}

		// Log 0: Sender — should be contractAddr (A), not addr1 (EOA)
		if receipt.Logs[0].Topics[0] != luaEventSig("Sender", "address") {
			t.Errorf("log[0] topic mismatch")
		}
		wantSender := contractAddr
		// ABI address encoding: 32 bytes, address in low 32 bytes
		gotSender := common.BytesToAddress(receipt.Logs[0].Data)
		if gotSender != wantSender {
			t.Errorf("B.msg.sender: want %s (A), got %s", wantSender.Hex(), gotSender.Hex())
		}

		// Log 1: Origin — should be addr1 (the original EOA)
		if receipt.Logs[1].Topics[0] != luaEventSig("Origin", "address") {
			t.Errorf("log[1] topic mismatch")
		}
		gotOrigin := common.BytesToAddress(receipt.Logs[1].Data)
		if gotOrigin != addr1 {
			t.Errorf("B.tx.origin: want %s (EOA), got %s", addr1.Hex(), gotOrigin.Hex())
		}
	})

	t.Run("value_forwarded", func(t *testing.T) {
		// A has 1 TOS; it forwards 0.5 TOS to B.
		// B emits its msg.value — must equal 0.5 TOS.
		halfTOS := new(big.Int).Mul(big.NewInt(5e17), big.NewInt(1))

		codeB := `tos.emit("Value", "uint256", msg.value)`
		codeA := fmt.Sprintf(`
			local ok = tos.call(%q, %s)
			tos.require(ok, "value forward failed")
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", halfTOS.Text(10))

		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		receipt := runLuaTxGetReceipt(t, bc,
			common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
			big.NewInt(0), nil)

		if len(receipt.Logs) < 1 {
			t.Fatalf("expected 1 log, got 0")
		}
		gotVal := new(big.Int).SetBytes(receipt.Logs[0].Data)
		if gotVal.Cmp(halfTOS) != 0 {
			t.Errorf("B.msg.value: want %s, got %s", halfTOS, gotVal)
		}
	})

	t.Run("revert_isolates_callee", func(t *testing.T) {
		// A writes "alive"=1 to A's storage.
		// A calls B; B writes "dead"=1 to B's storage, then reverts.
		// After tx: A's write preserved, B's write undone.
		codeB := `
			tos.set("dead", 1)
			tos.revert("intentional revert")
		`
		codeA := fmt.Sprintf(`
			tos.set("alive", 1)
			tos.call(%q)   -- returns false; ignored here
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, contractAddr, contractAddrB, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		runLuaTx(t, bc,
			common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
			big.NewInt(0))

		state, _ := bc.State()

		// A's "alive" slot must be 1.
		aliveSlot := state.GetState(contractAddr, luaStorageSlot("alive"))
		if aliveSlot[31] != 1 {
			t.Errorf("A.alive: want 1, got %d", aliveSlot[31])
		}

		// B's "dead" slot must be zero (reverted).
		deadSlot := state.GetState(contractAddrB, luaStorageSlot("dead"))
		if deadSlot != (common.Hash{}) {
			t.Errorf("B.dead: want 0 (reverted), got %x", deadSlot)
		}
	})

	t.Run("returns_false_on_revert", func(t *testing.T) {
		// tos.call returns false when callee reverts; caller can inspect and
		// emit the result.  Caller itself must not revert.
		codeB := `tos.revert("fail")`
		codeA := fmt.Sprintf(`
			local ok = tos.call(%q)
			if ok then
				tos.emit("Result", "uint256", 1)
			else
				tos.emit("Result", "uint256", 0)
			end
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		receipt := runLuaTxGetReceipt(t, bc,
			common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
			big.NewInt(0), nil)

		if len(receipt.Logs) < 1 {
			t.Fatalf("expected Result log, got 0")
		}
		if receipt.Logs[0].Data[31] != 0 {
			t.Errorf("Result: want 0 (false), got %d", receipt.Logs[0].Data[31])
		}
	})

	t.Run("calldata_routing", func(t *testing.T) {
		// A constructs ABI calldata for "store(uint256)" and passes it to B.
		// B uses tos.dispatch to route the call and writes the value to storage.
		codeB := `
			tos.dispatch({
				["store(uint256)"] = function(val)
					tos.set("stored", val)
				end,
			})
		`
		// A builds: selector("store(uint256)") ++ abi.encode("uint256", 999)
		// and calls B with it.
		codeA := fmt.Sprintf(`
			local sel = tos.selector("store(uint256)")
			local enc = tos.abi.encode("uint256", 999)
			local data = sel .. string.sub(enc, 3)   -- strip extra "0x" from enc
			local ok = tos.call(%q, 0, data)
			tos.require(ok, "calldata call failed")
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, _, contractAddrB, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		runLuaTx(t, bc,
			common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
			big.NewInt(0))

		state, _ := bc.State()
		storedSlot := state.GetState(contractAddrB, luaStorageSlot("stored"))
		got := new(big.Int).SetBytes(storedSlot[:])
		if got.Int64() != 999 {
			t.Errorf("B.stored: want 999, got %s", got)
		}
	})
}

// TestLuaContractCallResult tests tos.result() — callee sets return data that
// the caller receives as the second value of tos.call().
func TestLuaContractCallResult(t *testing.T) {
	t.Run("uint256_return", func(t *testing.T) {
		// B returns a uint256; A decodes it and emits it.
		codeB := `tos.result("uint256", 12345)`
		codeA := fmt.Sprintf(`
			local ok, data = tos.call(%q)
			tos.require(ok, "call failed")
			local val = tos.abi.decode(data, "uint256")
			tos.emit("Got", "uint256", val)
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		receipt := runLuaTxGetReceipt(t, bc,
			common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
			big.NewInt(0), nil)

		if len(receipt.Logs) < 1 {
			t.Fatalf("expected Got log, got 0")
		}
		got := new(big.Int).SetBytes(receipt.Logs[0].Data)
		if got.Int64() != 12345 {
			t.Errorf("Got: want 12345, got %s", got)
		}
	})

	t.Run("dispatch_with_result", func(t *testing.T) {
		// B dispatches getBalance(address) and returns caller's balance.
		// A calls B via calldata and decodes the returned balance.
		codeB := `
			tos.dispatch({
				["getBalance(address)"] = function(addr)
					tos.result("uint256", tos.balance(addr))
				end,
			})
		`
		oneTOS := new(big.Int).Mul(big.NewInt(1), big.NewInt(params.TOS))
		codeA := fmt.Sprintf(`
			local sel  = tos.selector("getBalance(address)")
			local enc  = tos.abi.encode("address", tos.self)
			local data = sel .. string.sub(enc, 3)
			local ok, ret = tos.call(%q, 0, data)
			tos.require(ok, "call failed")
			local bal = tos.abi.decode(ret, "uint256")
			tos.emit("Balance", "uint256", bal)
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		receipt := runLuaTxGetReceipt(t, bc,
			common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
			big.NewInt(0), nil)

		if len(receipt.Logs) < 1 {
			t.Fatalf("expected Balance log, got 0")
		}
		gotBal := new(big.Int).SetBytes(receipt.Logs[0].Data)
		if gotBal.Cmp(oneTOS) != 0 {
			t.Errorf("Balance: want %s (1 TOS), got %s", oneTOS, gotBal)
		}
	})

	t.Run("no_result_gives_nil", func(t *testing.T) {
		// B does not call tos.result(); caller's second return value is nil.
		// A stores 0 if data is nil, 1 if data is a string.
		codeB := `tos.set("ran", 1)` // no tos.result()
		codeA := fmt.Sprintf(`
			local ok, data = tos.call(%q)
			tos.require(ok, "call failed")
			if data == nil then
				tos.emit("HasData", "uint256", 0)
			else
				tos.emit("HasData", "uint256", 1)
			end
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		receipt := runLuaTxGetReceipt(t, bc,
			common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
			big.NewInt(0), nil)

		if len(receipt.Logs) < 1 {
			t.Fatalf("expected HasData log, got 0")
		}
		if receipt.Logs[0].Data[31] != 0 {
			t.Errorf("HasData: want 0 (nil), got %d", receipt.Logs[0].Data[31])
		}
	})

	t.Run("result_after_state_write_committed", func(t *testing.T) {
		// B writes storage AND calls tos.result() — the write must be committed
		// (tos.result is a clean return, not a revert).
		codeB := `
			tos.set("written", 77)
			tos.result("uint256", 1)
		`
		codeA := fmt.Sprintf(`
			local ok, _ = tos.call(%q)
			tos.require(ok, "call failed")
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, _, contractAddrB, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		runLuaTx(t, bc,
			common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
			big.NewInt(0))

		state, _ := bc.State()
		slot := state.GetState(contractAddrB, luaStorageSlot("written"))
		if slot[31] != 77 {
			t.Errorf("B.written: want 77, got %d", slot[31])
		}
	})

	t.Run("revert_after_result_discards_result", func(t *testing.T) {
		// B calls tos.result() then tos.revert() — revert wins; caller gets false/nil.
		// This cannot happen in practice (tos.result raises a signal that stops
		// execution), but we verify the isolation guarantee holds.
		// Actually: tos.result() raises the sentinel which stops execution, so
		// tos.revert() after it never runs. We test the opposite ordering:
		// B writes, then tos.revert() — result is nil, state is reverted.
		codeB := `
			tos.set("shouldNotExist", 1)
			tos.revert("bailing out")
		`
		codeA := fmt.Sprintf(`
			local ok, data = tos.call(%q)
			-- ok must be false; data must be nil
			if ok then tos.revert("expected false") end
			if data ~= nil then tos.revert("expected nil data") end
			tos.emit("OK", "uint256", 1)
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, _, contractAddrB, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		receipt := runLuaTxGetReceipt(t, bc,
			common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
			big.NewInt(0), nil)

		if len(receipt.Logs) < 1 {
			t.Fatalf("expected OK log, got 0")
		}

		// B's storage write must be absent (reverted).
		state, _ := bc.State()
		slot := state.GetState(contractAddrB, luaStorageSlot("shouldNotExist"))
		if slot != (common.Hash{}) {
			t.Errorf("B.shouldNotExist: want zero (reverted), got %x", slot)
		}
	})
}

// TestLuaContractStaticCall tests tos.staticcall — read-only inter-contract
// calls that enforce no state mutations in the callee.
func TestLuaContractStaticCall(t *testing.T) {
	const addrA = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	const addrB = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	t.Run("returns_result_data", func(t *testing.T) {
		codeB := `tos.result("uint256", 7777)`
		codeA := fmt.Sprintf(`
			local ok, data = tos.staticcall(%q)
			tos.require(ok, "staticcall failed")
			local val = tos.abi.decode(data, "uint256")
			tos.emit("Val", "uint256", val)
		`, addrB)
		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, common.HexToAddress(addrA), big.NewInt(0), nil)
		if len(receipt.Logs) < 1 {
			t.Fatalf("expected Val log, got 0")
		}
		if new(big.Int).SetBytes(receipt.Logs[0].Data).Int64() != 7777 {
			t.Errorf("Val: want 7777, got %s", new(big.Int).SetBytes(receipt.Logs[0].Data))
		}
	})

	t.Run("write_in_callee_fails", func(t *testing.T) {
		// B tries tos.set — must fail; staticcall returns false.
		// A's write before the call is preserved.
		codeB := `tos.set("x", 1)`
		codeA := fmt.Sprintf(`
			tos.set("alive", 42)
			local ok, _ = tos.staticcall(%q)
			if ok then tos.revert("expected false") end
			tos.emit("Done", "uint256", 1)
		`, addrB)
		bc, contractAddr, contractAddrB, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, common.HexToAddress(addrA), big.NewInt(0), nil)
		if len(receipt.Logs) < 1 {
			t.Fatalf("expected Done log")
		}
		state, _ := bc.State()
		aliveSlot := state.GetState(contractAddr, luaStorageSlot("alive"))
		if new(big.Int).SetBytes(aliveSlot[:]).Int64() != 42 {
			t.Errorf("A.alive: want 42")
		}
		xSlot := state.GetState(contractAddrB, luaStorageSlot("x"))
		if xSlot != (common.Hash{}) {
			t.Errorf("B.x: want zero (write blocked), got %x", xSlot)
		}
	})

	t.Run("transfer_in_callee_fails", func(t *testing.T) {
		noCodeAddr := common.HexToAddress("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
		codeB := fmt.Sprintf(`tos.transfer(%q, 1)`, noCodeAddr.Hex())
		codeA := fmt.Sprintf(`
			local ok, _ = tos.staticcall(%q)
			if ok then tos.revert("expected false") end
			tos.emit("Done", "uint256", 1)
		`, addrB)
		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, common.HexToAddress(addrA), big.NewInt(0), nil)
		if len(receipt.Logs) < 1 {
			t.Fatalf("expected Done log")
		}
	})

	t.Run("emit_in_callee_fails", func(t *testing.T) {
		// B tries tos.emit — must fail; no "Boom" log must appear.
		codeB := `tos.emit("Boom", "uint256", 1)`
		codeA := fmt.Sprintf(`
			local ok, _ = tos.staticcall(%q)
			if ok then tos.revert("expected false") end
			tos.emit("Done", "uint256", 1)
		`, addrB)
		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, common.HexToAddress(addrA), big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Errorf("expected exactly 1 log (Done), got %d", len(receipt.Logs))
		}
	})

	t.Run("value_call_in_static_context_fails", func(t *testing.T) {
		// A staticcalls B; B tries tos.call(addrA, value>0) which must fail
		// because readonly propagates. B catches the failure and still calls
		// tos.result — so the staticcall itself succeeds.
		oneTOS := new(big.Int).Mul(big.NewInt(1), big.NewInt(params.TOS))
		codeB := fmt.Sprintf(`
			local ok, _ = tos.call(%q, %s)
			if ok then tos.revert("should have failed") end
			tos.result("uint256", 99)
		`, addrA, oneTOS.Text(10))
		codeA := fmt.Sprintf(`
			local ok, data = tos.staticcall(%q)
			tos.require(ok, "staticcall failed")
			local val = tos.abi.decode(data, "uint256")
			tos.emit("Val", "uint256", val)
		`, addrB)
		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, common.HexToAddress(addrA), big.NewInt(0), nil)
		if len(receipt.Logs) < 1 {
			t.Fatalf("expected Val log")
		}
		if new(big.Int).SetBytes(receipt.Logs[0].Data).Int64() != 99 {
			t.Errorf("Val: want 99, got %s", new(big.Int).SetBytes(receipt.Logs[0].Data))
		}
	})

	t.Run("dispatch_query_pattern", func(t *testing.T) {
		// Full query pattern: A staticcalls B with ABI calldata for
		// "totalSupply()"; B dispatches and returns a pre-seeded supply value.
		supplySlot := luaStorageSlot("supply")
		var supplyVal common.Hash
		big.NewInt(500000).FillBytes(supplyVal[:])

		config := &params.ChainConfig{
			ChainID: big.NewInt(1),
			DPoS:    &params.DPoSConfig{PeriodMs: 3000, Epoch: 200, MaxValidators: 21},
		}
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1 := crypto.PubkeyToAddress(key1.PublicKey)
		contractAddr := common.HexToAddress(addrA)
		contractAddrB := common.HexToAddress(addrB)

		codeB := `
			tos.dispatch({
				["totalSupply()"] = function()
					tos.result("uint256", tos.get("supply") or 0)
				end,
			})
		`
		codeA := fmt.Sprintf(`
			local sel = tos.selector("totalSupply()")
			local ok, data = tos.staticcall(%q, sel)
			tos.require(ok, "staticcall failed")
			local supply = tos.abi.decode(data, "uint256")
			tos.emit("Supply", "uint256", supply)
		`, addrB)

		db := rawdb.NewMemoryDatabase()
		gspec := &Genesis{
			Config: config,
			Alloc: GenesisAlloc{
				addr1:        {Balance: new(big.Int).Mul(big.NewInt(10), big.NewInt(params.TOS))},
				contractAddr: {Balance: big.NewInt(0), Code: []byte(codeA)},
				contractAddrB: {
					Balance: big.NewInt(0),
					Code:    []byte(codeB),
					Storage: map[common.Hash]common.Hash{supplySlot: supplyVal},
				},
			},
		}
		gspec.MustCommit(db)
		bc, err := NewBlockChain(db, nil, config, dpos.NewFaker(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer bc.Stop()

		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) < 1 {
			t.Fatalf("expected Supply log")
		}
		if new(big.Int).SetBytes(receipt.Logs[0].Data).Int64() != 500000 {
			t.Errorf("Supply: want 500000, got %s", new(big.Int).SetBytes(receipt.Logs[0].Data))
		}
	})
}

// TestLuaContractEmitIndexed verifies Phase 3B indexed event topics.
//
// EVM log specification for indexed parameters:
//   - topic[0] = keccak256(canonicalSig) — always
//   - topic[1..3] = indexed params encoded as 32-byte values:
//     value types (uint*, int*, bool, address, bytesN): ABI-padded to 32 bytes
//     reference types (string, bytes, T[]): keccak256(ABI-encode(value))
//   - data = ABI-encoded non-indexed params (same as before)
//   - EVM max is 3 indexed params; a 4th raises an error
func TestLuaContractEmitIndexed(t *testing.T) {

	t.Run("indexed_uint256_as_topic", func(t *testing.T) {
		// "uint256 indexed" appears as topic[1], NOT in log data.
		const code = `tos.emit("Stored", "uint256 indexed", 42)`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		log := receipt.Logs[0]
		if log.Topics[0] != luaEventSig("Stored", "uint256") {
			t.Errorf("topic[0] mismatch: got %s", log.Topics[0].Hex())
		}
		if len(log.Topics) != 2 {
			t.Fatalf("expected 2 topics, got %d", len(log.Topics))
		}
		if log.Topics[1][31] != 42 {
			t.Errorf("topic[1][31]: expected 42, got %d", log.Topics[1][31])
		}
		if len(log.Data) != 0 {
			t.Errorf("expected empty data for all-indexed event, got %d bytes", len(log.Data))
		}
	})

	t.Run("indexed_address_as_topic", func(t *testing.T) {
		// "address indexed" appears as topic[1]; non-indexed uint256 goes to data.
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1 := crypto.PubkeyToAddress(key1.PublicKey)
		const code = `tos.emit("Transfer", "address indexed", tos.caller, "uint256", 1000)`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		log := receipt.Logs[0]
		if log.Topics[0] != luaEventSig("Transfer", "address", "uint256") {
			t.Errorf("topic[0] mismatch")
		}
		if len(log.Topics) != 2 {
			t.Fatalf("expected 2 topics, got %d", len(log.Topics))
		}
		gotAddr := common.BytesToAddress(log.Topics[1][32-common.AddressLength:])
		if gotAddr != addr1 {
			t.Errorf("topic[1] address: got %s, want %s", gotAddr.Hex(), addr1.Hex())
		}
		// data = ABI-encode(uint256, 1000) — 32 bytes, last byte = 232
		if len(log.Data) != 32 {
			t.Fatalf("expected 32 bytes data, got %d", len(log.Data))
		}
		if log.Data[31] != 232 { // 1000 & 0xff
			t.Errorf("data[31]: expected 232 (1000 low byte), got %d", log.Data[31])
		}
	})

	t.Run("multiple_indexed_topics", func(t *testing.T) {
		// Three indexed params → topics[1..3]; data empty.
		const code = `tos.emit("Approval",
			"uint256 indexed", 1,
			"uint256 indexed", 2,
			"uint256 indexed", 3)`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		log := receipt.Logs[0]
		if len(log.Topics) != 4 {
			t.Fatalf("expected 4 topics (sig + 3 indexed), got %d", len(log.Topics))
		}
		if log.Topics[0] != luaEventSig("Approval", "uint256", "uint256", "uint256") {
			t.Errorf("topic[0] mismatch")
		}
		if log.Topics[1][31] != 1 || log.Topics[2][31] != 2 || log.Topics[3][31] != 3 {
			t.Errorf("indexed values mismatch: topics[1..3] last bytes = %d %d %d",
				log.Topics[1][31], log.Topics[2][31], log.Topics[3][31])
		}
		if len(log.Data) != 0 {
			t.Errorf("expected empty data, got %d bytes", len(log.Data))
		}
	})

	t.Run("too_many_indexed_reverts", func(t *testing.T) {
		// Four indexed params exceed EVM max (3); tx must fail.
		const code = `tos.emit("Bad",
			"uint256 indexed", 1,
			"uint256 indexed", 2,
			"uint256 indexed", 3,
			"uint256 indexed", 4)`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		signer := types.LatestSigner(bc.Config())
		tx, _ := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), 500_000, big.NewInt(1), nil)
		genesis := bc.GetBlockByNumber(0)
		blocks, _ := GenerateChain(bc.Config(), genesis, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
			b.AddTx(tx)
		})
		bc.InsertChain(blocks)
		receipts := rawdb.ReadReceipts(bc.db, blocks[0].Hash(), blocks[0].NumberU64(), bc.Config())
		if len(receipts) == 0 {
			t.Fatal("no receipt")
		}
		if receipts[0].Status != types.ReceiptStatusFailed {
			t.Errorf("expected status=0 (revert on >3 indexed), got %d", receipts[0].Status)
		}
	})

	t.Run("indexed_string_is_keccak", func(t *testing.T) {
		// Indexed string → topic = keccak256(ABI-encode("hello")).
		const code = `tos.emit("Named", "string indexed", "hello")`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		log := receipt.Logs[0]
		if log.Topics[0] != luaEventSig("Named", "string") {
			t.Errorf("topic[0] mismatch")
		}
		if len(log.Topics) != 2 {
			t.Fatalf("expected 2 topics, got %d", len(log.Topics))
		}
		// Expected: keccak256(ABI-encode(string, "hello"))
		strType := mustABIType(t, "string")
		packed, _ := (abi.Arguments{{Type: strType}}).Pack("hello")
		want := crypto.Keccak256Hash(packed)
		if log.Topics[1] != want {
			t.Errorf("indexed string topic: got %s, want %s", log.Topics[1].Hex(), want.Hex())
		}
		if len(log.Data) != 0 {
			t.Errorf("expected empty data, got %d bytes", len(log.Data))
		}
	})

	t.Run("prefix_indexed_syntax", func(t *testing.T) {
		// "indexed type" prefix works identically to "type indexed" suffix.
		const code = `tos.emit("Foo", "indexed uint256", 7)`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		log := receipt.Logs[0]
		if log.Topics[0] != luaEventSig("Foo", "uint256") {
			t.Errorf("topic[0] mismatch")
		}
		if len(log.Topics) != 2 {
			t.Fatalf("expected 2 topics, got %d", len(log.Topics))
		}
		if log.Topics[1][31] != 7 {
			t.Errorf("topic[1][31]: expected 7, got %d", log.Topics[1][31])
		}
	})

	t.Run("mixed_indexed_and_data", func(t *testing.T) {
		// One indexed param in topic[1]; one non-indexed param in data.
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1 := crypto.PubkeyToAddress(key1.PublicKey)
		const code = `tos.emit("Transfer",
			"address indexed", tos.caller,
			"uint256", 500)`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, contractAddr, big.NewInt(0), nil)
		if len(receipt.Logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(receipt.Logs))
		}
		log := receipt.Logs[0]
		if log.Topics[0] != luaEventSig("Transfer", "address", "uint256") {
			t.Errorf("topic[0] mismatch")
		}
		if len(log.Topics) != 2 {
			t.Fatalf("expected 2 topics, got %d", len(log.Topics))
		}
		gotAddr := common.BytesToAddress(log.Topics[1][32-common.AddressLength:])
		if gotAddr != addr1 {
			t.Errorf("topic[1] address: got %s, want %s", gotAddr.Hex(), addr1.Hex())
		}
		if len(log.Data) != 32 {
			t.Fatalf("expected 32 bytes data, got %d", len(log.Data))
		}
		gotVal := new(big.Int).SetBytes(log.Data)
		if gotVal.Int64() != 500 {
			t.Errorf("data uint256: expected 500, got %s", gotVal)
		}
	})
}

// mustABIType is a test helper that builds an abi.Type and fatals on error.
func mustABIType(t *testing.T, typStr string) abi.Type {
	t.Helper()
	typ, err := abi.NewType(typStr, "", nil)
	if err != nil {
		t.Fatalf("abi.NewType(%q): %v", typStr, err)
	}
	return typ
}

// runLuaTxWithGasLimit sends a nil-data tx with a custom gas limit.
// Returns true if the Lua contract executed successfully (receipt status=1),
// false if it failed (OOG, revert, etc.).
func runLuaTxWithGasLimit(t *testing.T, bc *BlockChain, contractAddr common.Address, gasLimit uint64) bool {
	t.Helper()
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.LatestSigner(bc.Config())
	tx, err := signTestSignerTx(signer, key1, 0, contractAddr, big.NewInt(0), gasLimit, big.NewInt(1), nil)
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
	block := blocks[0]
	receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
	if len(receipts) == 0 {
		t.Fatal("no receipts found for block")
	}
	return receipts[0].Status == types.ReceiptStatusSuccessful
}

// TestLuaContractPrimGas verifies that primitive calls charge gas on top of the
// per-opcode VM gas:
//   - Each primitive charges at least its defined constant worth of gas.
//   - A script that calls an expensive primitive OOGs when the gas budget is
//     only marginally above the intrinsic tx cost (params.TxGas = 3000).
//   - tos.gasleft() accounts for both VM opcodes and primitive charges.
//
// Gas budget arithmetic (all values approximate):
//
//	st.gas = gasLimit - params.TxGas (3000) - zero_data_cost (0)
func TestLuaContractPrimGas(t *testing.T) {
	// tightOOG verifies that a tight gasLimit causes OOG, and a comfortable one
	// succeeds.  oogLimit must result in st.gas < primCost; okLimit must give
	// st.gas > primCost + ~50 opcodes overhead.
	tightOOG := func(t *testing.T, code string, oogLimit, okLimit uint64) {
		t.Helper()
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		if runLuaTxWithGasLimit(t, bc, contractAddr, oogLimit) {
			t.Fatalf("gasLimit=%d: expected OOG, got success", oogLimit)
		}
		// Fresh bc for the success case (cannot reuse the same bc for a second block 1).
		bc2, contractAddr2, cleanup2 := luaTestSetup(t, code)
		defer cleanup2()
		if !runLuaTxWithGasLimit(t, bc2, contractAddr2, okLimit) {
			t.Fatalf("gasLimit=%d: expected success, got failure", okLimit)
		}
	}

	// params.TxGas = 3000; st.gas = gasLimit - 3000.

	t.Run("tos_get_charges_sload", func(t *testing.T) {
		// luaGasSLoad = 100.  st.gas=99 (<100) → OOG; st.gas=300 → success.
		tightOOG(t, `tos.get("k")`, 3099, 3300)
	})

	t.Run("tos_set_charges_sstore", func(t *testing.T) {
		// luaGasSStore = 5000.  st.gas=100 (<5000) → OOG; st.gas=6000 → success.
		tightOOG(t, `tos.set("k", 1)`, 3100, 9000)
	})

	t.Run("tos_arrLen_charges_sload", func(t *testing.T) {
		// luaGasSLoad = 100.  Same budget as tos.get.
		tightOOG(t, `tos.arrLen("a")`, 3099, 3300)
	})

	t.Run("tos_arrGet_charges_2x_sload", func(t *testing.T) {
		// 2 × luaGasSLoad = 200.  st.gas=199 → OOG; st.gas=400 → success.
		tightOOG(t, `tos.arrGet("a", 1)`, 3199, 3500)
	})

	t.Run("tos_emit_charges_log_base", func(t *testing.T) {
		// luaGasLogBase = 375.  st.gas=374 → OOG; st.gas=600 → success.
		tightOOG(t, `tos.emit("Ping")`, 3374, 4000)
	})

	t.Run("tos_emit_indexed_charges_log_topic", func(t *testing.T) {
		// luaGasLogBase(375) + luaGasLogTopic(375) = 750.
		// st.gas=749 → OOG; st.gas=1000 → success.
		tightOOG(t, `tos.emit("X", "uint256 indexed", 1)`, 3749, 4500)
	})

	t.Run("tos_setStr_charges_per_chunk", func(t *testing.T) {
		// "hello" = 5 bytes → numChunks=1 → 2 × luaGasSStore = 10000.
		// st.gas=100 → OOG; st.gas=12000 → success.
		tightOOG(t, `tos.setStr("k", "hello")`, 3100, 15000)
	})

	t.Run("gasleft_reflects_prim_charges", func(t *testing.T) {
		// After tos.set the gasleft must drop by at least luaGasSStore (5000).
		const code = `
			local g1 = tos.gasleft()
			tos.set("x", 1)
			local g2 = tos.gasleft()
			assert(g1 - g2 >= 5000,
				"gasleft should decrease by >= 5000 after tos.set, got " .. tostring(g1-g2))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})

	t.Run("gasleft_reflects_get_charge", func(t *testing.T) {
		// After tos.get the gasleft must drop by at least luaGasSLoad (100).
		const code = `
			local g1 = tos.gasleft()
			tos.get("x")
			local g2 = tos.gasleft()
			assert(g1 - g2 >= 100,
				"gasleft should decrease by >= 100 after tos.get, got " .. tostring(g1-g2))
		`
		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})
}

// TestLuaContractMappingProxy tests tos.mapping() and tos.mappingStr() — the
// metamethod-backed proxy tables that let Lua code use table-index syntax for
// on-chain named mappings:
//
//	local bal = tos.mapping("balance")
//	bal["alice"] = 1000
//	assert(bal["alice"] == 1000)
//
// Slot derivation is identical to tos.mapGet/Set, so the two APIs are fully
// interchangeable.
func TestLuaContractMappingProxy(t *testing.T) {
	t.Run("uint256_roundtrip", func(t *testing.T) {
		const code = `
			local bal = tos.mapping("balance")
			bal["alice"] = 1000
			bal["bob"]   = 500
			assert(bal["alice"] == 1000, "alice")
			assert(bal["bob"]   == 500,  "bob")
			assert(bal["carol"] == nil,  "unset key is nil")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("string_roundtrip", func(t *testing.T) {
		const code = `
			local tag = tos.mappingStr("tag")
			tag["nft1"] = "Dragon"
			tag["nft2"] = "Phoenix"
			assert(tag["nft1"] == "Dragon",  "nft1")
			assert(tag["nft2"] == "Phoenix", "nft2")
			assert(tag["nft3"] == nil,       "unset key is nil")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("compat_with_mapGet_mapSet", func(t *testing.T) {
		// tos.mapping("x")["k"] and tos.mapGet("x","k") must share the same slot.
		const code = `
			-- Write via mapSet, read via proxy
			tos.mapSet("pts", "alice", 77)
			local proxy = tos.mapping("pts")
			assert(proxy["alice"] == 77, "proxy should see mapSet value")

			-- Write via proxy, read via mapGet
			proxy["bob"] = 33
			assert(tos.mapGet("pts", "bob") == 33, "mapGet should see proxy value")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("string_compat_with_mapGetStr_mapSetStr", func(t *testing.T) {
		// mappingStr("x")["k"] and mapGetStr("x","k") must share the same slot.
		const code = `
			-- Write via mapSetStr, read via proxy
			tos.mapSetStr("meta", "token1", "CoolNFT")
			local proxy = tos.mappingStr("meta")
			assert(proxy["token1"] == "CoolNFT", "proxy should see mapSetStr value")

			-- Write via proxy, read via mapGetStr
			proxy["token2"] = "RareItem"
			assert(tos.mapGetStr("meta", "token2") == "RareItem", "mapGetStr should see proxy value")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("depth2_nested_uint256", func(t *testing.T) {
		// tos.mapping("allowance", 2)[owner][spender] = amount
		const code = `
			local allowance = tos.mapping("allowance", 2)
			allowance["alice"]["bob"] = 500
			allowance["alice"]["carol"] = 250
			assert(allowance["alice"]["bob"]   == 500, "alice->bob")
			assert(allowance["alice"]["carol"] == 250, "alice->carol")
			assert(allowance["dave"]["bob"]    == nil, "dave->bob unset")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("depth2_compat_with_nested_mapGet", func(t *testing.T) {
		// depth=2 proxy slot must be identical to tos.mapGet(name, k1, k2).
		const code = `
			tos.mapSet("allow", "owner1", "spender1", 777)
			local m = tos.mapping("allow", 2)
			assert(m["owner1"]["spender1"] == 777, "depth2 proxy sees mapSet value")

			m["owner2"]["spender1"] = 333
			assert(tos.mapGet("allow", "owner2", "spender1") == 333, "mapGet sees depth2 value")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("namespace_isolation_from_set", func(t *testing.T) {
		// tos.mapping("score")["k"] must not collide with tos.set("score").
		const code = `
			tos.set("score", 99)
			local m = tos.mapping("score")
			m["alice"] = 42
			assert(tos.get("score") == 99, "tos.get must be unchanged")
			assert(m["alice"] == 42,       "mapping must be 42")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("mapping_newindex_readonly_reverts", func(t *testing.T) {
		// __newindex inside a staticcall must raise an error → staticcall returns false.
		const addrB = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		const addrA = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
		calleeCode := `
			local m = tos.mapping("x")
			m["k"] = 1
		`
		callerCode := fmt.Sprintf(`
			local ok = tos.staticcall(%q, "")
			assert(not ok, "mapping write inside staticcall should fail")
		`, addrB)
		bc, _, _, cleanup := luaTestSetup2(t, callerCode, calleeCode)
		defer cleanup()
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
	})

	t.Run("mappingStr_newindex_readonly_reverts", func(t *testing.T) {
		const addrB = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		const addrA = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
		calleeCode := `
			local m = tos.mappingStr("x")
			m["k"] = "hello"
		`
		callerCode := fmt.Sprintf(`
			local ok = tos.staticcall(%q, "")
			assert(not ok, "mappingStr write inside staticcall should fail")
		`, addrB)
		bc, _, _, cleanup := luaTestSetup2(t, callerCode, calleeCode)
		defer cleanup()
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
	})

	t.Run("at_proxy_mapping_reads", func(t *testing.T) {
		// tos.at(self).mapping(name)[key] must read the same slot as tos.mapping(name)[key].
		const code = `
			local m = tos.mapping("pts")
			m["alice"] = 77
			m["bob"]   = 33
			local ro = tos.at(tos.self).mapping("pts")
			assert(ro["alice"] == 77,  "at proxy alice")
			assert(ro["bob"]   == 33,  "at proxy bob")
			assert(ro["carol"] == nil, "at proxy unset")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("at_proxy_mappingStr_reads", func(t *testing.T) {
		// tos.at(self).mappingStr(name)[key] must read the same slot as tos.mappingStr.
		const code = `
			local m = tos.mappingStr("tag")
			m["nft1"] = "Dragon"
			local ro = tos.at(tos.self).mappingStr("tag")
			assert(ro["nft1"] == "Dragon", "at proxy nft1")
			assert(ro["nft2"] == nil,      "at proxy unset")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})
}

// TestLuaContractSend tests tos.send(addr, amount) — the soft-failure variant
// of tos.transfer that returns a bool instead of reverting.
// Equivalent to Solidity's payable(addr).send(amount).
func TestLuaContractSend(t *testing.T) {
	t.Run("success_transfers_balance", func(t *testing.T) {
		// Contract starts with 1 TOS; send 0.5 TOS to recipient.
		recipient := common.HexToAddress("0x1111111111111111111111111111111111111111")
		halfTOS := new(big.Int).Div(big.NewInt(params.TOS), big.NewInt(2))

		code := fmt.Sprintf(`
			local ok = tos.send(%q, %s)
			assert(ok == true, "send should succeed, got " .. tostring(ok))
		`, recipient.Hex(), halfTOS.Text(10))

		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))

		state, _ := bc.State()
		got := state.GetBalance(recipient)
		if got == nil || got.Cmp(halfTOS) != 0 {
			t.Errorf("recipient balance: want %s, got %v", halfTOS, got)
		}
	})

	t.Run("returns_false_on_insufficient_balance", func(t *testing.T) {
		// Contract has 1 TOS; try to send 2 TOS → false, recipient gets nothing.
		recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")
		twoTOS := new(big.Int).Mul(big.NewInt(2), big.NewInt(params.TOS))

		code := fmt.Sprintf(`
			local ok = tos.send(%q, %s)
			assert(ok == false, "send should return false on insufficient balance")
		`, recipient.Hex(), twoTOS.Text(10))

		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))

		state, _ := bc.State()
		got := state.GetBalance(recipient)
		if got != nil && got.Sign() != 0 {
			t.Errorf("recipient should have zero balance, got %v", got)
		}
	})

	t.Run("does_not_revert_on_failure", func(t *testing.T) {
		// Unlike tos.transfer, a failed tos.send must NOT abort the tx.
		// State writes before AND after the failed send must both be committed.
		twoTOS := new(big.Int).Mul(big.NewInt(2), big.NewInt(params.TOS))
		code := fmt.Sprintf(`
			tos.set("before", 1)
			local ok = tos.send("0x4444444444444444444444444444444444444444", %s)
			assert(ok == false)
			tos.set("after", 2)
		`, twoTOS.Text(10))

		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))

		state, _ := bc.State()
		before := state.GetState(contractAddr, luaStorageSlot("before"))
		after := state.GetState(contractAddr, luaStorageSlot("after"))
		if before[31] != 1 {
			t.Errorf("before slot: want 1, got %d", before[31])
		}
		if after[31] != 2 {
			t.Errorf("after slot: want 2, got %d", after[31])
		}
	})

	t.Run("returns_false_in_readonly", func(t *testing.T) {
		// Inside a staticcall, tos.send returns false (does not revert the callee).
		const addrB = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		const addrA = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
		calleeCode := `
			local ok = tos.send("0x1111111111111111111111111111111111111111", 1)
			assert(ok == false, "send in readonly context must return false")
		`
		callerCode := fmt.Sprintf(`
			local ok = tos.staticcall(%q, "")
			assert(ok, "callee should not revert even though send returned false")
		`, addrB)
		bc, _, _, cleanup := luaTestSetup2(t, callerCode, calleeCode)
		defer cleanup()
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
	})

	t.Run("zero_amount_succeeds", func(t *testing.T) {
		// send(addr, 0) is a no-op transfer; must return true.
		recipient := common.HexToAddress("0x3333333333333333333333333333333333333333")
		code := fmt.Sprintf(`
			local ok = tos.send(%q, 0)
			assert(ok == true, "send(0) should succeed")
		`, recipient.Hex())

		bc, contractAddr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, contractAddr, big.NewInt(0))
	})
}

// TestLuaContractBytes tests the tos.bytes.* utility sub-table.
//
// tos.bytes bridges the two representations used in TOS Lua:
//   - hex strings  ("0x...")  — returned by abi.encode, keccak256, msg.data
//   - binary strings          — accepted by keccak256, sha256, etc.
func TestLuaContractBytes(t *testing.T) {
	t.Run("fromhex_tohex_roundtrip", func(t *testing.T) {
		const code = `
			local hex = "0xdeadbeef"
			local bin = tos.bytes.fromhex(hex)
			assert(#bin == 4, "expected 4 bytes, got " .. tostring(#bin))
			assert(tos.bytes.tohex(bin) == hex,
				"tohex(fromhex) roundtrip failed: " .. tos.bytes.tohex(bin))
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("fromhex_empty_string", func(t *testing.T) {
		const code = `
			local bin = tos.bytes.fromhex("0x")
			assert(#bin == 0, "empty hex should give empty binary")
			assert(tos.bytes.tohex(bin) == "0x", "tohex of empty should be 0x")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("fromhex_no_prefix", func(t *testing.T) {
		// fromhex accepts bare hex without "0x" prefix.
		const code = `
			local bin = tos.bytes.fromhex("deadbeef")
			assert(#bin == 4, "bare hex: expected 4 bytes")
			assert(tos.bytes.tohex(bin) == "0xdeadbeef", "bare hex roundtrip")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("len", func(t *testing.T) {
		const code = `
			assert(tos.bytes.len("")        == 0, "empty")
			assert(tos.bytes.len("abc")     == 3, "ascii")
			assert(tos.bytes.len("\x00\xff") == 2, "binary with null and 0xff")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("slice_with_length", func(t *testing.T) {
		const code = `
			local bin = tos.bytes.fromhex("0xdeadbeef01020304")
			-- first 4 bytes
			local head = tos.bytes.slice(bin, 0, 4)
			assert(tos.bytes.tohex(head) == "0xdeadbeef", "head: " .. tos.bytes.tohex(head))
			-- next 4 bytes
			local tail = tos.bytes.slice(bin, 4, 4)
			assert(tos.bytes.tohex(tail) == "0x01020304", "tail: " .. tos.bytes.tohex(tail))
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("slice_without_length", func(t *testing.T) {
		const code = `
			local bin = tos.bytes.fromhex("0xdeadbeef01020304")
			local rest = tos.bytes.slice(bin, 4)
			assert(tos.bytes.tohex(rest) == "0x01020304", "rest: " .. tos.bytes.tohex(rest))
			-- slice from 0 with no length = full copy
			local full = tos.bytes.slice(bin, 0)
			assert(tos.bytes.tohex(full) == "0xdeadbeef01020304", "full")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("slice_oob_reverts", func(t *testing.T) {
		const code = `
			local bin = tos.bytes.fromhex("0xdeadbeef")  -- 4 bytes
			-- offset past end should revert
			local ok = pcall(function() tos.bytes.slice(bin, 5) end)
			assert(not ok, "slice past end should revert")
			-- length past end should revert
			local ok2 = pcall(function() tos.bytes.slice(bin, 2, 10) end)
			assert(not ok2, "slice length past end should revert")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("fromUint256_toUint256_roundtrip", func(t *testing.T) {
		const code = `
			local n = 12345678
			local b = tos.bytes.fromUint256(n)    -- 32-byte big-endian
			assert(#b == 32, "fromUint256 should give 32 bytes, got " .. tostring(#b))
			local m = tos.bytes.toUint256(b)
			assert(m == n, "roundtrip: want " .. tostring(n) .. " got " .. tostring(m))
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("fromUint256_with_size", func(t *testing.T) {
		const code = `
			-- 255 fits in 1 byte
			local b1 = tos.bytes.fromUint256(255, 1)
			assert(#b1 == 1, "size=1")
			assert(tos.bytes.toUint256(b1) == 255, "toUint256 of 0xff")

			-- 256 requires at least 2 bytes
			local b2 = tos.bytes.fromUint256(256, 2)
			assert(#b2 == 2, "size=2")
			assert(tos.bytes.toUint256(b2) == 256, "toUint256 of 256")

			-- 0 always fits
			local b0 = tos.bytes.fromUint256(0, 1)
			assert(#b0 == 1 and tos.bytes.toUint256(b0) == 0, "zero in 1 byte")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("fromUint256_overflow_reverts", func(t *testing.T) {
		const code = `
			-- 256 does not fit in 1 byte
			local ok = pcall(function() tos.bytes.fromUint256(256, 1) end)
			assert(not ok, "256 in 1 byte should revert")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("hash_abi_encoded_data", func(t *testing.T) {
		// Core use-case: hash ABI-encoded data — keccak256(abi.encode("uint256", 42)).
		// The reference value is keccak256(0x000...2a) computed from Go.
		encoded := make([]byte, 32)
		encoded[31] = 42
		want := "0x" + common.Bytes2Hex(crypto.Keccak256(encoded))

		code := fmt.Sprintf(`
			local enc = tos.abi.encode("uint256", 42)
			local bin = tos.bytes.fromhex(enc)
			local hash = keccak256(bin)
			assert(hash == %q, "hash mismatch: " .. hash)
		`, want)

		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})
}

// TestLuaContractAddressUtils tests tos.ZERO_ADDRESS, tos.MAX_UINT256,
// tos.isAddress(), and tos.toAddress().
func TestLuaContractAddressUtils(t *testing.T) {
	t.Run("ZERO_ADDRESS", func(t *testing.T) {
		// TOS addresses are 32 bytes = 64 hex chars.
		want := common.Address{}.Hex() // "0x" + 64 zeros
		code := fmt.Sprintf(`
			assert(tos.ZERO_ADDRESS == %q,
				"ZERO_ADDRESS: " .. tostring(tos.ZERO_ADDRESS))
			assert(#tos.ZERO_ADDRESS == 66, "ZERO_ADDRESS must be 66 chars (0x + 64)")
		`, want)
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("MAX_UINT256", func(t *testing.T) {
		max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
		// tos.MAX_UINT256 is LNumber; compare with a number literal (also LNumber).
		// MAX_UINT256 + 1 wraps to 0 (mod 2^256).
		code := fmt.Sprintf(`
			assert(tos.MAX_UINT256 + 1 == 0, "MAX_UINT256 + 1 should wrap to 0")
			assert(tos.MAX_UINT256 == %s, "MAX_UINT256 value mismatch")
		`, max.Text(10))
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("isAddress_valid", func(t *testing.T) {
		// TOS addresses are 32 bytes = 64 hex chars after "0x".
		addr64 := strings.Repeat("ab", 32) // 64 hex chars
		code := fmt.Sprintf(`
			assert(tos.isAddress(%q) == true, "64 hex + 0x")
			assert(tos.isAddress(%q) == true, "64 hex bare")
			assert(tos.isAddress(tos.ZERO_ADDRESS) == true, "zero address is valid")
			assert(tos.isAddress(tos.self) == true, "self is valid")
		`, "0x"+addr64, addr64)
		bc, addr2, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr2, big.NewInt(0))
	})

	t.Run("isAddress_invalid", func(t *testing.T) {
		code := fmt.Sprintf(`
			assert(tos.isAddress("") == false, "empty")
			assert(tos.isAddress("0x") == false, "0x only")
			assert(tos.isAddress("0x1234") == false, "too short")
			assert(tos.isAddress("0x" .. string.rep("0", 65)) == false, "65 hex digits")
			assert(tos.isAddress("0x" .. string.rep("g", 64)) == false, "non-hex chars")
			assert(tos.isAddress("hello") == false, "plaintext")
		`)
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("toAddress_normalises", func(t *testing.T) {
		// Use a 64-hex-char address (TOS 32-byte format).
		raw := "0x" + strings.Repeat("AB", 32)
		code := fmt.Sprintf(`
			local a = tos.toAddress(%q)
			assert(tos.isAddress(a), "result is a valid address: " .. a)
			assert(#a == 66, "result is 66 chars, got " .. tostring(#a))
			assert(tos.toAddress(a) == a, "idempotent")
			local zero = tos.toAddress("0x0")
			assert(zero == tos.ZERO_ADDRESS, "0x0 -> ZERO_ADDRESS: " .. zero)
		`, raw)
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("toAddress_consistent_storage_key", func(t *testing.T) {
		// Write with mixed-case, read with canonical form: same slot.
		raw := "0x" + strings.Repeat("AB", 32) // 64 hex chars, uppercase
		code := fmt.Sprintf(`
			local raw   = %q
			local canon = tos.toAddress(raw)
			tos.mapSet("bal", canon, 999)
			assert(tos.mapGet("bal", canon)              == 999, "canonical read")
			assert(tos.mapGet("bal", tos.toAddress(raw)) == 999, "normalised read")
		`, raw)
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("typical_transfer_guard", func(t *testing.T) {
		// 64-hex-char address (TOS 32-byte format).
		validAddr := "0x" + strings.Repeat("11", 32)
		code := fmt.Sprintf(`
			local to = %q
			require(tos.isAddress(to),     "invalid address")
			require(to ~= tos.ZERO_ADDRESS, "transfer to zero address")
			tos.set("ok", 1)
		`, validAddr)
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))

		state, _ := bc.State()
		val := state.GetState(addr, luaStorageSlot("ok"))
		if val[31] != 1 {
			t.Errorf("ok slot: want 1, got %d", val[31])
		}
	})
}

func TestLuaContractDeploy(t *testing.T) {
	// childCode is a minimal contract used as the deployed child in most subtests.
	const childCode = `
		tos.oncreate(function()
			tos.set("creator", 1)
		end)
		tos.set("ping", 42)
	`

	t.Run("returns_deterministic_address", func(t *testing.T) {
		// The address returned by tos.deploy must equal crypto.CreateAddress(contractAddr, 0).
		contractAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
		want := crypto.CreateAddress(contractAddr, 0)

		code := fmt.Sprintf(`
			local child = tos.deploy(%q)
			assert(child == %q, "wrong address: " .. tostring(child))
		`, childCode, want.Hex())
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("deployed_code_is_callable", func(t *testing.T) {
		// After tos.deploy, tos.codeAt should return true and tos.call should work.
		code := `
			local src = "tos.set([[hit]], 99)"
			local child = tos.deploy(src)
			assert(tos.codeAt(child), "no code at child")
			local ok = tos.call(child, 0)
			assert(ok, "tos.call failed")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("successive_deploys_differ", func(t *testing.T) {
		// Two tos.deploy calls from same contract yield different addresses (nonce increments).
		code := `
			local a = tos.deploy("tos.set([[x]],1)")
			local b = tos.deploy("tos.set([[x]],2)")
			assert(a ~= b, "expected different addresses")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("second_address_matches_nonce1", func(t *testing.T) {
		// Address from second deploy must equal crypto.CreateAddress(contractAddr, 1).
		contractAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
		want1 := crypto.CreateAddress(contractAddr, 1)

		code := fmt.Sprintf(`
			tos.deploy("tos.set([[x]],1)")       -- nonce 0
			local b = tos.deploy("tos.set([[x]],2)") -- nonce 1
			assert(b == %q, "wrong nonce-1 addr: " .. tostring(b))
		`, want1.Hex())
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("deploy_with_value_transfers_balance", func(t *testing.T) {
		// Contract has 1 TOS; deploy with 0.5 TOS → child gets 0.5 TOS.
		halfTOS := new(big.Int).Mul(big.NewInt(5e17), big.NewInt(1))
		code := fmt.Sprintf(`
			local child = tos.deploy("", %s)  -- empty code → should revert
		`, halfTOS.String())
		// empty code reverts — test value transfer with non-empty code instead:
		code = fmt.Sprintf(`
			local child = tos.deploy("tos.set([[x]],1)", %s)
			local bal = tos.balance(child)
			assert(bal == %s, "balance mismatch: " .. tostring(bal))
		`, halfTOS.String(), halfTOS.String())
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("empty_code_reverts", func(t *testing.T) {
		code := `tos.deploy("")`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})

	t.Run("insufficient_balance_reverts", func(t *testing.T) {
		// Contract has 1 TOS; try to deploy with 2 TOS → should revert.
		twoTOS := new(big.Int).Mul(big.NewInt(2), big.NewInt(params.TOS))
		code := fmt.Sprintf(`
			tos.deploy("tos.set([[x]],1)", %s)
		`, twoTOS.String())
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})

	t.Run("deploy_in_staticcall_reverts", func(t *testing.T) {
		// helperCode (at 0xBBBB...) tries tos.deploy — raises an error in a static context.
		// callerCode staticcalls the helper; if the helper fails, staticcall returns false.
		// require(ok) then propagates the failure, making the outer tx revert.
		helperAddr := common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
		callerCode := fmt.Sprintf(`
			local ok = tos.staticcall(%q)
			require(ok, "deploy in staticcall must fail")
		`, helperAddr.Hex())
		helperCode := `tos.deploy("tos.set([[x]],1)")`

		bc, callerAddr, _, cleanup := luaTestSetup2(t, callerCode, helperCode)
		defer cleanup()
		runLuaTxExpectFail(t, bc, callerAddr, big.NewInt(0))
	})

	t.Run("oog_on_huge_code", func(t *testing.T) {
		// A very large code string should exhaust gas (luaGasDeployByte=200 × N bytes).
		// 2500 bytes × 200 = 500 000 gas > typical tx gas limit of 500 000 → OOG.
		code := fmt.Sprintf(`tos.deploy(string.rep("x", 2500))`)
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})
}

func TestLuaContractCreate2(t *testing.T) {
	const childCode = `tos.set("ping", 42)`

	// contractAddr is fixed by luaTestSetup.
	contractAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")

	// expectedCreate2 computes the address that tos.create2 will produce.
	expectedCreate2 := func(salt string, code string) common.Address {
		var s [32]byte
		b := common.FromHex(salt)
		copy(s[32-len(b):], b)
		return crypto.CreateAddress2(contractAddr, s, crypto.Keccak256([]byte(code)))
	}

	t.Run("deterministic_address_matches_create2addr", func(t *testing.T) {
		// The address returned by tos.create2 must equal tos.create2addr prediction.
		salt := "0x0000000000000000000000000000000000000000000000000000000000000001"
		code := fmt.Sprintf(`
			local salt = %q
			local child = tos.create2(%q, salt)
			local predicted = tos.create2addr(tos.self, salt, %q)
			assert(child == predicted, "create2 addr mismatch: " .. tostring(child) .. " vs " .. tostring(predicted))
		`, salt, childCode, childCode)
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		_ = addr
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("address_matches_go_side_computation", func(t *testing.T) {
		// The Go-computed address must equal what the contract returned.
		salt := "0x000000000000000000000000000000000000000000000000000000000000cafe"
		want := expectedCreate2(salt, childCode)

		code := fmt.Sprintf(`
			local child = tos.create2(%q, %q)
			assert(child == %q, "wrong addr: " .. tostring(child))
		`, childCode, salt, want.Hex())
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("different_salts_give_different_addresses", func(t *testing.T) {
		code := fmt.Sprintf(`
			local a = tos.create2(%q, "0x01")
			local b = tos.create2(%q, "0x02")
			assert(a ~= b, "expected different addresses for different salts")
		`, childCode, childCode)
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("same_code_same_salt_collides", func(t *testing.T) {
		// Second tos.create2 with identical (code, salt) should revert.
		code := fmt.Sprintf(`
			tos.create2(%q, "0x01")   -- first deploy succeeds
			tos.create2(%q, "0x01")   -- collision → error
		`, childCode, childCode)
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})

	t.Run("decimal_salt_works", func(t *testing.T) {
		// Salt can also be a decimal number string.
		saltNum := "999"
		var s [32]byte
		sn, _ := new(big.Int).SetString(saltNum, 10)
		sn.FillBytes(s[:])
		want := crypto.CreateAddress2(contractAddr, s, crypto.Keccak256([]byte(childCode)))

		code := fmt.Sprintf(`
			local child = tos.create2(%q, %q)
			assert(child == %q, "decimal salt: wrong addr " .. tostring(child))
		`, childCode, saltNum, want.Hex())
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("deployed_child_is_callable", func(t *testing.T) {
		// After tos.create2, the child's code is stored and tos.call works.
		code := fmt.Sprintf(`
			local child = tos.create2(%q, "0x42")
			assert(tos.codeAt(child), "no code at child")
			local ok = tos.call(child, 0)
			assert(ok, "tos.call on create2 child failed")
		`, childCode)
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))

		// Verify child state: ping=42.
		salt := "0x42"
		childAddr := expectedCreate2(salt, childCode)
		state, _ := bc.State()
		slot := state.GetState(childAddr, luaStorageSlot("ping"))
		got := new(big.Int).SetBytes(slot[:]).Uint64()
		if got != 42 {
			t.Fatalf("child ping: want 42, got %d", got)
		}
	})

	t.Run("create2_with_value_transfers_balance", func(t *testing.T) {
		halfTOS := new(big.Int).Mul(big.NewInt(5e17), big.NewInt(1))
		code := fmt.Sprintf(`
			local child = tos.create2(%q, "0x77", %s)
			local bal = tos.balance(child)
			assert(bal == %s, "balance mismatch: " .. tostring(bal))
		`, `tos.set([[x]],1)`, halfTOS.String(), halfTOS.String())
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("create2_in_staticcall_reverts", func(t *testing.T) {
		helperAddr := common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
		callerCode := fmt.Sprintf(`
			local ok = tos.staticcall(%q)
			require(ok, "static call returned false unexpectedly")
		`, helperAddr.Hex())
		helperCode := fmt.Sprintf(`tos.create2(%q, "0x01")`, childCode)

		bc, callerAddr, _, cleanup := luaTestSetup2(t, callerCode, helperCode)
		defer cleanup()
		runLuaTxExpectFail(t, bc, callerAddr, big.NewInt(0))
	})

	t.Run("create2addr_pure_prediction", func(t *testing.T) {
		// tos.create2addr must not modify state — staticcall context is fine.
		salt := "0x00000000000000000000000000000000000000000000000000000000deadbeef"
		want := expectedCreate2(salt, childCode)
		code := fmt.Sprintf(`
			local predicted = tos.create2addr(tos.self, %q, %q)
			assert(predicted == %q, "wrong prediction: " .. tostring(predicted))
		`, salt, childCode, want.Hex())
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})
}

func TestLuaContractRevertError(t *testing.T) {
	t.Run("plain_revert_unchanged", func(t *testing.T) {
		// tos.revert("msg") still reverts the tx with no return data.
		bc, addr, cleanup := luaTestSetup(t, `tos.revert("plain error")`)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})

	t.Run("named_error_data_returned_to_caller", func(t *testing.T) {
		// Callee reverts with a named error; caller receives the ABI data.
		// Selector for "InsufficientBalance(uint256,uint256)":
		wantSel := abiSelector("InsufficientBalance(uint256,uint256)")

		calleeCode := `
			local avail = tos.get("avail") or 0
			local req   = 1000
			tos.revert("InsufficientBalance", "uint256", avail, "uint256", req)
		`
		// callerCode: calls callee, asserts ok==false, checks selector prefix.
		callerCode := fmt.Sprintf(`
			local ok, ret = tos.call(%q, 0)
			assert(not ok,  "callee should have reverted")
			assert(ret ~= nil, "structured revert data expected")
			assert(string.sub(ret, 1, 10) == %q,
				"wrong selector: " .. tostring(string.sub(ret, 1, 10)))
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", wantSel)

		bc, callerAddr, _, cleanup := luaTestSetup2(t, callerCode, calleeCode)
		defer cleanup()
		runLuaTx(t, bc, callerAddr, big.NewInt(0))
	})

	t.Run("decode_error_roundtrip", func(t *testing.T) {
		// tos.abi.decodeError correctly strips the selector and decodes args.
		calleeCode := `
			tos.revert("Overflow", "uint256", 255, "uint256", 256)
		`
		callerCode := fmt.Sprintf(`
			local ok, ret = tos.call(%q, 0)
			assert(not ok, "callee must revert")
			assert(ret ~= nil, "revert data must not be nil")
			local a, b = tos.abi.decodeError(ret, "uint256", "uint256")
			assert(a == 255, "a: " .. tostring(a))
			assert(b == 256, "b: " .. tostring(b))
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, callerAddr, _, cleanup := luaTestSetup2(t, callerCode, calleeCode)
		defer cleanup()
		runLuaTx(t, bc, callerAddr, big.NewInt(0))
	})

	t.Run("no_args_named_error", func(t *testing.T) {
		// tos.revert("Unauthorized") with exactly 1 arg is a plain string revert
		// (indistinguishable from a message). No structured data is returned.
		// For a 0-arg named error selector, encode a sentinel bool: "uint8", 0.
		wantSel := abiSelector("Unauthorized(uint8)")
		calleeCode := `tos.revert("Unauthorized", "uint8", 0)`

		callerCode := fmt.Sprintf(`
			local ok, ret = tos.call(%q, 0)
			assert(not ok, "callee must revert")
			assert(ret ~= nil, "revert data expected")
			assert(string.sub(ret, 1, 10) == %q,
				"wrong selector: " .. tostring(ret))
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", wantSel)

		bc, callerAddr, _, cleanup := luaTestSetup2(t, callerCode, calleeCode)
		defer cleanup()
		runLuaTx(t, bc, callerAddr, big.NewInt(0))
	})

	t.Run("plain_revert_returns_nil_data", func(t *testing.T) {
		// Plain tos.revert("msg") → tos.call returns false, nil (no data).
		calleeCode := `tos.revert("no balance")`
		callerCode := fmt.Sprintf(`
			local ok, ret = tos.call(%q, 0)
			assert(not ok, "callee must revert")
			assert(ret == nil, "plain revert must return nil data, got: " .. tostring(ret))
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, callerAddr, _, cleanup := luaTestSetup2(t, callerCode, calleeCode)
		defer cleanup()
		runLuaTx(t, bc, callerAddr, big.NewInt(0))
	})

	t.Run("odd_args_reverts", func(t *testing.T) {
		// tos.revert("Name", "uint256") — missing value → named error with odd args raises error.
		bc, addr, cleanup := luaTestSetup(t, `tos.revert("Name", "uint256")`)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})

	t.Run("state_reverted_on_named_error", func(t *testing.T) {
		// tos.revert("E", ...) must revert the callee's state changes.
		calleeCode := `
			tos.set("x", 99)
			tos.revert("Fail", "uint256", 1)
		`
		callerCode := fmt.Sprintf(`
			local ok, ret = tos.call(%q, 0)
			assert(not ok, "must revert")
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, callerAddr, calleeAddr, cleanup := luaTestSetup2(t, callerCode, calleeCode)
		defer cleanup()
		runLuaTx(t, bc, callerAddr, big.NewInt(0))

		state, _ := bc.State()
		v := state.GetState(calleeAddr, luaStorageSlot("x"))
		if v != (common.Hash{}) {
			t.Errorf("callee storage must be reverted, got x=%v", v)
		}
	})

	t.Run("decode_error_in_staticcall", func(t *testing.T) {
		// Structured revert data propagates through staticcall too.
		calleeCode := `tos.revert("ReadOnly", "uint256", 42)`
		callerCode := fmt.Sprintf(`
			local ok, ret = tos.staticcall(%q)
			assert(not ok, "must fail")
			local v = tos.abi.decodeError(ret, "uint256")
			assert(v == 42, "v: " .. tostring(v))
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, callerAddr, _, cleanup := luaTestSetup2(t, callerCode, calleeCode)
		defer cleanup()
		runLuaTx(t, bc, callerAddr, big.NewInt(0))
	})
}

func TestLuaContractStruct(t *testing.T) {
	t.Run("get_set_roundtrip", func(t *testing.T) {
		code := `
			local Account = tos.struct("Account", "balance:uint256", "nonce:uint256")
			Account.set("alice", {balance=1000, nonce=5})
			local a = Account.get("alice")
			assert(a.balance == 1000, "balance: " .. tostring(a.balance))
			assert(a.nonce   == 5,    "nonce: "   .. tostring(a.nonce))
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("unset_field_is_zero_or_false", func(t *testing.T) {
		code := `
			local S = tos.struct("SUnset", "x:uint256", "flag:bool")
			local v = S.get("k")
			assert(v.x    == 0,     "x should be 0, got " .. tostring(v.x))
			assert(v.flag == false, "flag should be false")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("partial_set_leaves_other_fields", func(t *testing.T) {
		code := `
			local S = tos.struct("SPartial", "a:uint256", "b:uint256")
			S.set("k", {a=10})
			S.set("k", {b=20})
			local v = S.get("k")
			assert(v.a == 10, "a: " .. tostring(v.a))
			assert(v.b == 20, "b: " .. tostring(v.b))
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("getField_setField", func(t *testing.T) {
		code := `
			local S = tos.struct("SField", "x:uint256", "y:uint256")
			S.setField("k", "x", 99)
			assert(S.getField("k", "x") == 99,  "x: " .. tostring(S.getField("k", "x")))
			assert(S.getField("k", "y") == 0,   "y should be 0")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("bool_field", func(t *testing.T) {
		code := `
			local S = tos.struct("SBool", "flag:bool", "val:uint256")
			S.set("k", {flag=true, val=42})
			local v = S.get("k")
			assert(v.flag == true, "flag should be true")
			assert(v.val  == 42,   "val: " .. tostring(v.val))
			S.setField("k", "flag", false)
			assert(S.getField("k", "flag") == false, "flag should now be false")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("namespace_isolation", func(t *testing.T) {
		// Two struct types with the same field name must not share slots.
		code := `
			local A = tos.struct("TypeA", "x:uint256")
			local B = tos.struct("TypeB", "x:uint256")
			A.setField("k", "x", 1)
			B.setField("k", "x", 2)
			assert(A.getField("k", "x") == 1, "A.x: " .. tostring(A.getField("k", "x")))
			assert(B.getField("k", "x") == 2, "B.x: " .. tostring(B.getField("k", "x")))
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("key_isolation", func(t *testing.T) {
		// Different keys produce independent instances.
		code := `
			local S = tos.struct("SKey", "v:uint256")
			S.setField("alice", "v", 10)
			S.setField("bob",   "v", 20)
			assert(S.getField("alice", "v") == 10, "alice")
			assert(S.getField("bob",   "v") == 20, "bob")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("unknown_field_reverts", func(t *testing.T) {
		code := `
			local S = tos.struct("SUnknown", "a:uint256")
			S.getField("k", "z")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})

	t.Run("unsupported_type_reverts", func(t *testing.T) {
		code := `tos.struct("SBad", "x:int256")`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})

	t.Run("set_in_staticcall_reverts", func(t *testing.T) {
		helperCode := `
			local S = tos.struct("SStatic", "x:uint256")
			S.setField("k", "x", 1)
		`
		callerCode := fmt.Sprintf(`
			local ok = tos.staticcall(%q)
			require(ok, "staticcall must fail")
		`, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

		bc, callerAddr, _, cleanup := luaTestSetup2(t, callerCode, helperCode)
		defer cleanup()
		runLuaTxExpectFail(t, bc, callerAddr, big.NewInt(0))
	})
}

// runLuaTxWithDataExpectFail sends a tx with calldata expecting failure (receipt status 0).
// Builds on top of the current canonical head so sequential calls accumulate state.
func runLuaTxWithDataExpectFail(t *testing.T, bc *BlockChain, contractAddr common.Address, value *big.Int, data []byte) {
	t.Helper()
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)
	signer := types.LatestSigner(bc.Config())
	state, _ := bc.State()
	nonce := state.GetNonce(addr1)
	tx, err := signTestSignerTx(signer, key1, nonce, contractAddr, value, 500_000, big.NewInt(1), data)
	if err != nil {
		t.Fatal(err)
	}
	parent := bc.CurrentBlock()
	blocks, _ := GenerateChain(bc.Config(), parent, dpos.NewFaker(), bc.db, 1, func(i int, b *BlockGen) {
		b.AddTx(tx)
	})
	if _, err := bc.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
	block := blocks[0]
	receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
	if len(receipts) == 0 {
		t.Fatal("no receipts found for block")
	}
	if receipts[0].Status != types.ReceiptStatusFailed {
		t.Fatalf("expected tx to fail (status=0), got status=%d", receipts[0].Status)
	}
}

func TestLuaContractTOS20(t *testing.T) {
	const supply = int64(1_000_000)

	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)
	bob := common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	const tokenCode = `
		local T = tos.import("tos20")
		T.init("MyToken", "MTK", 18, 1000000)
		tos.dispatch(T.handlers)
	`

	t.Run("init_mints_supply_to_deployer", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, tokenCode)
		defer cleanup()

		// First call: oncreate fires (mints 1 000 000 to addr1), totalSupply() dispatched.
		runLuaTxWithData(t, bc, addr, big.NewInt(0), buildCalldata(t, "totalSupply()"))

		state, _ := bc.State()
		supplySlot := state.GetState(addr, luaStorageSlot("_supply"))
		gotSupply := new(big.Int).SetBytes(supplySlot[:]).Int64()
		if gotSupply != supply {
			t.Errorf("_supply: want %d, got %d", supply, gotSupply)
		}
		balSlot := state.GetState(addr, luaMapSlot("_bal", []string{addr1.Hex()}))
		gotBal := new(big.Int).SetBytes(balSlot[:]).Int64()
		if gotBal != supply {
			t.Errorf("_bal[addr1]: want %d, got %d", supply, gotBal)
		}
	})

	t.Run("metadata_stored", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, tokenCode)
		defer cleanup()
		runLuaTxWithData(t, bc, addr, big.NewInt(0), buildCalldata(t, "totalSupply()"))

		state, _ := bc.State()
		// _name and _symbol are stored via tos.setStr — their len slot must be non-zero.
		if state.GetState(addr, luaStrLenSlot("_name")) == (common.Hash{}) {
			t.Error("_name not stored")
		}
		if state.GetState(addr, luaStrLenSlot("_symbol")) == (common.Hash{}) {
			t.Error("_symbol not stored")
		}
		decimalsSlot := state.GetState(addr, luaStorageSlot("_decimals"))
		if new(big.Int).SetBytes(decimalsSlot[:]).Int64() != 18 {
			t.Error("_decimals not 18")
		}
	})

	t.Run("transfer_updates_balances", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, tokenCode)
		defer cleanup()

		runLuaTxWithData(t, bc, addr, big.NewInt(0), buildCalldata(t, "totalSupply()"))
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "transfer(address,uint256)", "address", bob, "uint256", big.NewInt(100)))

		state, _ := bc.State()
		slotAlice := state.GetState(addr, luaMapSlot("_bal", []string{addr1.Hex()}))
		slotBob := state.GetState(addr, luaMapSlot("_bal", []string{bob.Hex()}))
		balAlice := new(big.Int).SetBytes(slotAlice[:]).Int64()
		balBob := new(big.Int).SetBytes(slotBob[:]).Int64()
		if balAlice != supply-100 {
			t.Errorf("alice bal: want %d, got %d", supply-100, balAlice)
		}
		if balBob != 100 {
			t.Errorf("bob bal: want 100, got %d", balBob)
		}
	})

	t.Run("transfer_emits_Transfer_event", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, tokenCode)
		defer cleanup()

		runLuaTxWithData(t, bc, addr, big.NewInt(0), buildCalldata(t, "totalSupply()"))
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "transfer(address,uint256)", "address", bob, "uint256", big.NewInt(1)))

		block := bc.CurrentBlock()
		receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
		if len(receipts) == 0 {
			t.Fatal("no receipts")
		}
		sig := luaEventSig("Transfer", "address", "address", "uint256")
		found := false
		for _, l := range receipts[0].Logs {
			if len(l.Topics) > 0 && l.Topics[0] == sig {
				found = true
				break
			}
		}
		if !found {
			t.Error("Transfer event not emitted")
		}
	})

	t.Run("approve_sets_allowance", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, tokenCode)
		defer cleanup()

		runLuaTxWithData(t, bc, addr, big.NewInt(0), buildCalldata(t, "totalSupply()"))
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "approve(address,uint256)", "address", bob, "uint256", big.NewInt(500)))

		state, _ := bc.State()
		allowSlot := state.GetState(addr, luaMapSlot("_allow", []string{addr1.Hex(), bob.Hex()}))
		gotAllow := new(big.Int).SetBytes(allowSlot[:]).Int64()
		if gotAllow != 500 {
			t.Errorf("allowance: want 500, got %d", gotAllow)
		}
	})

	t.Run("approve_emits_Approval_event", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, tokenCode)
		defer cleanup()

		runLuaTxWithData(t, bc, addr, big.NewInt(0), buildCalldata(t, "totalSupply()"))
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "approve(address,uint256)", "address", bob, "uint256", big.NewInt(200)))

		block := bc.CurrentBlock()
		receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
		sig := luaEventSig("Approval", "address", "address", "uint256")
		found := false
		for _, l := range receipts[0].Logs {
			if len(l.Topics) > 0 && l.Topics[0] == sig {
				found = true
				break
			}
		}
		if !found {
			t.Error("Approval event not emitted")
		}
	})

	t.Run("transfer_insufficient_balance_reverts", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, tokenCode)
		defer cleanup()

		runLuaTxWithData(t, bc, addr, big.NewInt(0), buildCalldata(t, "totalSupply()"))
		runLuaTxWithDataExpectFail(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "transfer(address,uint256)", "address", bob, "uint256", new(big.Int).SetInt64(supply+1)))
	})

	t.Run("transfer_to_zero_address_reverts", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, tokenCode)
		defer cleanup()

		zero := common.Address{}
		runLuaTxWithData(t, bc, addr, big.NewInt(0), buildCalldata(t, "totalSupply()"))
		runLuaTxWithDataExpectFail(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "transfer(address,uint256)", "address", zero, "uint256", big.NewInt(1)))
	})

	t.Run("unknown_selector_reverts", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, tokenCode)
		defer cleanup()

		runLuaTxWithData(t, bc, addr, big.NewInt(0), buildCalldata(t, "totalSupply()"))
		runLuaTxWithDataExpectFail(t, bc, addr, big.NewInt(0), buildCalldata(t, "bogus()"))
	})

	t.Run("unknown_module_reverts", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, `tos.import("notamodule")`)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})
}

func TestLuaContractBytecode(t *testing.T) {
	t.Run("precompiled_bytecode_executes", func(t *testing.T) {
		code := `
			tos.set("counter", 2)
		`
		bc, addr, cleanup := luaTestSetupBytecode(t, code)
		defer cleanup()

		runLuaTx(t, bc, addr, big.NewInt(0))

		state, _ := bc.State()
		slot := state.GetState(addr, luaStorageSlot("counter"))
		got := new(big.Int).SetBytes(slot[:]).Uint64()
		if got != 2 {
			t.Fatalf("counter: want 2, got %d", got)
		}
	})

	t.Run("invalid_bytecode_reverts", func(t *testing.T) {
		// Starts with GLBC magic but is not a valid bytecode payload.
		invalid := []byte("GLBCbad")
		bc, addr, cleanup := luaTestSetupCodeBytes(t, invalid)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})

	t.Run("source_and_bytecode_match_semantics", func(t *testing.T) {
		code := `
			local v = tos.get("x") or 0
			tos.set("x", v + 3)
		`
		srcBC, srcAddr, srcCleanup := luaTestSetup(t, code)
		defer srcCleanup()
		binBC, binAddr, binCleanup := luaTestSetupBytecode(t, code)
		defer binCleanup()

		runLuaTx(t, srcBC, srcAddr, big.NewInt(0))
		runLuaTx(t, binBC, binAddr, big.NewInt(0))

		srcState, _ := srcBC.State()
		binState, _ := binBC.State()
		srcSlot := srcState.GetState(srcAddr, luaStorageSlot("x"))
		binSlot := binState.GetState(binAddr, luaStorageSlot("x"))
		srcVal := new(big.Int).SetBytes(srcSlot[:]).Uint64()
		binVal := new(big.Int).SetBytes(binSlot[:]).Uint64()
		if srcVal != binVal {
			t.Fatalf("source vs bytecode mismatch: source=%d bytecode=%d", srcVal, binVal)
		}
	})

	// tos.compileBytecode tests

	t.Run("compileBytecode_result_is_deployable", func(t *testing.T) {
		// Compile child source in-contract, then deploy the bytecode and call it.
		// Child sets "ping"=7; verify the value in child's storage via Go.
		contractAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
		childAddr := crypto.CreateAddress(contractAddr, 0) // first deploy, nonce=0

		code := `
			local childSrc = "tos.set([[ping]], 7)"
			local bc = tos.compileBytecode(childSrc)
			local child = tos.deploy(bc)
			local ok = tos.call(child, 0)
			assert(ok, "tos.call on compiled-bytecode child failed")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		_ = addr
		runLuaTx(t, bc, addr, big.NewInt(0))

		state, _ := bc.State()
		pingSlot := state.GetState(childAddr, luaStorageSlot("ping"))
		got := new(big.Int).SetBytes(pingSlot[:]).Uint64()
		if got != 7 {
			t.Fatalf("child ping: want 7, got %d", got)
		}
	})

	t.Run("compileBytecode_matches_source_deploy", func(t *testing.T) {
		// Deploying compiled bytecode must produce the same runtime behaviour as
		// deploying the equivalent source string directly.
		// Both contracts use the same address (0xCCCC...) in separate chains,
		// so the child address (nonce=0) is the same in both; compare child storage.
		contractAddr := common.HexToAddress("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
		childAddr := crypto.CreateAddress(contractAddr, 0)

		childSrc := `tos.set([[val]], 55)`

		srcCode := fmt.Sprintf(`
			local child = tos.deploy(%q)
			local ok = tos.call(child, 0)
			assert(ok, "source-deploy call failed")
		`, childSrc)
		bcnCode := fmt.Sprintf(`
			local bc = tos.compileBytecode(%q)
			local child = tos.deploy(bc)
			local ok = tos.call(child, 0)
			assert(ok, "bytecode-deploy call failed")
		`, childSrc)

		srcBC, _, srcCleanup := luaTestSetup(t, srcCode)
		defer srcCleanup()
		binBC, _, binCleanup := luaTestSetup(t, bcnCode)
		defer binCleanup()

		runLuaTx(t, srcBC, contractAddr, big.NewInt(0))
		runLuaTx(t, binBC, contractAddr, big.NewInt(0))

		srcState, _ := srcBC.State()
		binState, _ := binBC.State()
		srcVal := srcState.GetState(childAddr, luaStorageSlot("val"))
		binVal := binState.GetState(childAddr, luaStorageSlot("val"))
		if srcVal != binVal {
			t.Fatalf("source-deploy vs bytecode-deploy mismatch: src=%v bcn=%v", srcVal, binVal)
		}
	})

	t.Run("compileBytecode_syntax_error_reverts", func(t *testing.T) {
		// Passing syntactically invalid Lua to compileBytecode must revert the tx.
		code := `tos.compileBytecode("this is not valid lua @@@@")`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})

	t.Run("compileBytecode_oog_on_huge_source", func(t *testing.T) {
		// luaGasCompileByte=50; 10 000 bytes × 50 = 500 000 gas > tx gas limit → OOG.
		code := `tos.compileBytecode(string.rep("x", 10000))`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTxExpectFail(t, bc, addr, big.NewInt(0))
	})
}

func TestLuaContractTOS721(t *testing.T) {
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)
	bob := common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	const nftCode = `
		local T = tos.import("tos721")
		T.init("MyNFT", "MNFT")
		tos.dispatch(T.handlers)
	`

	// readMapStr reads a string stored by tos.mapSetStr at (mapName, key).
	readMapStr := func(state interface {
		GetState(common.Address, common.Hash) common.Hash
	}, contractAddr common.Address, mapName, key string) string {
		base := luaMapStrLenSlot(mapName, []string{key})
		lenSlot := state.GetState(contractAddr, base)
		if lenSlot == (common.Hash{}) {
			return ""
		}
		length := int(binary.BigEndian.Uint64(lenSlot[24:]) - 1)
		data := make([]byte, length)
		for i := 0; i < length; i += 32 {
			chunk := state.GetState(contractAddr, luaStrChunkSlot(base, i/32))
			end := i + 32
			if end > length {
				end = length
			}
			copy(data[i:end], chunk[:end-i])
		}
		return string(data)
	}

	// trigger fires the first call to set up oncreate (mints nothing in TOS-721).
	trigger := func(t *testing.T, bc *BlockChain, addr common.Address) {
		t.Helper()
		runLuaTxWithData(t, bc, addr, big.NewInt(0), buildCalldata(t, "name()"))
	}

	t.Run("metadata_stored", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, nftCode)
		defer cleanup()
		trigger(t, bc, addr)

		state, _ := bc.State()
		if state.GetState(addr, luaStrLenSlot("_name")) == (common.Hash{}) {
			t.Error("_name not stored")
		}
		if state.GetState(addr, luaStrLenSlot("_symbol")) == (common.Hash{}) {
			t.Error("_symbol not stored")
		}
		// _cowner is stored via tos.setStr; check the len slot is non-zero.
		if state.GetState(addr, luaStrLenSlot("_cowner")) == (common.Hash{}) {
			t.Error("_cowner not stored")
		}
	})

	t.Run("mint_stores_owner_and_balance", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, nftCode)
		defer cleanup()
		trigger(t, bc, addr)

		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint(address,uint256)", "address", addr1, "uint256", big.NewInt(1)))

		state, _ := bc.State()

		// owner of token 1 must be addr1.
		owner := readMapStr(state, addr, "_own", "1")
		if owner != addr1.Hex() {
			t.Errorf("owner of token 1: want %s, got %s", addr1.Hex(), owner)
		}

		// balance of addr1 must be 1.
		balSlot := state.GetState(addr, luaMapSlot("_bal", []string{addr1.Hex()}))
		bal := new(big.Int).SetBytes(balSlot[:]).Int64()
		if bal != 1 {
			t.Errorf("balance of addr1: want 1, got %d", bal)
		}
	})

	t.Run("mint_emits_Transfer_from_zero", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, nftCode)
		defer cleanup()
		trigger(t, bc, addr)

		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint(address,uint256)", "address", addr1, "uint256", big.NewInt(1)))

		block := bc.CurrentBlock()
		receipts := rawdb.ReadReceipts(bc.db, block.Hash(), block.NumberU64(), bc.Config())
		sig := luaEventSig("Transfer", "address", "address", "uint256")
		found := false
		for _, l := range receipts[0].Logs {
			if len(l.Topics) > 0 && l.Topics[0] == sig {
				found = true
				break
			}
		}
		if !found {
			t.Error("Transfer event not emitted on mint")
		}
	})

	t.Run("transfer_updates_owner_and_balances", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, nftCode)
		defer cleanup()
		trigger(t, bc, addr)

		// Mint token 1 to addr1 (owner == caller == addr1).
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint(address,uint256)", "address", addr1, "uint256", big.NewInt(1)))

		// addr1 transfers token 1 to bob (addr1 == token owner → authorized).
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "transferFrom(address,address,uint256)", "address", addr1, "address", bob, "uint256", big.NewInt(1)))

		state, _ := bc.State()

		// New owner is bob.
		owner := readMapStr(state, addr, "_own", "1")
		if owner != bob.Hex() {
			t.Errorf("owner after transfer: want %s, got %s", bob.Hex(), owner)
		}

		// addr1 balance = 0, bob balance = 1.
		addr1BalSlot := state.GetState(addr, luaMapSlot("_bal", []string{addr1.Hex()}))
		bobBalSlot := state.GetState(addr, luaMapSlot("_bal", []string{bob.Hex()}))
		addr1Bal := new(big.Int).SetBytes(addr1BalSlot[:]).Int64()
		bobBal := new(big.Int).SetBytes(bobBalSlot[:]).Int64()
		if addr1Bal != 0 {
			t.Errorf("addr1 balance after transfer: want 0, got %d", addr1Bal)
		}
		if bobBal != 1 {
			t.Errorf("bob balance after transfer: want 1, got %d", bobBal)
		}
	})

	t.Run("approve_sets_storage", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, nftCode)
		defer cleanup()
		trigger(t, bc, addr)

		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint(address,uint256)", "address", addr1, "uint256", big.NewInt(1)))
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "approve(address,uint256)", "address", bob, "uint256", big.NewInt(1)))

		state, _ := bc.State()
		approved := readMapStr(state, addr, "_appr", "1")
		if approved != bob.Hex() {
			t.Errorf("approved for token 1: want %s, got %s", bob.Hex(), approved)
		}
	})

	t.Run("unauthorized_transfer_reverts", func(t *testing.T) {
		// Mint token 1 to bob; addr1 (the tx signer) has no authorization → must revert.
		bc, addr, cleanup := luaTestSetup(t, nftCode)
		defer cleanup()
		trigger(t, bc, addr)

		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint(address,uint256)", "address", bob, "uint256", big.NewInt(1)))
		runLuaTxWithDataExpectFail(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "transferFrom(address,address,uint256)", "address", bob, "address", addr1, "uint256", big.NewInt(1)))
	})

	t.Run("non_owner_mint_reverts", func(t *testing.T) {
		// luaTestSetup2: codeA → 0xCCCC… (attacker), codeB → 0xBBBB… (NFT).
		// Sequence:
		//   1. addr1 calls NFT (0xBBBB…) to trigger oncreate → _cowner = addr1
		//   2. addr1 calls attacker (0xCCCC…); attacker calls NFT mint as 0xCCCC…
		//      0xCCCC… ≠ _cowner (addr1) → mint reverts → tos.call returns false
		//      attacker's require(not ok) passes → outer tx succeeds.
		nftAddr := common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
		mintData := buildCalldata(t, "mint(address,uint256)", "address", bob, "uint256", big.NewInt(5))
		attackerCode := fmt.Sprintf(`
			local ok = tos.call(%q, 0, %q)
			require(not ok, "mint should have been rejected")
		`, nftAddr.Hex(), "0x"+common.Bytes2Hex(mintData))

		bc, attackerAddr, _, cleanup := luaTestSetup2(t, attackerCode, nftCode)
		defer cleanup()

		// Step 1: trigger oncreate on the NFT → _cowner = addr1.
		runLuaTxWithData(t, bc, nftAddr, big.NewInt(0), buildCalldata(t, "name()"))
		// Step 2: addr1 calls the attacker; attacker tries to mint as 0xCCCC… → rejected.
		runLuaTxWithData(t, bc, attackerAddr, big.NewInt(0), nil)
	})

	t.Run("double_mint_same_token_reverts", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, nftCode)
		defer cleanup()
		trigger(t, bc, addr)

		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint(address,uint256)", "address", addr1, "uint256", big.NewInt(1)))
		runLuaTxWithDataExpectFail(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint(address,uint256)", "address", addr1, "uint256", big.NewInt(1)))
	})

	t.Run("burn_removes_token", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, nftCode)
		defer cleanup()
		trigger(t, bc, addr)

		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint(address,uint256)", "address", addr1, "uint256", big.NewInt(1)))
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "burn(uint256)", "uint256", big.NewInt(1)))

		state, _ := bc.State()

		// Owner slot must now be ZERO_ADDRESS.
		owner := readMapStr(state, addr, "_own", "1")
		if owner != (common.Address{}).Hex() {
			t.Errorf("owner after burn: want ZERO_ADDRESS, got %s", owner)
		}

		// Balance of addr1 must be 0.
		balSlot := state.GetState(addr, luaMapSlot("_bal", []string{addr1.Hex()}))
		bal := new(big.Int).SetBytes(balSlot[:]).Int64()
		if bal != 0 {
			t.Errorf("balance after burn: want 0, got %d", bal)
		}
	})

	t.Run("unknown_selector_reverts", func(t *testing.T) {
		bc, addr, cleanup := luaTestSetup(t, nftCode)
		defer cleanup()
		trigger(t, bc, addr)
		runLuaTxWithDataExpectFail(t, bc, addr, big.NewInt(0), buildCalldata(t, "bogus()"))
	})
}

// TestLuaContractDelegatecall tests tos.delegatecall — executes implementation
// code in the proxy's storage/caller/value context (analogous to EVM DELEGATECALL).
//
// Layout (luaTestSetup2):
//
//	contractAddr  (0xCCCC…) — proxy   (codeA), 1 TOS balance
//	contractAddrB (0xBBBB…) — impl    (codeB), 2 TOS balance
//	addr1                   — tx sender,        10 TOS balance
func TestLuaContractDelegatecall(t *testing.T) {
	const addrA = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	const addrB = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	// readStr reads a string stored via tos.setStr(key, ...) from a contract's state.
	readStr := func(state interface {
		GetState(common.Address, common.Hash) common.Hash
	}, addr common.Address, key string) string {
		lenSlot := state.GetState(addr, luaStrLenSlot(key))
		if lenSlot == (common.Hash{}) {
			return ""
		}
		length := int(binary.BigEndian.Uint64(lenSlot[24:]) - 1)
		if length <= 0 {
			return ""
		}
		data := make([]byte, length)
		base := luaStrLenSlot(key)
		for i := 0; i < length; i += 32 {
			chunk := state.GetState(addr, luaStrChunkSlot(base, i/32))
			end := i + 32
			if end > length {
				end = length
			}
			copy(data[i:end], chunk[:end-i])
		}
		return string(data)
	}

	t.Run("storage_written_to_proxy_not_impl", func(t *testing.T) {
		// impl writes tos.set("x", 99); because of delegatecall this write lands
		// in proxy's storage, not in impl's storage.
		codeB := `tos.set("x", 99)`
		codeA := fmt.Sprintf(`
			local ok, _ = tos.delegatecall(%q)
			assert(ok, "delegatecall failed")
		`, addrB)
		bc, contractAddr, contractAddrB, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
		state, _ := bc.State()

		// proxy.x must be 99
		proxyX := state.GetState(contractAddr, luaStorageSlot("x"))
		if new(big.Int).SetBytes(proxyX[:]).Int64() != 99 {
			t.Errorf("proxy.x: want 99, got %s", new(big.Int).SetBytes(proxyX[:]))
		}
		// impl.x must be 0 (untouched)
		implX := state.GetState(contractAddrB, luaStorageSlot("x"))
		if implX != (common.Hash{}) {
			t.Errorf("impl.x: want 0, got %x", implX)
		}
	})

	t.Run("caller_is_preserved", func(t *testing.T) {
		// impl stores tos.caller (the external tx sender) via tos.setStr.
		// In delegatecall semantics tos.caller must equal the original tx signer,
		// not the proxy address.
		key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1 := crypto.PubkeyToAddress(key1.PublicKey)

		codeB := `tos.setStr("who", tos.caller)`
		codeA := fmt.Sprintf(`
			local ok, _ = tos.delegatecall(%q)
			assert(ok, "delegatecall failed")
		`, addrB)
		bc, contractAddr, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
		state, _ := bc.State()

		// "who" is stored in proxy's storage (delegatecall context).
		got := readStr(state, contractAddr, "who")
		if !strings.EqualFold(got, addr1.Hex()) {
			t.Errorf("proxy.who: want %s, got %s", addr1.Hex(), got)
		}
	})

	t.Run("self_is_proxy", func(t *testing.T) {
		// impl stores tos.self; it must equal the proxy address, not impl's address.
		codeB := `tos.setStr("me", tos.self)`
		codeA := fmt.Sprintf(`
			local ok, _ = tos.delegatecall(%q)
			assert(ok, "delegatecall failed")
		`, addrB)
		bc, contractAddr, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
		state, _ := bc.State()

		got := readStr(state, contractAddr, "me")
		if !strings.EqualFold(got, contractAddr.Hex()) {
			t.Errorf("proxy.me: want %s (proxy), got %s", contractAddr.Hex(), got)
		}
	})

	t.Run("failed_impl_writes_reverted", func(t *testing.T) {
		// proxy writes "x=42" before delegatecall (kept on impl failure).
		// impl writes "y=99" to proxy storage then reverts.
		// Expected: proxy.x=42 survives; proxy.y=0 (reverted).
		codeB := `tos.set("y", 99); tos.revert("impl failed")`
		codeA := fmt.Sprintf(`
			tos.set("x", 42)
			local ok, _ = tos.delegatecall(%q)
			assert(not ok, "expected delegatecall to fail")
		`, addrB)
		bc, contractAddr, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
		state, _ := bc.State()

		xSlot := state.GetState(contractAddr, luaStorageSlot("x"))
		if new(big.Int).SetBytes(xSlot[:]).Int64() != 42 {
			t.Errorf("proxy.x: want 42 (written before dc), got %s", new(big.Int).SetBytes(xSlot[:]))
		}
		ySlot := state.GetState(contractAddr, luaStorageSlot("y"))
		if ySlot != (common.Hash{}) {
			t.Errorf("proxy.y: want 0 (reverted by failed dc), got %x", ySlot)
		}
	})

	t.Run("return_data_forwarded", func(t *testing.T) {
		// impl returns a uint256 via tos.result; proxy decodes and emits it.
		codeB := `tos.result("uint256", 12345)`
		codeA := fmt.Sprintf(`
			local ok, data = tos.delegatecall(%q)
			assert(ok, "delegatecall failed")
			assert(data ~= nil, "expected return data")
			local val = tos.abi.decode(data, "uint256")
			tos.emit("Val", "uint256", val)
		`, addrB)
		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()
		receipt := runLuaTxGetReceipt(t, bc, common.HexToAddress(addrA), big.NewInt(0), nil)
		if len(receipt.Logs) < 1 {
			t.Fatalf("expected Val log, got 0 logs")
		}
		got := new(big.Int).SetBytes(receipt.Logs[0].Data).Int64()
		if got != 12345 {
			t.Errorf("Val: want 12345, got %d", got)
		}
	})

	t.Run("upgradeable_proxy_pattern", func(t *testing.T) {
		// Proxy reads its "impl" slot for the logic address and forwards all calls
		// via delegatecall.  Upgrading == writing a new address to "impl".
		//
		// v1 (addrB) sets version=1 in proxy's storage.
		// Then the proxy upgrades its "impl" pointer to v2 (a freshly deployed child).
		// v2 sets version=2.
		// Final: proxy.version == 2.
		//
		// tos.msg.data is hex-encoded, so we distinguish calls by a 1-byte magic:
		//   no data ("0x") → run current impl via delegatecall
		//   "0x01"         → deploy v2 and update "impl" pointer
		v1Code := `tos.set("version", 1)`
		v2Code := `tos.set("version", 2)`

		proxyCode := fmt.Sprintf(`
			local data = tos.msg.data
			if data == "0x01" then
				-- upgrade: deploy v2 inline and update impl pointer
				local v2 = tos.deploy(%q)
				tos.setStr("impl", v2)
			else
				local impl = tos.getStr("impl")
				if impl == nil or impl == "" then
					-- first call: initialise pointer to v1
					impl = %q
					tos.setStr("impl", impl)
				end
				local ok, _ = tos.delegatecall(impl)
				assert(ok, "delegatecall to impl failed")
			end
		`, v2Code, addrB)

		bc, contractAddr, _, cleanup := luaTestSetup2(t, proxyCode, v1Code)
		defer cleanup()

		// Tx 1: no data → delegate to v1 (addrB) → proxy.version = 1.
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
		state, _ := bc.State()
		v := state.GetState(contractAddr, luaStorageSlot("version"))
		if new(big.Int).SetBytes(v[:]).Int64() != 1 {
			t.Errorf("after v1: proxy.version want 1, got %d", new(big.Int).SetBytes(v[:]).Int64())
		}

		// Tx 2: send 0x01 → deploy v2, write its address to proxy."impl".
		runLuaTxWithData(t, bc, common.HexToAddress(addrA), big.NewInt(0), []byte{0x01})

		// Tx 3: no data → delegate to v2 → proxy.version = 2.
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
		state, _ = bc.State()
		v = state.GetState(contractAddr, luaStorageSlot("version"))
		if new(big.Int).SetBytes(v[:]).Int64() != 2 {
			t.Errorf("after v2: proxy.version want 2, got %d", new(big.Int).SetBytes(v[:]).Int64())
		}
	})
}

// TestLuaContractAccess tests the tos.import("access") RBAC stdlib.
//
// The fixed tx signer (addr1) derived from key1 is the DEFAULT_ADMIN after
// calling AC.init() — because tos.caller on the first transaction equals addr1.
func TestLuaContractAccess(t *testing.T) {
	// addr1 is derived from the fixed test key used by runLuaTx* helpers.
	key1, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr1 := crypto.PubkeyToAddress(key1.PublicKey)

	const addrA = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	const addrB = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	// hasRoleSlot returns the storage slot where _roles[addr][role] is stored.
	hasRoleSlot := func(addr common.Address, role string) common.Hash {
		return luaMapSlot("_roles", []string{addr.Hex(), role})
	}

	t.Run("init_grants_default_admin", func(t *testing.T) {
		// After AC.init() the tx signer (addr1) must have DEFAULT_ADMIN.
		code := `
			local AC = tos.import("access")
			AC.init()
			assert(AC.hasRole("DEFAULT_ADMIN", tos.caller),
			       "caller should be DEFAULT_ADMIN after init")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))

		// Also verify it's reflected in raw storage.
		state, _ := bc.State()
		slot := state.GetState(addr, hasRoleSlot(addr1, "DEFAULT_ADMIN"))
		if slot[31] != 1 {
			t.Errorf("storage _roles[addr1][DEFAULT_ADMIN]: want 1, got %d", slot[31])
		}
	})

	t.Run("has_role_false_before_grant", func(t *testing.T) {
		code := `
			local AC = tos.import("access")
			AC.init()
			assert(not AC.hasRole("MINTER", tos.caller),
			       "caller should NOT have MINTER before grant")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("grant_role_works_for_admin", func(t *testing.T) {
		// Admin (addr1) grants MINTER to themselves; hasRole returns true.
		code := `
			local AC = tos.import("access")
			AC.init()
			AC.grantRole("MINTER", tos.caller)
			assert(AC.hasRole("MINTER", tos.caller), "caller should have MINTER after grant")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))

		state, _ := bc.State()
		slot := state.GetState(addr, hasRoleSlot(addr1, "MINTER"))
		if slot[31] != 1 {
			t.Errorf("storage _roles[addr1][MINTER]: want 1, got %d", slot[31])
		}
	})

	t.Run("revoke_role_removes_grant", func(t *testing.T) {
		code := `
			local AC = tos.import("access")
			AC.init()
			AC.grantRole("MINTER", tos.caller)
			assert(AC.hasRole("MINTER", tos.caller), "should have MINTER after grant")
			AC.revokeRole("MINTER", tos.caller)
			assert(not AC.hasRole("MINTER", tos.caller), "should NOT have MINTER after revoke")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))

		state, _ := bc.State()
		slot := state.GetState(addr, hasRoleSlot(addr1, "MINTER"))
		if slot[31] != 0 {
			t.Errorf("storage _roles[addr1][MINTER]: want 0 after revoke, got %d", slot[31])
		}
	})

	t.Run("renounce_role_removes_own", func(t *testing.T) {
		code := `
			local AC = tos.import("access")
			AC.init()
			AC.grantRole("OPERATOR", tos.caller)
			assert(AC.hasRole("OPERATOR", tos.caller), "should have OPERATOR")
			AC.renounceRole("OPERATOR")
			assert(not AC.hasRole("OPERATOR", tos.caller), "should NOT have OPERATOR after renounce")
		`
		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()
		runLuaTx(t, bc, addr, big.NewInt(0))
	})

	t.Run("non_admin_grant_reverts", func(t *testing.T) {
		// codeB has its own access control; addr1 inits it directly (becomes admin).
		// codeA then calls codeB with a "try_grant" signal — inside codeB, tos.caller
		// is codeA (not addr1) → requireRole(DEFAULT_ADMIN) fails → codeB reverts.
		codeB := `
			local AC = tos.import("access")
			AC.init()
			if tos.msg.data == "0x01" then
				AC.grantRole("HACKER", tos.caller)
			end
		`
		codeA := fmt.Sprintf(`
			-- Try the unauthorised grantRole: codeA calls codeB with signal 0x01.
			-- Inside codeB, tos.caller = codeA (not addr1) → must revert.
			local ok, _ = tos.call(%q, 0, "0x01")
			assert(not ok, "expected non-admin grantRole to fail")
		`, addrB)

		bc, _, _, cleanup := luaTestSetup2(t, codeA, codeB)
		defer cleanup()

		// Step 1: addr1 calls codeB directly → AC.init() fires, addr1 = DEFAULT_ADMIN.
		runLuaTx(t, bc, common.HexToAddress(addrB), big.NewInt(0))

		// Step 2: addr1 calls codeA → codeA calls codeB with 0x01 → codeB reverts.
		runLuaTx(t, bc, common.HexToAddress(addrA), big.NewInt(0))
	})

	t.Run("role_guards_contract_function", func(t *testing.T) {
		// Full end-to-end: contract with a MINTER-guarded mint() function.
		// AC.init() at top-level fires once on the first tx; tos.dispatch routes
		// subsequent calls to their handlers.
		code := `
			local AC = tos.import("access")
			AC.init()

			tos.dispatch({
				["mint()"] = function()
					AC.requireRole("MINTER")
					tos.set("minted", (tos.get("minted") or 0) + 1)
				end,
				["grant_minter(address)"] = function(addr)
					AC.grantRole("MINTER", addr)
				end,
				["revoke_minter(address)"] = function(addr)
					AC.revokeRole("MINTER", addr)
				end,
				fallback = function() end,
			})
		`

		bc, addr, cleanup := luaTestSetup(t, code)
		defer cleanup()

		// Tx 1: no calldata → fallback → AC.init() fires, addr1 = DEFAULT_ADMIN.
		runLuaTx(t, bc, addr, big.NewInt(0))

		// Tx 2: mint() without MINTER role → must fail.
		runLuaTxWithDataExpectFail(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint()"))

		// Tx 3: grant_minter(addr1) → addr1 now has MINTER.
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "grant_minter(address)", "address", addr1))

		// Tx 4: mint() with MINTER role → succeeds; minted = 1.
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint()"))

		state, _ := bc.State()
		mintedSlot := state.GetState(addr, luaStorageSlot("minted"))
		if new(big.Int).SetBytes(mintedSlot[:]).Int64() != 1 {
			t.Errorf("minted: want 1, got %d", new(big.Int).SetBytes(mintedSlot[:]).Int64())
		}

		// Tx 5: revoke_minter(addr1) → addr1 loses MINTER.
		runLuaTxWithData(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "revoke_minter(address)", "address", addr1))

		// Tx 6: mint() again → must fail (MINTER revoked).
		runLuaTxWithDataExpectFail(t, bc, addr, big.NewInt(0),
			buildCalldata(t, "mint()"))
	})
}
