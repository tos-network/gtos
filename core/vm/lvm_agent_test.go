package vm

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/agent"
	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/delegation"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/pkgregistry"
	"github.com/tos-network/gtos/reputation"
	lua "github.com/tos-network/tolang"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

func newAgentTestState() *state.StateDB {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	s, _ := state.New(common.Hash{}, db, nil)
	return s
}

var testChainConfig = &params.ChainConfig{ChainID: big.NewInt(1)}

// newBlockCtx returns a minimal BlockContext sufficient for LVM execution.
func newBlockCtx() BlockContext {
	return BlockContext{
		CanTransfer: func(db StateDB, addr common.Address, amount *big.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, from, to common.Address, amount *big.Int) {
			db.SubBalance(from, amount)
			db.AddBalance(to, amount)
		},
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		BlockNumber: big.NewInt(1),
		Time:        big.NewInt(1_700_000_000),
		GasLimit:    10_000_000,
		BaseFee:     big.NewInt(0),
	}
}

// runLua executes a Lua source snippet inside the LVM Execute loop.
// Execute accepts raw Lua source bytes directly (no pre-compilation needed).
// contractAddr is the address used as tos.self; gasLimit caps execution.
// Returns (gasUsed, returnData, revertData, err).
func runLua(st StateDB, contractAddr common.Address, src string, gasLimit uint64) (uint64, []byte, []byte, error) {
	ctx := CallCtx{
		From:     common.Address{0xFF},
		To:       contractAddr,
		Value:    big.NewInt(0),
		Data:     []byte{},
		TxOrigin: common.Address{0xFF},
		TxPrice:  big.NewInt(1),
	}
	return Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(src), gasLimit)
}

// ── block.timestamp_ms ────────────────────────────────────────────────────────

// TestBlockTimestampMs verifies block.timestamp_ms == block.timestamp * 1000.
func TestBlockTimestampMs(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x01}

	// The Lua script stores block.timestamp_ms into a key so we can read it back.
	src := `
local ts    = tos.block.timestamp
local ts_ms = tos.block.timestamp_ms
-- ts_ms must equal ts * 1000
if ts_ms ~= ts * 1000 then
  error("timestamp_ms mismatch: " .. tostring(ts_ms) .. " vs " .. tostring(ts * 1000))
end
tos.sstore("ts_ms", ts_ms)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("timestamp_ms: %v", err)
	}

	// Read the stored value back from StateDB.
	raw := st.GetState(contractAddr, StorageSlot("ts_ms"))
	stored := raw.Big().Uint64()
	// Time in newBlockCtx() is 1_700_000_000, so ms = 1_700_000_000_000.
	expected := uint64(1_700_000_000) * 1000
	if stored != expected {
		t.Errorf("stored ts_ms: want %d, got %d", expected, stored)
	}
}

// ── tos.agentload ─────────────────────────────────────────────────────────────

// TestAgentLoadStake verifies tos.agentload returns the correct stake.
func TestAgentLoadStake(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x02}
	agentAddr := common.Address{0x10}

	stake := new(big.Int).Mul(big.NewInt(5_000), big.NewInt(1e18))
	agent.WriteStake(st, agentAddr, stake)
	agent.WriteStatus(st, agentAddr, agent.AgentActive)

	src := `
local addr = "` + agentAddr.Hex() + `"
local s = tos.agentload(addr, "stake")
tos.sstore("stake", s)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("agentload stake: %v", err)
	}

	raw := st.GetState(contractAddr, StorageSlot("stake"))
	got := raw.Big()
	if got.Cmp(stake) != 0 {
		t.Errorf("stake: want %v, got %v", stake, got)
	}
}

// TestAgentLoadIsRegistered verifies tos.agentload "is_registered" field.
func TestAgentLoadIsRegistered(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x03}
	agentAddr := common.Address{0x11}

	// Not registered initially.
	src := `
local addr = "` + agentAddr.Hex() + `"
local r = tos.agentload(addr, "is_registered")
tos.sstore("reg", r)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("agentload is_registered (unregistered): %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("reg"))
	if raw.Big().Sign() != 0 {
		t.Error("expected is_registered=0 for unregistered agent")
	}

	// Register the agent.
	agent.WriteStatus(st, agentAddr, agent.AgentActive)
	// Use writeRegisteredFlag via state.go unexported — just call IsRegistered after
	// directly setting the slot to simulate registration.
	var one common.Hash
	one[31] = 1
	regSlot := common.BytesToHash(crypto.Keccak256(
		append(append(agentAddr.Bytes(), 0x00), []byte("registered")...),
	))
	st.SetState(params.AgentRegistryAddress, regSlot, one)

	_, _, _, err = runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("agentload is_registered (registered): %v", err)
	}
	raw = st.GetState(contractAddr, StorageSlot("reg"))
	if raw.Big().Sign() == 0 {
		t.Error("expected is_registered=1 for registered agent")
	}
}

// TestAgentLoadSuspended verifies tos.agentload "suspended" field.
func TestAgentLoadSuspended(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x04}
	agentAddr := common.Address{0x12}

	agent.WriteSuspended(st, agentAddr, true)

	src := `
local addr = "` + agentAddr.Hex() + `"
local s = tos.agentload(addr, "suspended")
tos.sstore("susp", s)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("agentload suspended: %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("susp"))
	if raw.Big().Sign() == 0 {
		t.Error("expected suspended=1")
	}
}

// TestAgentLoadCapabilities verifies tos.agentload "capabilities" field.
func TestAgentLoadCapabilities(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x05}
	agentAddr := common.Address{0x13}

	capability.GrantCapability(st, agentAddr, 0)
	capability.GrantCapability(st, agentAddr, 3)

	src := `
local addr = "` + agentAddr.Hex() + `"
local c = tos.agentload(addr, "capabilities")
tos.sstore("caps", c)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("agentload capabilities: %v", err)
	}

	raw := st.GetState(contractAddr, StorageSlot("caps"))
	bitmap := raw.Big()
	// bit 0 and bit 3 should be set → value = 1 + 8 = 9
	expected := new(big.Int)
	expected.SetBit(expected, 0, 1)
	expected.SetBit(expected, 3, 1)
	if bitmap.Cmp(expected) != 0 {
		t.Errorf("capabilities bitmap: want %v, got %v", expected, bitmap)
	}
}

// TestAgentLoadReputation verifies tos.agentload "reputation" and "rating_count".
func TestAgentLoadReputation(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x06}
	agentAddr := common.Address{0x14}

	reputation.RecordScore(st, agentAddr, big.NewInt(42))
	reputation.RecordScore(st, agentAddr, big.NewInt(-7))

	src := `
local addr = "` + agentAddr.Hex() + `"
local rep = tos.agentload(addr, "reputation")
local cnt = tos.agentload(addr, "rating_count")
tos.sstore("rep", rep)
tos.sstore("cnt", cnt)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("agentload reputation: %v", err)
	}

	rawCnt := st.GetState(contractAddr, StorageSlot("cnt"))
	if rawCnt.Big().Int64() != 2 {
		t.Errorf("rating_count: want 2, got %v", rawCnt.Big())
	}
	// Net score = 42 - 7 = 35; stored as uint256 two's complement.
	rawRep := st.GetState(contractAddr, StorageSlot("rep"))
	if rawRep.Big().Int64() != 35 {
		t.Errorf("reputation: want 35, got %v", rawRep.Big())
	}
}

// TestAgentLoadUnknownField verifies unknown field returns nil (no error).
func TestAgentLoadUnknownField(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x07}
	agentAddr := common.Address{0x15}

	src := `
local addr = "` + agentAddr.Hex() + `"
local v = tos.agentload(addr, "nonexistent_field")
if v ~= nil then
  error("expected nil for unknown field")
end
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("agentload unknown field: %v", err)
	}
}

// TestAgentInfoAlias verifies tos.agentinfo mirrors tos.agentload semantics.
func TestAgentInfoAlias(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x70}
	agentAddr := common.Address{0x71}

	stake := new(big.Int).Mul(big.NewInt(7_000), big.NewInt(1e18))
	agent.WriteStake(st, agentAddr, stake)
	agent.WriteStatus(st, agentAddr, agent.AgentActive)

	src := `
local addr = "` + agentAddr.Hex() + `"
local s1 = tos.agentload(addr, "stake")
local s2 = tos.agentinfo(addr, "stake")
if s1 ~= s2 then
  error("agentinfo mismatch")
end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("agentinfo alias: %v", err)
	}
	if st.GetState(contractAddr, StorageSlot("ok")) == (common.Hash{}) {
		t.Fatal("ok slot not set")
	}
}

// ── tos.hascapability ─────────────────────────────────────────────────────────

// TestHasCapability verifies tos.hascapability returns correct bool.
func TestHasCapability(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x08}
	agentAddr := common.Address{0x16}

	capability.GrantCapability(st, agentAddr, 5)

	src := `
local addr = "` + agentAddr.Hex() + `"
if not tos.hascapability(addr, 5) then
  error("expected hascapability=true for bit 5")
end
if tos.hascapability(addr, 6) then
  error("expected hascapability=false for bit 6")
end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("hascapability: %v", err)
	}
}

// ── tos.capabilitybit ─────────────────────────────────────────────────────────

// TestCapabilityBit verifies tos.capabilitybit resolves name → bit.
func TestCapabilityBit(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x09}

	bit, err2 := capability.RegisterCapabilityName(st, "oracle")
	if err2 != nil {
		t.Fatalf("RegisterCapabilityName: %v", err2)
	}

	src := `
local b = tos.capabilitybit("oracle")
if b == nil then
  error("expected non-nil bit for 'oracle'")
end
tos.sstore("bit", b)
local missing = tos.capabilitybit("nonexistent")
if missing ~= nil then
  error("expected nil for unregistered name")
end
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("capabilitybit: %v", err)
	}

	raw := st.GetState(contractAddr, StorageSlot("bit"))
	if uint8(raw.Big().Uint64()) != bit {
		t.Errorf("capabilitybit: want %d, got %d", bit, raw.Big().Uint64())
	}
}

// ── tos.delegationused ────────────────────────────────────────────────────────

// TestDelegationUsed verifies tos.delegationused reflects MarkUsed state.
func TestDelegationUsed(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x0A}
	principal := common.Address{0x17}
	nonce := big.NewInt(99)

	src := `
local p = "` + principal.Hex() + `"
if tos.delegationused(p, 99) then
  error("nonce should not be used yet")
end
tos.sstore("before", 0)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("delegationused (before): %v", err)
	}

	delegation.MarkUsed(st, principal, nonce)

	src2 := `
local p = "` + principal.Hex() + `"
if not tos.delegationused(p, 99) then
  error("nonce should be used")
end
tos.sstore("after", 1)
`
	_, _, _, err = runLua(st, contractAddr, src2, 1_000_000)
	if err != nil {
		t.Fatalf("delegationused (after): %v", err)
	}
}

// ── tos.escrow / tos.release / tos.slash / tos.escrowbalanceof ───────────────

// TestEscrowDepositAndRelease verifies the full escrow→release cycle.
func TestEscrowDepositAndRelease(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x0B}
	agentAddr := common.Address{0x18}

	// Fund the contract so it can escrow.
	depositAmount := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18))
	st.AddBalance(contractAddr, depositAmount)

	src := `
local agent  = "` + agentAddr.Hex() + `"
local amount = 5000000000000000000  -- 5 TOS in wei
tos.escrow(agent, amount, 0)
local bal = tos.escrowbalanceof(agent, 0)
if bal ~= amount then
  error("escrow balance mismatch: " .. tostring(bal))
end
tos.sstore("escrowed", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("escrow deposit: %v", err)
	}

	// Verify contract balance was reduced.
	half := new(big.Int).Div(depositAmount, big.NewInt(2))
	contractBal := st.GetBalance(contractAddr)
	if contractBal.Cmp(half) != 0 {
		t.Errorf("contract balance after escrow: want %v, got %v", half, contractBal)
	}

	// Release back to agent.
	src2 := `
local agent  = "` + agentAddr.Hex() + `"
local amount = 5000000000000000000
tos.release(agent, amount, 0)
local bal = tos.escrowbalanceof(agent, 0)
if bal ~= 0 then
  error("escrow balance should be 0 after release")
end
tos.sstore("released", 1)
`
	_, _, _, err = runLua(st, contractAddr, src2, 1_000_000)
	if err != nil {
		t.Fatalf("escrow release: %v", err)
	}

	// Agent should have received 5 TOS.
	agentBal := st.GetBalance(agentAddr)
	if agentBal.Cmp(half) != 0 {
		t.Errorf("agent balance after release: want %v, got %v", half, agentBal)
	}
}

// TestEscrowSlash verifies escrow → slash transfers to a third-party recipient.
func TestEscrowSlash(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x0C}
	agentAddr := common.Address{0x19}
	recipient := common.Address{0x1A}

	amount := new(big.Int).Mul(big.NewInt(3), big.NewInt(1e18))
	st.AddBalance(contractAddr, new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)))

	// First, escrow.
	src := `
local agent = "` + agentAddr.Hex() + `"
tos.escrow(agent, 3000000000000000000, 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("escrow: %v", err)
	}

	// Then slash.
	src2 := `
local agent     = "` + agentAddr.Hex() + `"
local recipient = "` + recipient.Hex() + `"
tos.slash(agent, 3000000000000000000, recipient, 1)
local bal = tos.escrowbalanceof(agent, 1)
if bal ~= 0 then
  error("escrow balance should be 0 after slash")
end
`
	_, _, _, err = runLua(st, contractAddr, src2, 1_000_000)
	if err != nil {
		t.Fatalf("slash: %v", err)
	}

	// Recipient should have received 3 TOS.
	recvBal := st.GetBalance(recipient)
	if recvBal.Cmp(amount) != 0 {
		t.Errorf("recipient balance: want %v, got %v", amount, recvBal)
	}
	// Agent should still have 0.
	if st.GetBalance(agentAddr).Sign() != 0 {
		t.Errorf("agent balance should be 0 after slash, got %v", st.GetBalance(agentAddr))
	}
}

// TestEscrowInsufficientBalance verifies escrow fails when contract has no balance.
func TestEscrowInsufficientBalance(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x0D}
	agentAddr := common.Address{0x1B}
	// Contract has 0 balance.

	src := `
local agent = "` + agentAddr.Hex() + `"
tos.escrow(agent, 1000000000000000000, 0)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err == nil {
		t.Fatal("expected error when contract has insufficient balance for escrow")
	}
}

// TestEscrowReleaseInsufficientEscrow verifies release fails when escrow < amount.
func TestEscrowReleaseInsufficientEscrow(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x0E}
	agentAddr := common.Address{0x1C}

	// Fund and escrow 1 TOS.
	st.AddBalance(contractAddr, new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)))
	srcEscrow := `tos.escrow("` + agentAddr.Hex() + `", 1000000000000000000, 0)`
	_, _, _, err := runLua(st, contractAddr, srcEscrow, 1_000_000)
	if err != nil {
		t.Fatalf("escrow: %v", err)
	}

	// Try to release 2 TOS (more than escrowed).
	srcRelease := `tos.release("` + agentAddr.Hex() + `", 2000000000000000000, 0)`
	_, _, _, err = runLua(st, contractAddr, srcRelease, 1_000_000)
	if err == nil {
		t.Fatal("expected error releasing more than escrowed")
	}
}

// TestEscrowIsolation verifies escrow is scoped per (contract, agent, purpose).
func TestEscrowIsolation(t *testing.T) {
	st := newAgentTestState()
	contract1 := common.Address{0x0F}
	contract2 := common.Address{0x20}
	agentAddr := common.Address{0x1D}

	st.AddBalance(contract1, new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)))
	st.AddBalance(contract2, new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)))

	amount := `5000000000000000000`
	srcEscrow := `tos.escrow("` + agentAddr.Hex() + `", ` + amount + `, 0)`

	// Escrow from contract1.
	_, _, _, err := runLua(st, contract1, srcEscrow, 1_000_000)
	if err != nil {
		t.Fatalf("escrow from contract1: %v", err)
	}

	// contract2 should see 0 escrow for the same agent/purpose.
	srcCheck := `
local bal = tos.escrowbalanceof("` + agentAddr.Hex() + `", 0)
if bal ~= 0 then
  error("contract2 should see 0 escrow, got: " .. tostring(bal))
end
`
	_, _, _, err = runLua(st, contract2, srcCheck, 1_000_000)
	if err != nil {
		t.Fatalf("escrow isolation check: %v", err)
	}
}

func compileAndDeployTestPackage(t *testing.T, st *state.StateDB, addr common.Address, contractName, packageName, version string) []byte {
	t.Helper()
	src := []byte(`pragma tolang 0.4.0;
package ` + packageName + `;
contract ` + contractName + ` {
    function ping() public pure returns (u256) { return 1; }
}`)
	pkgBytes, err := lua.CompilePackage(src, contractName+".tol", &lua.PackageOptions{
		PackageName:    packageName,
		PackageVersion: version,
	})
	if err != nil {
		t.Fatalf("CompilePackage failed: %v", err)
	}
	st.SetCode(addr, pkgBytes)
	return pkgBytes
}

func TestPackageInfoAndPublisherInfo(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x72}
	pkgAddr := common.Address{0x73}
	pubID := [32]byte{0x44}
	controller := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	pkgBytes := compileAndDeployTestPackage(t, st, pkgAddr, "Greeter", "demo.checkout", "1.0.0")

	pkgregistry.WritePublisher(st, pkgregistry.PublisherRecord{
		PublisherID: pubID,
		Controller:  controller,
		Namespace:   "demo",
		Status:      pkgregistry.PkgActive,
	})
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "1.0.0",
		PackageHash:    crypto.Keccak256Hash(pkgBytes),
		PublisherID:    pubID,
		Channel:        pkgregistry.ChannelStable,
		Status:         pkgregistry.PkgActive,
		ContractCount:  1,
		PublishedAt:    99,
	})

	src := `
local addr = "` + pkgAddr.Hex() + `"
if tos.packageinfo(addr, "package_name") ~= "demo.checkout" then
  error("package_name mismatch")
end
if tos.packageinfo(addr, "package_version") ~= "1.0.0" then
  error("package_version mismatch")
end
if tos.packageinfo(addr, "channel") ~= "stable" then
  error("channel mismatch")
end
if tos.packageinfo(addr, "status") ~= "active" then
  error("status mismatch")
end
if tos.packageinfo(addr, "effective_status") ~= "active" then
  error("effective_status mismatch")
end
if tos.packageinfo(addr, "namespace") ~= "demo" then
  error("namespace mismatch")
end
if tos.packageinfo(addr, "contract_count") ~= 1 then
  error("contract_count mismatch")
end
local pub = tos.packageinfo(addr, "publisher_id")
if pub == nil then
  error("publisher_id missing")
end
if tos.publisherinfo(pub, "status") ~= "active" then
  error("publisher status mismatch")
end
if tos.publisherinfo(pub, "effective_status") ~= "active" then
  error("publisher effective status mismatch")
end
if tos.namespaceinfo("demo", "status") ~= "clear" then
  error("namespace status mismatch")
end
if tos.publisherinfo(pub, "controller") ~= "` + controller.Hex() + `" then
  error("publisher controller mismatch")
end
if tos.packagelatest("demo.checkout", "stable", "package_version") ~= "1.0.0" then
  error("packagelatest mismatch")
end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 5_000_000)
	if err != nil {
		t.Fatalf("packageinfo/publisherinfo: %v", err)
	}
	if st.GetState(contractAddr, StorageSlot("ok")) == (common.Hash{}) {
		t.Fatal("ok slot not set")
	}
}

func TestPackageInfoReflectsNamespaceDispute(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x76}
	pkgAddr := common.Address{0x77}
	pkgBytes := compileAndDeployTestPackage(t, st, pkgAddr, "Greeter", "demo.checkout", "1.0.0")
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000000000000000000000000000")
	pubID := [32]byte{0xAA}
	pkgregistry.WritePublisher(st, pkgregistry.PublisherRecord{
		PublisherID: pubID,
		Controller:  controller,
		Namespace:   "demo",
		Status:      pkgregistry.PkgActive,
	})
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "1.0.0",
		PackageHash:    crypto.Keccak256Hash(pkgBytes),
		PublisherID:    pubID,
		Channel:        pkgregistry.ChannelStable,
		Status:         pkgregistry.PkgActive,
		ContractCount:  1,
	})
	pkgregistry.WriteNamespaceGovernance(st, pkgregistry.NamespaceGovernanceRecord{
		Namespace:   "demo",
		PublisherID: pubID,
		Status:      pkgregistry.NamespaceDisputed,
	})

	src := `
local addr = "` + pkgAddr.Hex() + `"
local pub = tos.packageinfo(addr, "publisher_id")
if tos.packageinfo(addr, "effective_status") ~= "namespace_disputed" then
  error("package effective_status mismatch")
end
if tos.packageinfo(addr, "trusted") ~= false then
  error("expected package to be untrusted")
end
if tos.publisherinfo(pub, "effective_status") ~= "namespace_disputed" then
  error("publisher effective_status mismatch")
end
if tos.namespaceinfo("demo", "status") ~= "disputed" then
  error("namespace status mismatch")
end
if tos.packagelatest("demo.checkout", "stable", "package_version") ~= nil then
  error("expected packagelatest to hide disputed package")
end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 5_000_000)
	if err != nil {
		t.Fatalf("packageinfo disputed namespace: %v", err)
	}
	if st.GetState(contractAddr, StorageSlot("ok")) == (common.Hash{}) {
		t.Fatal("ok slot not set")
	}
}

func TestPackageInfoReturnsNilForUnpublishedOrUnknownChannel(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0x74}
	pkgAddr := common.Address{0x75}
	compileAndDeployTestPackage(t, st, pkgAddr, "Greeter", "demo.unpublished", "0.1.0")

	src := `
local addr = "` + pkgAddr.Hex() + `"
if tos.packageinfo(addr, "package_name") ~= nil then
  error("expected nil for unpublished package")
end
if tos.packagelatest("demo.unpublished", "nightly", "package_version") ~= nil then
  error("expected nil for unknown channel")
end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 5_000_000)
	if err != nil {
		t.Fatalf("packageinfo unpublished: %v", err)
	}
	if st.GetState(contractAddr, StorageSlot("ok")) == (common.Hash{}) {
		t.Fatal("ok slot not set")
	}
}
