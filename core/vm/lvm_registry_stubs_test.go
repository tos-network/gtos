package vm

// Tests for protocol-backed annotation registry implementations:
// tos.hascapability (name path), tos.hasdelegation, tos.isverified, tos.canpay.
//
// Capability/delegation checks are exercised in two modes:
//   1. state-backed default resolution from on-chain registry state
//   2. explicit mock RegistryReader injection for override behaviour

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/paypolicy"
	"github.com/tos-network/gtos/registry"
	"github.com/tos-network/gtos/verifyregistry"
)

// ── mock RegistryReader ──────────────────────────────────────────────────────

type mockRegistryReader struct {
	// capabilities maps name → status.
	capabilities map[string]uint8
	// agentCaps maps "addr|name" → true.
	agentCaps map[string]bool
	// delegations maps "principal|delegate|scope" → {status, expiryMS}.
	delegations map[string]mockDelegation
}

type mockDelegation struct {
	status      uint8
	notBeforeMS uint64
	expiryMS    uint64
}

func (m *mockRegistryReader) ReadCapabilityStatus(name string) (uint8, bool) {
	s, ok := m.capabilities[name]
	return s, ok
}

func (m *mockRegistryReader) ReadAgentCapabilityBit(addr common.Address, name string) (bool, bool) {
	key := addr.Hex() + "|" + name
	has, ok := m.agentCaps[key]
	return has, ok
}

func (m *mockRegistryReader) ReadDelegationStatus(principal, delegate common.Address, scope [32]byte) (uint8, uint64, uint64, bool) {
	key := principal.Hex() + "|" + delegate.Hex() + "|" + string(scope[:])
	d, ok := m.delegations[key]
	if !ok {
		return 0, 0, 0, false
	}
	return d.status, d.notBeforeMS, d.expiryMS, true
}

// runLuaWithRegistry is like runLua but allows injecting a RegistryReader via
// a custom BlockContext.
func runLuaWithRegistry(st StateDB, contractAddr common.Address, src string, gasLimit uint64, rr RegistryReader) (uint64, []byte, []byte, error) {
	ctx := CallCtx{
		From:     common.Address{0xFF},
		To:       contractAddr,
		Value:    big.NewInt(0),
		Data:     []byte{},
		TxOrigin: common.Address{0xFF},
		TxPrice:  big.NewInt(1),
	}
	bctx := newBlockCtx()
	bctx.RegistryReader = rr
	return Execute(st, bctx, testChainConfig, ctx, []byte(src), gasLimit)
}

// ── tos.hasdelegation ────────────────────────────────────────────────────────

func TestDelegationRegistryStateBacked(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xD1}
	principal := common.Address{0xFF}
	delegate := common.HexToAddress("0xaaaa")
	var scope [32]byte
	copy(scope[:], []byte("transfer"))
	registry.WriteDelegation(st, registry.DelegationRecord{
		Principal:   principal,
		Delegate:    delegate,
		ScopeRef:    scope,
		NotBeforeMS: 1,
		ExpiryMS:    2_000_000_000_000,
		Status:      registry.DelActive,
	})

	src := `
local ok = tos.hasdelegation(tos.caller, "0xaaaa", "transfer")
if not ok then
  error("state-backed delegation should return true")
end
tos.sstore("delegation_ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	slot := st.GetState(contractAddr, StorageSlot("delegation_ok"))
	if slot == (common.Hash{}) {
		t.Fatal("delegation_ok slot not set")
	}
}

// TestDelegationRegistryBacked verifies tos.hasdelegation uses the registry
// when a RegistryReader is available.
func TestDelegationRegistryBacked(t *testing.T) {
	principalAddr := common.Address{0xFF} // matches tos.caller in runLuaWithRegistry
	delegateAddr := common.HexToAddress("0xaaaa")
	var scope [32]byte
	copy(scope[:], []byte("transfer"))

	delegKey := principalAddr.Hex() + "|" + delegateAddr.Hex() + "|" + string(scope[:])

	t.Run("active_not_expired", func(t *testing.T) {
		st := newAgentTestState()
		contractAddr := common.Address{0xD4}
		rr := &mockRegistryReader{
			delegations: map[string]mockDelegation{
				delegKey: {status: RegistryStatusActive, expiryMS: 2_000_000_000_000}, // far future
			},
		}
		src := `
local ok = tos.hasdelegation(tos.caller, "0xaaaa", "transfer")
if not ok then error("expected true for active delegation") end
tos.sstore("ok", 1)
`
		_, _, _, err := runLuaWithRegistry(st, contractAddr, src, 1_000_000, rr)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}
		if st.GetState(contractAddr, StorageSlot("ok")) == (common.Hash{}) {
			t.Fatal("ok slot not set")
		}
	})

	t.Run("revoked", func(t *testing.T) {
		st := newAgentTestState()
		contractAddr := common.Address{0xD5}
		rr := &mockRegistryReader{
			delegations: map[string]mockDelegation{
				delegKey: {status: RegistryStatusRevoked, expiryMS: 0},
			},
		}
		src := `
local ok = tos.hasdelegation(tos.caller, "0xaaaa", "transfer")
if ok then error("expected false for revoked delegation") end
tos.sstore("ok", 1)
`
		_, _, _, err := runLuaWithRegistry(st, contractAddr, src, 1_000_000, rr)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		st := newAgentTestState()
		contractAddr := common.Address{0xD6}
		rr := &mockRegistryReader{
			delegations: map[string]mockDelegation{
				// expiryMS = 1000 ms → 1 second. blockCtx.Time = 1_700_000_000 s → far past expiry.
				delegKey: {status: RegistryStatusActive, expiryMS: 1000},
			},
		}
		src := `
local ok = tos.hasdelegation(tos.caller, "0xaaaa", "transfer")
if ok then error("expected false for expired delegation") end
tos.sstore("ok", 1)
`
		_, _, _, err := runLuaWithRegistry(st, contractAddr, src, 1_000_000, rr)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}
	})

	t.Run("not_yet_active", func(t *testing.T) {
		st := newAgentTestState()
		contractAddr := common.Address{0xD7}
		rr := &mockRegistryReader{
			delegations: map[string]mockDelegation{
				delegKey: {status: RegistryStatusActive, notBeforeMS: 2_000_000_000_000, expiryMS: 3_000_000_000_000},
			},
		}
		src := `
local ok = tos.hasdelegation(tos.caller, "0xaaaa", "transfer")
if ok then error("expected false for not-yet-active delegation") end
tos.sstore("ok", 1)
`
		_, _, _, err := runLuaWithRegistry(st, contractAddr, src, 1_000_000, rr)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}
	})
}

// ── tos.hascapability (name path) ────────────────────────────────────────────

func TestHasCapabilityNameStateBacked(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xD8}
	addr := common.HexToAddress("0x1234")
	if _, err := capability.RegisterCapabilityName(st, "oracle"); err != nil {
		t.Fatalf("register capability name: %v", err)
	}
	capability.GrantCapability(st, addr, 0)

	src := `
local ok = tos.hascapability("0x1234", "oracle")
if not ok then error("expected true for state-backed capability") end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if st.GetState(contractAddr, StorageSlot("ok")) == (common.Hash{}) {
		t.Fatal("ok slot not set")
	}
}

// TestHasCapabilityNameRegistryBacked verifies registry-backed capability
// checks by name.
func TestHasCapabilityNameRegistryBacked(t *testing.T) {
	agentAddr := common.HexToAddress("0x1234")

	t.Run("active_and_held", func(t *testing.T) {
		st := newAgentTestState()
		contractAddr := common.Address{0xD9}
		rr := &mockRegistryReader{
			capabilities: map[string]uint8{"oracle": RegistryStatusActive},
			agentCaps:    map[string]bool{agentAddr.Hex() + "|oracle": true},
		}
		src := `
local ok = tos.hascapability("0x1234", "oracle")
if not ok then error("expected true") end
tos.sstore("ok", 1)
`
		_, _, _, err := runLuaWithRegistry(st, contractAddr, src, 1_000_000, rr)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}
	})

	t.Run("active_not_held", func(t *testing.T) {
		st := newAgentTestState()
		contractAddr := common.Address{0xDA}
		rr := &mockRegistryReader{
			capabilities: map[string]uint8{"oracle": RegistryStatusActive},
			agentCaps:    map[string]bool{}, // agent does NOT hold it
		}
		src := `
local ok = tos.hascapability("0x1234", "oracle")
if ok then error("expected false — agent does not hold capability") end
tos.sstore("ok", 1)
`
		_, _, _, err := runLuaWithRegistry(st, contractAddr, src, 1_000_000, rr)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}
	})

	t.Run("deprecated", func(t *testing.T) {
		st := newAgentTestState()
		contractAddr := common.Address{0xDB}
		rr := &mockRegistryReader{
			capabilities: map[string]uint8{"oracle": RegistryStatusDeprecated},
			agentCaps:    map[string]bool{agentAddr.Hex() + "|oracle": true},
		}
		src := `
local ok = tos.hascapability("0x1234", "oracle")
if ok then error("expected false — capability deprecated") end
tos.sstore("ok", 1)
`
		_, _, _, err := runLuaWithRegistry(st, contractAddr, src, 1_000_000, rr)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}
	})

	t.Run("no_record_fail_closed", func(t *testing.T) {
		st := newAgentTestState()
		contractAddr := common.Address{0xDC}
		rr := &mockRegistryReader{
			capabilities: map[string]uint8{}, // no record for "oracle"
		}
		src := `
local ok = tos.hascapability("0x1234", "oracle")
if ok then error("expected false — no record must fail closed") end
tos.sstore("ok", 1)
`
		_, _, _, err := runLuaWithRegistry(st, contractAddr, src, 1_000_000, rr)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}
	})
}

// ── tos.isverified ───────────────────────────────────────────────────────────

func TestVerificationRegistryBacked(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xD2}
	caller := common.Address{0xFF}
	verifyregistry.WriteVerifier(st, verifyregistry.VerifierRecord{
		Name:         "state_proof",
		VerifierType: 1,
		VerifierAddr: common.HexToAddress("0x1234000000000000000000000000000000000000"),
		Version:      1,
		Status:       verifyregistry.VerifierActive,
	})
	verifyregistry.WriteSubjectVerification(st, verifyregistry.SubjectVerificationRecord{
		Subject:    caller,
		ProofType:  "state_proof",
		VerifiedAt: 1,
		ExpiryMS:   2_000_000_000_000,
		Status:     verifyregistry.VerificationActive,
	})

	src := `
local ok = tos.isverified(tos.caller, "state_proof")
if not ok then
  error("isverified should return true for active verification")
end
tos.sstore("verified_ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	slot := st.GetState(contractAddr, StorageSlot("verified_ok"))
	if slot == (common.Hash{}) {
		t.Fatal("verified_ok slot not set")
	}
}

func TestVerificationRegistryExpired(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xE2}
	caller := common.Address{0xFF}
	verifyregistry.WriteVerifier(st, verifyregistry.VerifierRecord{
		Name:         "state_proof",
		VerifierType: 1,
		VerifierAddr: common.HexToAddress("0x1234000000000000000000000000000000000000"),
		Version:      1,
		Status:       verifyregistry.VerifierActive,
	})
	verifyregistry.WriteSubjectVerification(st, verifyregistry.SubjectVerificationRecord{
		Subject:    caller,
		ProofType:  "state_proof",
		VerifiedAt: 1,
		ExpiryMS:   1000,
		Status:     verifyregistry.VerificationActive,
	})
	src := `
local ok = tos.isverified(tos.caller, "state_proof")
if ok then
  error("isverified should return false for expired verification")
end
tos.sstore("verified_expired", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
}

// ── tos.canpay ───────────────────────────────────────────────────────────────

func TestPaymentRegistryBacked(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xD3}
	caller := common.Address{0xFF}
	st.AddBalance(caller, big.NewInt(1_000))
	paypolicy.WritePolicy(st, paypolicy.PolicyRecord{
		PolicyID:  [32]byte{0x01},
		Kind:      2,
		Owner:     caller,
		Asset:     "TOS",
		MaxAmount: big.NewInt(600),
		Status:    paypolicy.PolicyActive,
	})

	src := `
local ok = tos.canpay(tos.caller, "500", "TOS")
if not ok then
  error("canpay should return true within balance and policy cap")
end
tos.sstore("canpay_ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	slot := st.GetState(contractAddr, StorageSlot("canpay_ok"))
	if slot == (common.Hash{}) {
		t.Fatal("canpay_ok slot not set")
	}
}

func TestPaymentRegistryCapExceeded(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xE3}
	caller := common.Address{0xFF}
	st.AddBalance(caller, big.NewInt(1_000))
	paypolicy.WritePolicy(st, paypolicy.PolicyRecord{
		PolicyID:  [32]byte{0x02},
		Kind:      2,
		Owner:     caller,
		Asset:     "TOS",
		MaxAmount: big.NewInt(300),
		Status:    paypolicy.PolicyActive,
	})
	src := `
local ok = tos.canpay(tos.caller, "500", "TOS")
if ok then
  error("canpay should return false when policy cap is exceeded")
end
tos.sstore("canpay_denied", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
}

// suppress unused import warning
var _ = params.AgentLoadGas
