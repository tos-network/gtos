package vm

// Tests for protocol-backed annotation registry stubs:
// tos.hasdelegation, tos.isverified, tos.canpay.
//
// These host functions are stubs that always return true, pending full
// protocol registry implementation. The tests verify the stubs are
// registered correctly, accept the expected arguments, and return true.

import (
	"testing"

	"github.com/tos-network/gtos/common"
)

// TestDelegationRegistryStub verifies tos.hasdelegation(caller, operator, scope)
// returns true (stub behaviour).
func TestDelegationRegistryStub(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xD1}

	src := `
local ok = tos.hasdelegation(tos.caller, "0xaaaa", "transfer")
if not ok then
  error("hasdelegation stub should return true")
end
tos.sstore("delegation_ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	slot := st.GetState(contractAddr, StorageSlot("delegation_ok"))
	if slot == (common.Hash{}) {
		t.Fatal("delegation_ok slot not set; stub did not return true")
	}
}

// TestVerificationRegistryStub verifies tos.isverified(caller, proof_type)
// returns true (stub behaviour).
func TestVerificationRegistryStub(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xD2}

	src := `
local ok = tos.isverified(tos.caller, "state_proof")
if not ok then
  error("isverified stub should return true")
end
tos.sstore("verified_ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	slot := st.GetState(contractAddr, StorageSlot("verified_ok"))
	if slot == (common.Hash{}) {
		t.Fatal("verified_ok slot not set; stub did not return true")
	}
}

// TestPaymentRegistryStub verifies tos.canpay(caller, amount, asset)
// returns true (stub behaviour).
func TestPaymentRegistryStub(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xD3}

	src := `
local ok = tos.canpay(tos.caller, "1000", "TOS")
if not ok then
  error("canpay stub should return true")
end
tos.sstore("canpay_ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	slot := st.GetState(contractAddr, StorageSlot("canpay_ok"))
	if slot == (common.Hash{}) {
		t.Fatal("canpay_ok slot not set; stub did not return true")
	}
}
