package vm

// Regression tests for nested-call rollback semantics at the VM level.
//
// These tests verify that when a nested call (tos.call) reverts, all state
// changes made by the callee are correctly rolled back, including storage
// mutations, value transfers, and that structured revert data propagates
// intact through call boundaries.

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
)

// ---------------------------------------------------------------------------
// Test 1: Nested call storage rollback
//
// A parent calls a child that modifies storage then reverts. Parent's view
// of child's storage must show pre-call (zero) state.
// ---------------------------------------------------------------------------
func TestNestedCallStorageRollback(t *testing.T) {
	childAddr := common.Address{0xC1}
	childCode := `
		tos.sstore("modified", 999)
		error("intentional revert")
	`

	parentAddr := common.Address{0xA1}
	parentCode := fmt.Sprintf(`
		local ok, _ = tos.call(%q, 0)
		tos.sstore("call_ok", ok and 1 or 0)
	`, childAddr.Hex())

	st := newAgentTestState()
	st.CreateAccount(childAddr)
	st.SetCode(childAddr, []byte(childCode))
	st.CreateAccount(parentAddr)

	// Pre-verify child slot is zero.
	preVal := st.GetState(childAddr, StorageSlot("modified"))
	if preVal != (common.Hash{}) {
		t.Fatalf("pre-condition: child 'modified' slot should be zero, got %x", preVal)
	}

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err != nil {
		t.Fatalf("parent execution failed: %v", err)
	}

	// Verify: parent recorded that child call failed.
	okSlot := st.GetState(parentAddr, StorageSlot("call_ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 0 {
		t.Fatalf("call_ok: want 0 (child reverted), got %d", got)
	}

	// Verify: child's storage slot is still zero (rollback worked).
	postVal := st.GetState(childAddr, StorageSlot("modified"))
	if postVal != (common.Hash{}) {
		t.Fatalf("child 'modified' slot after rollback: want zero, got %x", postVal[:])
	}
}

// ---------------------------------------------------------------------------
// Test 2: Nested call value rollback
//
// A parent sends value to a child call that reverts. The value must be
// returned to the parent (not lost).
// ---------------------------------------------------------------------------
func TestNestedCallValueRollback(t *testing.T) {
	childAddr := common.Address{0xC2}
	childCode := `
		tos.sstore("got_value", tos.value)
		error("revert after receiving value")
	`

	parentAddr := common.Address{0xA2}
	parentCode := fmt.Sprintf(`
		local ok, _ = tos.call(%q, 500)
		tos.sstore("call_ok", ok and 1 or 0)
	`, childAddr.Hex())

	st := newAgentTestState()
	st.CreateAccount(childAddr)
	st.SetCode(childAddr, []byte(childCode))
	st.CreateAccount(parentAddr)

	// Fund the parent with 1000 wei.
	st.AddBalance(parentAddr, big.NewInt(1000))

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err != nil {
		t.Fatalf("parent execution failed: %v", err)
	}

	// Verify: call failed.
	okSlot := st.GetState(parentAddr, StorageSlot("call_ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 0 {
		t.Fatalf("call_ok: want 0 (child reverted), got %d", got)
	}

	// Verify: parent balance is still 1000 (value was rolled back).
	parentBal := st.GetBalance(parentAddr)
	if parentBal.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("parent balance after value rollback: want 1000, got %s", parentBal.String())
	}

	// Verify: child balance is still 0.
	childBal := st.GetBalance(childAddr)
	if childBal.Sign() != 0 {
		t.Fatalf("child balance after value rollback: want 0, got %s", childBal.String())
	}
}

// ---------------------------------------------------------------------------
// Test 4: Sponsor/relay account path rollback
//
// If a relay contract sends value to a child and the child reverts, the value
// transfer must be rolled back. The relay's balance must be restored and the
// target must receive nothing.
// ---------------------------------------------------------------------------
func TestSponsorRelayValueRollback(t *testing.T) {
	targetAddr := common.Address{0xD1}
	revertingTarget := `
		tos.sstore("received", tos.value)
		error("target revert")
	`

	relayAddr := common.Address{0xD2}
	relayCode := fmt.Sprintf(`
		local ok, _ = tos.call(%q, 300)
		tos.sstore("forward_ok", ok and 1 or 0)
	`, targetAddr.Hex())

	st := newAgentTestState()
	st.CreateAccount(targetAddr)
	st.SetCode(targetAddr, []byte(revertingTarget))
	st.CreateAccount(relayAddr)

	// Fund the relay with 1000 wei.
	st.AddBalance(relayAddr, big.NewInt(1000))

	_, _, _, err := runLua(st, relayAddr, relayCode, 5_000_000)
	if err != nil {
		t.Fatalf("relay execution failed: %v", err)
	}

	// Verify: forward call failed.
	okSlot := st.GetState(relayAddr, StorageSlot("forward_ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 0 {
		t.Fatalf("forward_ok: want 0 (target reverted), got %d", got)
	}

	// Verify: relay balance is still 1000 (value was rolled back).
	relayBal := st.GetBalance(relayAddr)
	if relayBal.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("relay balance after value rollback: want 1000, got %s", relayBal.String())
	}

	// Verify: target balance is 0.
	targetBal := st.GetBalance(targetAddr)
	if targetBal.Sign() != 0 {
		t.Fatalf("target balance after rollback: want 0, got %s", targetBal.String())
	}

	// Verify: target's storage is clean (rollback undid the sstore).
	targetSlot := st.GetState(targetAddr, StorageSlot("received"))
	if targetSlot != (common.Hash{}) {
		t.Fatalf("target 'received' slot after rollback: want zero, got %x", targetSlot[:])
	}
}

// ---------------------------------------------------------------------------
// Test 5: Structured custom revert propagation
//
// A child call reverts with a typed custom error via tos.revert("ErrorName", ...).
// The parent must receive the revert data intact through the nested call
// boundary, including the 4-byte selector and ABI-encoded arguments.
// ---------------------------------------------------------------------------
func TestStructuredCustomRevertPropagation(t *testing.T) {
	childAddr := common.Address{0xC5}
	childCode := `
		tos.revert("InsufficientFunds", "uint256", 42)
	`

	parentAddr := common.Address{0xA5}
	parentCode := fmt.Sprintf(`
		local ok, revertData = tos.call(%q, 0)
		tos.sstore("call_ok", ok and 1 or 0)
		if revertData ~= nil then
			tos.setStr("revert_data", revertData)
		else
			tos.setStr("revert_data", "")
		end
	`, childAddr.Hex())

	st := newAgentTestState()
	st.CreateAccount(childAddr)
	st.SetCode(childAddr, []byte(childCode))
	st.CreateAccount(parentAddr)

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err != nil {
		t.Fatalf("parent execution failed: %v", err)
	}

	// Verify: child call failed.
	okSlot := st.GetState(parentAddr, StorageSlot("call_ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 0 {
		t.Fatalf("call_ok: want 0 (child reverted), got %d", got)
	}

	// Read the revert data stored by parent.
	gotRevertHex := readStoredString(st, parentAddr, "revert_data")
	if gotRevertHex == "" {
		t.Fatal("revert_data is empty; expected structured revert data from child")
	}

	// The revert data should start with the 4-byte selector of InsufficientFunds(uint256).
	wantSelector := common.Bytes2Hex(crypto.Keccak256([]byte("InsufficientFunds(uint256)"))[:4])
	gotRevertClean := gotRevertHex
	if len(gotRevertClean) >= 2 && gotRevertClean[:2] == "0x" {
		gotRevertClean = gotRevertClean[2:]
	}
	if len(gotRevertClean) < 8 {
		t.Fatalf("revert_data too short: %q", gotRevertHex)
	}
	gotSelector := gotRevertClean[:8]
	if gotSelector != wantSelector {
		t.Fatalf("revert selector mismatch: got=%s want=%s (full: %s)", gotSelector, wantSelector, gotRevertHex)
	}

	// The remaining 32 bytes should ABI-encode uint256(42).
	if len(gotRevertClean) < 72 { // 8 hex chars selector + 64 hex chars uint256
		t.Fatalf("revert_data too short for selector+uint256: %q", gotRevertHex)
	}
	valHex := gotRevertClean[8:72]
	gotVal := new(big.Int).SetBytes(common.FromHex("0x" + valHex))
	if gotVal.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("revert data value: got=%s want=42", gotVal.String())
	}
}

// readStoredString reads a string value from the LVM's string storage.
// This mirrors the readStringSlot helper from the e2e tests but uses the
// VM package's slot derivation functions directly.
func readStoredString(st StateDB, addr common.Address, key string) string {
	lenSlot := StrLenSlot(key)
	rawLen := st.GetState(addr, lenSlot)
	if rawLen == (common.Hash{}) {
		return ""
	}
	length := int(new(big.Int).SetBytes(rawLen[:]).Int64()) - 1
	if length <= 0 {
		return ""
	}
	data := make([]byte, length)
	for i := 0; i < length; i += 32 {
		chunk := st.GetState(addr, StrChunkSlot(lenSlot, i/32))
		end := i + 32
		if end > length {
			end = length
		}
		copy(data[i:end], chunk[:end-i])
	}
	return string(data)
}
