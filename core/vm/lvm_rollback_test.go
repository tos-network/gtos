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
	"strings"
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

// ===========================================================================
// tos.multicall tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Test: All calls in multicall succeed → all mutations persist.
// ---------------------------------------------------------------------------
func TestMulticallAllSucceed(t *testing.T) {
	contractA := common.Address{0xE1}
	codeA := `tos.sstore("slotA", 111)`

	contractB := common.Address{0xE2}
	codeB := `tos.sstore("slotB", 222)`

	parentAddr := common.Address{0xE0}
	parentCode := fmt.Sprintf(`
		local ok, results = tos.multicall({
			{ addr = %q, data = "" },
			{ addr = %q, data = "" },
		})
		tos.sstore("ok", ok and 1 or 0)
	`, contractA.Hex(), contractB.Hex())

	st := newAgentTestState()
	st.CreateAccount(contractA)
	st.SetCode(contractA, []byte(codeA))
	st.CreateAccount(contractB)
	st.SetCode(contractB, []byte(codeB))
	st.CreateAccount(parentAddr)

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err != nil {
		t.Fatalf("parent execution failed: %v", err)
	}

	// ok should be 1 (true).
	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 1 {
		t.Fatalf("ok: want 1 (all succeeded), got %d", got)
	}

	// Contract A's storage should be persisted.
	valA := st.GetState(contractA, StorageSlot("slotA"))
	if got := new(big.Int).SetBytes(valA[:]).Uint64(); got != 111 {
		t.Fatalf("slotA: want 111, got %d", got)
	}

	// Contract B's storage should be persisted.
	valB := st.GetState(contractB, StorageSlot("slotB"))
	if got := new(big.Int).SetBytes(valB[:]).Uint64(); got != 222 {
		t.Fatalf("slotB: want 222, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Test: Second call fails → first call's mutations are rolled back.
// ---------------------------------------------------------------------------
func TestMulticallSecondFailsFirstRolledBack(t *testing.T) {
	contractA := common.Address{0xE3}
	codeA := `tos.sstore("slotA", 333)`

	contractB := common.Address{0xE4}
	codeB := `
		tos.sstore("slotB", 444)
		error("fail")
	`

	parentAddr := common.Address{0xE5}
	parentCode := fmt.Sprintf(`
		local ok, results = tos.multicall({
			{ addr = %q, data = "" },
			{ addr = %q, data = "" },
		})
		tos.sstore("ok", ok and 1 or 0)
	`, contractA.Hex(), contractB.Hex())

	st := newAgentTestState()
	st.CreateAccount(contractA)
	st.SetCode(contractA, []byte(codeA))
	st.CreateAccount(contractB)
	st.SetCode(contractB, []byte(codeB))
	st.CreateAccount(parentAddr)

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err != nil {
		t.Fatalf("parent execution failed: %v", err)
	}

	// ok should be 0 (false — second call reverted).
	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 0 {
		t.Fatalf("ok: want 0 (second call reverted), got %d", got)
	}

	// Contract A's storage must be rolled back to zero.
	valA := st.GetState(contractA, StorageSlot("slotA"))
	if valA != (common.Hash{}) {
		t.Fatalf("slotA after rollback: want zero, got %x", valA[:])
	}

	// Contract B's storage must also be zero (it reverted mid-execution).
	valB := st.GetState(contractB, StorageSlot("slotB"))
	if valB != (common.Hash{}) {
		t.Fatalf("slotB after rollback: want zero, got %x", valB[:])
	}
}

// ---------------------------------------------------------------------------
// Test: Middle call of 3 fails → all 3 contracts' mutations are rolled back.
// ---------------------------------------------------------------------------
func TestMulticallMiddleFailsAllRolledBack(t *testing.T) {
	contractA := common.Address{0xE6}
	codeA := `tos.sstore("slotA", 10)`

	contractB := common.Address{0xE7}
	codeB := `
		tos.sstore("slotB", 20)
		error("middle fail")
	`

	contractC := common.Address{0xE8}
	codeC := `tos.sstore("slotC", 30)`

	parentAddr := common.Address{0xE9}
	parentCode := fmt.Sprintf(`
		local ok, results = tos.multicall({
			{ addr = %q, data = "" },
			{ addr = %q, data = "" },
			{ addr = %q, data = "" },
		})
		tos.sstore("ok", ok and 1 or 0)
	`, contractA.Hex(), contractB.Hex(), contractC.Hex())

	st := newAgentTestState()
	st.CreateAccount(contractA)
	st.SetCode(contractA, []byte(codeA))
	st.CreateAccount(contractB)
	st.SetCode(contractB, []byte(codeB))
	st.CreateAccount(contractC)
	st.SetCode(contractC, []byte(codeC))
	st.CreateAccount(parentAddr)

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err != nil {
		t.Fatalf("parent execution failed: %v", err)
	}

	// ok should be 0 (middle call reverted).
	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 0 {
		t.Fatalf("ok: want 0 (middle call reverted), got %d", got)
	}

	// All three contracts' storage slots must be zero.
	for _, tc := range []struct {
		addr common.Address
		slot string
	}{
		{contractA, "slotA"},
		{contractB, "slotB"},
		{contractC, "slotC"},
	} {
		val := st.GetState(tc.addr, StorageSlot(tc.slot))
		if val != (common.Hash{}) {
			t.Fatalf("%s on %x after rollback: want zero, got %x", tc.slot, tc.addr, val[:])
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Value transfer is rolled back when a later call fails.
// ---------------------------------------------------------------------------
func TestMulticallValueTransferRollback(t *testing.T) {
	contractA := common.Address{0xEA}
	codeA := `tos.sstore("got_value", tos.value)`

	contractB := common.Address{0xEB}
	codeB := `error("revert")`

	parentAddr := common.Address{0xEC}
	parentCode := fmt.Sprintf(`
		local ok, results = tos.multicall({
			{ addr = %q, data = "", value = 500 },
			{ addr = %q, data = "" },
		})
		tos.sstore("ok", ok and 1 or 0)
	`, contractA.Hex(), contractB.Hex())

	st := newAgentTestState()
	st.CreateAccount(contractA)
	st.SetCode(contractA, []byte(codeA))
	st.CreateAccount(contractB)
	st.SetCode(contractB, []byte(codeB))
	st.CreateAccount(parentAddr)

	// Fund the parent with 1000 wei.
	st.AddBalance(parentAddr, big.NewInt(1000))

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err != nil {
		t.Fatalf("parent execution failed: %v", err)
	}

	// ok should be 0 (second call failed).
	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 0 {
		t.Fatalf("ok: want 0 (second call reverted), got %d", got)
	}

	// Parent balance must be restored to 1000.
	parentBal := st.GetBalance(parentAddr)
	if parentBal.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("parent balance after rollback: want 1000, got %s", parentBal.String())
	}

	// Contract A should not have kept the 500 wei.
	aBal := st.GetBalance(contractA)
	if aBal.Sign() != 0 {
		t.Fatalf("contractA balance after rollback: want 0, got %s", aBal.String())
	}

	// Contract A's storage slot must also be rolled back.
	valA := st.GetState(contractA, StorageSlot("got_value"))
	if valA != (common.Hash{}) {
		t.Fatalf("contractA 'got_value' after rollback: want zero, got %x", valA[:])
	}
}

// ---------------------------------------------------------------------------
// Test: multicall in a readonly (staticcall) context is rejected.
// ---------------------------------------------------------------------------
func TestMulticallInStaticCallRejected(t *testing.T) {
	parentAddr := common.Address{0xED}
	parentCode := `
		local ok, results = tos.multicall({})
	`

	st := newAgentTestState()
	st.CreateAccount(parentAddr)

	ctx := CallCtx{
		From:     common.Address{0xFF},
		To:       parentAddr,
		Value:    big.NewInt(0),
		Data:     []byte{},
		TxOrigin: common.Address{0xFF},
		TxPrice:  big.NewInt(1),
		Readonly: true,
	}
	_, _, _, err := Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(parentCode), 5_000_000)
	if err == nil {
		t.Fatal("expected error for multicall in readonly context")
	}
	// Error should mention staticcall or readonly.
	errMsg := err.Error()
	if !strings.Contains(errMsg, "staticcall") && !strings.Contains(errMsg, "readonly") && !strings.Contains(errMsg, "static") && !strings.Contains(errMsg, "read-only") {
		t.Fatalf("error should mention staticcall/readonly, got: %s", errMsg)
	}
}

// ---------------------------------------------------------------------------
// Test: multicall with empty table returns (true, ...) with no error.
// ---------------------------------------------------------------------------
func TestMulticallEmptyTable(t *testing.T) {
	parentAddr := common.Address{0xEE}
	parentCode := `
		local ok, results = tos.multicall({})
		if not ok then
			error("expected ok=true for empty multicall")
		end
		tos.sstore("ok", 1)
	`

	st := newAgentTestState()
	st.CreateAccount(parentAddr)

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err != nil {
		t.Fatalf("empty multicall failed: %v", err)
	}

	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 1 {
		t.Fatalf("ok: want 1, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Test: Revert data from a failing child propagates through multicall.
// ---------------------------------------------------------------------------
func TestMulticallRevertDataPropagation(t *testing.T) {
	childAddr := common.Address{0xEF}
	childCode := `tos.revert("InsufficientFunds", "uint256", 42)`

	parentAddr := common.Address{0xF0}
	parentCode := fmt.Sprintf(`
		local ok, revertData = tos.multicall({
			{ addr = %q, data = "" },
		})
		tos.sstore("ok", ok and 1 or 0)
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

	// ok should be 0 (child reverted).
	okSlot := st.GetState(parentAddr, StorageSlot("ok"))
	if got := new(big.Int).SetBytes(okSlot[:]).Uint64(); got != 0 {
		t.Fatalf("ok: want 0 (child reverted), got %d", got)
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

// ---------------------------------------------------------------------------
// Test: Invalid descriptor fields fail fast and roll back earlier successes.
// ---------------------------------------------------------------------------
func TestMulticallInvalidDescriptorRejected(t *testing.T) {
	contractA := common.Address{0xF1}
	codeA := `tos.sstore("slotA", 777)`

	parentAddr := common.Address{0xF2}
	parentCode := fmt.Sprintf(`
		local ok, results = tos.multicall({
			{ addr = %q, data = "" },
			{ addr = %q, data = "", value = "not-a-number" },
		})
		tos.sstore("ok", ok and 1 or 0)
	`, contractA.Hex(), contractA.Hex())

	st := newAgentTestState()
	st.CreateAccount(contractA)
	st.SetCode(contractA, []byte(codeA))
	st.CreateAccount(parentAddr)

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err == nil {
		t.Fatal("expected invalid descriptor to raise an error")
	}
	if !strings.Contains(err.Error(), "invalid 'value'") {
		t.Fatalf("unexpected error: %v", err)
	}

	valA := st.GetState(contractA, StorageSlot("slotA"))
	if valA != (common.Hash{}) {
		t.Fatalf("slotA after invalid descriptor: want zero, got %x", valA[:])
	}
}

// ---------------------------------------------------------------------------
// Test: Malformed addr hex fails fast and rolls back earlier successes.
// ---------------------------------------------------------------------------
func TestMulticallMalformedAddrRejected(t *testing.T) {
	contractA := common.Address{0xF8}
	codeA := `tos.sstore("slotA", 321)`

	parentAddr := common.Address{0xF9}
	parentCode := fmt.Sprintf(`
		local ok, results = tos.multicall({
			{ addr = %q, data = "" },
			{ addr = "0x00000000000000000000000000000000000000zz", data = "" },
		})
		tos.sstore("ok", ok and 1 or 0)
	`, contractA.Hex())

	st := newAgentTestState()
	st.CreateAccount(contractA)
	st.SetCode(contractA, []byte(codeA))
	st.CreateAccount(parentAddr)

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err == nil {
		t.Fatal("expected malformed addr descriptor to raise an error")
	}
	if !strings.Contains(err.Error(), "invalid 'addr'") {
		t.Fatalf("unexpected error: %v", err)
	}

	valA := st.GetState(contractA, StorageSlot("slotA"))
	if valA != (common.Hash{}) {
		t.Fatalf("slotA after malformed addr descriptor: want zero, got %x", valA[:])
	}
}

// ---------------------------------------------------------------------------
// Test: Invalid data descriptor type fails fast and rolls back earlier successes.
// ---------------------------------------------------------------------------
func TestMulticallInvalidDataDescriptorRejected(t *testing.T) {
	contractA := common.Address{0xF6}
	codeA := `tos.sstore("slotA", 888)`

	parentAddr := common.Address{0xF7}
	parentCode := fmt.Sprintf(`
		local ok, results = tos.multicall({
			{ addr = %q, data = "" },
			{ addr = %q, data = 123 },
		})
		tos.sstore("ok", ok and 1 or 0)
	`, contractA.Hex(), contractA.Hex())

	st := newAgentTestState()
	st.CreateAccount(contractA)
	st.SetCode(contractA, []byte(codeA))
	st.CreateAccount(parentAddr)

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err == nil {
		t.Fatal("expected invalid data descriptor to raise an error")
	}
	if !strings.Contains(err.Error(), "invalid 'data'") {
		t.Fatalf("unexpected error: %v", err)
	}

	valA := st.GetState(contractA, StorageSlot("slotA"))
	if valA != (common.Hash{}) {
		t.Fatalf("slotA after invalid data descriptor: want zero, got %x", valA[:])
	}
}

// ---------------------------------------------------------------------------
// Test: Malformed data hex fails fast and rolls back earlier successes.
// ---------------------------------------------------------------------------
func TestMulticallMalformedDataRejected(t *testing.T) {
	contractA := common.Address{0xFA}
	codeA := `tos.sstore("slotA", 654)`

	parentAddr := common.Address{0xFB}
	parentCode := fmt.Sprintf(`
		local ok, results = tos.multicall({
			{ addr = %q, data = "" },
			{ addr = %q, data = "0x12zz" },
		})
		tos.sstore("ok", ok and 1 or 0)
	`, contractA.Hex(), contractA.Hex())

	st := newAgentTestState()
	st.CreateAccount(contractA)
	st.SetCode(contractA, []byte(codeA))
	st.CreateAccount(parentAddr)

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err == nil {
		t.Fatal("expected malformed data descriptor to raise an error")
	}
	if !strings.Contains(err.Error(), "invalid 'data'") {
		t.Fatalf("unexpected error: %v", err)
	}

	valA := st.GetState(contractA, StorageSlot("slotA"))
	if valA != (common.Hash{}) {
		t.Fatalf("slotA after malformed data descriptor: want zero, got %x", valA[:])
	}
}

// ---------------------------------------------------------------------------
// Test: Success results preserve call ordering even when children return no data.
// ---------------------------------------------------------------------------
func TestMulticallResultsPreserveDensePositions(t *testing.T) {
	contractA := common.Address{0xF3}
	codeA := `tos.sstore("slotA", 1)`

	contractB := common.Address{0xF4} // no code

	parentAddr := common.Address{0xF5}
	parentCode := fmt.Sprintf(`
		local ok, results = tos.multicall({
			{ addr = %q, data = "" },
			{ addr = %q, data = "" },
		})
		if not ok then
			error("expected multicall success")
		end
		tos.sstore("result_len", #results)
		tos.setStr("result_1", results[1] or "<nil>")
		tos.setStr("result_2", results[2] or "<nil>")
	`, contractA.Hex(), contractB.Hex())

	st := newAgentTestState()
	st.CreateAccount(contractA)
	st.SetCode(contractA, []byte(codeA))
	st.CreateAccount(contractB)
	st.CreateAccount(parentAddr)

	_, _, _, err := runLua(st, parentAddr, parentCode, 5_000_000)
	if err != nil {
		t.Fatalf("parent execution failed: %v", err)
	}

	lenSlot := st.GetState(parentAddr, StorageSlot("result_len"))
	if got := new(big.Int).SetBytes(lenSlot[:]).Uint64(); got != 2 {
		t.Fatalf("result_len: want 2, got %d", got)
	}
	if got := readStoredString(st, parentAddr, "result_1"); got != "0x" {
		t.Fatalf("result_1: want 0x, got %q", got)
	}
	if got := readStoredString(st, parentAddr, "result_2"); got != "0x" {
		t.Fatalf("result_2: want 0x, got %q", got)
	}
}
