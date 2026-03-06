package kyc

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

// newTestState creates a fresh in-memory StateDB for tests.
func newTestState() *state.StateDB {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	s, _ := state.New(common.Hash{}, db, nil)
	return s
}

// newCtx creates a sysaction.Context with the given from address and value.
func newCtx(st *state.StateDB, from common.Address, value *big.Int) *sysaction.Context {
	return &sysaction.Context{
		From:        from,
		Value:       value,
		BlockNumber: big.NewInt(1),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{},
	}
}

var h = &kycHandler{}

// tAddr generates a deterministic test address.
func tAddr(b byte) common.Address { return common.Address{b} }

// mustMarshal is a helper to produce JSON payload bytes for a sysaction.
func mustMarshal(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// TestKYCSetByNonCommittee verifies that KYC_SET without the KYC committee
// capability returns ErrKYCNotCommittee.
func TestKYCSetByNonCommittee(t *testing.T) {
	st := newTestState()
	caller := tAddr(0x01)
	target := tAddr(0x02)

	sa := &sysaction.SysAction{
		Action: sysaction.ActionKYCSet,
		Payload: mustMarshal(setPayload{
			Target: target.Hex(),
			Level:  KycLevelBasic,
		}),
	}
	if err := h.Handle(newCtx(st, caller, big.NewInt(0)), sa); err != ErrKYCNotCommittee {
		t.Errorf("want ErrKYCNotCommittee, got %v", err)
	}
}

// TestKYCSetInvalidLevel verifies that a non-cumulative level (5) is rejected
// with ErrKYCInvalidLevel.
func TestKYCSetInvalidLevel(t *testing.T) {
	st := newTestState()
	caller := tAddr(0x03)
	target := tAddr(0x04)

	// Grant committee capability to caller.
	capability.GrantCapability(st, caller, params.KYCCommitteeBit)

	sa := &sysaction.SysAction{
		Action: sysaction.ActionKYCSet,
		Payload: mustMarshal(setPayload{
			Target: target.Hex(),
			Level:  5, // not a valid cumulative value
		}),
	}
	if err := h.Handle(newCtx(st, caller, big.NewInt(0)), sa); err != ErrKYCInvalidLevel {
		t.Errorf("want ErrKYCInvalidLevel, got %v", err)
	}
}

// TestKYCSetValid verifies that a committee member can set a valid KYC level and
// that ReadLevel, ReadStatus, and MeetsLevel return the expected values.
func TestKYCSetValid(t *testing.T) {
	st := newTestState()
	caller := tAddr(0x05)
	target := tAddr(0x06)

	capability.GrantCapability(st, caller, params.KYCCommitteeBit)

	sa := &sysaction.SysAction{
		Action: sysaction.ActionKYCSet,
		Payload: mustMarshal(setPayload{
			Target: target.Hex(),
			Level:  KycLevelIdentity, // 31
		}),
	}
	if err := h.Handle(newCtx(st, caller, big.NewInt(0)), sa); err != nil {
		t.Fatalf("KYC_SET: %v", err)
	}

	if got := ReadLevel(st, target); got != KycLevelIdentity {
		t.Errorf("ReadLevel: want %d, got %d", KycLevelIdentity, got)
	}
	if got := ReadStatus(st, target); got != KycActive {
		t.Errorf("ReadStatus: want KycActive, got %v", got)
	}
	if !MeetsLevel(st, target, KycLevelIdentity) {
		t.Error("MeetsLevel(31): want true, got false")
	}
	if MeetsLevel(st, target, KycLevelAddress) {
		t.Error("MeetsLevel(63): want false, got true")
	}
}

// TestKYCSuspend verifies that after setting KYC and then suspending, the
// status is KycSuspended and MeetsLevel returns false.
func TestKYCSuspend(t *testing.T) {
	st := newTestState()
	caller := tAddr(0x07)
	target := tAddr(0x08)

	capability.GrantCapability(st, caller, params.KYCCommitteeBit)

	// Set KYC first.
	setSA := &sysaction.SysAction{
		Action: sysaction.ActionKYCSet,
		Payload: mustMarshal(setPayload{
			Target: target.Hex(),
			Level:  KycLevelBasic, // 7
		}),
	}
	if err := h.Handle(newCtx(st, caller, big.NewInt(0)), setSA); err != nil {
		t.Fatalf("KYC_SET: %v", err)
	}

	// Now suspend.
	suspendSA := &sysaction.SysAction{
		Action: sysaction.ActionKYCSuspend,
		Payload: mustMarshal(suspendPayload{
			Target: target.Hex(),
		}),
	}
	if err := h.Handle(newCtx(st, caller, big.NewInt(0)), suspendSA); err != nil {
		t.Fatalf("KYC_SUSPEND: %v", err)
	}

	if got := ReadStatus(st, target); got != KycSuspended {
		t.Errorf("ReadStatus: want KycSuspended, got %v", got)
	}
	if MeetsLevel(st, target, KycLevelBasic) {
		t.Error("MeetsLevel after suspend: want false, got true")
	}
	// Level bits must be preserved after suspension.
	if got := ReadLevel(st, target); got != KycLevelBasic {
		t.Errorf("ReadLevel after suspend: want %d, got %d", KycLevelBasic, got)
	}
}

// TestKYCSuspendNonActive verifies that suspending an account with no active KYC
// record returns ErrKYCNotActive.
func TestKYCSuspendNonActive(t *testing.T) {
	st := newTestState()
	caller := tAddr(0x09)
	target := tAddr(0x0a)

	capability.GrantCapability(st, caller, params.KYCCommitteeBit)

	sa := &sysaction.SysAction{
		Action: sysaction.ActionKYCSuspend,
		Payload: mustMarshal(suspendPayload{
			Target: target.Hex(),
		}),
	}
	if err := h.Handle(newCtx(st, caller, big.NewInt(0)), sa); err != ErrKYCNotActive {
		t.Errorf("want ErrKYCNotActive, got %v", err)
	}
}
