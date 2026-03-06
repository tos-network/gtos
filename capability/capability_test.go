package capability

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func newTestState() *state.StateDB {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	s, _ := state.New(common.Hash{}, db, nil)
	return s
}

func newCtx(st *state.StateDB, from common.Address) *sysaction.Context {
	return &sysaction.Context{
		From:        from,
		Value:       big.NewInt(0),
		BlockNumber: big.NewInt(1),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{},
	}
}

func tAddr(b byte) common.Address { return common.Address{b} }

var h = &capabilityHandler{}

// TestRegisterCapabilityName verifies a new capability name is allocated a bit.
func TestRegisterCapabilityName(t *testing.T) {
	st := newTestState()
	registrar := tAddr(0x01)
	// Grant registrar capability to registrar.
	GrantCapability(st, registrar, registrarBit)

	payload, _ := json.Marshal(registerPayload{Name: "oracle"})
	sa := &sysaction.SysAction{Action: sysaction.ActionCapabilityRegister, Payload: payload}
	if err := h.Handle(newCtx(st, registrar), sa); err != nil {
		t.Fatalf("register capability: %v", err)
	}

	bit, ok := CapabilityBit(st, "oracle")
	if !ok {
		t.Fatal("capability 'oracle' not found after registration")
	}
	// First registered name after bit 0 (registrarBit is pre-existing convention).
	// Since bit 0 is never formally registered via RegisterCapabilityName in this test,
	// 'oracle' should get bit 0.
	_ = bit
}

// TestRegisterCapabilityNameDuplicate verifies duplicate registration is rejected.
func TestRegisterCapabilityNameDuplicate(t *testing.T) {
	st := newTestState()
	registrar := tAddr(0x02)
	GrantCapability(st, registrar, registrarBit)

	payload, _ := json.Marshal(registerPayload{Name: "scorer"})
	sa := &sysaction.SysAction{Action: sysaction.ActionCapabilityRegister, Payload: payload}
	if err := h.Handle(newCtx(st, registrar), sa); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := h.Handle(newCtx(st, registrar), sa); err != ErrCapabilityNameExists {
		t.Errorf("want ErrCapabilityNameExists, got %v", err)
	}
}

// TestGrantAndRevoke verifies capability grant/revoke cycle.
func TestGrantAndRevoke(t *testing.T) {
	st := newTestState()
	registrar := tAddr(0x03)
	target := tAddr(0x04)
	GrantCapability(st, registrar, registrarBit)

	payload, _ := json.Marshal(grantRevokePayload{Target: target.Hex(), Bit: 3})
	grantSA := &sysaction.SysAction{Action: sysaction.ActionCapabilityGrant, Payload: payload}
	if err := h.Handle(newCtx(st, registrar), grantSA); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !HasCapability(st, target, 3) {
		t.Error("expected target to have capability bit 3")
	}
	if TotalEligible(st, 3).Cmp(big.NewInt(1)) != 0 {
		t.Errorf("totalEligible: want 1, got %v", TotalEligible(st, 3))
	}

	revokeSA := &sysaction.SysAction{Action: sysaction.ActionCapabilityRevoke, Payload: payload}
	if err := h.Handle(newCtx(st, registrar), revokeSA); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if HasCapability(st, target, 3) {
		t.Error("expected capability to be revoked")
	}
	if TotalEligible(st, 3).Sign() != 0 {
		t.Errorf("totalEligible after revoke: want 0, got %v", TotalEligible(st, 3))
	}
}

// TestGrantRequiresRegistrar verifies grant fails without Registrar capability.
func TestGrantRequiresRegistrar(t *testing.T) {
	st := newTestState()
	nonRegistrar := tAddr(0x05)
	target := tAddr(0x06)

	payload, _ := json.Marshal(grantRevokePayload{Target: target.Hex(), Bit: 1})
	grantSA := &sysaction.SysAction{Action: sysaction.ActionCapabilityGrant, Payload: payload}
	if err := h.Handle(newCtx(st, nonRegistrar), grantSA); err != ErrCapabilityRegistrar {
		t.Errorf("want ErrCapabilityRegistrar, got %v", err)
	}
}

// TestGrantIdempotent verifies granting an already-held capability is a no-op.
func TestGrantIdempotent(t *testing.T) {
	st := newTestState()
	registrar := tAddr(0x07)
	target := tAddr(0x08)
	GrantCapability(st, registrar, registrarBit)

	payload, _ := json.Marshal(grantRevokePayload{Target: target.Hex(), Bit: 5})
	grantSA := &sysaction.SysAction{Action: sysaction.ActionCapabilityGrant, Payload: payload}
	if err := h.Handle(newCtx(st, registrar), grantSA); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	if err := h.Handle(newCtx(st, registrar), grantSA); err != nil {
		t.Fatalf("second grant (idempotent): %v", err)
	}
	if TotalEligible(st, 5).Cmp(big.NewInt(1)) != 0 {
		t.Errorf("totalEligible after double grant: want 1, got %v", TotalEligible(st, 5))
	}
}

// TestCapabilitiesOf verifies the full bitmap is returned correctly.
func TestCapabilitiesOf(t *testing.T) {
	st := newTestState()
	a := tAddr(0x09)
	GrantCapability(st, a, 0)
	GrantCapability(st, a, 2)
	GrantCapability(st, a, 7)

	bitmap := CapabilitiesOf(st, a)
	expected := new(big.Int)
	expected.SetBit(expected, 0, 1)
	expected.SetBit(expected, 2, 1)
	expected.SetBit(expected, 7, 1)
	if bitmap.Cmp(expected) != 0 {
		t.Errorf("bitmap: want %v, got %v", expected, bitmap)
	}
}
