package agent

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

func newTestState() *state.StateDB {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	s, _ := state.New(common.Hash{}, db, nil)
	return s
}

func newCtx(st *state.StateDB, from common.Address, value *big.Int) *sysaction.Context {
	return &sysaction.Context{
		From:        from,
		Value:       value,
		BlockNumber: big.NewInt(1),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{},
	}
}

func tAddr(b byte) common.Address { return common.Address{b} }

func fund(st *state.StateDB, a common.Address, amount *big.Int) {
	extra := new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18))
	st.AddBalance(a, new(big.Int).Add(amount, extra))
}

var h = &agentHandler{}

var regSA = &sysaction.SysAction{Action: sysaction.ActionAgentRegister}

// TestRegisterHappyPath verifies successful agent registration.
func TestRegisterHappyPath(t *testing.T) {
	st := newTestState()
	a := tAddr(0x01)
	fund(st, a, params.AgentMinStake)

	if err := h.Handle(newCtx(st, a, params.AgentMinStake), regSA); err != nil {
		t.Fatalf("register: %v", err)
	}

	if !IsRegistered(st, a) {
		t.Error("expected agent to be registered")
	}
	if ReadStatus(st, a) != AgentActive {
		t.Error("expected agent to be active")
	}
	if ReadStake(st, a).Cmp(params.AgentMinStake) != 0 {
		t.Errorf("stake mismatch: want %v, got %v", params.AgentMinStake, ReadStake(st, a))
	}
}

// TestRegisterTwice verifies duplicate registration is rejected.
func TestRegisterTwice(t *testing.T) {
	st := newTestState()
	a := tAddr(0x02)
	fund(st, a, params.AgentMinStake)

	if err := h.Handle(newCtx(st, a, params.AgentMinStake), regSA); err != nil {
		t.Fatalf("first register: %v", err)
	}
	fund(st, a, params.AgentMinStake)
	if err := h.Handle(newCtx(st, a, params.AgentMinStake), regSA); err != ErrAgentAlreadyRegistered {
		t.Errorf("want ErrAgentAlreadyRegistered, got %v", err)
	}
}

// TestRegisterInsufficientStake verifies stake below minimum is rejected.
func TestRegisterInsufficientStake(t *testing.T) {
	st := newTestState()
	a := tAddr(0x03)
	below := new(big.Int).Sub(params.AgentMinStake, big.NewInt(1))
	fund(st, a, below)

	if err := h.Handle(newCtx(st, a, below), regSA); err != ErrAgentInsufficientStake {
		t.Errorf("want ErrAgentInsufficientStake, got %v", err)
	}
}

// TestRegisterInsufficientBalance verifies balance check.
func TestRegisterInsufficientBalance(t *testing.T) {
	st := newTestState()
	a := tAddr(0x04)
	// Do NOT fund — balance is zero.
	if err := h.Handle(newCtx(st, a, params.AgentMinStake), regSA); err != ErrAgentInsufficientBalance {
		t.Errorf("want ErrAgentInsufficientBalance, got %v", err)
	}
}

// TestIncreaseStake verifies stake can be increased after registration.
func TestIncreaseStake(t *testing.T) {
	st := newTestState()
	a := tAddr(0x05)
	fund(st, a, params.AgentMinStake)

	if err := h.Handle(newCtx(st, a, params.AgentMinStake), regSA); err != nil {
		t.Fatalf("register: %v", err)
	}

	extra := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	fund(st, a, extra)
	incrSA := &sysaction.SysAction{Action: sysaction.ActionAgentIncreaseStake}
	if err := h.Handle(newCtx(st, a, extra), incrSA); err != nil {
		t.Fatalf("increase stake: %v", err)
	}

	expected := new(big.Int).Add(params.AgentMinStake, extra)
	if ReadStake(st, a).Cmp(expected) != 0 {
		t.Errorf("stake: want %v, got %v", expected, ReadStake(st, a))
	}
}

// TestDecreaseStake verifies full withdrawal zeroes stake and sets inactive.
func TestDecreaseStake(t *testing.T) {
	st := newTestState()
	a := tAddr(0x06)
	fund(st, a, params.AgentMinStake)

	if err := h.Handle(newCtx(st, a, params.AgentMinStake), regSA); err != nil {
		t.Fatalf("register: %v", err)
	}

	payload, _ := json.Marshal(decreaseStakePayload{Amount: params.AgentMinStake.String()})
	decrSA := &sysaction.SysAction{
		Action:  sysaction.ActionAgentDecreaseStake,
		Payload: payload,
	}
	if err := h.Handle(newCtx(st, a, big.NewInt(0)), decrSA); err != nil {
		t.Fatalf("decrease stake: %v", err)
	}

	if ReadStake(st, a).Sign() != 0 {
		t.Error("expected zero stake after full withdrawal")
	}
	if ReadStatus(st, a) != AgentInactive {
		t.Error("expected agent to be inactive after full withdrawal")
	}
}

// TestSuspendRequiresCapability verifies suspend fails without Registrar capability.
func TestSuspendRequiresCapability(t *testing.T) {
	st := newTestState()
	caller := tAddr(0x07)
	target := tAddr(0x08)

	// Register target.
	fund(st, target, params.AgentMinStake)
	if err := h.Handle(newCtx(st, target, params.AgentMinStake), regSA); err != nil {
		t.Fatalf("register target: %v", err)
	}

	payload, _ := json.Marshal(targetPayload{Target: target.Hex()})
	suspSA := &sysaction.SysAction{
		Action:  sysaction.ActionAgentSuspend,
		Payload: payload,
	}
	// caller has no Registrar capability.
	if err := h.Handle(newCtx(st, caller, big.NewInt(0)), suspSA); err != ErrCapabilityRequired {
		t.Errorf("want ErrCapabilityRequired, got %v", err)
	}
}

// TestSuspendAndUnsuspend verifies suspend/unsuspend with proper capability.
func TestSuspendAndUnsuspend(t *testing.T) {
	st := newTestState()
	registrar := tAddr(0x09)
	target := tAddr(0x0A)

	// Grant registrar capability to registrar address.
	capability.GrantCapability(st, registrar, registrarBit)

	// Register target.
	fund(st, target, params.AgentMinStake)
	if err := h.Handle(newCtx(st, target, params.AgentMinStake), regSA); err != nil {
		t.Fatalf("register target: %v", err)
	}

	payload, _ := json.Marshal(targetPayload{Target: target.Hex()})
	suspSA := &sysaction.SysAction{Action: sysaction.ActionAgentSuspend, Payload: payload}
	if err := h.Handle(newCtx(st, registrar, big.NewInt(0)), suspSA); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if !IsSuspended(st, target) {
		t.Error("expected target to be suspended")
	}

	unsuspSA := &sysaction.SysAction{Action: sysaction.ActionAgentUnsuspend, Payload: payload}
	if err := h.Handle(newCtx(st, registrar, big.NewInt(0)), unsuspSA); err != nil {
		t.Fatalf("unsuspend: %v", err)
	}
	if IsSuspended(st, target) {
		t.Error("expected target to not be suspended")
	}
}

// TestUpdateProfile verifies metadata URI can be updated by the agent.
func TestUpdateProfile(t *testing.T) {
	st := newTestState()
	a := tAddr(0x0B)
	fund(st, a, params.AgentMinStake)

	if err := h.Handle(newCtx(st, a, params.AgentMinStake), regSA); err != nil {
		t.Fatalf("register: %v", err)
	}

	uri := "ipfs://QmTest"
	payload, _ := json.Marshal(updateProfilePayload{URI: uri})
	profSA := &sysaction.SysAction{Action: sysaction.ActionAgentUpdateProfile, Payload: payload}
	if err := h.Handle(newCtx(st, a, big.NewInt(0)), profSA); err != nil {
		t.Fatalf("update profile: %v", err)
	}

	if got := MetadataOf(st, a); got != uri {
		t.Errorf("metadata: want %q, got %q", uri, got)
	}
}

// TestListAppendOnce verifies that re-registration after full withdrawal does not
// duplicate the address in the list.
func TestListAppendOnce(t *testing.T) {
	st := newTestState()
	a := tAddr(0x0C)
	fund(st, a, params.AgentMinStake)

	if err := h.Handle(newCtx(st, a, params.AgentMinStake), regSA); err != nil {
		t.Fatalf("first register: %v", err)
	}

	// Full withdrawal.
	payload, _ := json.Marshal(decreaseStakePayload{Amount: params.AgentMinStake.String()})
	decrSA := &sysaction.SysAction{Action: sysaction.ActionAgentDecreaseStake, Payload: payload}
	if err := h.Handle(newCtx(st, a, big.NewInt(0)), decrSA); err != nil {
		t.Fatalf("decrease stake: %v", err)
	}

	// Re-register.
	fund(st, a, params.AgentMinStake)
	if err := h.Handle(newCtx(st, a, params.AgentMinStake), regSA); err != nil {
		t.Fatalf("re-register: %v", err)
	}

	// List must have exactly one entry.
	if cnt := readAgentCount(st); cnt != 1 {
		t.Errorf("agent list count: want 1, got %d", cnt)
	}
}
