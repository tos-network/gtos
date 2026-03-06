package referral

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

var h = &referralHandler{}

// tAddr generates a deterministic test address.
func tAddr(b byte) common.Address { return common.Address{b} }

// bindSA creates a REFERRAL_BIND SysAction with the given referrer address.
func bindSA(referrer common.Address) *sysaction.SysAction {
	payload, _ := json.Marshal(struct {
		Referrer string `json:"referrer"`
	}{Referrer: referrer.Hex()})
	return &sysaction.SysAction{
		Action:  sysaction.ActionReferralBind,
		Payload: payload,
	}
}

// TestReferralBindBasic verifies that a basic bind sets referrer, direct count,
// and team size correctly.
func TestReferralBindBasic(t *testing.T) {
	st := newTestState()
	a := tAddr(0x01)
	b := tAddr(0x02)

	// A binds B as referrer.
	if err := h.Handle(newCtx(st, a, big.NewInt(0)), bindSA(b)); err != nil {
		t.Fatalf("bind: %v", err)
	}

	if !HasReferrer(st, a) {
		t.Error("HasReferrer(A): want true, got false")
	}
	if got := ReadReferrer(st, a); got != b {
		t.Errorf("ReadReferrer(A): want %v, got %v", b, got)
	}
	if got := ReadDirectCount(st, b); got != 1 {
		t.Errorf("ReadDirectCount(B): want 1, got %d", got)
	}
	if got := ReadTeamSize(st, b); got != 1 {
		t.Errorf("ReadTeamSize(B): want 1, got %d", got)
	}
}

// TestReferralSelf verifies that binding yourself as referrer returns ErrReferralSelf.
func TestReferralSelf(t *testing.T) {
	st := newTestState()
	a := tAddr(0x01)

	if err := h.Handle(newCtx(st, a, big.NewInt(0)), bindSA(a)); err != ErrReferralSelf {
		t.Errorf("self-bind: want ErrReferralSelf, got %v", err)
	}
}

// TestReferralAlreadyBound verifies that a second bind attempt returns ErrReferralAlreadyBound.
func TestReferralAlreadyBound(t *testing.T) {
	st := newTestState()
	a := tAddr(0x01)
	b := tAddr(0x02)
	c := tAddr(0x03)

	if err := h.Handle(newCtx(st, a, big.NewInt(0)), bindSA(b)); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	if err := h.Handle(newCtx(st, a, big.NewInt(0)), bindSA(c)); err != ErrReferralAlreadyBound {
		t.Errorf("second bind: want ErrReferralAlreadyBound, got %v", err)
	}
}

// TestReferralCircular verifies that a binding that would create a cycle
// returns ErrReferralCircular.
func TestReferralCircular(t *testing.T) {
	st := newTestState()
	a := tAddr(0x01)
	b := tAddr(0x02)

	// B binds A as referrer first.
	if err := h.Handle(newCtx(st, b, big.NewInt(0)), bindSA(a)); err != nil {
		t.Fatalf("B->A bind: %v", err)
	}
	// A tries to bind B — would create A->B->A cycle.
	if err := h.Handle(newCtx(st, a, big.NewInt(0)), bindSA(b)); err != ErrReferralCircular {
		t.Errorf("circular bind: want ErrReferralCircular, got %v", err)
	}
}

// TestReferralChain verifies multi-level chain properties.
// Chain: A's referrer = B, B's referrer = C.
func TestReferralChain(t *testing.T) {
	st := newTestState()
	a := tAddr(0x01)
	b := tAddr(0x02)
	c := tAddr(0x03)

	// B binds C as referrer.
	if err := h.Handle(newCtx(st, b, big.NewInt(0)), bindSA(c)); err != nil {
		t.Fatalf("B->C bind: %v", err)
	}
	// A binds B as referrer.
	if err := h.Handle(newCtx(st, a, big.NewInt(0)), bindSA(b)); err != nil {
		t.Fatalf("A->B bind: %v", err)
	}

	uplines := GetUplines(st, a, 2)
	if len(uplines) != 2 {
		t.Fatalf("GetUplines(A,2): want len=2, got %d", len(uplines))
	}
	if uplines[0] != b {
		t.Errorf("uplines[0]: want %v, got %v", b, uplines[0])
	}
	if uplines[1] != c {
		t.Errorf("uplines[1]: want %v, got %v", c, uplines[1])
	}

	if got := GetReferralDepth(st, a); got != 2 {
		t.Errorf("GetReferralDepth(A): want 2, got %d", got)
	}

	if !IsDownline(st, b, a, 5) {
		t.Error("IsDownline(B,A,5): want true, got false")
	}
	if !IsDownline(st, c, a, 5) {
		t.Error("IsDownline(C,A,5): want true, got false")
	}
	// C is a root; A is not an ancestor of C.
	if IsDownline(st, a, c, 5) {
		t.Error("IsDownline(A,C,5): want false, got true")
	}
}

// TestAddTeamVolume verifies that AddTeamVolume distributes volume correctly
// through the upline chain.
// Chain: A's referrer = B, B's referrer = C.
func TestAddTeamVolume(t *testing.T) {
	st := newTestState()
	a := tAddr(0x01)
	b := tAddr(0x02)
	c := tAddr(0x03)

	// Build A->B->C chain.
	if err := h.Handle(newCtx(st, b, big.NewInt(0)), bindSA(c)); err != nil {
		t.Fatalf("B->C bind: %v", err)
	}
	if err := h.Handle(newCtx(st, a, big.NewInt(0)), bindSA(b)); err != nil {
		t.Fatalf("A->B bind: %v", err)
	}

	amount := big.NewInt(100)
	AddTeamVolume(st, a, amount, 2)

	// B is level 1: both team_volume and direct_volume should be 100.
	if got := ReadTeamVolume(st, b); got.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("ReadTeamVolume(B): want 100, got %s", got)
	}
	if got := ReadDirectVolume(st, b); got.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("ReadDirectVolume(B): want 100, got %s", got)
	}

	// C is level 2: team_volume=100, direct_volume=0.
	if got := ReadTeamVolume(st, c); got.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("ReadTeamVolume(C): want 100, got %s", got)
	}
	if got := ReadDirectVolume(st, c); got.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("ReadDirectVolume(C): want 0, got %s", got)
	}
}
