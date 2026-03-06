package tns

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

func newCtx(st *state.StateDB, from common.Address, value *big.Int) *sysaction.Context {
	return &sysaction.Context{
		From:        from,
		Value:       value,
		BlockNumber: big.NewInt(1),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{},
	}
}

var h = &tnsHandler{}

// tAddr generates a deterministic test address.
func tAddr(b byte) common.Address { return common.Address{b} }

// fund gives an address enough balance to cover the fee plus 1 TOS for gas.
func fund(st *state.StateDB, a common.Address, amount *big.Int) {
	extra := new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)) // 1 extra TOS
	st.AddBalance(a, new(big.Int).Add(amount, extra))
}

// regSA builds a TNS_REGISTER SysAction with the given name.
func regSA(name string) *sysaction.SysAction {
	payload, _ := json.Marshal(map[string]string{"name": name})
	return &sysaction.SysAction{
		Action:  sysaction.ActionTNSRegister,
		Payload: payload,
	}
}

// TestTNSRegisterValid registers "alice" and verifies both mapping directions.
func TestTNSRegisterValid(t *testing.T) {
	st := newTestState()
	addr := tAddr(0x01)
	fund(st, addr, params.TNSRegistrationFee)

	if err := h.Handle(newCtx(st, addr, params.TNSRegistrationFee), regSA("alice")); err != nil {
		t.Fatalf("register: %v", err)
	}

	nameHash := HashName("alice")
	if got := Resolve(st, nameHash); got != addr {
		t.Errorf("Resolve: want %v, got %v", addr, got)
	}
	if !HasName(st, addr) {
		t.Errorf("HasName: want true, got false")
	}
}

// TestTNSRegisterDuplicateName verifies that registering the same name twice
// from a different account returns ErrTNSAlreadyRegistered.
func TestTNSRegisterDuplicateName(t *testing.T) {
	st := newTestState()
	addr1 := tAddr(0x01)
	addr2 := tAddr(0x02)
	fund(st, addr1, params.TNSRegistrationFee)
	fund(st, addr2, params.TNSRegistrationFee)

	if err := h.Handle(newCtx(st, addr1, params.TNSRegistrationFee), regSA("alice")); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := h.Handle(newCtx(st, addr2, params.TNSRegistrationFee), regSA("alice")); err != ErrTNSAlreadyRegistered {
		t.Errorf("second register: want ErrTNSAlreadyRegistered, got %v", err)
	}
}

// TestTNSRegisterSecondName verifies that registering a second name from the
// same account returns ErrTNSAccountHasName.
func TestTNSRegisterSecondName(t *testing.T) {
	st := newTestState()
	addr := tAddr(0x03)
	// Fund enough for two registrations.
	twoFee := new(big.Int).Mul(params.TNSRegistrationFee, big.NewInt(2))
	fund(st, addr, twoFee)

	if err := h.Handle(newCtx(st, addr, params.TNSRegistrationFee), regSA("alice")); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := h.Handle(newCtx(st, addr, params.TNSRegistrationFee), regSA("bob")); err != ErrTNSAccountHasName {
		t.Errorf("second name: want ErrTNSAccountHasName, got %v", err)
	}
}

// TestTNSRegisterInvalidName verifies that invalid name formats are all rejected.
func TestTNSRegisterInvalidName(t *testing.T) {
	st := newTestState()
	cases := []struct {
		name  string
		label string
	}{
		{"", "empty"},
		{"ab", "too short"},
		{"123abc", "digit start"},
		{"admin", "reserved"},
		{"alice.", "trailing separator"},
		{"alice..bob", "consecutive separators"},
	}

	for _, tc := range cases {
		addr := tAddr(0x10)
		fund(st, addr, params.TNSRegistrationFee)
		err := h.Handle(newCtx(st, addr, params.TNSRegistrationFee), regSA(tc.name))
		if err != ErrTNSInvalidName {
			t.Errorf("case %q (%s): want ErrTNSInvalidName, got %v", tc.name, tc.label, err)
		}
	}
}

// TestTNSRegisterInsufficientFee verifies that a zero-value ctx returns ErrTNSInsufficientFee.
func TestTNSRegisterInsufficientFee(t *testing.T) {
	st := newTestState()
	addr := tAddr(0x20)
	fund(st, addr, params.TNSRegistrationFee)

	if err := h.Handle(newCtx(st, addr, big.NewInt(0)), regSA("alice")); err != ErrTNSInsufficientFee {
		t.Errorf("want ErrTNSInsufficientFee, got %v", err)
	}
}

// TestTNSReverse verifies that after registering "alice", Reverse returns HashName("alice").
func TestTNSReverse(t *testing.T) {
	st := newTestState()
	addr := tAddr(0x30)
	fund(st, addr, params.TNSRegistrationFee)

	if err := h.Handle(newCtx(st, addr, params.TNSRegistrationFee), regSA("alice")); err != nil {
		t.Fatalf("register: %v", err)
	}

	want := HashName("alice")
	if got := Reverse(st, addr); got != want {
		t.Errorf("Reverse: want %v, got %v", want, got)
	}
}
