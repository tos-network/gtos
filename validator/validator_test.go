package validator

import (
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

var h = &validatorHandler{}

// tAddr generates a deterministic test address.
func tAddr(b byte) common.Address { return common.Address{b} }

// fund gives an address enough balance to cover the stake plus 1 TOS.
func fund(st *state.StateDB, a common.Address, amount *big.Int) {
	extra := new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)) // 1 extra TOS
	st.AddBalance(a, new(big.Int).Add(amount, extra))
}

// regSA and wdSA are convenience SysAction values.
var (
	regSA = &sysaction.SysAction{Action: sysaction.ActionValidatorRegister}
	wdSA  = &sysaction.SysAction{Action: sysaction.ActionValidatorWithdraw}
)

// TestRegisterTwice verifies that a second VALIDATOR_REGISTER returns ErrAlreadyRegistered.
func TestRegisterTwice(t *testing.T) {
	st := newTestState()
	a := tAddr(0x01)
	fund(st, a, params.DPoSMinValidatorStake)

	if err := h.Handle(newCtx(st, a, params.DPoSMinValidatorStake), regSA); err != nil {
		t.Fatalf("first register: %v", err)
	}
	// Fund again for second attempt (balance was deducted).
	fund(st, a, params.DPoSMinValidatorStake)
	if err := h.Handle(newCtx(st, a, params.DPoSMinValidatorStake), regSA); err != ErrAlreadyRegistered {
		t.Errorf("second register: want ErrAlreadyRegistered, got %v", err)
	}
}

// TestReregisterAfterWithdraw verifies that after withdrawing, re-registration
// succeeds and the address appears only once in the validator list.
func TestReregisterAfterWithdraw(t *testing.T) {
	st := newTestState()
	a := tAddr(0x02)
	fund(st, a, params.DPoSMinValidatorStake)

	if err := h.Handle(newCtx(st, a, params.DPoSMinValidatorStake), regSA); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := h.Handle(newCtx(st, a, big.NewInt(0)), wdSA); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	// Re-register after withdraw.
	fund(st, a, params.DPoSMinValidatorStake)
	if err := h.Handle(newCtx(st, a, params.DPoSMinValidatorStake), regSA); err != nil {
		t.Fatalf("re-register: %v", err)
	}

	// Validator list must have exactly one entry for a.
	if count := readValidatorCount(st); count != 1 {
		t.Errorf("validator list length: want 1, got %d", count)
	}
	if got := readValidatorAt(st, 0); got != a {
		t.Errorf("validator list[0]: want %v, got %v", a, got)
	}
}

// TestWithdrawRegistryBalanceGuard verifies that handleWithdraw returns
// ErrValidatorRegistryBalanceBroken when registry balance < selfStake (invariant violation).
func TestWithdrawRegistryBalanceGuard(t *testing.T) {
	st := newTestState()
	a := tAddr(0x03)
	fund(st, a, params.DPoSMinValidatorStake)

	if err := h.Handle(newCtx(st, a, params.DPoSMinValidatorStake), regSA); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Corrupt registry balance by draining it entirely.
	registryBalance := st.GetBalance(params.ValidatorRegistryAddress)
	st.SubBalance(params.ValidatorRegistryAddress, registryBalance)

	if err := h.Handle(newCtx(st, a, big.NewInt(0)), wdSA); err != ErrValidatorRegistryBalanceBroken {
		t.Errorf("want ErrValidatorRegistryBalanceBroken, got %v", err)
	}
}

// TestRegisterLegacyTxLowBalance verifies that a sender with insufficient balance
// gets ErrInsufficientBalance (R2-C5: legacy tx does not check tx.Value in buyGas).
func TestRegisterLegacyTxLowBalance(t *testing.T) {
	st := newTestState()
	a := tAddr(0x04)
	// Fund less than the minimum stake.
	st.AddBalance(a, new(big.Int).Sub(params.DPoSMinValidatorStake, big.NewInt(1)))

	if err := h.Handle(newCtx(st, a, params.DPoSMinValidatorStake), regSA); err != ErrInsufficientBalance {
		t.Errorf("want ErrInsufficientBalance, got %v", err)
	}
}

// TestValidatorSortOrder verifies that ReadActiveValidators returns validators
// sorted by address ascending after selecting the top stakers.
func TestValidatorSortOrder(t *testing.T) {
	st := newTestState()

	// Register three validators with different stakes.
	// tAddr(0x03) gets largest stake, tAddr(0x01) smallest.
	type entry struct {
		a     common.Address
		stake *big.Int
	}
	entries := []entry{
		{tAddr(0x01), new(big.Int).Mul(params.DPoSMinValidatorStake, big.NewInt(1))},
		{tAddr(0x03), new(big.Int).Mul(params.DPoSMinValidatorStake, big.NewInt(3))},
		{tAddr(0x02), new(big.Int).Mul(params.DPoSMinValidatorStake, big.NewInt(2))},
	}
	for _, e := range entries {
		fund(st, e.a, e.stake)
		if err := h.Handle(newCtx(st, e.a, e.stake), regSA); err != nil {
			t.Fatalf("register %v: %v", e.a, err)
		}
	}

	// All three active, maxValidators=10 → all returned, sorted by address asc.
	validators := ReadActiveValidators(st, 10)
	if len(validators) != 3 {
		t.Fatalf("want 3 validators, got %d", len(validators))
	}
	// Expected address order: 0x01, 0x02, 0x03 (ascending by first byte).
	for i, want := range []common.Address{tAddr(0x01), tAddr(0x02), tAddr(0x03)} {
		if validators[i] != want {
			t.Errorf("validators[%d]: want %v, got %v", i, want, validators[i])
		}
	}
}

// TestReadActiveValidatorsPerf verifies that inactive validators are excluded.
func TestReadActiveValidatorsPerf(t *testing.T) {
	st := newTestState()

	// Register two validators.
	for _, a := range []common.Address{tAddr(0x10), tAddr(0x11)} {
		fund(st, a, params.DPoSMinValidatorStake)
		if err := h.Handle(newCtx(st, a, params.DPoSMinValidatorStake), regSA); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	// Withdraw tAddr(0x11).
	if err := h.Handle(newCtx(st, tAddr(0x11), big.NewInt(0)), wdSA); err != nil {
		t.Fatalf("withdraw: %v", err)
	}

	// Only tAddr(0x10) should be active.
	result := ReadActiveValidators(st, 10)
	if len(result) != 1 || result[0] != tAddr(0x10) {
		t.Errorf("want [tAddr(0x10)], got %v", result)
	}
}

// TestInsufficientStake verifies that a stake below the minimum is rejected.
func TestInsufficientStake(t *testing.T) {
	st := newTestState()
	a := tAddr(0x20)
	belowMin := new(big.Int).Sub(params.DPoSMinValidatorStake, big.NewInt(1))
	fund(st, a, belowMin)

	if err := h.Handle(newCtx(st, a, belowMin), regSA); err != ErrInsufficientStake {
		t.Errorf("want ErrInsufficientStake, got %v", err)
	}
}

// TestWithdrawNotActive verifies that withdrawing from a non-active address fails.
func TestWithdrawNotActive(t *testing.T) {
	st := newTestState()
	a := tAddr(0x21)
	if err := h.Handle(newCtx(st, a, big.NewInt(0)), wdSA); err != ErrNotActive {
		t.Errorf("want ErrNotActive, got %v", err)
	}
}
