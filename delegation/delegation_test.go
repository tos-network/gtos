package delegation

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

var h = &delegationHandler{}

// TestMarkUsedHappyPath verifies a nonce can be consumed once.
func TestMarkUsedHappyPath(t *testing.T) {
	st := newTestState()
	principal := tAddr(0x01)
	nonce := big.NewInt(42)

	payload, _ := json.Marshal(noncePayload{
		Principal: principal.Hex(),
		Nonce:     nonce.String(),
	})
	sa := &sysaction.SysAction{Action: sysaction.ActionDelegationMarkUsed, Payload: payload}
	if err := h.Handle(newCtx(st, principal), sa); err != nil {
		t.Fatalf("mark used: %v", err)
	}
	if !IsUsed(st, principal, nonce) {
		t.Error("expected nonce to be marked as used")
	}
}

// TestMarkUsedReplay verifies a consumed nonce cannot be consumed again.
func TestMarkUsedReplay(t *testing.T) {
	st := newTestState()
	principal := tAddr(0x02)
	nonce := big.NewInt(1)

	payload, _ := json.Marshal(noncePayload{
		Principal: principal.Hex(),
		Nonce:     nonce.String(),
	})
	sa := &sysaction.SysAction{Action: sysaction.ActionDelegationMarkUsed, Payload: payload}
	if err := h.Handle(newCtx(st, principal), sa); err != nil {
		t.Fatalf("first mark: %v", err)
	}
	if err := h.Handle(newCtx(st, principal), sa); err != ErrNonceAlreadyUsed {
		t.Errorf("want ErrNonceAlreadyUsed on replay, got %v", err)
	}
}

// TestMarkUsedUnauthorized verifies only the principal can consume their own nonces.
func TestMarkUsedUnauthorized(t *testing.T) {
	st := newTestState()
	principal := tAddr(0x03)
	attacker := tAddr(0x04)
	nonce := big.NewInt(99)

	payload, _ := json.Marshal(noncePayload{
		Principal: principal.Hex(),
		Nonce:     nonce.String(),
	})
	sa := &sysaction.SysAction{Action: sysaction.ActionDelegationMarkUsed, Payload: payload}
	// attacker tries to consume principal's nonce.
	if err := h.Handle(newCtx(st, attacker), sa); err != ErrUnauthorizedPrincipal {
		t.Errorf("want ErrUnauthorizedPrincipal, got %v", err)
	}
	if IsUsed(st, principal, nonce) {
		t.Error("nonce must not be marked when unauthorized caller attempted to consume it")
	}
}

// TestRevokeIdempotent verifies revoking an already-used nonce is safe.
func TestRevokeIdempotent(t *testing.T) {
	st := newTestState()
	principal := tAddr(0x05)
	nonce := big.NewInt(7)

	payload, _ := json.Marshal(noncePayload{
		Principal: principal.Hex(),
		Nonce:     nonce.String(),
	})
	revokeSA := &sysaction.SysAction{Action: sysaction.ActionDelegationRevoke, Payload: payload}
	if err := h.Handle(newCtx(st, principal), revokeSA); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	// Second revoke is idempotent (no error).
	if err := h.Handle(newCtx(st, principal), revokeSA); err != nil {
		t.Fatalf("second revoke (idempotent): %v", err)
	}
	if !IsUsed(st, principal, nonce) {
		t.Error("nonce must be used after revoke")
	}
}

// TestNextNonce verifies the hint advances when sequential nonces are consumed.
func TestNextNonce(t *testing.T) {
	st := newTestState()
	principal := tAddr(0x06)

	if NextNonce(st, principal).Sign() != 0 {
		t.Error("initial NextNonce must be 0")
	}

	for i := int64(0); i < 3; i++ {
		nonce := big.NewInt(i)
		MarkUsed(st, principal, nonce)
	}

	if got := NextNonce(st, principal).Int64(); got != 3 {
		t.Errorf("NextNonce after 3 sequential: want 3, got %d", got)
	}
}
