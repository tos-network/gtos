package paypolicy

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
		BlockNumber: big.NewInt(9),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{},
	}
}

func makeSysAction(t *testing.T, action sysaction.ActionKind, payload any) *sysaction.SysAction {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return &sysaction.SysAction{Action: action, Payload: raw}
}

func TestRegisterAndDeactivatePayPolicy(t *testing.T) {
	st := newTestState()
	h := &handler{}
	owner := common.HexToAddress("0x1234000000000000000000000000000000000000")
	policyID := common.HexToHash("0x01")

	register := makeSysAction(t, sysaction.ActionRegistryRegisterPayPolicy, registerPolicyPayload{
		PolicyID:  policyID.Hex(),
		Kind:      2,
		Owner:     owner.Hex(),
		Asset:     "TOS",
		MaxAmount: "1000",
	})
	if err := h.Handle(newCtx(st, owner), register); err != nil {
		t.Fatalf("register policy: %v", err)
	}
	rec := ReadPolicyByOwnerAsset(st, owner, "TOS")
	if rec.Owner != owner || rec.MaxAmount == nil || rec.MaxAmount.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("unexpected policy %+v", rec)
	}

	deactivate := makeSysAction(t, sysaction.ActionRegistryDeactivatePayPolicy, deactivatePolicyPayload{
		PolicyID: policyID.Hex(),
	})
	if err := h.Handle(newCtx(st, owner), deactivate); err != nil {
		t.Fatalf("deactivate policy: %v", err)
	}
	if got := ReadPolicy(st, policyID); got.Status != PolicyRevoked {
		t.Fatalf("expected revoked status, got %d", got.Status)
	}
}
