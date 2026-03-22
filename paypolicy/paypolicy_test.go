package paypolicy

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/registry"
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

func grantGovernor(t *testing.T, st *state.StateDB, addr common.Address) {
	t.Helper()
	capability.GrantCapability(st, addr, registry.GovernorCapabilityBit)
}

func TestRegisterAndDeactivatePayPolicy(t *testing.T) {
	st := newTestState()
	h := &handler{}
	owner := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
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
	if rec.Owner != owner || rec.MaxAmount == nil || rec.MaxAmount.Cmp(big.NewInt(1000)) != 0 || rec.CreatedAt != 9 || rec.UpdatedAt != 9 {
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

	if err := h.Handle(newCtx(st, owner), deactivate); err != ErrPolicyAlreadyRevoked {
		t.Fatalf("expected already revoked error, got %v", err)
	}
}

func TestGovernorCanRegisterAndDeactivatePayPolicy(t *testing.T) {
	st := newTestState()
	h := &handler{}
	governor := common.HexToAddress("0xf4897a85e6ac20f6b7b22e2c3a8fac52fb6c36430b80655354e5aa4f5e1a3533")
	owner := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	policyID := common.HexToHash("0x02")
	grantGovernor(t, st, governor)

	register := makeSysAction(t, sysaction.ActionRegistryRegisterPayPolicy, registerPolicyPayload{
		PolicyID:  policyID.Hex(),
		Kind:      2,
		Owner:     owner.Hex(),
		Asset:     "TOS",
		MaxAmount: "500",
	})
	if err := h.Handle(newCtx(st, governor), register); err != nil {
		t.Fatalf("governor register policy: %v", err)
	}
	deactivate := makeSysAction(t, sysaction.ActionRegistryDeactivatePayPolicy, deactivatePolicyPayload{
		PolicyID: policyID.Hex(),
	})
	if err := h.Handle(newCtx(st, governor), deactivate); err != nil {
		t.Fatalf("governor deactivate policy: %v", err)
	}
	if got := ReadPolicy(st, policyID); got.Status != PolicyRevoked || got.UpdatedAt != 9 {
		t.Fatalf("unexpected revoked policy %+v", got)
	}
}
