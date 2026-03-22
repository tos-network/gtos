package registry

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

// ---------------------------------------------------------------------------
// Capability round-trip tests
// ---------------------------------------------------------------------------

func TestCapabilityRoundTrip(t *testing.T) {
	st := newTestState()

	rec := CapabilityRecord{
		Owner:       common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d"),
		Name:        "Transfer",
		BitIndex:    3,
		Category:    1,
		Version:     2,
		Status:      CapActive,
		ManifestRef: [32]byte{0xAA, 0xBB},
		CreatedAt:   10,
		UpdatedAt:   12,
	}

	WriteCapability(st, rec)
	got := ReadCapability(st, "Transfer")

	if got.Name != rec.Name {
		t.Errorf("Name: want %q, got %q", rec.Name, got.Name)
	}
	if got.BitIndex != rec.BitIndex {
		t.Errorf("BitIndex: want %d, got %d", rec.BitIndex, got.BitIndex)
	}
	if got.Category != rec.Category {
		t.Errorf("Category: want %d, got %d", rec.Category, got.Category)
	}
	if got.Version != rec.Version {
		t.Errorf("Version: want %d, got %d", rec.Version, got.Version)
	}
	if got.Status != rec.Status {
		t.Errorf("Status: want %d, got %d", rec.Status, got.Status)
	}
	if got.Owner != rec.Owner {
		t.Errorf("Owner: want %s, got %s", rec.Owner.Hex(), got.Owner.Hex())
	}
	if got.ManifestRef != rec.ManifestRef {
		t.Errorf("ManifestRef: want %x, got %x", rec.ManifestRef, got.ManifestRef)
	}
	if got.CreatedAt != rec.CreatedAt || got.UpdatedAt != rec.UpdatedAt {
		t.Errorf("timestamps: want (%d,%d), got (%d,%d)", rec.CreatedAt, rec.UpdatedAt, got.CreatedAt, got.UpdatedAt)
	}
}

func TestCapabilityNotFound(t *testing.T) {
	st := newTestState()
	got := ReadCapability(st, "NonExistent")
	if got.Name != "" {
		t.Errorf("expected empty Name for non-existent capability, got %q", got.Name)
	}
}

func TestCapabilityStatusUpdate(t *testing.T) {
	st := newTestState()

	rec := CapabilityRecord{
		Owner:     common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d"),
		Name:      "Mint",
		BitIndex:  7,
		Version:   1,
		Status:    CapActive,
		CreatedAt: 3,
		UpdatedAt: 4,
	}
	WriteCapability(st, rec)

	// Deprecate.
	rec.Status = CapDeprecated
	WriteCapability(st, rec)
	got := ReadCapability(st, "Mint")
	if got.Status != CapDeprecated {
		t.Errorf("Status: want %d (deprecated), got %d", CapDeprecated, got.Status)
	}

	// Revoke.
	rec.Status = CapRevoked
	WriteCapability(st, rec)
	got = ReadCapability(st, "Mint")
	if got.Status != CapRevoked {
		t.Errorf("Status: want %d (revoked), got %d", CapRevoked, got.Status)
	}
}

func makeRegistryAction(t *testing.T, action sysaction.ActionKind, payload any) *sysaction.SysAction {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return &sysaction.SysAction{Action: action, Payload: raw}
}

func makeRegistryCtx(st *state.StateDB, from common.Address) *sysaction.Context {
	return &sysaction.Context{
		From:        from,
		Value:       big.NewInt(0),
		BlockNumber: big.NewInt(9),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{},
	}
}

func grantGovernor(t *testing.T, st *state.StateDB, addr common.Address) {
	t.Helper()
	capability.GrantCapability(st, addr, GovernorCapabilityBit)
}

func TestCapabilityTransitionGuards(t *testing.T) {
	st := newTestState()
	h := &registryHandler{}
	admin := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	grantGovernor(t, st, admin)

	register := makeRegistryAction(t, sysaction.ActionRegistryRegisterCap, registerCapPayload{
		Name:     "Mint",
		BitIndex: 0,
		Version:  1,
	})
	if err := h.Handle(makeRegistryCtx(st, admin), register); err != nil {
		t.Fatalf("register capability: %v", err)
	}

	deprecate := makeRegistryAction(t, sysaction.ActionRegistryDeprecateCap, capNamePayload{Name: "Mint"})
	if err := h.Handle(makeRegistryCtx(st, admin), deprecate); err != nil {
		t.Fatalf("deprecate capability: %v", err)
	}
	if got := ReadCapability(st, "Mint"); got.Status != CapDeprecated || got.Owner != admin || got.CreatedAt != 9 || got.UpdatedAt != 9 {
		t.Fatalf("unexpected deprecated capability %+v", got)
	}
	if err := h.Handle(makeRegistryCtx(st, admin), deprecate); err != ErrCapabilityAlreadyDeprecated {
		t.Fatalf("expected already deprecated error, got %v", err)
	}

	revoke := makeRegistryAction(t, sysaction.ActionRegistryRevokeCap, capNamePayload{Name: "Mint"})
	if err := h.Handle(makeRegistryCtx(st, admin), revoke); err != nil {
		t.Fatalf("revoke capability: %v", err)
	}
	if got := ReadCapability(st, "Mint"); got.Status != CapRevoked || got.UpdatedAt != 9 {
		t.Fatalf("unexpected revoked capability %+v", got)
	}
	if err := h.Handle(makeRegistryCtx(st, admin), revoke); err != ErrCapabilityAlreadyRevoked {
		t.Fatalf("expected already revoked error, got %v", err)
	}
}

func TestCapabilityTransitionRequiresOwnerOrGovernor(t *testing.T) {
	st := newTestState()
	h := &registryHandler{}
	governor := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	other := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")
	grantGovernor(t, st, governor)

	register := makeRegistryAction(t, sysaction.ActionRegistryRegisterCap, registerCapPayload{
		Name: "Trade", BitIndex: 0, Version: 1,
	})
	if err := h.Handle(makeRegistryCtx(st, governor), register); err != nil {
		t.Fatalf("register capability: %v", err)
	}
	deprecate := makeRegistryAction(t, sysaction.ActionRegistryDeprecateCap, capNamePayload{Name: "Trade"})
	if err := h.Handle(makeRegistryCtx(st, other), deprecate); err != ErrUnauthorizedCapability {
		t.Fatalf("expected unauthorized capability error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Delegation round-trip tests
// ---------------------------------------------------------------------------

func TestDelegationRoundTrip(t *testing.T) {
	st := newTestState()

	principal := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	delegate := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")
	scope := [32]byte{0x01, 0x02, 0x03}

	rec := DelegationRecord{
		Principal:     principal,
		Delegate:      delegate,
		ScopeRef:      scope,
		CapabilityRef: [32]byte{0xCC, 0xDD},
		PolicyRef:     [32]byte{0xEE, 0xFF},
		NotBeforeMS:   1000,
		ExpiryMS:      9999,
		Status:        DelActive,
		CreatedAt:     10,
		UpdatedAt:     11,
	}

	WriteDelegation(st, rec)
	got := ReadDelegation(st, principal, delegate, scope)

	if got.Principal != rec.Principal {
		t.Errorf("Principal: want %s, got %s", rec.Principal.Hex(), got.Principal.Hex())
	}
	if got.Delegate != rec.Delegate {
		t.Errorf("Delegate: want %s, got %s", rec.Delegate.Hex(), got.Delegate.Hex())
	}
	if got.ScopeRef != rec.ScopeRef {
		t.Errorf("ScopeRef: want %x, got %x", rec.ScopeRef, got.ScopeRef)
	}
	if got.CapabilityRef != rec.CapabilityRef {
		t.Errorf("CapabilityRef: want %x, got %x", rec.CapabilityRef, got.CapabilityRef)
	}
	if got.PolicyRef != rec.PolicyRef {
		t.Errorf("PolicyRef: want %x, got %x", rec.PolicyRef, got.PolicyRef)
	}
	if got.NotBeforeMS != rec.NotBeforeMS {
		t.Errorf("NotBeforeMS: want %d, got %d", rec.NotBeforeMS, got.NotBeforeMS)
	}
	if got.ExpiryMS != rec.ExpiryMS {
		t.Errorf("ExpiryMS: want %d, got %d", rec.ExpiryMS, got.ExpiryMS)
	}
	if got.Status != rec.Status {
		t.Errorf("Status: want %d, got %d", rec.Status, got.Status)
	}
	if got.CreatedAt != rec.CreatedAt || got.UpdatedAt != rec.UpdatedAt {
		t.Errorf("timestamps: want (%d,%d), got (%d,%d)", rec.CreatedAt, rec.UpdatedAt, got.CreatedAt, got.UpdatedAt)
	}
}

func TestDelegationExists(t *testing.T) {
	st := newTestState()

	principal := common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7")
	delegate := common.HexToAddress("0xf4897a85e6ac20f6b7b22e2c3a8fac52fb6c36430b80655354e5aa4f5e1a3533")
	scope := [32]byte{0x55}

	if DelegationExists(st, principal, delegate, scope) {
		t.Error("expected delegation to not exist before write")
	}

	rec := DelegationRecord{
		Principal:     principal,
		Delegate:      delegate,
		ScopeRef:      scope,
		CapabilityRef: [32]byte{0x01},
		NotBeforeMS:   100,
		ExpiryMS:      200,
		Status:        DelActive,
		CreatedAt:     1,
		UpdatedAt:     1,
	}
	WriteDelegation(st, rec)

	if !DelegationExists(st, principal, delegate, scope) {
		t.Error("expected delegation to exist after write")
	}
}

func TestDelegationRevoke(t *testing.T) {
	st := newTestState()

	principal := common.HexToAddress("0x3ccadfb801017cfb0f5dc61ef0e96fdaacbdb11c91ba5a230959e8d14020ea50")
	delegate := common.HexToAddress("0xc93118fe4956b46c1460d1bb6740f640236701d1210f2160f9c1e0cfeed6b41e")
	scope := [32]byte{0x99}

	rec := DelegationRecord{
		Principal:     principal,
		Delegate:      delegate,
		ScopeRef:      scope,
		CapabilityRef: [32]byte{0xAA},
		NotBeforeMS:   500,
		ExpiryMS:      1500,
		Status:        DelActive,
		CreatedAt:     7,
		UpdatedAt:     7,
	}
	WriteDelegation(st, rec)

	// Revoke.
	rec.Status = DelRevoked
	WriteDelegation(st, rec)

	got := ReadDelegation(st, principal, delegate, scope)
	if got.Status != DelRevoked {
		t.Errorf("Status: want %d (revoked), got %d", DelRevoked, got.Status)
	}
	// Other fields should be preserved.
	if got.NotBeforeMS != 500 {
		t.Errorf("NotBeforeMS: want 500, got %d", got.NotBeforeMS)
	}
	if got.ExpiryMS != 1500 {
		t.Errorf("ExpiryMS: want 1500, got %d", got.ExpiryMS)
	}
	if got.CreatedAt != 7 || got.UpdatedAt != 7 {
		t.Errorf("timestamps: want 7/7, got %d/%d", got.CreatedAt, got.UpdatedAt)
	}
}

func TestDelegationRejectsInvalidWindow(t *testing.T) {
	st := newTestState()
	h := &registryHandler{}
	sender := common.HexToAddress("0x0791868d8f29ea735f26a17a9aea038cd4255baac26eac5a74e58a07ed2f1975")
	delegate := common.HexToAddress("0xc56e1aa20e343822f1ec16c0a9230f7a17603f07dafd3ad5dbb1dd43ee34fdad")
	scope := common.HexToHash("0x77")

	err := h.Handle(makeRegistryCtx(st, sender), makeRegistryAction(t, sysaction.ActionRegistryGrantDelegation, grantDelegationPayload{
		Principal:   sender.Hex(),
		Delegate:    delegate.Hex(),
		ScopeRef:    scope.Hex(),
		NotBeforeMS: 2000,
		ExpiryMS:    1000,
	}))
	if err != ErrInvalidDelegationWindow {
		t.Fatalf("expected invalid delegation window error, got %v", err)
	}
}

func TestDelegationGrantAndRevokeRequirePrincipalOrGovernor(t *testing.T) {
	st := newTestState()
	h := &registryHandler{}
	principal := common.HexToAddress("0xf71d99c2b05b3ab38ebabfae54f08b149f9dffa9fd49cf69e20b9f0ea86514f2")
	delegate := common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7")
	other := common.HexToAddress("0xf4897a85e6ac20f6b7b22e2c3a8fac52fb6c36430b80655354e5aa4f5e1a3533")
	scope := common.HexToHash("0x55")

	grant := makeRegistryAction(t, sysaction.ActionRegistryGrantDelegation, grantDelegationPayload{
		Principal: principal.Hex(),
		Delegate:  delegate.Hex(),
		ScopeRef:  scope.Hex(),
	})
	if err := h.Handle(makeRegistryCtx(st, other), grant); err != ErrUnauthorizedDelegation {
		t.Fatalf("expected unauthorized delegation error, got %v", err)
	}
	if err := h.Handle(makeRegistryCtx(st, principal), grant); err != nil {
		t.Fatalf("grant delegation: %v", err)
	}
	got := ReadDelegation(st, principal, delegate, scope)
	if got.CreatedAt != 9 || got.UpdatedAt != 9 {
		t.Fatalf("unexpected delegation timestamps %+v", got)
	}

	revoke := makeRegistryAction(t, sysaction.ActionRegistryRevokeDelegation, revokeDelegationPayload{
		Principal: principal.Hex(),
		Delegate:  delegate.Hex(),
		ScopeRef:  scope.Hex(),
	})
	if err := h.Handle(makeRegistryCtx(st, other), revoke); err != ErrUnauthorizedDelegation {
		t.Fatalf("expected unauthorized delegation revoke error, got %v", err)
	}
}
