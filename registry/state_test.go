package registry

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

// ---------------------------------------------------------------------------
// Capability round-trip tests
// ---------------------------------------------------------------------------

func TestCapabilityRoundTrip(t *testing.T) {
	st := newTestState()

	rec := CapabilityRecord{
		Name:        "Transfer",
		BitIndex:    3,
		Category:    1,
		Version:     2,
		Status:      CapActive,
		ManifestRef: [32]byte{0xAA, 0xBB},
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
	if got.ManifestRef != rec.ManifestRef {
		t.Errorf("ManifestRef: want %x, got %x", rec.ManifestRef, got.ManifestRef)
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
		Name:     "Mint",
		BitIndex: 7,
		Version:  1,
		Status:   CapActive,
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

func TestCapabilityTransitionGuards(t *testing.T) {
	st := newTestState()
	h := &registryHandler{}
	admin := common.HexToAddress("0x1111111111111111111111111111111111111111")

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
	if got := ReadCapability(st, "Mint"); got.Status != CapDeprecated {
		t.Fatalf("expected deprecated status, got %d", got.Status)
	}
	if err := h.Handle(makeRegistryCtx(st, admin), deprecate); err != ErrCapabilityAlreadyDeprecated {
		t.Fatalf("expected already deprecated error, got %v", err)
	}

	revoke := makeRegistryAction(t, sysaction.ActionRegistryRevokeCap, capNamePayload{Name: "Mint"})
	if err := h.Handle(makeRegistryCtx(st, admin), revoke); err != nil {
		t.Fatalf("revoke capability: %v", err)
	}
	if got := ReadCapability(st, "Mint"); got.Status != CapRevoked {
		t.Fatalf("expected revoked status, got %d", got.Status)
	}
	if err := h.Handle(makeRegistryCtx(st, admin), revoke); err != ErrCapabilityAlreadyRevoked {
		t.Fatalf("expected already revoked error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Delegation round-trip tests
// ---------------------------------------------------------------------------

func TestDelegationRoundTrip(t *testing.T) {
	st := newTestState()

	principal := common.HexToAddress("0x1111111111111111111111111111111111111111")
	delegate := common.HexToAddress("0x2222222222222222222222222222222222222222")
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
}

func TestDelegationExists(t *testing.T) {
	st := newTestState()

	principal := common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	delegate := common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
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
	}
	WriteDelegation(st, rec)

	if !DelegationExists(st, principal, delegate, scope) {
		t.Error("expected delegation to exist after write")
	}
}

func TestDelegationRevoke(t *testing.T) {
	st := newTestState()

	principal := common.HexToAddress("0x3333333333333333333333333333333333333333")
	delegate := common.HexToAddress("0x4444444444444444444444444444444444444444")
	scope := [32]byte{0x99}

	rec := DelegationRecord{
		Principal:     principal,
		Delegate:      delegate,
		ScopeRef:      scope,
		CapabilityRef: [32]byte{0xAA},
		NotBeforeMS:   500,
		ExpiryMS:      1500,
		Status:        DelActive,
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
}

func TestDelegationRejectsInvalidWindow(t *testing.T) {
	st := newTestState()
	h := &registryHandler{}
	sender := common.HexToAddress("0x5555555555555555555555555555555555555555")
	delegate := common.HexToAddress("0x6666666666666666666666666666666666666666")
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
