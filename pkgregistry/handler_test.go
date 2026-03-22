package pkgregistry

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

func newHandlerTestState() *state.StateDB {
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	s, _ := state.New(common.Hash{}, db, nil)
	return s
}

func newHandlerCtx(st *state.StateDB, from common.Address) *sysaction.Context {
	return &sysaction.Context{
		From:        from,
		Value:       big.NewInt(0),
		BlockNumber: big.NewInt(42),
		StateDB:     st,
		ChainConfig: &params.ChainConfig{},
	}
}

func makePackageSysAction(t *testing.T, action sysaction.ActionKind, payload any) *sysaction.SysAction {
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

func TestRegisterPublisherAndPublishPackage(t *testing.T) {
	st := newHandlerTestState()
	h := &pkgRegistryHandler{}
	pubID := common.HexToHash("0x01")

	register := makePackageSysAction(t, sysaction.ActionPackageRegisterPublisher, registerPublisherPayload{
		PublisherID: pubID.Hex(),
		Controller:  "0x1234000000000000000000000000000000000000000000000000000000000000",
		MetadataRef: common.HexToHash("0xabc").Hex(),
		Namespace:   "demo",
	})
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000000000000000000000000000")
	if err := h.Handle(newHandlerCtx(st, controller), register); err != nil {
		t.Fatalf("register publisher: %v", err)
	}
	var pubKey [32]byte
	copy(pubKey[:], pubID[:])
	if got := ReadPublisher(st, pubKey); got.Controller == (common.Address{}) {
		t.Fatal("publisher not written")
	}
	if got := ReadPublisher(st, pubKey); got.Namespace != "demo" {
		t.Fatalf("unexpected publisher namespace %q", got.Namespace)
	}
	if got := ReadPublisher(st, pubKey); got.CreatedAt != 42 || got.UpdatedAt != 42 {
		t.Fatalf("unexpected publisher timestamps %+v", got)
	}

	publish := makePackageSysAction(t, sysaction.ActionPackagePublish, publishPackagePayload{
		PackageName:    "demo.checkout",
		PackageVersion: "1.0.0",
		PackageHash:    common.HexToHash("0x11").Hex(),
		PublisherID:    pubID.Hex(),
		ManifestHash:   common.HexToHash("0x22").Hex(),
		Channel:        uint16(ChannelStable),
		ContractCount:  2,
		DiscoveryRef:   common.HexToHash("0x33").Hex(),
	})
	if err := h.Handle(newHandlerCtx(st, controller), publish); err != nil {
		t.Fatalf("publish package: %v", err)
	}
	rec := ReadPackage(st, "demo.checkout", "1.0.0")
	if rec.PackageName != "demo.checkout" || rec.PackageVersion != "1.0.0" {
		t.Fatalf("unexpected package record %+v", rec)
	}
	if rec.PublishedAt != 42 {
		t.Fatalf("expected published_at to default to block number 42, got %d", rec.PublishedAt)
	}
	if rec.CreatedAt != 42 || rec.UpdatedAt != 42 {
		t.Fatalf("expected package timestamps to default to block number 42, got %+v", rec)
	}
}

func TestRegisterPublisherRejectsDuplicateNamespace(t *testing.T) {
	st := newHandlerTestState()
	h := &pkgRegistryHandler{}
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000000000000000000000000000")

	first := makePackageSysAction(t, sysaction.ActionPackageRegisterPublisher, registerPublisherPayload{
		PublisherID: common.HexToHash("0x01").Hex(),
		Controller:  controller.Hex(),
		Namespace:   "demo",
	})
	if err := h.Handle(newHandlerCtx(st, controller), first); err != nil {
		t.Fatalf("register first publisher: %v", err)
	}
	second := makePackageSysAction(t, sysaction.ActionPackageRegisterPublisher, registerPublisherPayload{
		PublisherID: common.HexToHash("0x02").Hex(),
		Controller:  controller.Hex(),
		Namespace:   "demo",
	})
	if err := h.Handle(newHandlerCtx(st, controller), second); err != ErrNamespaceExists {
		t.Fatalf("expected ErrNamespaceExists, got %v", err)
	}
}

func TestPackageStatusTransitions(t *testing.T) {
	st := newHandlerTestState()
	h := &pkgRegistryHandler{}
	pubID := common.HexToHash("0x02")
	var pubKey [32]byte
	copy(pubKey[:], pubID[:])
	WritePublisher(st, PublisherRecord{
		PublisherID: pubKey,
		Controller:  common.HexToAddress("0x1234000000000000000000000000000000000000000000000000000000000000"),
		Namespace:   "demo",
		Status:      PkgActive,
		CreatedAt:   1,
		UpdatedAt:   1,
	})
	WritePackage(st, PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "2.0.0",
		PackageHash:    [32]byte{0x55},
		PublisherID:    pubKey,
		Status:         PkgActive,
		Channel:        ChannelBeta,
		CreatedAt:      1,
		UpdatedAt:      1,
	})

	deprecate := makePackageSysAction(t, sysaction.ActionPackageDeprecate, packageStatusPayload{
		PackageName: "demo.checkout", PackageVersion: "2.0.0",
	})
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000000000000000000000000000")
	if err := h.Handle(newHandlerCtx(st, controller), deprecate); err != nil {
		t.Fatalf("deprecate package: %v", err)
	}
	if got := ReadPackage(st, "demo.checkout", "2.0.0"); got.Status != PkgDeprecated {
		t.Fatalf("expected deprecated status, got %d", got.Status)
	}
	if got := ReadPackage(st, "demo.checkout", "2.0.0"); got.UpdatedAt != 42 {
		t.Fatalf("expected deprecated update timestamp, got %+v", got)
	}

	revoke := makePackageSysAction(t, sysaction.ActionPackageRevoke, packageStatusPayload{
		PackageName: "demo.checkout", PackageVersion: "2.0.0",
	})
	if err := h.Handle(newHandlerCtx(st, controller), revoke); err != nil {
		t.Fatalf("revoke package: %v", err)
	}
	if got := ReadPackage(st, "demo.checkout", "2.0.0"); got.Status != PkgRevoked {
		t.Fatalf("expected revoked status, got %d", got.Status)
	}
}

func TestPublishRejectsNamespaceMismatch(t *testing.T) {
	st := newHandlerTestState()
	h := &pkgRegistryHandler{}
	pubID := common.HexToHash("0x03")
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000000000000000000000000000")
	var pubKey [32]byte
	copy(pubKey[:], pubID[:])
	WritePublisher(st, PublisherRecord{
		PublisherID: pubKey,
		Controller:  controller,
		Namespace:   "demo",
		Status:      PkgActive,
		CreatedAt:   1,
		UpdatedAt:   1,
	})

	publish := makePackageSysAction(t, sysaction.ActionPackagePublish, publishPackagePayload{
		PackageName:    "other.checkout",
		PackageVersion: "1.0.0",
		PackageHash:    common.HexToHash("0x11").Hex(),
		PublisherID:    pubID.Hex(),
		Channel:        uint16(ChannelStable),
		ContractCount:  1,
	})
	if err := h.Handle(newHandlerCtx(st, controller), publish); err != ErrNamespaceMismatch {
		t.Fatalf("expected ErrNamespaceMismatch, got %v", err)
	}
}

func TestPublisherStatusRequiresControllerOrGovernor(t *testing.T) {
	st := newHandlerTestState()
	h := &pkgRegistryHandler{}
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000000000000000000000000000")
	outsider := common.HexToAddress("0x9999000000000000000000000000000000000000000000000000000000000000")
	pubHash := common.HexToHash("0x04")
	var pubID [32]byte
	copy(pubID[:], pubHash[:])
	WritePublisher(st, PublisherRecord{
		PublisherID: pubID,
		Controller:  controller,
		Namespace:   "demo",
		Status:      PkgActive,
		CreatedAt:   1,
		UpdatedAt:   1,
	})

	suspend := makePackageSysAction(t, sysaction.ActionPackageSetPublisherStatus, setPublisherStatusPayload{
		PublisherID: pubHash.Hex(),
		Status:      uint8(PkgDeprecated),
	})
	if err := h.Handle(newHandlerCtx(st, outsider), suspend); err != ErrUnauthorizedPublisher {
		t.Fatalf("expected ErrUnauthorizedPublisher, got %v", err)
	}

	governor := common.HexToAddress("0x7777000000000000000000000000000000000000000000000000000000000000")
	grantGovernor(t, st, governor)
	if err := h.Handle(newHandlerCtx(st, governor), suspend); err != nil {
		t.Fatalf("governor suspend publisher: %v", err)
	}
	if got := ReadPublisher(st, pubID); got.Status != PkgDeprecated || got.UpdatedAt != 42 {
		t.Fatalf("unexpected publisher after governor suspend %+v", got)
	}
}

func TestPublisherCanResumeFromDeprecatedButNotFromRevoked(t *testing.T) {
	st := newHandlerTestState()
	h := &pkgRegistryHandler{}
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000000000000000000000000000")
	pubHash := common.HexToHash("0x05")
	var pubID [32]byte
	copy(pubID[:], pubHash[:])
	WritePublisher(st, PublisherRecord{
		PublisherID: pubID,
		Controller:  controller,
		Namespace:   "demo",
		Status:      PkgDeprecated,
		CreatedAt:   2,
		UpdatedAt:   2,
	})

	resume := makePackageSysAction(t, sysaction.ActionPackageSetPublisherStatus, setPublisherStatusPayload{
		PublisherID: pubHash.Hex(),
		Status:      uint8(PkgActive),
	})
	if err := h.Handle(newHandlerCtx(st, controller), resume); err != nil {
		t.Fatalf("resume publisher: %v", err)
	}
	if got := ReadPublisher(st, pubID); got.Status != PkgActive {
		t.Fatalf("expected publisher active after resume, got %+v", got)
	}

	WritePublisher(st, PublisherRecord{
		PublisherID: pubID,
		Controller:  controller,
		Namespace:   "demo",
		Status:      PkgRevoked,
		CreatedAt:   2,
		UpdatedAt:   2,
	})
	if err := h.Handle(newHandlerCtx(st, controller), resume); err != ErrInvalidPublisherState {
		t.Fatalf("expected ErrInvalidPublisherState from revoked publisher, got %v", err)
	}
}

func TestPublishAndPackageStatusAllowGovernorOverride(t *testing.T) {
	st := newHandlerTestState()
	h := &pkgRegistryHandler{}
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000000000000000000000000000")
	governor := common.HexToAddress("0x7777000000000000000000000000000000000000000000000000000000000000")
	grantGovernor(t, st, governor)
	pubHash := common.HexToHash("0x06")
	var pubID [32]byte
	copy(pubID[:], pubHash[:])
	WritePublisher(st, PublisherRecord{
		PublisherID: pubID,
		Controller:  controller,
		Namespace:   "demo",
		Status:      PkgActive,
		CreatedAt:   3,
		UpdatedAt:   3,
	})

	publish := makePackageSysAction(t, sysaction.ActionPackagePublish, publishPackagePayload{
		PackageName:    "demo.checkout",
		PackageVersion: "3.0.0",
		PackageHash:    common.HexToHash("0x66").Hex(),
		PublisherID:    pubHash.Hex(),
		Channel:        uint16(ChannelStable),
		ContractCount:  1,
	})
	if err := h.Handle(newHandlerCtx(st, governor), publish); err != nil {
		t.Fatalf("governor publish package: %v", err)
	}
	if got := ReadPackage(st, "demo.checkout", "3.0.0"); got.PackageHash == ([32]byte{}) {
		t.Fatalf("expected package to be published by governor override")
	}

	revoke := makePackageSysAction(t, sysaction.ActionPackageRevoke, packageStatusPayload{
		PackageName:    "demo.checkout",
		PackageVersion: "3.0.0",
	})
	if err := h.Handle(newHandlerCtx(st, governor), revoke); err != nil {
		t.Fatalf("governor revoke package: %v", err)
	}
	if got := ReadPackage(st, "demo.checkout", "3.0.0"); got.Status != PkgRevoked {
		t.Fatalf("expected revoked package, got %+v", got)
	}
}

func TestNamespaceDisputeBlocksPublishUntilResolved(t *testing.T) {
	st := newHandlerTestState()
	h := &pkgRegistryHandler{}
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000000000000000000000000000")
	governor := common.HexToAddress("0x7777000000000000000000000000000000000000000000000000000000000000")
	grantGovernor(t, st, governor)
	pubHash := common.HexToHash("0x07")
	var pubID [32]byte
	copy(pubID[:], pubHash[:])
	WritePublisher(st, PublisherRecord{
		PublisherID: pubID,
		Controller:  controller,
		Namespace:   "demo",
		Status:      PkgActive,
		CreatedAt:   1,
		UpdatedAt:   1,
	})

	dispute := makePackageSysAction(t, sysaction.ActionPackageDisputeNamespace, namespaceGovernancePayload{
		Namespace:   "demo",
		EvidenceRef: common.HexToHash("0xdead").Hex(),
	})
	if err := h.Handle(newHandlerCtx(st, governor), dispute); err != nil {
		t.Fatalf("dispute namespace: %v", err)
	}
	ns := ReadNamespaceGovernance(st, "demo")
	if ns.Status != NamespaceDisputed || ns.UpdatedBy != governor {
		t.Fatalf("unexpected namespace governance %+v", ns)
	}

	publish := makePackageSysAction(t, sysaction.ActionPackagePublish, publishPackagePayload{
		PackageName:    "demo.checkout",
		PackageVersion: "1.0.0",
		PackageHash:    common.HexToHash("0x11").Hex(),
		PublisherID:    pubHash.Hex(),
		Channel:        uint16(ChannelStable),
		ContractCount:  1,
	})
	if err := h.Handle(newHandlerCtx(st, controller), publish); err != ErrNamespaceDisputed {
		t.Fatalf("expected ErrNamespaceDisputed, got %v", err)
	}

	resolve := makePackageSysAction(t, sysaction.ActionPackageResolveNamespace, namespaceGovernancePayload{
		Namespace: "demo",
	})
	if err := h.Handle(newHandlerCtx(st, governor), resolve); err != nil {
		t.Fatalf("resolve namespace: %v", err)
	}
	if got := ReadNamespaceGovernance(st, "demo"); got.Status != NamespaceClear {
		t.Fatalf("expected cleared namespace status, got %+v", got)
	}
	if err := h.Handle(newHandlerCtx(st, controller), publish); err != nil {
		t.Fatalf("publish after resolve: %v", err)
	}
}
