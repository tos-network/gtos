package pkgregistry

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

func TestRegisterPublisherAndPublishPackage(t *testing.T) {
	st := newHandlerTestState()
	h := &pkgRegistryHandler{}
	pubID := common.HexToHash("0x01")

	register := makePackageSysAction(t, sysaction.ActionPackageRegisterPublisher, registerPublisherPayload{
		PublisherID: pubID.Hex(),
		Controller:  "0x1234000000000000000000000000000000000000",
		MetadataRef: "0xabc",
	})
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000")
	if err := h.Handle(newHandlerCtx(st, controller), register); err != nil {
		t.Fatalf("register publisher: %v", err)
	}
	var pubKey [32]byte
	copy(pubKey[:], pubID[:])
	if got := ReadPublisher(st, pubKey); got.Controller == (common.Address{}) {
		t.Fatal("publisher not written")
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
}

func TestPackageStatusTransitions(t *testing.T) {
	st := newHandlerTestState()
	h := &pkgRegistryHandler{}
	pubID := common.HexToHash("0x02")
	var pubKey [32]byte
	copy(pubKey[:], pubID[:])
	WritePublisher(st, PublisherRecord{
		PublisherID: pubKey,
		Controller:  common.HexToAddress("0x1234000000000000000000000000000000000000"),
		Status:      PkgActive,
	})
	WritePackage(st, PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "2.0.0",
		PackageHash:    [32]byte{0x55},
		PublisherID:    pubKey,
		Status:         PkgActive,
		Channel:        ChannelBeta,
	})

	deprecate := makePackageSysAction(t, sysaction.ActionPackageDeprecate, packageStatusPayload{
		PackageName: "demo.checkout", PackageVersion: "2.0.0",
	})
	controller := common.HexToAddress("0x1234000000000000000000000000000000000000")
	if err := h.Handle(newHandlerCtx(st, controller), deprecate); err != nil {
		t.Fatalf("deprecate package: %v", err)
	}
	if got := ReadPackage(st, "demo.checkout", "2.0.0"); got.Status != PkgDeprecated {
		t.Fatalf("expected deprecated status, got %d", got.Status)
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
