package pkgregistry

import (
	"testing"

	"github.com/tos-network/gtos/common"
)

// mockStateDB is a simple in-memory state store for testing.
type mockStateDB struct {
	store map[common.Address]map[common.Hash]common.Hash
}

func newMockStateDB() *mockStateDB {
	return &mockStateDB{store: make(map[common.Address]map[common.Hash]common.Hash)}
}

func (m *mockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if slots, ok := m.store[addr]; ok {
		return slots[key]
	}
	return common.Hash{}
}

func (m *mockStateDB) SetState(addr common.Address, key, val common.Hash) {
	if _, ok := m.store[addr]; !ok {
		m.store[addr] = make(map[common.Hash]common.Hash)
	}
	m.store[addr][key] = val
}

func TestPublisherRoundTrip(t *testing.T) {
	db := newMockStateDB()

	pubID := [32]byte{0x01, 0x02, 0x03}
	controller := common.HexToAddress("0xABCDEF0123456789ABCDEF0123456789ABCDEF01")
	metaRef := [32]byte{0xAA, 0xBB, 0xCC}

	rec := PublisherRecord{
		PublisherID: pubID,
		Controller:  controller,
		MetadataRef: metaRef,
		Status:      PkgActive,
	}
	WritePublisher(db, rec)

	got := ReadPublisher(db, pubID)
	if got.Controller != controller {
		t.Fatalf("Controller mismatch: got %s, want %s", got.Controller.Hex(), controller.Hex())
	}
	if got.MetadataRef != metaRef {
		t.Fatalf("MetadataRef mismatch")
	}
	if got.Status != PkgActive {
		t.Fatalf("Status mismatch: got %d, want %d", got.Status, PkgActive)
	}

	// Update status
	rec.Status = PkgRevoked
	WritePublisher(db, rec)
	got = ReadPublisher(db, pubID)
	if got.Status != PkgRevoked {
		t.Fatalf("Status after update: got %d, want %d", got.Status, PkgRevoked)
	}
}

func TestPackageRoundTrip(t *testing.T) {
	db := newMockStateDB()

	rec := PackageRecord{
		PackageName:    "tol.std.token",
		PackageVersion: "1.2.0",
		PackageHash:    [32]byte{0x11, 0x22, 0x33},
		PublisherID:    [32]byte{0x01, 0x02, 0x03},
		ManifestHash:   [32]byte{0xDD, 0xEE, 0xFF},
		Channel:        ChannelStable,
		Status:         PkgActive,
		ContractCount:  3,
		DiscoveryRef:   [32]byte{0xA1, 0xB2, 0xC3},
		PublishedAt:    1700000000,
	}
	WritePackage(db, rec)

	got := ReadPackage(db, "tol.std.token", "1.2.0")
	if got.PackageName != rec.PackageName {
		t.Fatalf("PackageName: got %q, want %q", got.PackageName, rec.PackageName)
	}
	if got.PackageVersion != rec.PackageVersion {
		t.Fatalf("PackageVersion: got %q, want %q", got.PackageVersion, rec.PackageVersion)
	}
	if got.PackageHash != rec.PackageHash {
		t.Fatalf("PackageHash mismatch")
	}
	if got.PublisherID != rec.PublisherID {
		t.Fatalf("PublisherID mismatch")
	}
	if got.ManifestHash != rec.ManifestHash {
		t.Fatalf("ManifestHash mismatch")
	}
	if got.Channel != ChannelStable {
		t.Fatalf("Channel: got %d, want %d", got.Channel, ChannelStable)
	}
	if got.Status != PkgActive {
		t.Fatalf("Status: got %d, want %d", got.Status, PkgActive)
	}
	if got.ContractCount != 3 {
		t.Fatalf("ContractCount: got %d, want 3", got.ContractCount)
	}
	if got.DiscoveryRef != rec.DiscoveryRef {
		t.Fatalf("DiscoveryRef mismatch")
	}
	if got.PublishedAt != 1700000000 {
		t.Fatalf("PublishedAt: got %d, want 1700000000", got.PublishedAt)
	}
}

func TestPackageByHashLookup(t *testing.T) {
	db := newMockStateDB()

	rec := PackageRecord{
		PackageName:    "tol.std.erc20",
		PackageVersion: "2.0.0",
		PackageHash:    [32]byte{0xFA, 0xFB, 0xFC},
		PublisherID:    [32]byte{0x99},
		Channel:        ChannelBeta,
		Status:         PkgDeprecated,
		ContractCount:  1,
		PublishedAt:    1700001000,
	}
	WritePackage(db, rec)

	got := ReadPackageByHash(db, rec.PackageHash)
	if got.PackageName != "tol.std.erc20" {
		t.Fatalf("hash lookup PackageName: got %q, want %q", got.PackageName, "tol.std.erc20")
	}
	if got.PackageVersion != "2.0.0" {
		t.Fatalf("hash lookup PackageVersion: got %q, want %q", got.PackageVersion, "2.0.0")
	}
	if got.Channel != ChannelBeta {
		t.Fatalf("hash lookup Channel: got %d, want %d", got.Channel, ChannelBeta)
	}
	if got.Status != PkgDeprecated {
		t.Fatalf("hash lookup Status: got %d, want %d", got.Status, PkgDeprecated)
	}
}

func TestPackageByHashNotFound(t *testing.T) {
	db := newMockStateDB()
	got := ReadPackageByHash(db, [32]byte{0xFF})
	if got.PackageName != "" || got.PackageVersion != "" {
		t.Fatalf("expected empty record for unknown hash, got name=%q version=%q",
			got.PackageName, got.PackageVersion)
	}
}

func TestPublisherNotFound(t *testing.T) {
	db := newMockStateDB()
	got := ReadPublisher(db, [32]byte{0x42})
	if got.Controller != (common.Address{}) {
		t.Fatalf("expected zero controller for unknown publisher, got %s", got.Controller.Hex())
	}
	if got.Status != PkgActive {
		t.Fatalf("expected zero status for unknown publisher, got %d", got.Status)
	}
}
