package tosapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/agent"
	"github.com/tos-network/gtos/agentdiscovery"
	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/paypolicy"
	"github.com/tos-network/gtos/pkgregistry"
	"github.com/tos-network/gtos/registry"
	"github.com/tos-network/gtos/verifyregistry"
)

func agentSlotForTest(addr common.Address, field string) []byte {
	key := make([]byte, 0, common.AddressLength+1+len(field))
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return crypto.Keccak256(key)
}

func TestTolGetCapabilityReturnsNilForEmptyState(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	got, err := api.TolGetCapability(context.Background(), "transfer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty state, got %+v", got)
	}
}

func TestTolGetCapabilityReturnsRegistryBackedRecord(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	if err := capability.RegisterCapabilityNameAtBit(st, "oracle", 0); err != nil {
		t.Fatalf("register capability bit: %v", err)
	}
	registry.WriteCapability(st, registry.CapabilityRecord{
		Name:        "oracle",
		BitIndex:    0,
		Category:    7,
		Version:     2,
		Status:      registry.CapActive,
		ManifestRef: [32]byte{0xAA},
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	got, err := api.TolGetCapability(context.Background(), "oracle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil capability")
	}
	if got.BitIndex != 0 || got.Category != 7 || got.Version != 2 || got.Status != "active" {
		t.Fatalf("unexpected capability payload %+v", got)
	}
}

func TestTolGetDelegationReturnsNilForEmptyState(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	got, err := api.TolGetDelegation(context.Background(), "0xabc", "0xdef", "0x123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty state, got %+v", got)
	}
}

func TestTolGetDelegationReturnsRecord(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	principal := common.HexToAddress("0x1111111111111111111111111111111111111111")
	delegate := common.HexToAddress("0x2222222222222222222222222222222222222222")
	scope := common.HexToHash("0x01")
	registry.WriteDelegation(st, registry.DelegationRecord{
		Principal:     principal,
		Delegate:      delegate,
		ScopeRef:      scope,
		CapabilityRef: [32]byte{0xAA},
		PolicyRef:     [32]byte{0xBB},
		NotBeforeMS:   100,
		ExpiryMS:      200,
		Status:        registry.DelActive,
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	got, err := api.TolGetDelegation(context.Background(), principal.Hex(), delegate.Hex(), scope.Hex())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil delegation")
	}
	if got.Status != "active" || got.NotBeforeMS != 100 || got.ExpiryMS != 200 {
		t.Fatalf("unexpected delegation payload %+v", got)
	}
}

func TestTolGetPackageReturnsNilForEmptyState(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	got, err := api.TolGetPackage(context.Background(), "demo.checkout", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty state, got %+v", got)
	}
}

func TestTolGetPackageReturnsRecord(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	rec := pkgregistry.PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "1.0.0",
		PackageHash:    [32]byte{0x11},
		PublisherID:    [32]byte{0x22},
		ManifestHash:   [32]byte{0x33},
		Channel:        pkgregistry.ChannelStable,
		Status:         pkgregistry.PkgActive,
		ContractCount:  2,
		DiscoveryRef:   [32]byte{0x44},
		PublishedAt:    1234,
	}
	pkgregistry.WritePackage(st, rec)
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	got, err := api.TolGetPackage(context.Background(), "demo.checkout", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil package")
	}
	if got.Channel != "stable" || got.ContractCount != 2 || got.PublishedAt != 1234 {
		t.Fatalf("unexpected package payload %+v", got)
	}
	byHash, err := api.TolGetPackageByHash(context.Background(), common.Hash(rec.PackageHash).Hex())
	if err != nil {
		t.Fatalf("unexpected hash lookup error: %v", err)
	}
	if byHash == nil || byHash.Name != "demo.checkout" {
		t.Fatalf("unexpected hash lookup payload %+v", byHash)
	}
}

func TestTolGetLatestPackageReturnsIndexedStableRecord(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "1.0.0",
		PackageHash:    [32]byte{0x10},
		PublisherID:    [32]byte{0xAA},
		Channel:        pkgregistry.ChannelStable,
		Status:         pkgregistry.PkgActive,
	})
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "1.1.0",
		PackageHash:    [32]byte{0x11},
		PublisherID:    [32]byte{0xAA},
		Channel:        pkgregistry.ChannelStable,
		Status:         pkgregistry.PkgActive,
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	got, err := api.TolGetLatestPackage(context.Background(), "demo.checkout", "stable")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil latest package")
	}
	if got.Version != "1.1.0" || got.Channel != "stable" {
		t.Fatalf("unexpected latest package %+v", got)
	}
}

func TestTolGetLatestPackageReturnsNilForUnknownChannel(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	got, err := api.TolGetLatestPackage(context.Background(), "demo.checkout", "nightly")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for unknown channel, got %+v", got)
	}
}

func TestTolGetPublisherReturnsNilForEmptyState(t *testing.T) {
	api := NewTOSAPI(newBackendMock())
	got, err := api.TolGetPublisher(context.Background(), "pub-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty state, got %+v", got)
	}
}

func TestTolGetPublisherReturnsRecord(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	rec := pkgregistry.PublisherRecord{
		PublisherID: [32]byte{0x99},
		Controller:  common.HexToAddress("0x1234000000000000000000000000000000000000"),
		MetadataRef: [32]byte{0xAB},
		Status:      pkgregistry.PkgActive,
	}
	pkgregistry.WritePublisher(st, rec)
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	got, err := api.TolGetPublisher(context.Background(), common.Hash(rec.PublisherID).Hex())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil publisher")
	}
	if got.Controller != rec.Controller.Hex() || got.Status != "active" {
		t.Fatalf("unexpected publisher payload %+v", got)
	}
}

func TestTolGetVerifierAndVerificationReturnRecords(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	verifierAddr := common.HexToAddress("0x1234000000000000000000000000000000000000")
	verifyregistry.WriteVerifier(st, verifyregistry.VerifierRecord{
		Name:         "state_proof",
		VerifierType: 1,
		VerifierAddr: verifierAddr,
		Version:      1,
		Status:       verifyregistry.VerifierActive,
	})
	subject := common.HexToAddress("0xabcd")
	verifyregistry.WriteSubjectVerification(st, verifyregistry.SubjectVerificationRecord{
		Subject:    subject,
		ProofType:  "state_proof",
		VerifiedAt: 7,
		ExpiryMS:   1000,
		Status:     verifyregistry.VerificationActive,
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	verifier, err := api.TolGetVerifier(context.Background(), "state_proof")
	if err != nil {
		t.Fatalf("unexpected verifier error: %v", err)
	}
	if verifier == nil || verifier.VerifierAddr != verifierAddr.Hex() {
		t.Fatalf("unexpected verifier payload %+v", verifier)
	}
	claim, err := api.TolGetVerification(context.Background(), subject.Hex(), "state_proof")
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if claim == nil || claim.Status != "active" || claim.VerifiedAt != 7 {
		t.Fatalf("unexpected verification payload %+v", claim)
	}
}

func TestTolGetSettlementPolicyReturnsRecord(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	owner := common.HexToAddress("0x2222000000000000000000000000000000000000")
	paypolicy.WritePolicy(st, paypolicy.PolicyRecord{
		PolicyID:  [32]byte{0x55},
		Kind:      2,
		Owner:     owner,
		Asset:     "TOS",
		MaxAmount: big.NewInt(500),
		Status:    paypolicy.PolicyActive,
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	got, err := api.TolGetSettlementPolicy(context.Background(), owner.Hex(), "TOS")
	if err != nil {
		t.Fatalf("unexpected settlement policy error: %v", err)
	}
	if got == nil || got.MaxAmount != "500" || got.Status != "active" {
		t.Fatalf("unexpected settlement policy payload %+v", got)
	}
}

func TestTolGetAgentIdentityReturnsRecord(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x9999000000000000000000000000000000000000")
	agent.WriteStatus(st, addr, agent.AgentActive)
	agent.WriteStake(st, addr, big.NewInt(123))
	agent.WriteMetadata(st, addr, "https://agent.example/profile")
	agent.WriteSuspended(st, addr, false)
	// Mark registered using the real handler helper sequence.
	// The public state package uses the registered flag as the source of truth.
	type registeredWriter interface {
		SetState(common.Address, common.Hash, common.Hash)
	}
	if rw, ok := any(st).(registeredWriter); ok {
		var one common.Hash
		one[31] = 1
		// mirror agent.agentSlot(addr, "registered") formula locally
		slot := common.BytesToHash(agentSlotForTest(addr, "registered"))
		rw.SetState(params.AgentRegistryAddress, slot, one)
	}
	agentdiscovery.WriteIdentityBinding(st, &agentdiscovery.IdentityBinding{
		AgentAddress:      addr,
		OnChainVerified:   true,
		CapabilitiesMatch: true,
		Active:            true,
		BindingHash:       common.HexToHash("0xab"),
		VerifiedAt:        1,
		ExpiresAt:         999,
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	got, err := api.TolGetAgentIdentity(context.Background(), addr.Hex())
	if err != nil {
		t.Fatalf("unexpected agent identity error: %v", err)
	}
	if got == nil || !got.Registered || got.Stake != "123" || !got.BindingVerified {
		t.Fatalf("unexpected agent identity payload %+v", got)
	}
}
