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
		Owner:       common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d"),
		Name:        "oracle",
		BitIndex:    0,
		Category:    7,
		Version:     2,
		Status:      registry.CapActive,
		ManifestRef: [32]byte{0xAA},
		CreatedAt:   12,
		UpdatedAt:   13,
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
	if got.BitIndex != 0 || got.Category != 7 || got.Version != 2 || got.Status != "active" || got.Owner == "" || got.CreatedAt != 12 || got.UpdatedAt != 13 {
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
	principal := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	delegate := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")
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
		CreatedAt:     14,
		UpdatedAt:     15,
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
	if got.Status != "active" || got.NotBeforeMS != 100 || got.ExpiryMS != 200 || got.CreatedAt != 14 || got.UpdatedAt != 15 {
		t.Fatalf("unexpected delegation payload %+v", got)
	}
}

func TestTolGetDelegationReturnsEffectiveExpiredStatus(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	principal := common.HexToAddress("0x8ac013baac6fd392efc57bb097b1c813eae702332ba3eaa1625f942c5472626d")
	delegate := common.HexToAddress("0x473302ca547d5f9877e272cffe58d4def43198b66ba35cff4b2e584be19efa05")
	scope := common.HexToHash("0x01")
	registry.WriteDelegation(st, registry.DelegationRecord{
		Principal:   principal,
		Delegate:    delegate,
		ScopeRef:    scope,
		NotBeforeMS: 100,
		ExpiryMS:    200,
		Status:      registry.DelActive,
		CreatedAt:   16,
		UpdatedAt:   17,
	})
	backend := newBackendMock()
	backend.state = st
	backend.current.Time = 1
	api := NewTOSAPI(backend)

	got, err := api.TolGetDelegation(context.Background(), principal.Hex(), delegate.Hex(), scope.Hex())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.EffectiveStatus != "expired" {
		t.Fatalf("expected expired effective status, got %+v", got)
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
		CreatedAt:      1234,
		UpdatedAt:      1235,
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
	if got.Channel != "stable" || got.ContractCount != 2 || got.PublishedAt != 1234 || got.CreatedAt != 1234 || got.UpdatedAt != 1235 || got.EffectiveStatus != "active" || got.NamespaceStatus != "clear" {
		t.Fatalf("unexpected package payload %+v", got)
	}
	if got.Trusted {
		t.Fatalf("expected package to be untrusted without publisher record, got %+v", got)
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
		CreatedAt:      1,
		UpdatedAt:      1,
	})
	pkgregistry.WritePublisher(st, pkgregistry.PublisherRecord{
		PublisherID: [32]byte{0xAA},
		Controller:  common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7"),
		Namespace:   "demo",
		Status:      pkgregistry.PkgActive,
		CreatedAt:   2,
		UpdatedAt:   2,
	})
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "1.1.0",
		PackageHash:    [32]byte{0x11},
		PublisherID:    [32]byte{0xAA},
		Channel:        pkgregistry.ChannelStable,
		Status:         pkgregistry.PkgActive,
		CreatedAt:      3,
		UpdatedAt:      3,
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
	if got.Version != "1.1.0" || got.Channel != "stable" || got.Namespace != "demo" || !got.Trusted || got.EffectiveStatus != "active" {
		t.Fatalf("unexpected latest package %+v", got)
	}
}

func TestTolGetLatestPackageReturnsNilWhenNamespaceDisputed(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	pubID := [32]byte{0xAA}
	pkgregistry.WritePublisher(st, pkgregistry.PublisherRecord{
		PublisherID: pubID,
		Controller:  common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7"),
		Namespace:   "demo",
		Status:      pkgregistry.PkgActive,
	})
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "1.1.0",
		PackageHash:    [32]byte{0x11},
		PublisherID:    pubID,
		Channel:        pkgregistry.ChannelStable,
		Status:         pkgregistry.PkgActive,
	})
	pkgregistry.WriteNamespaceGovernance(st, pkgregistry.NamespaceGovernanceRecord{
		Namespace:   "demo",
		PublisherID: pubID,
		Status:      pkgregistry.NamespaceDisputed,
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)
	got, err := api.TolGetLatestPackage(context.Background(), "demo.checkout", "stable")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil latest package under namespace dispute, got %+v", got)
	}
}

func TestTolGetNamespaceClaimReturnsGovernorState(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	pubID := [32]byte{0xAA}
	pkgregistry.WritePublisher(st, pkgregistry.PublisherRecord{
		PublisherID: pubID,
		Controller:  common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7"),
		Namespace:   "demo",
		Status:      pkgregistry.PkgActive,
	})
	pkgregistry.WriteNamespaceGovernance(st, pkgregistry.NamespaceGovernanceRecord{
		Namespace:   "demo",
		PublisherID: pubID,
		Status:      pkgregistry.NamespaceDisputed,
		EvidenceRef: [32]byte{0x77},
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)
	got, err := api.TolGetNamespaceClaim(context.Background(), "demo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Status != "disputed" || got.PublisherID != common.Hash(pubID).Hex() {
		t.Fatalf("unexpected namespace claim %+v", got)
	}
}

func TestTolGetPackageReturnsUntrustedWhenPublisherSuspended(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	pubID := [32]byte{0xAB}
	pkgregistry.WritePublisher(st, pkgregistry.PublisherRecord{
		PublisherID: pubID,
		Controller:  common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7"),
		Namespace:   "demo",
		Status:      pkgregistry.PkgDeprecated,
		CreatedAt:   2,
		UpdatedAt:   3,
	})
	pkgregistry.WritePackage(st, pkgregistry.PackageRecord{
		PackageName:    "demo.checkout",
		PackageVersion: "2.0.0",
		PackageHash:    [32]byte{0x22},
		PublisherID:    pubID,
		Channel:        pkgregistry.ChannelStable,
		Status:         pkgregistry.PkgActive,
		CreatedAt:      4,
		UpdatedAt:      4,
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	got, err := api.TolGetPackage(context.Background(), "demo.checkout", "2.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Trusted {
		t.Fatalf("expected package to be untrusted under suspended publisher, got %+v", got)
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
		Controller:  common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7"),
		MetadataRef: [32]byte{0xAB},
		Namespace:   "demo.checkout",
		Status:      pkgregistry.PkgActive,
		CreatedAt:   55,
		UpdatedAt:   56,
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
	if got.Controller != rec.Controller.Hex() || got.Status != "active" || got.Namespace != "demo.checkout" || got.CreatedAt != 55 || got.UpdatedAt != 56 {
		t.Fatalf("unexpected publisher payload %+v", got)
	}
}

func TestTolGetPublisherByNamespaceReturnsRecord(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	rec := pkgregistry.PublisherRecord{
		PublisherID: [32]byte{0x98},
		Controller:  common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7"),
		Namespace:   "demo.checkout",
		Status:      pkgregistry.PkgDeprecated,
		CreatedAt:   77,
		UpdatedAt:   88,
	}
	pkgregistry.WritePublisher(st, rec)
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	got, err := api.TolGetPublisherByNamespace(context.Background(), "demo.checkout")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil publisher")
	}
	if got.Namespace != "demo.checkout" || got.Controller != rec.Controller.Hex() {
		t.Fatalf("unexpected publisher payload %+v", got)
	}
	if got.Status != "suspended" || got.CreatedAt != 77 || got.UpdatedAt != 88 {
		t.Fatalf("unexpected publisher lifecycle payload %+v", got)
	}
}

func TestTolGetVerifierAndVerificationReturnRecords(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	verifierAddr := common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7")
	verifyregistry.WriteVerifier(st, verifyregistry.VerifierRecord{
		Name:         "state_proof",
		VerifierType: 1,
		Controller:   common.HexToAddress("0xf4897a85e6ac20f6b7b22e2c3a8fac52fb6c36430b80655354e5aa4f5e1a3533"),
		VerifierAddr: verifierAddr,
		Version:      1,
		Status:       verifyregistry.VerifierActive,
		CreatedAt:    20,
		UpdatedAt:    21,
	})
	subject := common.HexToAddress("0x3ccadfb801017cfb0f5dc61ef0e96fdaacbdb11c91ba5a230959e8d14020ea50")
	verifyregistry.WriteSubjectVerification(st, verifyregistry.SubjectVerificationRecord{
		Subject:    subject,
		ProofType:  "state_proof",
		VerifiedAt: 7,
		ExpiryMS:   1000,
		Status:     verifyregistry.VerificationActive,
		UpdatedAt:  22,
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	verifier, err := api.TolGetVerifier(context.Background(), "state_proof")
	if err != nil {
		t.Fatalf("unexpected verifier error: %v", err)
	}
	if verifier == nil || verifier.VerifierAddr != verifierAddr.Hex() || verifier.Controller == "" || verifier.VerifierClass != "zk_proof" || verifier.CreatedAt != 20 || verifier.UpdatedAt != 21 {
		t.Fatalf("unexpected verifier payload %+v", verifier)
	}
	claim, err := api.TolGetVerification(context.Background(), subject.Hex(), "state_proof")
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if claim == nil || claim.Status != "active" || claim.VerifierClass != "zk_proof" || claim.ProofClass != "zk_proof" || claim.VerifiedAt != 7 || claim.UpdatedAt != 22 {
		t.Fatalf("unexpected verification payload %+v", claim)
	}
}

func TestTolGetVerificationReturnsEffectiveExpiredStatus(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	verifierAddr := common.HexToAddress("0xdf96edbc954f43d46dc80e0180291bb781ac0a8a3a69c785631d4193e9a9d5e7")
	verifyregistry.WriteVerifier(st, verifyregistry.VerifierRecord{
		Name:         "state_proof",
		VerifierType: 1,
		Controller:   common.HexToAddress("0xf4897a85e6ac20f6b7b22e2c3a8fac52fb6c36430b80655354e5aa4f5e1a3533"),
		VerifierAddr: verifierAddr,
		Version:      1,
		Status:       verifyregistry.VerifierActive,
		CreatedAt:    20,
		UpdatedAt:    21,
	})
	subject := common.HexToAddress("0x3ccadfb801017cfb0f5dc61ef0e96fdaacbdb11c91ba5a230959e8d14020ea50")
	verifyregistry.WriteSubjectVerification(st, verifyregistry.SubjectVerificationRecord{
		Subject:    subject,
		ProofType:  "state_proof",
		VerifiedAt: 7,
		ExpiryMS:   1000,
		Status:     verifyregistry.VerificationActive,
		UpdatedAt:  22,
	})
	backend := newBackendMock()
	backend.state = st
	backend.current.Time = 2
	api := NewTOSAPI(backend)

	claim, err := api.TolGetVerification(context.Background(), subject.Hex(), "state_proof")
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if claim == nil || claim.EffectiveStatus != "expired" {
		t.Fatalf("expected expired effective status, got %+v", claim)
	}
}

func TestTolGetSettlementPolicyReturnsRecord(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	owner := common.HexToAddress("0xc93118fe4956b46c1460d1bb6740f640236701d1210f2160f9c1e0cfeed6b41e")
	paypolicy.WritePolicy(st, paypolicy.PolicyRecord{
		PolicyID:  [32]byte{0x55},
		Kind:      2,
		Owner:     owner,
		Asset:     "TOS",
		MaxAmount: big.NewInt(500),
		Status:    paypolicy.PolicyActive,
		CreatedAt: 30,
		UpdatedAt: 31,
	})
	backend := newBackendMock()
	backend.state = st
	api := NewTOSAPI(backend)

	got, err := api.TolGetSettlementPolicy(context.Background(), owner.Hex(), "TOS")
	if err != nil {
		t.Fatalf("unexpected settlement policy error: %v", err)
	}
	if got == nil || got.MaxAmount != "500" || got.PolicyClass != "pay" || got.Status != "active" || got.CreatedAt != 30 || got.UpdatedAt != 31 {
		t.Fatalf("unexpected settlement policy payload %+v", got)
	}
}

func TestTolGetAgentIdentityReturnsRecord(t *testing.T) {
	st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	addr := common.HexToAddress("0x0791868d8f29ea735f26a17a9aea038cd4255baac26eac5a74e58a07ed2f1975")
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
