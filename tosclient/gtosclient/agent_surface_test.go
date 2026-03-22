package gtosclient

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/tos-network/gtos/agentdiscovery"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/rpc"
	"github.com/tos-network/gtos/tosclient"
	tolmeta "github.com/tos-network/tolang/metadata"
)

type agentSurfaceRPCService struct {
	lastAddress          common.Address
	lastBlock            string
	lastNode             string
	lastSearchCapability string
	lastSearchLimit      *int
	lastDirectoryNode    string
	lastDirectoryCap     string
	lastDirectoryLimit   *int
	lastReceiptRef       common.Hash
	lastSettlementRef    common.Hash
}

func (s *agentSurfaceRPCService) GetContractMetadata(address common.Address, block string) interface{} {
	s.lastAddress = address
	s.lastBlock = block
	if address == common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000aa") {
		return tosclient.DeployedCodeInfo{
			Address:  address,
			CodeHash: common.HexToHash("0x1111"),
			CodeKind: "toc",
			Artifact: &tosclient.TOLArtifactInfo{
				ContractName: "TaskSettlement",
				Profile: &tolmeta.AgentContractProfile{
					SchemaVersion: tolmeta.AgentProfileSchemaVersion,
					Identity: tolmeta.ProfileIdentity{
						PackageName:    "tolang.openlib.settlement",
						PackageVersion: "1.0.0",
					},
				},
				Routing: &agentdiscovery.TypedRoutingProfile{
					ContractType:    "settlement",
					ServiceKinds:    []string{"marketplace", "settlement"},
					ServiceKind:     "settlement",
					CapabilityKind:  "managed_execution",
					PricingKind:     "fixed",
					PrivacyMode:     "public",
					ReceiptMode:     "required",
					DisclosureReady: false,
				},
				SuggestedCard: &agentdiscovery.PublishedCard{
					AgentID:     "settlement-agent",
					PackageName: "tolang.openlib.settlement",
				},
			},
		}
	}
	if address == common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000cc") {
		manifest, _ := json.Marshal(map[string]any{
			"name":          "privacy",
			"package":       "tolang.openlib.privacy",
			"version":       "1.0.1",
			"main_contract": "ConfidentialEscrow",
		})
		return tosclient.DeployedCodeInfo{
			Address:  address,
			CodeHash: common.HexToHash("0x3333"),
			CodeKind: "tor",
			Package: &tosclient.TOLPackageInfo{
				Name:         "privacy",
				Package:      "tolang.openlib.privacy",
				Version:      "1.0.1",
				MainContract: "ConfidentialEscrow",
				Manifest:     manifest,
				Profile: &tolmeta.AgentBundleProfile{
					SchemaVersion:  tolmeta.AgentBundleProfileSchemaVersion,
					Family:         "privacy",
					PackageName:    "tolang.openlib.privacy",
					PackageVersion: "1.0.1",
				},
				Published: &tosclient.PackageInfo{
					Name:        "tolang.openlib.privacy",
					Version:     "1.0.1",
					PublisherID: common.HexToHash("0x1234").Hex(),
					Trusted:     false,
					Status:      "active",
					Channel:     "stable",
				},
				Publisher: &tosclient.PublisherInfo{
					PublisherID: common.HexToHash("0x1234").Hex(),
					Namespace:   "tolang.openlib",
					Status:      "active",
				},
				SuggestedCard: &agentdiscovery.PublishedCard{
					AgentID:        "privacy-untrusted-agent",
					PackageName:    "tolang.openlib.privacy",
					PackageVersion: "1.0.1",
				},
			},
		}
	}
	manifest, _ := json.Marshal(map[string]any{
		"name":          "privacy",
		"package":       "tolang.openlib.privacy",
		"version":       "1.0.0",
		"main_contract": "ConfidentialEscrow",
	})
	return tosclient.DeployedCodeInfo{
		Address:  address,
		CodeHash: common.HexToHash("0x2222"),
		CodeKind: "tor",
		Package: &tosclient.TOLPackageInfo{
			Name:         "privacy",
			Package:      "tolang.openlib.privacy",
			Version:      "1.0.0",
			MainContract: "ConfidentialEscrow",
			Manifest:     manifest,
			Profile: &tolmeta.AgentBundleProfile{
				SchemaVersion:  tolmeta.AgentBundleProfileSchemaVersion,
				Family:         "privacy",
				PackageName:    "tolang.openlib.privacy",
				PackageVersion: "1.0.0",
			},
			Published: &tosclient.PackageInfo{
				Name:        "tolang.openlib.privacy",
				Version:     "1.0.0",
				PublisherID: common.HexToHash("0x1234").Hex(),
				Trusted:     true,
				Status:      "active",
				Channel:     "stable",
			},
			Publisher: &tosclient.PublisherInfo{
				PublisherID: common.HexToHash("0x1234").Hex(),
				Namespace:   "tolang.openlib",
				Status:      "active",
			},
			SuggestedCard: &agentdiscovery.PublishedCard{
				AgentID:        "privacy-agent",
				PackageName:    "tolang.openlib.privacy",
				PackageVersion: "1.0.0",
			},
		},
	}
}

func (s *agentSurfaceRPCService) AgentDiscoveryGetCard(nodeRecord string) interface{} {
	s.lastNode = nodeRecord
	switch nodeRecord {
	case "enr:-artifact":
		return agentdiscovery.CardResponse{
			NodeID:     "node-artifact",
			NodeRecord: nodeRecord,
			CardJSON:   `{"agent_id":"settlement-agent"}`,
			ParsedCard: &agentdiscovery.PublishedCard{
				AgentID:      "settlement-agent",
				AgentAddress: common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000aa").Hex(),
			},
		}
	case "enr:-missing-address":
		return agentdiscovery.CardResponse{
			NodeID:     "node-missing",
			NodeRecord: nodeRecord,
			CardJSON:   `{"agent_id":"missing-agent"}`,
			ParsedCard: &agentdiscovery.PublishedCard{
				AgentID: "missing-agent",
			},
		}
	case "enr:-package":
		return agentdiscovery.CardResponse{
			NodeID:     "node-package",
			NodeRecord: nodeRecord,
			CardJSON:   `{"agent_id":"privacy-agent"}`,
			ParsedCard: &agentdiscovery.PublishedCard{
				AgentID:      "privacy-agent",
				AgentAddress: common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000bb").Hex(),
			},
		}
	case "enr:-untrusted-package":
		return agentdiscovery.CardResponse{
			NodeID:     "node-untrusted-package",
			NodeRecord: nodeRecord,
			CardJSON:   `{"agent_id":"privacy-untrusted-agent"}`,
			ParsedCard: &agentdiscovery.PublishedCard{
				AgentID:      "privacy-untrusted-agent",
				AgentAddress: common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000cc").Hex(),
			},
		}
	default:
		return agentdiscovery.CardResponse{
			NodeID:     "node-invalid",
			NodeRecord: nodeRecord,
			CardJSON:   `{"agent_id":"invalid-agent"}`,
			ParsedCard: &agentdiscovery.PublishedCard{
				AgentID:      "invalid-agent",
				AgentAddress: "0x1234",
			},
		}
	}
}

func (s *agentSurfaceRPCService) AgentDiscoverySearch(capability string, limit *int) interface{} {
	s.lastSearchCapability = capability
	s.lastSearchLimit = limit
	if capability == "settlement.rank" {
		return []agentdiscovery.SearchResult{
			{
				NodeID:          "node-untrusted-package",
				NodeRecord:      "enr:-untrusted-package",
				PrimaryIdentity: common.HexToAddress("0x1234").Hex(),
				ConnectionModes: agentdiscovery.ConnectionModeTalkReq,
				Capabilities:    []string{"settlement.rank"},
				Trust: &agentdiscovery.ProviderTrustSummary{
					Registered:           true,
					HasOnchainCapability: true,
					LocalRankScore:       99,
				},
			},
			{
				NodeID:          "node-artifact",
				NodeRecord:      "enr:-artifact",
				PrimaryIdentity: common.HexToAddress("0x1234").Hex(),
				ConnectionModes: agentdiscovery.ConnectionModeTalkReq | agentdiscovery.ConnectionModeHTTPS,
				Capabilities:    []string{"settlement.rank"},
				Trust: &agentdiscovery.ProviderTrustSummary{
					Registered:           true,
					HasOnchainCapability: true,
					LocalRankScore:       95,
				},
			},
			{
				NodeID:          "node-package",
				NodeRecord:      "enr:-package",
				PrimaryIdentity: common.HexToAddress("0x1234").Hex(),
				ConnectionModes: agentdiscovery.ConnectionModeTalkReq | agentdiscovery.ConnectionModeStream,
				Capabilities:    []string{"settlement.rank"},
				Trust: &agentdiscovery.ProviderTrustSummary{
					Registered:           true,
					HasOnchainCapability: true,
					LocalRankScore:       80,
				},
			},
		}
	}
	return []agentdiscovery.SearchResult{
		{
			NodeID:          "node-artifact",
			NodeRecord:      "enr:-artifact",
			PrimaryIdentity: common.HexToAddress("0x1234").Hex(),
			Capabilities:    []string{"settlement.execute"},
			Trust: &agentdiscovery.ProviderTrustSummary{
				Registered:           true,
				HasOnchainCapability: true,
				LocalRankScore:       70,
			},
		},
	}
}

func (s *agentSurfaceRPCService) AgentDiscoveryDirectorySearch(nodeRecord string, capability string, limit *int) interface{} {
	s.lastDirectoryNode = nodeRecord
	s.lastDirectoryCap = capability
	s.lastDirectoryLimit = limit
	if capability == "settlement.rank" {
		return []agentdiscovery.SearchResult{
			{
				NodeID:          "node-package",
				NodeRecord:      "enr:-package",
				PrimaryIdentity: common.HexToAddress("0x1234").Hex(),
				ConnectionModes: agentdiscovery.ConnectionModeTalkReq | agentdiscovery.ConnectionModeStream,
				Capabilities:    []string{"settlement.rank"},
				Trust: &agentdiscovery.ProviderTrustSummary{
					Registered:           true,
					HasOnchainCapability: true,
					LocalRankScore:       81,
				},
			},
			{
				NodeID:          "node-artifact",
				NodeRecord:      "enr:-artifact",
				PrimaryIdentity: common.HexToAddress("0x1234").Hex(),
				ConnectionModes: agentdiscovery.ConnectionModeTalkReq | agentdiscovery.ConnectionModeHTTPS,
				Capabilities:    []string{"settlement.rank"},
				Trust: &agentdiscovery.ProviderTrustSummary{
					Registered:           true,
					HasOnchainCapability: true,
					LocalRankScore:       90,
				},
			},
		}
	}
	return []agentdiscovery.SearchResult{
		{
			NodeID:          "node-artifact",
			NodeRecord:      "enr:-artifact",
			PrimaryIdentity: common.HexToAddress("0x1234").Hex(),
			Capabilities:    []string{"settlement.execute"},
			Trust: &agentdiscovery.ProviderTrustSummary{
				Registered:           true,
				HasOnchainCapability: true,
				LocalRankScore:       70,
			},
		},
	}
}

func (s *agentSurfaceRPCService) GetRuntimeReceipt(receiptRef common.Hash) interface{} {
	s.lastReceiptRef = receiptRef
	switch receiptRef {
	case common.HexToHash("0xaaa1"):
		return tosclient.RuntimeReceiptInfo{
			ReceiptRef:    receiptRef.Hex(),
			ReceiptKind:   7,
			Status:        "success",
			Mode:          1,
			ModeName:      "PUBLIC_TRANSFER",
			Sender:        common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000aa").Hex(),
			Recipient:     common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000bb").Hex(),
			Sponsor:       common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000cc").Hex(),
			SettlementRef: common.HexToHash("0xbbb1").Hex(),
			OpenedAt:      10,
			FinalizedAt:   11,
		}
	default:
		return nil
	}
}

func (s *agentSurfaceRPCService) GetSettlementEffect(settlementRef common.Hash) interface{} {
	s.lastSettlementRef = settlementRef
	switch settlementRef {
	case common.HexToHash("0xbbb1"):
		return tosclient.SettlementEffectInfo{
			SettlementRef: settlementRef.Hex(),
			ReceiptRef:    common.HexToHash("0xaaa1").Hex(),
			Mode:          1,
			ModeName:      "PUBLIC_TRANSFER",
			Sender:        common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000aa").Hex(),
			Recipient:     common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000bb").Hex(),
			Sponsor:       common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000cc").Hex(),
			CreatedAt:     10,
		}
	default:
		return nil
	}
}

func newAgentSurfaceClient(t *testing.T) (*Client, *agentSurfaceRPCService, func()) {
	t.Helper()
	svc := new(agentSurfaceRPCService)
	server := rpc.NewServer()
	if err := server.RegisterName("tos", svc); err != nil {
		t.Fatalf("RegisterName: %v", err)
	}
	if err := server.RegisterName("settlement", svc); err != nil {
		t.Fatalf("RegisterName settlement: %v", err)
	}
	raw := rpc.DialInProc(server)
	return New(raw), svc, func() { raw.Close(); server.Stop() }
}

func TestGetAgentRuntimeSurfaceArtifact(t *testing.T) {
	client, svc, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	addr := common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000aa")
	surface, err := client.GetAgentRuntimeSurface(context.Background(), addr, big.NewInt(9))
	if err != nil {
		t.Fatalf("GetAgentRuntimeSurface error: %v", err)
	}
	if svc.lastBlock != "0x9" {
		t.Fatalf("block arg = %q, want 0x9", svc.lastBlock)
	}
	if surface == nil || surface.CodeKind != "toc" || surface.Profile == nil || surface.Routing == nil {
		t.Fatalf("unexpected artifact surface: %+v", surface)
	}
	if surface.PackageName != "tolang.openlib.settlement" || surface.SuggestedCard == nil || surface.SuggestedCard.AgentID != "settlement-agent" {
		t.Fatalf("unexpected artifact fields: %+v", surface)
	}
}

func TestGetAgentRuntimeSurfacePackage(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	addr := common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000bb")
	surface, err := client.GetAgentRuntimeSurface(context.Background(), addr, nil)
	if err != nil {
		t.Fatalf("GetAgentRuntimeSurface error: %v", err)
	}
	if surface == nil || surface.CodeKind != "tor" || surface.BundleProfile == nil {
		t.Fatalf("unexpected package surface: %+v", surface)
	}
	if surface.Published == nil || !surface.Published.Trusted || surface.Publisher == nil || surface.SuggestedCard == nil {
		t.Fatalf("missing trust/card fields: %+v", surface)
	}
	if surface.PackageName != "tolang.openlib.privacy" || surface.ContractName != "ConfidentialEscrow" {
		t.Fatalf("unexpected normalized package fields: %+v", surface)
	}
}

func TestGetDiscoveredAgentSurfaceJoinsRuntimeMetadata(t *testing.T) {
	client, svc, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	surface, err := client.GetDiscoveredAgentSurface(context.Background(), "enr:-artifact", big.NewInt(4))
	if err != nil {
		t.Fatalf("GetDiscoveredAgentSurface error: %v", err)
	}
	if svc.lastNode != "enr:-artifact" {
		t.Fatalf("node record arg = %q, want enr:-artifact", svc.lastNode)
	}
	if surface == nil || surface.Card == nil || surface.Runtime == nil {
		t.Fatalf("expected joined discovery/runtime surface, got %+v", surface)
	}
	if surface.Runtime.ContractName != "TaskSettlement" || surface.Runtime.SuggestedCard == nil {
		t.Fatalf("unexpected runtime join: %+v", surface.Runtime)
	}
}

func TestGetDiscoveredAgentSurfaceSkipsMissingAddress(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	surface, err := client.GetDiscoveredAgentSurface(context.Background(), "enr:-missing-address", nil)
	if err != nil {
		t.Fatalf("GetDiscoveredAgentSurface error: %v", err)
	}
	if surface == nil || surface.Card == nil || surface.Runtime != nil {
		t.Fatalf("expected card-only surface, got %+v", surface)
	}
}

func TestGetDiscoveredAgentSurfaceSkipsMalformedAddress(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	surface, err := client.GetDiscoveredAgentSurface(context.Background(), "enr:-malformed", nil)
	if err != nil {
		t.Fatalf("GetDiscoveredAgentSurface error: %v", err)
	}
	if surface == nil || surface.Card == nil || surface.Runtime != nil {
		t.Fatalf("expected malformed address to fail closed without runtime join, got %+v", surface)
	}
}

func TestGetRuntimeReceiptSurfaceJoinsReceiptEffectAndRuntime(t *testing.T) {
	client, svc, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	surface, err := client.GetRuntimeReceiptSurface(context.Background(), common.HexToHash("0xaaa1"), big.NewInt(4))
	if err != nil {
		t.Fatalf("GetRuntimeReceiptSurface error: %v", err)
	}
	if svc.lastReceiptRef != common.HexToHash("0xaaa1") || svc.lastSettlementRef != common.HexToHash("0xbbb1") {
		t.Fatalf("unexpected lookup refs: receipt=%s settlement=%s", svc.lastReceiptRef.Hex(), svc.lastSettlementRef.Hex())
	}
	if surface == nil || surface.Receipt == nil || surface.Effect == nil {
		t.Fatalf("expected settlement surface, got %+v", surface)
	}
	if surface.SenderRuntime == nil || surface.SenderRuntime.ContractName != "TaskSettlement" {
		t.Fatalf("expected sender runtime join, got %+v", surface.SenderRuntime)
	}
	if surface.RecipientRuntime == nil || surface.RecipientRuntime.PackageName != "tolang.openlib.privacy" {
		t.Fatalf("expected recipient runtime join, got %+v", surface.RecipientRuntime)
	}
	if surface.Receipt.Sponsor != common.HexToAddress("0x00000000000000000000000000000000000000000000000000000000000000cc").Hex() || surface.Effect.Sponsor != surface.Receipt.Sponsor {
		t.Fatalf("expected sponsor join on runtime settlement surface, got receipt=%+v effect=%+v", surface.Receipt, surface.Effect)
	}
}

func TestGetSettlementEffectSurfaceJoinsReceiptAndRuntime(t *testing.T) {
	client, svc, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	surface, err := client.GetSettlementEffectSurface(context.Background(), common.HexToHash("0xbbb1"), big.NewInt(5))
	if err != nil {
		t.Fatalf("GetSettlementEffectSurface error: %v", err)
	}
	if svc.lastSettlementRef != common.HexToHash("0xbbb1") || svc.lastReceiptRef != common.HexToHash("0xaaa1") {
		t.Fatalf("unexpected lookup refs: settlement=%s receipt=%s", svc.lastSettlementRef.Hex(), svc.lastReceiptRef.Hex())
	}
	if surface == nil || surface.Effect == nil || surface.Receipt == nil {
		t.Fatalf("expected joined effect surface, got %+v", surface)
	}
	if surface.Receipt.ReceiptRef != common.HexToHash("0xaaa1").Hex() {
		t.Fatalf("unexpected receipt info: %+v", surface.Receipt)
	}
}

func TestSearchDiscoveredAgentSurfacesJoinsResults(t *testing.T) {
	client, svc, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 2
	results, err := client.SearchDiscoveredAgentSurfaces(context.Background(), "settlement.execute", &limit, big.NewInt(3))
	if err != nil {
		t.Fatalf("SearchDiscoveredAgentSurfaces error: %v", err)
	}
	if svc.lastSearchCapability != "settlement.execute" || svc.lastSearchLimit == nil || *svc.lastSearchLimit != 2 {
		t.Fatalf("unexpected search args: capability=%q limit=%v", svc.lastSearchCapability, svc.lastSearchLimit)
	}
	if len(results) != 1 || results[0].Surface == nil || results[0].Surface.Runtime == nil {
		t.Fatalf("expected joined search result, got %+v", results)
	}
	if results[0].Surface.Runtime.ContractName != "TaskSettlement" {
		t.Fatalf("unexpected joined runtime surface: %+v", results[0].Surface.Runtime)
	}
}

func TestDirectorySearchDiscoveredAgentSurfacesJoinsResults(t *testing.T) {
	client, svc, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 1
	results, err := client.DirectorySearchDiscoveredAgentSurfaces(context.Background(), "enr:-directory", "settlement.execute", &limit, nil)
	if err != nil {
		t.Fatalf("DirectorySearchDiscoveredAgentSurfaces error: %v", err)
	}
	if svc.lastDirectoryNode != "enr:-directory" || svc.lastDirectoryCap != "settlement.execute" || svc.lastDirectoryLimit == nil || *svc.lastDirectoryLimit != 1 {
		t.Fatalf("unexpected directory search args: node=%q capability=%q limit=%v", svc.lastDirectoryNode, svc.lastDirectoryCap, svc.lastDirectoryLimit)
	}
	if len(results) != 1 || results[0].Surface == nil || results[0].Surface.Runtime == nil {
		t.Fatalf("expected joined directory result, got %+v", results)
	}
}

func TestSearchTrustedAgentSurfacesFiltersAndSorts(t *testing.T) {
	client, svc, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 5
	results, err := client.SearchTrustedAgentSurfaces(context.Background(), "settlement.rank", &limit, nil)
	if err != nil {
		t.Fatalf("SearchTrustedAgentSurfaces error: %v", err)
	}
	if svc.lastSearchCapability != "settlement.rank" {
		t.Fatalf("unexpected capability arg: %q", svc.lastSearchCapability)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 trusted results after filtering, got %+v", results)
	}
	if results[0].Result.NodeRecord != "enr:-artifact" || results[0].TrustScore != 95 {
		t.Fatalf("expected artifact result ranked first, got %+v", results[0])
	}
	if results[1].Result.NodeRecord != "enr:-package" || results[1].TrustScore != 80 {
		t.Fatalf("expected trusted package result second, got %+v", results[1])
	}
}

func TestDirectorySearchTrustedAgentSurfacesFiltersAndSorts(t *testing.T) {
	client, svc, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 3
	results, err := client.DirectorySearchTrustedAgentSurfaces(context.Background(), "enr:-directory", "settlement.rank", &limit, nil)
	if err != nil {
		t.Fatalf("DirectorySearchTrustedAgentSurfaces error: %v", err)
	}
	if svc.lastDirectoryCap != "settlement.rank" {
		t.Fatalf("unexpected directory capability arg: %q", svc.lastDirectoryCap)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 trusted directory results, got %+v", results)
	}
	if results[0].Result.NodeRecord != "enr:-artifact" || results[0].TrustScore != 90 {
		t.Fatalf("expected higher-ranked artifact first, got %+v", results[0])
	}
}

func TestSearchPreferredAgentSurfacesAppliesPreferences(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 5
	results, err := client.SearchPreferredAgentSurfaces(context.Background(), "settlement.rank", &limit, nil, ProviderSelectionPreferences{
		MinTrustScore:           90,
		RequiredConnectionModes: agentdiscovery.ConnectionModeHTTPS,
		ServiceKind:             "settlement",
		CapabilityKind:          "managed_execution",
		PrivacyMode:             "public",
		ReceiptMode:             "required",
	})
	if err != nil {
		t.Fatalf("SearchPreferredAgentSurfaces error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one preferred provider, got %+v", results)
	}
	if results[0].Result.NodeRecord != "enr:-artifact" {
		t.Fatalf("expected artifact provider to satisfy routing prefs, got %+v", results[0])
	}
}

func TestDirectorySearchPreferredAgentSurfacesAppliesPreferences(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 3
	results, err := client.DirectorySearchPreferredAgentSurfaces(context.Background(), "enr:-directory", "settlement.rank", &limit, nil, ProviderSelectionPreferences{
		RequiredConnectionModes: agentdiscovery.ConnectionModeStream,
		PackagePrefix:           "tolang.openlib.privacy",
		MinTrustScore:           80,
	})
	if err != nil {
		t.Fatalf("DirectorySearchPreferredAgentSurfaces error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one preferred directory provider, got %+v", results)
	}
	if results[0].Result.NodeRecord != "enr:-package" {
		t.Fatalf("expected trusted package provider, got %+v", results[0])
	}
}

func TestSelectPreferredAgentSurfaceReturnsBestMatch(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 5
	trusted, err := client.SearchTrustedAgentSurfaces(context.Background(), "settlement.rank", &limit, nil)
	if err != nil {
		t.Fatalf("SearchTrustedAgentSurfaces error: %v", err)
	}
	selected := SelectPreferredAgentSurface(trusted, ProviderSelectionPreferences{
		PackagePrefix: "tolang.openlib.privacy",
	})
	if selected == nil {
		t.Fatalf("expected package-preferring selection to succeed")
	}
	if selected.Result.NodeRecord != "enr:-package" {
		t.Fatalf("expected package result to be selected, got %+v", selected)
	}

	selected = SelectPreferredAgentSurface(trusted, ProviderSelectionPreferences{
		MinTrustScore:           90,
		RequiredConnectionModes: agentdiscovery.ConnectionModeHTTPS,
		ServiceKind:             "settlement",
	})
	if selected == nil {
		t.Fatalf("expected routing-aware selection to succeed")
	}
	if selected.Result.NodeRecord != "enr:-artifact" {
		t.Fatalf("expected artifact result to be selected, got %+v", selected)
	}
}

func TestResolvePreferredAgentSurfaceReturnsBestMatch(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 5
	selected, err := client.ResolvePreferredAgentSurface(context.Background(), "settlement.rank", &limit, nil, ProviderSelectionPreferences{
		RequiredConnectionModes: agentdiscovery.ConnectionModeHTTPS,
		ServiceKind:             "settlement",
		MinTrustScore:           90,
	})
	if err != nil {
		t.Fatalf("ResolvePreferredAgentSurface error: %v", err)
	}
	if selected == nil {
		t.Fatalf("expected best preferred provider")
	}
	if selected.Result.NodeRecord != "enr:-artifact" {
		t.Fatalf("expected artifact provider, got %+v", selected)
	}
}

func TestResolvePreferredAgentSurfaceReturnsNilWhenNoMatch(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 5
	selected, err := client.ResolvePreferredAgentSurface(context.Background(), "settlement.rank", &limit, nil, ProviderSelectionPreferences{
		PackagePrefix: "tolang.openlib.unknown",
	})
	if err != nil {
		t.Fatalf("ResolvePreferredAgentSurface error: %v", err)
	}
	if selected != nil {
		t.Fatalf("expected no preferred provider, got %+v", selected)
	}
}

func TestResolveDirectoryPreferredAgentSurfaceReturnsBestMatch(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 3
	selected, err := client.ResolveDirectoryPreferredAgentSurface(context.Background(), "enr:-directory", "settlement.rank", &limit, nil, ProviderSelectionPreferences{
		PackagePrefix:           "tolang.openlib.privacy",
		RequiredConnectionModes: agentdiscovery.ConnectionModeStream,
		MinTrustScore:           80,
	})
	if err != nil {
		t.Fatalf("ResolveDirectoryPreferredAgentSurface error: %v", err)
	}
	if selected == nil {
		t.Fatalf("expected best preferred directory provider")
	}
	if selected.Result.NodeRecord != "enr:-package" {
		t.Fatalf("expected package provider, got %+v", selected)
	}
}

func TestSearchPreferredAgentSurfaceDiagnosticsReportsTrustAndPreferenceFailures(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 5
	diags, err := client.SearchPreferredAgentSurfaceDiagnostics(context.Background(), "settlement.rank", &limit, nil, ProviderSelectionPreferences{
		MinTrustScore:           90,
		RequiredConnectionModes: agentdiscovery.ConnectionModeHTTPS,
		ServiceKind:             "settlement",
		CapabilityKind:          "managed_execution",
		PrivacyMode:             "public",
		ReceiptMode:             "required",
	})
	if err != nil {
		t.Fatalf("SearchPreferredAgentSurfaceDiagnostics error: %v", err)
	}
	if len(diags) != 3 {
		t.Fatalf("expected diagnostics for all candidates, got %+v", diags)
	}
	if !diags[1].Preferred || diags[1].Result.NodeRecord != "enr:-artifact" {
		t.Fatalf("expected artifact provider to be preferred, got %+v", diags[1])
	}
	if diags[0].Trusted || len(diags[0].TrustFailures) == 0 {
		t.Fatalf("expected untrusted package to fail trust gate, got %+v", diags[0])
	}
	if diags[2].Preferred || len(diags[2].PreferenceFailures) == 0 {
		t.Fatalf("expected trusted package to fail preference filters, got %+v", diags[2])
	}
}

func TestDirectorySearchPreferredAgentSurfaceDiagnosticsReportsDirectorySelection(t *testing.T) {
	client, _, cleanup := newAgentSurfaceClient(t)
	defer cleanup()

	limit := 3
	diags, err := client.DirectorySearchPreferredAgentSurfaceDiagnostics(context.Background(), "enr:-directory", "settlement.rank", &limit, nil, ProviderSelectionPreferences{
		PackagePrefix:           "tolang.openlib.privacy",
		RequiredConnectionModes: agentdiscovery.ConnectionModeStream,
		MinTrustScore:           80,
	})
	if err != nil {
		t.Fatalf("DirectorySearchPreferredAgentSurfaceDiagnostics error: %v", err)
	}
	if len(diags) != 2 {
		t.Fatalf("expected two directory diagnostics, got %+v", diags)
	}
	if !diags[0].Preferred || diags[0].Result.NodeRecord != "enr:-package" {
		t.Fatalf("expected package provider to be preferred in directory diagnostics, got %+v", diags[0])
	}
	if diags[1].Preferred || len(diags[1].PreferenceFailures) == 0 {
		t.Fatalf("expected artifact provider to fail directory preferences, got %+v", diags[1])
	}
}
