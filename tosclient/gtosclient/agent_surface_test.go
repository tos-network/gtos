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
	lastAddress common.Address
	lastBlock   string
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
					ContractType:   "settlement",
					CapabilityKind: "managed_execution",
				},
				SuggestedCard: &agentdiscovery.PublishedCard{
					AgentID:     "settlement-agent",
					PackageName: "tolang.openlib.settlement",
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

func newAgentSurfaceClient(t *testing.T) (*Client, *agentSurfaceRPCService, func()) {
	t.Helper()
	svc := new(agentSurfaceRPCService)
	server := rpc.NewServer()
	if err := server.RegisterName("tos", svc); err != nil {
		t.Fatalf("RegisterName: %v", err)
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
