package agentdiscovery

import (
	"testing"

	tolmeta "github.com/tos-network/tolang/metadata"
)

func TestBuildPublishedCardFromProfile(t *testing.T) {
	profile := &tolmeta.AgentContractProfile{
		Identity: tolmeta.ProfileIdentity{
			PackageName:    "tolang.openlib.settlement.task_settlement",
			PackageVersion: "1.0.0",
		},
		Contract: tolmeta.ProfileContract{
			Name: "TaskSettlement",
		},
		Capabilities: []string{"settlement.execute"},
		ThreatModel: &tolmeta.ThreatModelProfile{
			Family:             "settlement",
			TrustBoundary:      "task poster, worker, dispute resolver",
			FailurePosture:     "fail closed on wrong status or wrong actor",
			RuntimeDependency:  "strong dependency on host escrow and release correctness plus rollback",
			CriticalInvariants: []string{"single terminal payout path"},
		},
	}
	discovery := &tolmeta.DiscoveryManifest{
		PackageName:  "tolang.openlib.settlement.task_settlement",
		ContractType: "task_escrow",
		ServiceKinds: []string{"query", "escrow"},
		TypedDiscovery: &tolmeta.TypedDiscoveryProfile{
			ServiceKind:    "SETTLEMENT",
			CapabilityKind: "WRITE_EXECUTION",
			Privacy: &tolmeta.TypedDiscoveryPrivacy{
				Mode:            "AUDITABLE_CONFIDENTIAL",
				DisclosureReady: true,
			},
			Receipts: &tolmeta.TypedDiscoveryReceipt{Mode: "AUTO_RECEIPT"},
		},
	}

	card := BuildPublishedCardFromProfile(profile, discovery)
	if card == nil {
		t.Fatal("expected card")
	}
	if card.AgentID != "tasksettlement" {
		t.Fatalf("AgentID = %q, want tasksettlement", card.AgentID)
	}
	if card.ProfileRef != "openlib/releases/settlement/TaskSettlement.profile.json" {
		t.Fatalf("unexpected profile ref %q", card.ProfileRef)
	}
	if card.RoutingProfile == nil || card.RoutingProfile.ServiceKind != "SETTLEMENT" {
		t.Fatalf("unexpected routing profile %+v", card.RoutingProfile)
	}
	if card.ThreatModel == nil || card.ThreatModel.Family != "settlement" {
		t.Fatalf("unexpected threat model %+v", card.ThreatModel)
	}
	if len(card.Capabilities) != 1 || card.Capabilities[0].Name != "settlement.execute" {
		t.Fatalf("unexpected capabilities %+v", card.Capabilities)
	}
}

func TestBuildPublishedCardFromBundle(t *testing.T) {
	bundle := &tolmeta.AgentBundleProfile{
		Family:         "privacy",
		PackageName:    "tolang.openlib.privacy",
		PackageVersion: "1.0.0",
		Contracts: []*tolmeta.AgentContractProfile{
			{
				Capabilities: []string{"privacy.disclose"},
				TypedDiscovery: &tolmeta.TypedDiscoveryProfile{
					ServiceKind: "PRIVACY",
				},
			},
		},
		ThreatModel: &tolmeta.ThreatModelProfile{
			Family:         "privacy",
			TrustBoundary:  "UNO bridge, resolver, and disclosure policy",
			FailurePosture: "fail closed",
		},
	}

	card := BuildPublishedCardFromBundle(bundle)
	if card == nil {
		t.Fatal("expected card")
	}
	if card.PackageName != "tolang.openlib.privacy" {
		t.Fatalf("unexpected package name %q", card.PackageName)
	}
	if card.ProfileRef != "openlib/releases/privacy/privacy.bundle.profile.json" {
		t.Fatalf("unexpected bundle profile ref %q", card.ProfileRef)
	}
	if card.ThreatModel == nil || card.ThreatModel.Family != "privacy" {
		t.Fatalf("unexpected threat model %+v", card.ThreatModel)
	}
	if card.RoutingProfile == nil || card.RoutingProfile.ServiceKind != "PRIVACY" {
		t.Fatalf("unexpected routing profile %+v", card.RoutingProfile)
	}
}
