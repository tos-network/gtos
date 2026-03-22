package agentdiscovery

import (
	"testing"

	tolmeta "github.com/tos-network/tolang/metadata"
)

func TestBuildTypedRoutingProfile(t *testing.T) {
	dm := &tolmeta.DiscoveryManifest{
		ContractType: "discovery",
		ServiceKinds: []string{"query", "directory_query"},
		TypedDiscovery: &tolmeta.TypedDiscoveryProfile{
			ServiceKind:    "DISCOVERY",
			CapabilityKind: "READ_ONLY",
			Pricing: &tolmeta.TypedDiscoveryPricing{
				Kind:    "FREE",
				BaseFee: "0",
			},
			Privacy: &tolmeta.TypedDiscoveryPrivacy{
				Mode:            "DISCLOSURE_READY",
				DisclosureReady: true,
			},
			Receipts: &tolmeta.TypedDiscoveryReceipt{
				Mode: "AUDIT_RECEIPT_REQUIRED",
			},
			Refs: &tolmeta.TypedDiscoveryRefs{
				TrustFloorRef: "0xabc",
			},
		},
	}

	got := BuildTypedRoutingProfile(dm)
	if got == nil {
		t.Fatal("BuildTypedRoutingProfile returned nil")
	}
	if got.ContractType != "discovery" {
		t.Fatalf("ContractType: got %q want %q", got.ContractType, "discovery")
	}
	if len(got.ServiceKinds) != 2 {
		t.Fatalf("ServiceKinds len: got %d want %d", len(got.ServiceKinds), 2)
	}
	if got.ServiceKind != "DISCOVERY" {
		t.Fatalf("ServiceKind: got %q want %q", got.ServiceKind, "DISCOVERY")
	}
	if got.CapabilityKind != "READ_ONLY" {
		t.Fatalf("CapabilityKind: got %q want %q", got.CapabilityKind, "READ_ONLY")
	}
	if got.PricingKind != "FREE" || got.BaseFee != "0" {
		t.Fatalf("unexpected pricing %#v", got)
	}
	if got.PrivacyMode != "DISCLOSURE_READY" || !got.DisclosureReady {
		t.Fatalf("unexpected privacy %#v", got)
	}
	if got.ReceiptMode != "AUDIT_RECEIPT_REQUIRED" {
		t.Fatalf("unexpected receipt mode %#v", got)
	}
	if got.TrustFloorRef != "0xabc" {
		t.Fatalf("unexpected trust floor ref %#v", got)
	}
}
