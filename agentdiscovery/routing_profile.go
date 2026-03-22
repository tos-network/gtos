package agentdiscovery

import tolmeta "github.com/tos-network/tolang/metadata"

// TypedRoutingProfile is the GTOS-side normalized routing view extracted from
// Tolang discovery metadata. It lets callers consume typed routing semantics
// without digging through the full manifest tree.
type TypedRoutingProfile struct {
	ContractType    string   `json:"contract_type,omitempty"`
	ServiceKinds    []string `json:"service_kinds,omitempty"`
	ServiceKind     string   `json:"service_kind,omitempty"`
	CapabilityKind  string   `json:"capability_kind,omitempty"`
	PricingKind     string   `json:"pricing_kind,omitempty"`
	BaseFee         string   `json:"base_fee,omitempty"`
	PrivacyMode     string   `json:"privacy_mode,omitempty"`
	ReceiptMode     string   `json:"receipt_mode,omitempty"`
	DisclosureReady bool     `json:"disclosure_ready,omitempty"`
	TrustFloorRef   string   `json:"trust_floor_ref,omitempty"`
}

// BuildTypedRoutingProfile projects the discovery manifest into a smaller,
// routing-oriented shape for GTOS/OpenFox consumption.
func BuildTypedRoutingProfile(dm *tolmeta.DiscoveryManifest) *TypedRoutingProfile {
	if dm == nil {
		return nil
	}
	profile := &TypedRoutingProfile{
		ContractType: dm.ContractType,
	}
	if len(dm.ServiceKinds) > 0 {
		profile.ServiceKinds = append([]string(nil), dm.ServiceKinds...)
	}
	if dm.TypedDiscovery != nil {
		profile.ServiceKind = dm.TypedDiscovery.ServiceKind
		profile.CapabilityKind = dm.TypedDiscovery.CapabilityKind
		if dm.TypedDiscovery.Pricing != nil {
			profile.PricingKind = dm.TypedDiscovery.Pricing.Kind
			profile.BaseFee = dm.TypedDiscovery.Pricing.BaseFee
		}
		if dm.TypedDiscovery.Privacy != nil {
			profile.PrivacyMode = dm.TypedDiscovery.Privacy.Mode
			profile.DisclosureReady = dm.TypedDiscovery.Privacy.DisclosureReady
		}
		if dm.TypedDiscovery.Receipts != nil {
			profile.ReceiptMode = dm.TypedDiscovery.Receipts.Mode
		}
		if dm.TypedDiscovery.Refs != nil {
			profile.TrustFloorRef = dm.TypedDiscovery.Refs.TrustFloorRef
		}
	}
	if profile.ContractType == "" && len(profile.ServiceKinds) == 0 && profile.ServiceKind == "" && profile.CapabilityKind == "" {
		return nil
	}
	return profile
}
