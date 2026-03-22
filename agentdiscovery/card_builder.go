package agentdiscovery

import (
	"strings"

	tolmeta "github.com/tos-network/tolang/metadata"
)

// BuildPublishedCardFromProfile derives a recommended structured discovery card
// from the unified Tolang profile and optional discovery manifest. It is
// intentionally additive: callers can still keep richer custom card JSON, but
// this produces a canonical baseline that is aligned with exported release
// metadata.
func BuildPublishedCardFromProfile(profile *tolmeta.AgentContractProfile, discovery *tolmeta.DiscoveryManifest) *PublishedCard {
	if profile == nil {
		return nil
	}
	card := &PublishedCard{
		Version:        1,
		AgentID:        defaultAgentID(profile),
		PackageName:    profile.Identity.PackageName,
		PackageVersion: profile.Identity.PackageVersion,
		ProfileRef:     profileRefPath(profile),
		Capabilities:   buildPublishedCapabilities(profile, discovery),
	}
	if discovery != nil {
		card.RoutingProfile = BuildTypedRoutingProfile(discovery)
		if strings.TrimSpace(card.DiscoveryRef) == "" {
			card.DiscoveryRef = discoveryRefPath(discovery)
		}
	}
	if profile.ThreatModel != nil {
		card.ThreatModel = buildPublishedThreatModel(profile.ThreatModel)
	}
	return trimEmptyCard(card)
}

// BuildPublishedCardFromBundle derives a recommended family-level card view
// from a bundle profile. It is useful for agents that want to advertise one
// package-level card before exposing contract-specific entrypoints.
func BuildPublishedCardFromBundle(bundle *tolmeta.AgentBundleProfile) *PublishedCard {
	if bundle == nil {
		return nil
	}
	card := &PublishedCard{
		Version:        1,
		AgentID:        strings.TrimSpace(bundle.PackageName),
		PackageName:    strings.TrimSpace(bundle.PackageName),
		PackageVersion: strings.TrimSpace(bundle.PackageVersion),
		ProfileRef:     bundleProfileRefPath(bundle),
	}
	if bundle.ThreatModel != nil {
		card.ThreatModel = buildPublishedThreatModel(bundle.ThreatModel)
	}
	capSeen := map[string]struct{}{}
	for _, contract := range bundle.Contracts {
		if contract == nil {
			continue
		}
		for _, cap := range contract.Capabilities {
			name := strings.TrimSpace(strings.ToLower(cap))
			if name == "" {
				continue
			}
			if _, ok := capSeen[name]; ok {
				continue
			}
			capSeen[name] = struct{}{}
			card.Capabilities = append(card.Capabilities, PublishedCapability{Name: name, Mode: "declared"})
		}
		if card.RoutingProfile == nil && contract.TypedDiscovery != nil {
			card.RoutingProfile = &TypedRoutingProfile{
				ServiceKind:    contract.TypedDiscovery.ServiceKind,
				CapabilityKind: contract.TypedDiscovery.CapabilityKind,
			}
			if contract.TypedDiscovery.Pricing != nil {
				card.RoutingProfile.PricingKind = contract.TypedDiscovery.Pricing.Kind
				card.RoutingProfile.BaseFee = contract.TypedDiscovery.Pricing.BaseFee
			}
			if contract.TypedDiscovery.Privacy != nil {
				card.RoutingProfile.PrivacyMode = contract.TypedDiscovery.Privacy.Mode
				card.RoutingProfile.DisclosureReady = contract.TypedDiscovery.Privacy.DisclosureReady
			}
			if contract.TypedDiscovery.Receipts != nil {
				card.RoutingProfile.ReceiptMode = contract.TypedDiscovery.Receipts.Mode
			}
		}
	}
	return trimEmptyCard(card)
}

func buildPublishedCapabilities(profile *tolmeta.AgentContractProfile, discovery *tolmeta.DiscoveryManifest) []PublishedCapability {
	seen := map[string]struct{}{}
	out := make([]PublishedCapability, 0)
	for _, cap := range profile.Capabilities {
		name := strings.TrimSpace(strings.ToLower(cap))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, PublishedCapability{Name: name, Mode: "declared"})
	}
	if discovery != nil {
		for _, cap := range discovery.Capabilities {
			name := strings.TrimSpace(strings.ToLower(cap))
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, PublishedCapability{Name: name, Mode: "declared"})
		}
	}
	return out
}

func buildPublishedThreatModel(model *tolmeta.ThreatModelProfile) *PublishedThreatModel {
	if model == nil {
		return nil
	}
	return &PublishedThreatModel{
		Family:            model.Family,
		TrustBoundary:     model.TrustBoundary,
		FailurePosture:    model.FailurePosture,
		RuntimeDependency: model.RuntimeDependency,
		Invariants:        append([]string(nil), model.CriticalInvariants...),
	}
}

func defaultAgentID(profile *tolmeta.AgentContractProfile) string {
	if profile == nil {
		return ""
	}
	if name := strings.TrimSpace(profile.Contract.Name); name != "" {
		return strings.ToLower(name)
	}
	return strings.TrimSpace(profile.Identity.PackageName)
}

func profileRefPath(profile *tolmeta.AgentContractProfile) string {
	if profile == nil || strings.TrimSpace(profile.Identity.PackageName) == "" || strings.TrimSpace(profile.Contract.Name) == "" {
		return ""
	}
	family := packageFamily(profile.Identity.PackageName)
	if family == "" {
		return ""
	}
	return "openlib/releases/" + family + "/" + profile.Contract.Name + ".profile.json"
}

func discoveryRefPath(discovery *tolmeta.DiscoveryManifest) string {
	if discovery == nil || strings.TrimSpace(discovery.PackageName) == "" {
		return ""
	}
	family := packageFamily(discovery.PackageName)
	if family == "" {
		return ""
	}
	contract := strings.TrimSpace(contractNameFromPackage(discovery.PackageName))
	if contract == "" {
		return ""
	}
	return "openlib/releases/" + family + "/" + contract + ".discovery.json"
}

func bundleProfileRefPath(bundle *tolmeta.AgentBundleProfile) string {
	if bundle == nil || strings.TrimSpace(bundle.Family) == "" {
		return ""
	}
	return "openlib/releases/" + strings.TrimSpace(bundle.Family) + "/" + strings.TrimSpace(bundle.Family) + ".bundle.profile.json"
}

func packageFamily(packageName string) string {
	name := strings.TrimSpace(packageName)
	const prefix = "tolang.openlib."
	if !strings.HasPrefix(name, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(name, prefix)
	if rest == "" {
		return ""
	}
	parts := strings.Split(rest, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func contractNameFromPackage(packageName string) string {
	name := strings.TrimSpace(packageName)
	const prefix = "tolang.openlib."
	if !strings.HasPrefix(name, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(name, prefix)
	parts := strings.Split(rest, ".")
	if len(parts) < 2 {
		return ""
	}
	last := parts[len(parts)-1]
	if last == "" {
		return ""
	}
	return toContractName(last)
}

func toContractName(name string) string {
	parts := strings.Split(strings.TrimSpace(name), "_")
	out := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		out += strings.ToUpper(part[:1]) + part[1:]
	}
	return out
}

func trimEmptyCard(card *PublishedCard) *PublishedCard {
	if card == nil {
		return nil
	}
	if len(card.Capabilities) == 0 {
		card.Capabilities = nil
	}
	if card.RoutingProfile != nil && card.RoutingProfile.ContractType == "" &&
		len(card.RoutingProfile.ServiceKinds) == 0 &&
		card.RoutingProfile.ServiceKind == "" &&
		card.RoutingProfile.CapabilityKind == "" &&
		card.RoutingProfile.PricingKind == "" &&
		card.RoutingProfile.BaseFee == "" &&
		card.RoutingProfile.PrivacyMode == "" &&
		card.RoutingProfile.ReceiptMode == "" &&
		!card.RoutingProfile.DisclosureReady &&
		card.RoutingProfile.TrustFloorRef == "" {
		card.RoutingProfile = nil
	}
	if card.ThreatModel != nil &&
		card.ThreatModel.Family == "" &&
		card.ThreatModel.TrustBoundary == "" &&
		card.ThreatModel.FailurePosture == "" &&
		card.ThreatModel.RuntimeDependency == "" &&
		len(card.ThreatModel.Invariants) == 0 {
		card.ThreatModel = nil
	}
	return card
}
