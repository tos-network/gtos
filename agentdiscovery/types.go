package agentdiscovery

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/p2p/enr"
)

const (
	ProfileVersion uint16 = 1
	TalkProtocol          = "agent/discovery/1"

	ConnectionModeTalkReq uint8 = 0x01
	ConnectionModeHTTPS   uint8 = 0x02
	ConnectionModeStream  uint8 = 0x04
)

const (
	enrKeyProfileVersion = "agv"
	enrKeyPrimaryAddress = "aga"
	enrKeyConnectionMode = "agm"
	enrKeyCapabilityBits = "agb"
	enrKeyCardSequence   = "ags"
)

type profileVersionEntry uint16

func (profileVersionEntry) ENRKey() string { return enrKeyProfileVersion }

type primaryAddressEntry [32]byte

func (primaryAddressEntry) ENRKey() string { return enrKeyPrimaryAddress }

type connectionModesEntry uint8

func (connectionModesEntry) ENRKey() string { return enrKeyConnectionMode }

type capabilityBloomEntry [32]byte

func (capabilityBloomEntry) ENRKey() string { return enrKeyCapabilityBits }

type cardSequenceEntry uint64

func (cardSequenceEntry) ENRKey() string { return enrKeyCardSequence }

type PublishConfig struct {
	PrimaryIdentity common.Address
	Capabilities    []string
	ConnectionModes uint8
	CardJSON        string
	CardSequence    uint64
}

// PublishCardConfig publishes a structured card directly, deriving the
// capability bloom from the card contents and normalizing the card into the
// canonical JSON form used on the wire.
type PublishCardConfig struct {
	PrimaryIdentity common.Address
	ConnectionModes uint8
	Card            *PublishedCard
	CardSequence    uint64
}

// PublishedCard is the structured subset of an agent discovery card that GTOS
// understands natively. Unknown fields may still exist in the raw card JSON;
// this type only captures the normalized routing/threat/profile hints that
// clients most commonly need.
type PublishedCard struct {
	Version         uint16                    `json:"version,omitempty"`
	AgentID         string                    `json:"agent_id,omitempty"`
	AgentAddress    string                    `json:"agent_address,omitempty"`
	ProfileRef      string                    `json:"profile_ref,omitempty"`
	DiscoveryRef    string                    `json:"discovery_ref,omitempty"`
	PackageName     string                    `json:"package_name,omitempty"`
	PackageVersion  string                    `json:"package_version,omitempty"`
	Capabilities    []PublishedCapability     `json:"capabilities,omitempty"`
	RoutingProfile  *TypedRoutingProfile      `json:"routing_profile,omitempty"`
	ThreatModel     *PublishedThreatModel     `json:"threat_model,omitempty"`
	DeploymentTrust *PublishedDeploymentTrust `json:"deployment_trust,omitempty"`
}

type PublishedCapability struct {
	Name string `json:"name"`
	Mode string `json:"mode,omitempty"`
	Ref  string `json:"ref,omitempty"`
}

// PublishedThreatModel is the normalized threat posture subset that discovery
// clients can consume directly from an agent card.
type PublishedThreatModel struct {
	Family            string   `json:"family,omitempty"`
	TrustBoundary     string   `json:"trust_boundary,omitempty"`
	FailurePosture    string   `json:"failure_posture,omitempty"`
	RuntimeDependency string   `json:"runtime_dependency,omitempty"`
	Invariants        []string `json:"critical_invariants,omitempty"`
}

type PublishedDeploymentTrust struct {
	PackageName     string `json:"package_name,omitempty"`
	PackageVersion  string `json:"package_version,omitempty"`
	PublisherID     string `json:"publisher_id,omitempty"`
	Trusted         bool   `json:"trusted"`
	Status          string `json:"status,omitempty"`
	EffectiveStatus string `json:"effective_status,omitempty"`
	NamespaceStatus string `json:"namespace_status,omitempty"`
}

type Info struct {
	Enabled          bool     `json:"enabled"`
	ProfileVersion   uint16   `json:"profileVersion"`
	TalkProtocol     string   `json:"talkProtocol"`
	NodeID           string   `json:"nodeId,omitempty"`
	NodeRecord       string   `json:"nodeRecord,omitempty"`
	PrimaryIdentity  string   `json:"primaryIdentity,omitempty"`
	CardSequence     uint64   `json:"cardSequence,omitempty"`
	ConnectionModes  uint8    `json:"connectionModes,omitempty"`
	Capabilities     []string `json:"capabilities,omitempty"`
	HasPublishedCard bool     `json:"hasPublishedCard"`
}

type SearchResult struct {
	NodeID          string                `json:"nodeId"`
	NodeRecord      string                `json:"nodeRecord"`
	PrimaryIdentity string                `json:"primaryIdentity,omitempty"`
	ConnectionModes uint8                 `json:"connectionModes,omitempty"`
	CardSequence    uint64                `json:"cardSequence,omitempty"`
	Capabilities    []string              `json:"capabilities,omitempty"`
	Trust           *ProviderTrustSummary `json:"trust,omitempty"`
}

type ProviderTrustSummary struct {
	Registered           bool   `json:"registered"`
	Suspended            bool   `json:"suspended"`
	Stake                string `json:"stake"`
	StakeBucket          string `json:"stakeBucket,omitempty"`
	Reputation           string `json:"reputation"`
	ReputationBucket     string `json:"reputationBucket,omitempty"`
	RatingCount          string `json:"ratingCount"`
	CapabilityRegistered bool   `json:"capabilityRegistered"`
	CapabilityBit        *uint8 `json:"capabilityBit,omitempty"`
	HasOnchainCapability bool   `json:"hasOnchainCapability"`
	LocalRankScore       int64  `json:"localRankScore,omitempty"`
	LocalRankReason      string `json:"localRankReason,omitempty"`
}

type CardResponse struct {
	NodeID     string         `json:"nodeId"`
	NodeRecord string         `json:"nodeRecord"`
	CardJSON   string         `json:"cardJson"`
	ParsedCard *PublishedCard `json:"parsed_card,omitempty"`
}

type talkMessage struct {
	Type       string         `json:"type"`
	Card       string         `json:"card,omitempty"`
	Capability string         `json:"capability,omitempty"`
	Limit      int            `json:"limit,omitempty"`
	Results    []SearchResult `json:"results,omitempty"`
	Error      string         `json:"error,omitempty"`
}

func normalizeCapability(capability string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(capability))
	if normalized == "" {
		return "", fmt.Errorf("capability must not be empty")
	}
	for _, ch := range normalized {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '.' || ch == '-' || ch == '_':
		default:
			return "", fmt.Errorf("invalid capability %q", capability)
		}
	}
	return normalized, nil
}

func normalizeCapabilities(capabilities []string) ([]string, error) {
	normalized := make([]string, 0, len(capabilities))
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		name, err := normalizeCapability(capability)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	return normalized, nil
}

func buildCapabilityBloom(capabilities []string) (capabilityBloomEntry, error) {
	var bloom capabilityBloomEntry
	normalized, err := normalizeCapabilities(capabilities)
	if err != nil {
		return bloom, err
	}
	for _, capability := range normalized {
		sum := crypto.Keccak256([]byte(capability))
		for i := 0; i < 3; i++ {
			word := uint16(sum[i*2])<<8 | uint16(sum[i*2+1])
			pos := word % 256
			bloom[pos/8] |= 1 << (pos % 8)
		}
	}
	return bloom, nil
}

func bloomMatches(bloom capabilityBloomEntry, capability string) bool {
	normalized, err := normalizeCapability(capability)
	if err != nil {
		return false
	}
	sum := crypto.Keccak256([]byte(normalized))
	for i := 0; i < 3; i++ {
		word := uint16(sum[i*2])<<8 | uint16(sum[i*2+1])
		pos := word % 256
		if bloom[pos/8]&(1<<(pos%8)) == 0 {
			return false
		}
	}
	return true
}

func encodeTalkMessage(msg talkMessage) []byte {
	payload, _ := json.Marshal(msg)
	return payload
}

func decodeTalkMessage(payload []byte) (talkMessage, error) {
	var msg talkMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return talkMessage{}, err
	}
	return msg, nil
}

func loadProfileVersion(record enr.Record) (uint16, error) {
	var entry profileVersionEntry
	if err := record.Load(&entry); err != nil {
		return 0, err
	}
	return uint16(entry), nil
}
