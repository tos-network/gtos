package agentdiscovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/p2p/discover"
	"github.com/tos-network/gtos/p2p/enode"
)

var ErrDiscoveryDisabled = errors.New("agent discovery requires discv5 to be enabled")

type Service struct {
	localNode *enode.LocalNode
	udp       *discover.UDPv5

	mu              sync.RWMutex
	capabilities    []string
	cardJSON        string
	parsedCard      *PublishedCard
	cardSequence    uint64
	primaryIdentity common.Address
	connectionModes uint8
	summaryProvider func(common.Address, string) *ProviderTrustSummary
}

func New(localNode *enode.LocalNode, udp *discover.UDPv5) (*Service, error) {
	if localNode == nil || udp == nil {
		return nil, ErrDiscoveryDisabled
	}
	svc := &Service{
		localNode: localNode,
		udp:       udp,
	}
	udp.RegisterTalkHandler(TalkProtocol, svc.handleTalkRequest)
	return svc, nil
}

func (s *Service) Enabled() bool {
	return s != nil && s.localNode != nil && s.udp != nil
}

func (s *Service) SetSummaryProvider(provider func(common.Address, string) *ProviderTrustSummary) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.summaryProvider = provider
}

func (s *Service) Publish(cfg PublishConfig) (Info, error) {
	if !s.Enabled() {
		return Info{}, ErrDiscoveryDisabled
	}
	cardJSON := strings.TrimSpace(cfg.CardJSON)
	if cardJSON == "" {
		return Info{}, fmt.Errorf("card JSON must not be empty")
	}
	if !json.Valid([]byte(cardJSON)) {
		return Info{}, fmt.Errorf("card JSON is not valid JSON")
	}
	normalizedCaps, err := normalizeCapabilities(cfg.Capabilities)
	if err != nil {
		return Info{}, err
	}
	parsedCard, err := ParsePublishedCard(cardJSON)
	if err != nil {
		return Info{}, err
	}
	if parsedCard != nil {
		if err := ensureCardCapabilitiesMatch(parsedCard, normalizedCaps); err != nil {
			return Info{}, err
		}
	}
	bloom, err := buildCapabilityBloom(normalizedCaps)
	if err != nil {
		return Info{}, err
	}

	s.localNode.Set(profileVersionEntry(ProfileVersion))
	s.localNode.Set(primaryAddressEntry(cfg.PrimaryIdentity))
	s.localNode.Set(connectionModesEntry(cfg.ConnectionModes))
	s.localNode.Set(bloom)
	if cfg.CardSequence > 0 {
		s.localNode.Set(cardSequenceEntry(cfg.CardSequence))
	} else {
		s.localNode.Delete(cardSequenceEntry(0))
	}

	s.mu.Lock()
	s.capabilities = normalizedCaps
	s.cardJSON = cardJSON
	s.parsedCard = parsedCard
	s.cardSequence = cfg.CardSequence
	s.primaryIdentity = cfg.PrimaryIdentity
	s.connectionModes = cfg.ConnectionModes
	s.mu.Unlock()

	return s.Info(), nil
}

// PublishCard publishes a structured card directly, deriving the capability
// bloom and canonical wire JSON from the normalized card content.
func (s *Service) PublishCard(cfg PublishCardConfig) (Info, error) {
	if cfg.Card == nil {
		return Info{}, fmt.Errorf("card must not be nil")
	}
	card, caps, err := canonicalizePublishedCard(cfg.Card, cfg.PrimaryIdentity)
	if err != nil {
		return Info{}, err
	}
	cardJSON, err := json.Marshal(card)
	if err != nil {
		return Info{}, fmt.Errorf("marshal card JSON: %w", err)
	}
	return s.Publish(PublishConfig{
		PrimaryIdentity: cfg.PrimaryIdentity,
		Capabilities:    caps,
		ConnectionModes: cfg.ConnectionModes,
		CardJSON:        string(cardJSON),
		CardSequence:    cfg.CardSequence,
	})
}

func (s *Service) Clear() Info {
	if !s.Enabled() {
		return Info{
			Enabled:        false,
			ProfileVersion: ProfileVersion,
			TalkProtocol:   TalkProtocol,
		}
	}

	s.localNode.Delete(profileVersionEntry(0))
	s.localNode.Delete(primaryAddressEntry{})
	s.localNode.Delete(connectionModesEntry(0))
	s.localNode.Delete(capabilityBloomEntry{})
	s.localNode.Delete(cardSequenceEntry(0))

	s.mu.Lock()
	s.capabilities = nil
	s.cardJSON = ""
	s.parsedCard = nil
	s.cardSequence = 0
	s.primaryIdentity = common.Address{}
	s.connectionModes = 0
	s.mu.Unlock()

	return s.Info()
}

func (s *Service) Info() Info {
	if !s.Enabled() {
		return Info{
			Enabled:        false,
			ProfileVersion: ProfileVersion,
			TalkProtocol:   TalkProtocol,
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	node := s.localNode.Node()
	return Info{
		Enabled:          true,
		ProfileVersion:   ProfileVersion,
		TalkProtocol:     TalkProtocol,
		NodeID:           node.ID().String(),
		NodeRecord:       node.String(),
		PrimaryIdentity:  s.primaryIdentity.Hex(),
		CardSequence:     s.cardSequence,
		ConnectionModes:  s.connectionModes,
		Capabilities:     slices.Clone(s.capabilities),
		HasPublishedCard: s.cardJSON != "",
	}
}

func (s *Service) Search(capability string, limit int) ([]SearchResult, error) {
	if !s.Enabled() {
		return nil, ErrDiscoveryDisabled
	}
	normalized, err := normalizeCapability(capability)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 10
	}

	results := make([]SearchResult, 0, limit)
	seen := make(map[enode.ID]struct{})
	for _, node := range s.collectCandidates(limit * 3) {
		if node == nil || node.ID() == s.localNode.ID() {
			continue
		}
		node = s.udp.Resolve(node)
		if _, ok := seen[node.ID()]; ok {
			continue
		}
		seen[node.ID()] = struct{}{}

		record := node.Record()
		var version profileVersionEntry
		if err := record.Load(&version); err != nil || uint16(version) != ProfileVersion {
			continue
		}

		var bloom capabilityBloomEntry
		if err := record.Load(&bloom); err != nil || !bloomMatches(bloom, normalized) {
			continue
		}

		var identity primaryAddressEntry
		_ = record.Load(&identity)

		var modes connectionModesEntry
		_ = record.Load(&modes)

		var seq cardSequenceEntry
		_ = record.Load(&seq)

		result := SearchResult{
			NodeID:          node.ID().String(),
			NodeRecord:      node.String(),
			PrimaryIdentity: common.Address(identity).Hex(),
			ConnectionModes: uint8(modes),
			CardSequence:    uint64(seq),
			Capabilities:    []string{normalized},
		}
		if trust := s.providerTrustSummary(common.Address(identity), normalized); trust != nil {
			result.Trust = trust
		}

		results = append(results, result)
		if len(results) >= limit {
			continue
		}
	}
	sort.SliceStable(results, func(i, j int) bool {
		return compareSearchResults(results[i], results[j])
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (s *Service) DirectorySearch(node *enode.Node, capability string, limit int) ([]SearchResult, error) {
	if !s.Enabled() {
		return nil, ErrDiscoveryDisabled
	}
	if node == nil {
		return nil, fmt.Errorf("node must not be nil")
	}
	normalized, err := normalizeCapability(capability)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 10
	}

	payload := encodeTalkMessage(talkMessage{
		Type:       "SEARCH",
		Capability: normalized,
		Limit:      limit,
	})
	reply, err := s.udp.TalkRequest(node, TalkProtocol, payload)
	if err != nil {
		return nil, err
	}
	msg, err := decodeTalkMessage(reply)
	if err != nil {
		return nil, err
	}
	switch msg.Type {
	case "RESULTS":
		return msg.Results, nil
	case "ERROR":
		return nil, errors.New(msg.Error)
	default:
		return nil, fmt.Errorf("unexpected talk response %q", msg.Type)
	}
}

func (s *Service) GetCard(node *enode.Node) (CardResponse, error) {
	if !s.Enabled() {
		return CardResponse{}, ErrDiscoveryDisabled
	}
	if node == nil {
		return CardResponse{}, fmt.Errorf("node must not be nil")
	}
	payload := encodeTalkMessage(talkMessage{Type: "GET_CARD"})
	reply, err := s.udp.TalkRequest(node, TalkProtocol, payload)
	if err != nil {
		return CardResponse{}, err
	}
	msg, err := decodeTalkMessage(reply)
	if err != nil {
		return CardResponse{}, err
	}
	switch msg.Type {
	case "CARD":
		if strings.TrimSpace(msg.Card) == "" {
			return CardResponse{}, fmt.Errorf("provider returned an empty card")
		}
		return CardResponse{
			NodeID:     node.ID().String(),
			NodeRecord: node.String(),
			CardJSON:   msg.Card,
			ParsedCard: parsePublishedCardForResponse(msg.Card),
		}, nil
	case "ERROR":
		return CardResponse{}, errors.New(msg.Error)
	default:
		return CardResponse{}, fmt.Errorf("unexpected talk response %q", msg.Type)
	}
}

func (s *Service) handleTalkRequest(_ enode.ID, _ *net.UDPAddr, message []byte) []byte {
	msg, err := decodeTalkMessage(message)
	if err != nil {
		return encodeTalkMessage(talkMessage{Type: "ERROR", Error: "invalid JSON"})
	}
	switch msg.Type {
	case "PING":
		return encodeTalkMessage(talkMessage{Type: "PONG"})
	case "GET_CARD":
		s.mu.RLock()
		cardJSON := s.cardJSON
		s.mu.RUnlock()
		if cardJSON == "" {
			return encodeTalkMessage(talkMessage{Type: "ERROR", Error: "card not published"})
		}
		return encodeTalkMessage(talkMessage{Type: "CARD", Card: cardJSON})
	case "SEARCH":
		if !s.hasCapability("directory.search") {
			return encodeTalkMessage(talkMessage{Type: "ERROR", Error: "directory search not supported"})
		}
		results, err := s.Search(msg.Capability, msg.Limit)
		if err != nil {
			return encodeTalkMessage(talkMessage{Type: "ERROR", Error: err.Error()})
		}
		return encodeTalkMessage(talkMessage{Type: "RESULTS", Results: results})
	default:
		return encodeTalkMessage(talkMessage{Type: "ERROR", Error: "unsupported request type"})
	}
}

func ParsePublishedCard(cardJSON string) (*PublishedCard, error) {
	trimmed := strings.TrimSpace(cardJSON)
	if trimmed == "" {
		return nil, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return nil, fmt.Errorf("invalid card JSON: %w", err)
	}
	if !hasStructuredCardFields(raw) {
		return nil, nil
	}
	var card PublishedCard
	if err := json.Unmarshal([]byte(trimmed), &card); err != nil {
		return nil, fmt.Errorf("invalid structured card JSON: %w", err)
	}
	for i := range card.Capabilities {
		name, err := normalizeCapability(card.Capabilities[i].Name)
		if err != nil {
			return nil, fmt.Errorf("invalid card capability %q: %w", card.Capabilities[i].Name, err)
		}
		card.Capabilities[i].Name = name
	}
	return &card, nil
}

func parsePublishedCardForResponse(cardJSON string) *PublishedCard {
	card, err := ParsePublishedCard(cardJSON)
	if err != nil {
		return nil
	}
	return card
}

func hasStructuredCardFields(raw map[string]json.RawMessage) bool {
	for _, key := range []string{
		"version",
		"agent_id",
		"agent_address",
		"profile_ref",
		"discovery_ref",
		"package_name",
		"package_version",
		"capabilities",
		"routing_profile",
		"threat_model",
	} {
		if _, ok := raw[key]; ok {
			return true
		}
	}
	return false
}

func ensureCardCapabilitiesMatch(card *PublishedCard, normalizedCaps []string) error {
	if card == nil || len(card.Capabilities) == 0 {
		return nil
	}
	if len(card.Capabilities) != len(normalizedCaps) {
		return fmt.Errorf("card capabilities do not match published capabilities")
	}
	want := make(map[string]struct{}, len(normalizedCaps))
	for _, capability := range normalizedCaps {
		want[capability] = struct{}{}
	}
	for _, capability := range card.Capabilities {
		if _, ok := want[capability.Name]; !ok {
			return fmt.Errorf("card capabilities do not match published capabilities")
		}
	}
	return nil
}

func canonicalizePublishedCard(card *PublishedCard, primaryIdentity common.Address) (*PublishedCard, []string, error) {
	if card == nil {
		return nil, nil, fmt.Errorf("card must not be nil")
	}
	cloned := clonePublishedCard(card)
	if strings.TrimSpace(cloned.AgentAddress) == "" && primaryIdentity != (common.Address{}) {
		cloned.AgentAddress = primaryIdentity.Hex()
	}
	cloned = trimEmptyCard(cloned)
	caps, err := publishedCardCapabilities(cloned)
	if err != nil {
		return nil, nil, err
	}
	return cloned, caps, nil
}

func publishedCardCapabilities(card *PublishedCard) ([]string, error) {
	if card == nil {
		return nil, fmt.Errorf("card must not be nil")
	}
	names := make([]string, 0, len(card.Capabilities))
	for _, capability := range card.Capabilities {
		name := strings.TrimSpace(capability.Name)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	normalized, err := normalizeCapabilities(names)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("card must declare at least one capability")
	}
	return normalized, nil
}

func clonePublishedCard(card *PublishedCard) *PublishedCard {
	if card == nil {
		return nil
	}
	cloned := *card
	cloned.Capabilities = append([]PublishedCapability(nil), card.Capabilities...)
	if card.RoutingProfile != nil {
		routing := *card.RoutingProfile
		cloned.RoutingProfile = &routing
	}
	if card.ThreatModel != nil {
		threat := *card.ThreatModel
		threat.Invariants = append([]string(nil), card.ThreatModel.Invariants...)
		cloned.ThreatModel = &threat
	}
	return &cloned
}

func (s *Service) collectCandidates(limit int) []*enode.Node {
	candidates := make([]*enode.Node, 0, limit)
	for _, node := range s.udp.AllNodes() {
		candidates = append(candidates, node)
		if len(candidates) >= limit {
			return candidates
		}
	}

	for _, node := range s.localNode.Database().QuerySeeds(limit-len(candidates), 24*time.Hour) {
		candidates = append(candidates, node)
		if len(candidates) >= limit {
			return candidates
		}
	}
	if len(candidates) >= limit {
		return candidates
	}

	it := s.udp.RandomNodes()
	defer it.Close()
	for _, node := range enode.ReadNodes(it, limit-len(candidates)) {
		candidates = append(candidates, node)
	}
	return candidates
}

func ParseNode(raw string) (*enode.Node, error) {
	return enode.Parse(enode.ValidSchemes, strings.TrimSpace(raw))
}

func (s *Service) hasCapability(capability string) bool {
	normalized, err := normalizeCapability(capability)
	if err != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Contains(s.capabilities, normalized)
}

func (s *Service) providerTrustSummary(identity common.Address, capability string) *ProviderTrustSummary {
	if identity == (common.Address{}) {
		return nil
	}

	s.mu.RLock()
	provider := s.summaryProvider
	s.mu.RUnlock()
	if provider == nil {
		return nil
	}
	return provider(identity, capability)
}

func compareSearchResults(left SearchResult, right SearchResult) bool {
	leftTrust := left.Trust
	rightTrust := right.Trust
	if leftTrust != nil || rightTrust != nil {
		leftScore := int64(0)
		rightScore := int64(0)
		if leftTrust != nil {
			leftScore = leftTrust.LocalRankScore
		}
		if rightTrust != nil {
			rightScore = rightTrust.LocalRankScore
		}
		if leftScore != rightScore {
			return leftScore > rightScore
		}
	}
	return left.CardSequence > right.CardSequence
}
