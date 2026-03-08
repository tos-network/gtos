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
	s.cardSequence = cfg.CardSequence
	s.primaryIdentity = cfg.PrimaryIdentity
	s.connectionModes = cfg.ConnectionModes
	s.mu.Unlock()

	return s.Info(), nil
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
