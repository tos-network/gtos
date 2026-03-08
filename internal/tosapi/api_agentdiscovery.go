package tosapi

import (
	"fmt"
	"strings"

	"github.com/tos-network/gtos/agentdiscovery"
	"github.com/tos-network/gtos/common"
)

type agentDiscoveryBackend interface {
	AgentDiscovery() *agentdiscovery.Service
}

type AgentDiscoveryPublishArgs struct {
	PrimaryIdentity string   `json:"primaryIdentity"`
	Capabilities    []string `json:"capabilities"`
	ConnectionModes []string `json:"connectionModes"`
	CardJSON        string   `json:"cardJson"`
	CardSequence    uint64   `json:"cardSequence"`
}

func (s *TOSAPI) AgentDiscoveryInfo() (agentdiscovery.Info, error) {
	svc := s.agentDiscoveryService()
	if svc == nil {
		return agentdiscovery.Info{
			Enabled:        false,
			ProfileVersion: agentdiscovery.ProfileVersion,
			TalkProtocol:   agentdiscovery.TalkProtocol,
		}, nil
	}
	return svc.Info(), nil
}

func (s *TOSAPI) AgentDiscoveryPublish(args AgentDiscoveryPublishArgs) (agentdiscovery.Info, error) {
	svc := s.agentDiscoveryService()
	if svc == nil {
		return agentdiscovery.Info{}, agentdiscovery.ErrDiscoveryDisabled
	}
	primaryIdentity := strings.TrimSpace(args.PrimaryIdentity)
	if primaryIdentity == "" {
		return agentdiscovery.Info{}, fmt.Errorf("primaryIdentity is required")
	}
	if !common.IsHexAddress(primaryIdentity) {
		return agentdiscovery.Info{}, fmt.Errorf("invalid primaryIdentity %q", primaryIdentity)
	}

	return svc.Publish(agentdiscovery.PublishConfig{
		PrimaryIdentity: common.HexToAddress(primaryIdentity),
		Capabilities:    args.Capabilities,
		ConnectionModes: parseConnectionModes(args.ConnectionModes),
		CardJSON:        args.CardJSON,
		CardSequence:    args.CardSequence,
	})
}

func (s *TOSAPI) AgentDiscoverySearch(capability string, limit *int) ([]agentdiscovery.SearchResult, error) {
	svc := s.agentDiscoveryService()
	if svc == nil {
		return nil, agentdiscovery.ErrDiscoveryDisabled
	}
	maxResults := 10
	if limit != nil {
		maxResults = *limit
	}
	return svc.Search(capability, maxResults)
}

func (s *TOSAPI) AgentDiscoveryGetCard(nodeRecord string) (agentdiscovery.CardResponse, error) {
	svc := s.agentDiscoveryService()
	if svc == nil {
		return agentdiscovery.CardResponse{}, agentdiscovery.ErrDiscoveryDisabled
	}
	node, err := agentdiscovery.ParseNode(nodeRecord)
	if err != nil {
		return agentdiscovery.CardResponse{}, err
	}
	return svc.GetCard(node)
}

func (s *TOSAPI) AgentDiscoveryDirectorySearch(nodeRecord string, capability string, limit *int) ([]agentdiscovery.SearchResult, error) {
	svc := s.agentDiscoveryService()
	if svc == nil {
		return nil, agentdiscovery.ErrDiscoveryDisabled
	}
	node, err := agentdiscovery.ParseNode(nodeRecord)
	if err != nil {
		return nil, err
	}
	maxResults := 10
	if limit != nil {
		maxResults = *limit
	}
	return svc.DirectorySearch(node, capability, maxResults)
}

func (s *TOSAPI) agentDiscoveryService() *agentdiscovery.Service {
	backend, ok := s.b.(agentDiscoveryBackend)
	if !ok {
		return nil
	}
	return backend.AgentDiscovery()
}

func parseConnectionModes(modes []string) uint8 {
	if len(modes) == 0 {
		return agentdiscovery.ConnectionModeTalkReq
	}
	var out uint8
	for _, mode := range modes {
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "talkreq", "talk":
			out |= agentdiscovery.ConnectionModeTalkReq
		case "https", "http":
			out |= agentdiscovery.ConnectionModeHTTPS
		case "stream", "ws", "websocket":
			out |= agentdiscovery.ConnectionModeStream
		}
	}
	if out == 0 {
		return agentdiscovery.ConnectionModeTalkReq
	}
	return out
}
