package tosapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/tos-network/gtos/agentdiscovery"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/rpc"
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

type AgentDiscoveryPublishSuggestedArgs struct {
	Address         string                  `json:"address"`
	PrimaryIdentity string                  `json:"primaryIdentity"`
	ConnectionModes []string                `json:"connectionModes"`
	CardSequence    uint64                  `json:"cardSequence"`
	Block           *rpc.BlockNumberOrHash  `json:"block,omitempty"`
}

type AgentDiscoverySuggestedCardArgs struct {
	Address string                 `json:"address"`
	Block   *rpc.BlockNumberOrHash `json:"block,omitempty"`
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

func (s *TOSAPI) AgentDiscoveryPublishSuggested(ctx context.Context, args AgentDiscoveryPublishSuggestedArgs) (agentdiscovery.Info, error) {
	svc := s.agentDiscoveryService()
	if svc == nil {
		return agentdiscovery.Info{}, agentdiscovery.ErrDiscoveryDisabled
	}
	primaryIdentity, err := parsePrimaryIdentity(args.PrimaryIdentity)
	if err != nil {
		return agentdiscovery.Info{}, err
	}
	address := strings.TrimSpace(args.Address)
	if address == "" {
		return agentdiscovery.Info{}, fmt.Errorf("address is required")
	}
	if !common.IsHexAddress(address) {
		return agentdiscovery.Info{}, fmt.Errorf("invalid address %q", address)
	}
	card, err := s.loadSuggestedCard(ctx, address, args.Block)
	if err != nil {
		return agentdiscovery.Info{}, err
	}
	return svc.PublishCard(agentdiscovery.PublishCardConfig{
		PrimaryIdentity: primaryIdentity,
		ConnectionModes: parseConnectionModes(args.ConnectionModes),
		CardSequence:    args.CardSequence,
		Card:            card,
	})
}

func (s *TOSAPI) AgentDiscoveryGetSuggestedCard(ctx context.Context, args AgentDiscoverySuggestedCardArgs) (*agentdiscovery.PublishedCard, error) {
	return s.loadSuggestedCard(ctx, args.Address, args.Block)
}

func (s *TOSAPI) AgentDiscoveryClear() (agentdiscovery.Info, error) {
	svc := s.agentDiscoveryService()
	if svc == nil {
		return agentdiscovery.Info{}, agentdiscovery.ErrDiscoveryDisabled
	}
	return svc.Clear(), nil
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

func parsePrimaryIdentity(raw string) (common.Address, error) {
	primaryIdentity := strings.TrimSpace(raw)
	if primaryIdentity == "" {
		return common.Address{}, fmt.Errorf("primaryIdentity is required")
	}
	if !common.IsHexAddress(primaryIdentity) {
		return common.Address{}, fmt.Errorf("invalid primaryIdentity %q", primaryIdentity)
	}
	return common.HexToAddress(primaryIdentity), nil
}

func (s *TOSAPI) loadSuggestedCard(ctx context.Context, rawAddress string, block *rpc.BlockNumberOrHash) (*agentdiscovery.PublishedCard, error) {
	address := strings.TrimSpace(rawAddress)
	if address == "" {
		return nil, fmt.Errorf("address is required")
	}
	if !common.IsHexAddress(address) {
		return nil, fmt.Errorf("invalid address %q", address)
	}
	resolved := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	if block != nil {
		resolved = *block
	}
	if err := enforceHistoryRetentionByBlockArg(s.b, resolved); err != nil {
		return nil, err
	}
	st, header, err := s.b.StateAndHeaderByNumberOrHash(ctx, resolved)
	if st == nil || header == nil || err != nil {
		return nil, err
	}
	target := common.HexToAddress(address)
	info, err := inspectDeployedCode(target, st.GetCodeHash(target), st.GetCode(target), st)
	if err != nil {
		return nil, err
	}
	return suggestedCardFromDeployedInfo(info)
}

func suggestedCardFromDeployedInfo(info *DeployedCodeInfo) (*agentdiscovery.PublishedCard, error) {
	if info == nil {
		return nil, fmt.Errorf("contract metadata unavailable")
	}
	if info.Artifact != nil && info.Artifact.SuggestedCard != nil {
		return info.Artifact.SuggestedCard, nil
	}
	if info.Package != nil && info.Package.SuggestedCard != nil {
		return info.Package.SuggestedCard, nil
	}
	switch info.CodeKind {
	case "empty":
		return nil, fmt.Errorf("no code deployed at address")
	case "raw":
		return nil, fmt.Errorf("raw code has no suggested discovery card")
	case "tor":
		return nil, fmt.Errorf("package metadata does not expose a suggested card")
	case "toc":
		return nil, fmt.Errorf("artifact metadata does not expose a suggested card")
	default:
		return nil, fmt.Errorf("unsupported code kind %q", info.CodeKind)
	}
}
