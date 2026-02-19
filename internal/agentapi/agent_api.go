// Package agentapi provides the agent_* and discover_* RPC namespaces for gtos.
package agentapi

import (
	"context"

	"github.com/tos-network/gtos/agent"
)

// AgentAPI implements the agent_* RPC namespace.
type AgentAPI struct {
	registry *agent.Registry
}

// NewAgentAPI creates an AgentAPI backed by the given registry.
func NewAgentAPI(registry *agent.Registry) *AgentAPI {
	return &AgentAPI{registry: registry}
}

// GetRecord returns the AgentRecord for the given agent ID.
func (a *AgentAPI) GetRecord(_ context.Context, agentID string) (*agent.AgentRecord, error) {
	rec, ok := a.registry.Get(agentID)
	if !ok {
		return nil, nil
	}
	return &rec, nil
}

// GetManifest returns the ToolManifest for the given agent ID.
func (a *AgentAPI) GetManifest(_ context.Context, agentID string) (*agent.ToolManifest, error) {
	m, ok := a.registry.GetManifest(agentID)
	if !ok {
		return nil, nil
	}
	return &m, nil
}
