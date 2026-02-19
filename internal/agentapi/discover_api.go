package agentapi

import (
	"context"

	"github.com/tos-network/gtos/agent"
)

// DiscoverAPI implements the discover_* RPC namespace.
type DiscoverAPI struct {
	registry *agent.Registry
}

// NewDiscoverAPI creates a DiscoverAPI backed by the given registry.
func NewDiscoverAPI(registry *agent.Registry) *DiscoverAPI {
	return &DiscoverAPI{registry: registry}
}

// Query searches the local capability index.
func (d *DiscoverAPI) Query(_ context.Context, req agent.QueryRequest) []agent.QueryResult {
	return d.registry.Query(req)
}

// Resolve returns the ToolManifest by agent ID (not by hash in this MVP).
func (d *DiscoverAPI) Resolve(_ context.Context, agentID string) (*agent.ToolManifest, error) {
	m, ok := d.registry.GetManifest(agentID)
	if !ok {
		return nil, nil
	}
	return &m, nil
}
