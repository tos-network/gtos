// Package agent implements the TOS Agent Registry for gtos nodes.
//
// Agent records and tool manifests are stored on-chain via system action
// transactions. This package provides the in-memory index that gtos nodes
// maintain locally for fast discovery queries.
package agent

// Endpoint describes one network endpoint of an agent.
type Endpoint struct {
	Type         string `json:"type"`
	URL          string `json:"url"`
	MultiAddr    string `json:"multiaddr,omitempty"`
	Reachability string `json:"reachability"`
	Priority     int    `json:"priority"`
}

// ToolSpec describes a single tool exposed by an agent.
type ToolSpec struct {
	ToolID          string         `json:"tool_id"`
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	Category        string         `json:"category"`
	InputSchema     map[string]interface{} `json:"input_schema,omitempty"`
	OutputSchema    map[string]interface{} `json:"output_schema,omitempty"`
	PricingModel    string                 `json:"pricing_model,omitempty"`
	PricingAmount   string                 `json:"pricing_amount,omitempty"`
	PricingCurrency string                 `json:"pricing_currency,omitempty"`
	SettlementRail  string                 `json:"settlement_rail,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ToolManifest is the full capability manifest for an agent, signed by the agent.
type ToolManifest struct {
	ManifestVersion string     `json:"manifest_version"`
	AgentID         string     `json:"agent_id"`
	UpdatedAt       int64      `json:"updated_at"`
	ExpiresAt       int64      `json:"expires_at"`
	Tools           []ToolSpec `json:"tools"`
	SigAlg          string     `json:"sig_alg,omitempty"`
	Sig             string     `json:"sig,omitempty"`
}

// AgentRecord is the on-chain registry record for one agent.
type AgentRecord struct {
	RecordVersion    string     `json:"record_version"`
	AgentID          string     `json:"agent_id"`
	OwnerAddress     string     `json:"owner_address"` // TOS address of the registrant
	Pubkey           string     `json:"pubkey"`
	Endpoints        []Endpoint `json:"endpoints"`
	ManifestHash     string     `json:"manifest_hash"`
	CapabilityDigest string     `json:"capability_digest"`
	TrustPolicy      string     `json:"trust_policy"`
	Region           string     `json:"region,omitempty"`
	ProviderTier     string     `json:"provider_tier,omitempty"`
	ExpiresAt        int64      `json:"expires_at"`
	UpdatedAt        int64      `json:"updated_at"`
	RegisteredBlock  uint64     `json:"registered_block"`
}

// QueryRequest is the input to Registry.Query.
type QueryRequest struct {
	Category        string            `json:"category"`
	Query           string            `json:"q"`
	Facets          map[string]string `json:"facets"`
	Limit           int               `json:"limit"`
	ToolID          string            `json:"tool_id"`
	MaxLatencyMs    int               `json:"max_latency_ms"`
	PreferredRegion string            `json:"preferred_region"`
	ProviderTiers   []string          `json:"provider_tiers"`
}

// QueryResult is one hit from Registry.Query.
type QueryResult struct {
	Record AgentRecord
	Score  int
}
