package gateway

import (
	"github.com/tos-network/gtos/boundary"
	"github.com/tos-network/gtos/common"
)

// GatewayConfigResult is the JSON-friendly result for GetGatewayConfig.
type GatewayConfigResult struct {
	AgentAddress   common.Address `json:"agent_address"`
	Endpoint       string         `json:"endpoint"`
	SupportedKinds []string       `json:"supported_kinds"`
	MaxRelayGas    uint64         `json:"max_relay_gas"`
	FeePolicy      string         `json:"fee_policy"`
	FeeAmount      string         `json:"fee_amount"`
	Active         bool           `json:"active"`
	RegisteredAt   uint64         `json:"registered_at"`
}

// PublicGatewayAPI provides RPC methods for querying gateway state.
type PublicGatewayAPI struct {
	stateReader func() stateDB
}

// NewPublicGatewayAPI creates a new gateway API instance.
func NewPublicGatewayAPI(stateReader func() stateDB) *PublicGatewayAPI {
	return &PublicGatewayAPI{stateReader: stateReader}
}

// GetGatewayConfig returns the gateway configuration for an agent.
func (api *PublicGatewayAPI) GetGatewayConfig(agent common.Address) (*GatewayConfigResult, error) {
	db := api.stateReader()
	if !ReadActive(db, agent) {
		// Check if it was ever registered by looking at registeredAt.
		if ReadRegisteredAt(db, agent) == 0 {
			return nil, ErrGatewayNotFound
		}
	}
	return &GatewayConfigResult{
		AgentAddress:   agent,
		Endpoint:       ReadEndpoint(db, agent),
		SupportedKinds: ReadSupportedKinds(db, agent),
		MaxRelayGas:    ReadMaxRelayGas(db, agent),
		FeePolicy:      ReadFeePolicy(db, agent),
		FeeAmount:      ReadFeeAmount(db, agent).String(),
		Active:         ReadActive(db, agent),
		RegisteredAt:   ReadRegisteredAt(db, agent),
	}, nil
}

// IsGatewayActive returns whether a gateway is active.
func (api *PublicGatewayAPI) IsGatewayActive(agent common.Address) (bool, error) {
	db := api.stateReader()
	return ReadActive(db, agent), nil
}

// GetBoundaryVersion returns the boundary schema version used by this node.
func (api *PublicGatewayAPI) GetBoundaryVersion() string {
	return boundary.SchemaVersion
}

// GetSchemaVersion returns the boundary schema version and negotiation info.
func (api *PublicGatewayAPI) GetSchemaVersion() map[string]interface{} {
	return map[string]interface{}{
		"schema_version": boundary.SchemaVersion,
		"namespace":      "gateway",
	}
}
