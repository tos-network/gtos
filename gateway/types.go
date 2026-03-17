// Package gateway implements first-class gateway relay capabilities for GTOS.
//
// Gateway relay is a first-class protocol capability, not off-band infrastructure.
// Agents with the GatewayRelay capability can relay requests on behalf of other
// agents, providing signer, paymaster, oracle, and other relay services directly
// within the protocol layer.
package gateway

import (
	"errors"
	"math/big"

	"github.com/tos-network/gtos/common"
)

const (
	// CapabilityName is the registered capability name for gateway relay.
	CapabilityName = "GatewayRelay"

	// System actions.
	ActionRegisterGateway   = "GATEWAY_REGISTER"
	ActionUpdateGateway     = "GATEWAY_UPDATE"
	ActionDeregisterGateway = "GATEWAY_DEREGISTER"
)

// GatewayConfig holds the on-chain configuration for a registered gateway relay.
type GatewayConfig struct {
	AgentAddress   common.Address `json:"agent_address"`
	Endpoint       string         `json:"endpoint"`
	SupportedKinds []string       `json:"supported_kinds"` // "signer", "paymaster", "oracle", etc.
	MaxRelayGas    uint64         `json:"max_relay_gas"`
	FeePolicy      string         `json:"fee_policy"` // "free", "fixed", "percent"
	FeeAmount      *big.Int       `json:"fee_amount,omitempty"`
	Active         bool           `json:"active"`
	RegisteredAt   uint64         `json:"registered_at"`
}

// RegisterGatewayPayload is the JSON payload for ActionRegisterGateway (GATEWAY_REGISTER).
type RegisterGatewayPayload struct {
	Endpoint       string   `json:"endpoint"`
	SupportedKinds []string `json:"supported_kinds"`
	MaxRelayGas    uint64   `json:"max_relay_gas"`
	FeePolicy      string   `json:"fee_policy"`
	FeeAmount      string   `json:"fee_amount,omitempty"`
}

// UpdateGatewayPayload is the JSON payload for ActionUpdateGateway (GATEWAY_UPDATE).
type UpdateGatewayPayload struct {
	Endpoint       string   `json:"endpoint,omitempty"`
	SupportedKinds []string `json:"supported_kinds,omitempty"`
	MaxRelayGas    uint64   `json:"max_relay_gas,omitempty"`
	FeePolicy      string   `json:"fee_policy,omitempty"`
	FeeAmount      string   `json:"fee_amount,omitempty"`
}

// DeregisterGatewayPayload is the JSON payload for ActionDeregisterGateway (GATEWAY_DEREGISTER).
type DeregisterGatewayPayload struct{}

// Sentinel errors returned by gateway handlers.
var (
	ErrNotRegisteredAgent   = errors.New("gateway: agent is not registered")
	ErrNoGatewayCapability  = errors.New("gateway: agent lacks GatewayRelay capability")
	ErrGatewayAlreadyActive = errors.New("gateway: gateway already registered and active")
	ErrGatewayNotFound      = errors.New("gateway: no gateway config for agent")
	ErrGatewayNotActive     = errors.New("gateway: gateway is not active")
	ErrInvalidEndpoint      = errors.New("gateway: endpoint must not be empty")
	ErrInvalidFeePolicy     = errors.New("gateway: fee_policy must be free, fixed, or percent")
	ErrInvalidFeeAmount     = errors.New("gateway: invalid fee_amount")
	ErrNoSupportedKinds     = errors.New("gateway: supported_kinds must not be empty")
	ErrMaxRelayGasZero      = errors.New("gateway: max_relay_gas must be > 0")
)

// MaxEndpointLength is the maximum stored endpoint string length.
const MaxEndpointLength = 256

// MaxSupportedKinds is the maximum number of supported_kinds entries.
const MaxSupportedKinds = 16

// MaxKindLength is the maximum length of a single kind string.
const MaxKindLength = 32

// Valid fee policies.
var validFeePolicies = map[string]bool{
	"free":    true,
	"fixed":   true,
	"percent": true,
}
