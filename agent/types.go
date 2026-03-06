// Package agent implements the Agent-Native agent registry system action handler.
package agent

import "errors"

// AgentStatus represents the lifecycle state of a registered agent.
type AgentStatus uint8

const (
	// AgentInactive is the default state; agent has not registered or has withdrawn.
	AgentInactive AgentStatus = 0
	// AgentActive means the agent has locked stake and is eligible to operate.
	AgentActive AgentStatus = 1
)

// Sentinel errors returned by agent system action handlers.
var (
	ErrAgentAlreadyRegistered   = errors.New("agent: already registered")
	ErrAgentNotRegistered       = errors.New("agent: not registered")
	ErrAgentSuspended           = errors.New("agent: suspended")
	ErrAgentInsufficientStake   = errors.New("agent: insufficient stake")
	ErrAgentInsufficientBalance = errors.New("agent: sender balance below stake amount")
	ErrCapabilityRequired       = errors.New("agent: Registrar capability required")
	ErrAgentNotActive           = errors.New("agent: not active")
	ErrDecreaseExceedsStake     = errors.New("agent: decrease amount exceeds current stake")
	ErrRegistryBalanceBroken    = errors.New("agent: registry balance invariant violated")
)
