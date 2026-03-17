package agentdiscovery

import (
	"errors"
	"math/big"

	"github.com/tos-network/gtos/agent"
	"github.com/tos-network/gtos/common"
)

// stateDB is the minimal storage interface needed for identity binding.
// It mirrors the interface used by agent/ and policywallet/.
type stateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

// Sentinel errors for identity binding.
var (
	ErrAgentNotRegistered = errors.New("agentdiscovery: agent not registered on-chain")
	ErrAgentSuspended     = errors.New("agentdiscovery: agent is suspended")
	ErrCardNilAgent       = errors.New("agentdiscovery: card has zero agent address")
)

// AgentCard represents the off-chain discoverable profile of an agent.
type AgentCard struct {
	AgentAddress    common.Address    `json:"agent_address"`
	Name            string            `json:"name"`
	ServiceKinds    []string          `json:"service_kinds"`                // "signer", "paymaster", "gateway", "oracle", "solver"
	Capabilities    []string          `json:"capabilities"`
	Endpoint        string            `json:"endpoint"`
	GatewayEndpoint string            `json:"gateway_endpoint,omitempty"`
	TrustTier       uint8             `json:"trust_tier"`
	SponsorSupport  bool              `json:"sponsor_support"`
	FeeSchedule     *FeeSchedule      `json:"fee_schedule,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	UpdatedAt       uint64            `json:"updated_at"`
	OnChainVerified bool              `json:"on_chain_verified"` // whether on-chain agent record exists
}

// FeeSchedule describes the fee structure an agent charges.
type FeeSchedule struct {
	BaseFee    *big.Int `json:"base_fee"`
	PerGasFee  *big.Int `json:"per_gas_fee"`
	PercentFee uint64   `json:"percent_fee"` // basis points (100 = 1%)
}

// BindAgentCard verifies and binds an off-chain card to on-chain identity.
// It checks that the agent referenced by card.AgentAddress is registered and
// not suspended, then marks the card as on-chain verified.
func BindAgentCard(state stateDB, card *AgentCard) error {
	if card.AgentAddress == (common.Address{}) {
		return ErrCardNilAgent
	}
	if !agent.IsRegistered(state, card.AgentAddress) {
		return ErrAgentNotRegistered
	}
	if agent.IsSuspended(state, card.AgentAddress) {
		return ErrAgentSuspended
	}
	card.OnChainVerified = true
	return nil
}

// ResolveAgentCard looks up on-chain agent state and builds a verified card.
// Returns nil fields for fee schedule if the agent has no metadata URI.
func ResolveAgentCard(state stateDB, addr common.Address) (*AgentCard, error) {
	if !agent.IsRegistered(state, addr) {
		return nil, ErrAgentNotRegistered
	}

	suspended := agent.IsSuspended(state, addr)
	status := agent.ReadStatus(state, addr)
	metadataURI := agent.MetadataOf(state, addr)

	card := &AgentCard{
		AgentAddress:    addr,
		OnChainVerified: true,
		TrustTier:       uint8(status),
	}

	if metadataURI != "" {
		card.Endpoint = metadataURI
	}

	// A suspended agent is still resolvable but flagged.
	if suspended {
		card.OnChainVerified = false
	}

	return card, nil
}
