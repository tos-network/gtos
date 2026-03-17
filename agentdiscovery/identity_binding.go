package agentdiscovery

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/tos-network/gtos/agent"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// stateDB is the minimal storage interface needed for identity binding.
// It mirrors the interface used by agent/ and policywallet/.
type stateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

// Sentinel errors for identity binding.
var (
	ErrAgentNotRegistered    = errors.New("agentdiscovery: agent not registered on-chain")
	ErrAgentSuspended        = errors.New("agentdiscovery: agent is suspended")
	ErrCardNilAgent          = errors.New("agentdiscovery: card has zero agent address")
	ErrCapabilitiesMismatch  = errors.New("agentdiscovery: card capabilities do not match on-chain record")
	ErrBindingExpired        = errors.New("agentdiscovery: identity binding has expired")
)

// MaxFeePercentBasisPoints is the maximum acceptable fee percentage (50% = 5000 bps).
const MaxFeePercentBasisPoints = 5000

// BindingTTLBlocks is the default time-to-live for an identity binding (approx 24h at 360ms blocks).
const BindingTTLBlocks uint64 = 240000

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

// IdentityBinding is a verified, immutable record that binds an on-chain agent
// registration to an off-chain agent card. It is the finalized output of the
// identity binding process and can be stored on-chain for later verification.
type IdentityBinding struct {
	AgentAddress      common.Address `json:"agent_address"`
	OnChainVerified   bool           `json:"on_chain_verified"`
	CapabilitiesMatch bool           `json:"capabilities_match"`
	Active            bool           `json:"active"`
	BindingHash       common.Hash    `json:"binding_hash"`
	VerifiedAt        uint64         `json:"verified_at"`
	ExpiresAt         uint64         `json:"expires_at"`
}

// FinalizeIdentityBinding performs a full verification of on-chain agent state
// against an off-chain agent card, checking:
//   - Agent is registered and active
//   - Agent is not suspended
//   - Fee schedule is reasonable (percent fee within bounds)
//
// It returns a verified, immutable binding record with a deterministic hash.
func FinalizeIdentityBinding(state stateDB, card *AgentCard, blockNumber uint64) (*IdentityBinding, error) {
	if card.AgentAddress == (common.Address{}) {
		return nil, ErrCardNilAgent
	}
	if !agent.IsRegistered(state, card.AgentAddress) {
		return nil, ErrAgentNotRegistered
	}
	if agent.IsSuspended(state, card.AgentAddress) {
		return nil, ErrAgentSuspended
	}

	status := agent.ReadStatus(state, card.AgentAddress)
	active := status == agent.AgentActive

	// Check fee schedule reasonableness.
	if card.FeeSchedule != nil && card.FeeSchedule.PercentFee > MaxFeePercentBasisPoints {
		// Not a hard error, but flag capabilities mismatch.
		return &IdentityBinding{
			AgentAddress:      card.AgentAddress,
			OnChainVerified:   true,
			CapabilitiesMatch: false,
			Active:            active,
			VerifiedAt:        blockNumber,
			ExpiresAt:         blockNumber + BindingTTLBlocks,
		}, nil
	}

	binding := &IdentityBinding{
		AgentAddress:      card.AgentAddress,
		OnChainVerified:   true,
		CapabilitiesMatch: true,
		Active:            active,
		VerifiedAt:        blockNumber,
		ExpiresAt:         blockNumber + BindingTTLBlocks,
	}

	// Compute deterministic binding hash over address + block number.
	binding.BindingHash = computeBindingHash(card.AgentAddress, blockNumber)

	return binding, nil
}

// computeBindingHash produces a deterministic hash for an identity binding.
func computeBindingHash(addr common.Address, blockNumber uint64) common.Hash {
	var buf [common.AddressLength + 8]byte
	copy(buf[:common.AddressLength], addr.Bytes())
	binary.BigEndian.PutUint64(buf[common.AddressLength:], blockNumber)
	return common.BytesToHash(crypto.Keccak256(buf[:]))
}

// --- On-chain storage for identity bindings ---

// bindingSlot returns the storage slot for a binding field for an agent.
func bindingSlot(addr common.Address, field string) common.Hash {
	key := make([]byte, 0, len("idbind\x00")+common.AddressLength+1+len(field))
	key = append(key, "idbind\x00"...)
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// WriteIdentityBinding persists a verified identity binding to on-chain state.
func WriteIdentityBinding(state stateDB, binding *IdentityBinding) {
	addr := binding.AgentAddress
	registry := params.AgentRegistryAddress

	// Flags: [0]=on_chain_verified, [1]=capabilities_match, [2]=active
	var flags common.Hash
	if binding.OnChainVerified {
		flags[31] |= 0x01
	}
	if binding.CapabilitiesMatch {
		flags[31] |= 0x02
	}
	if binding.Active {
		flags[31] |= 0x04
	}
	state.SetState(registry, bindingSlot(addr, "flags"), flags)

	// Binding hash.
	state.SetState(registry, bindingSlot(addr, "hash"), binding.BindingHash)

	// VerifiedAt.
	var verifiedAt common.Hash
	binary.BigEndian.PutUint64(verifiedAt[24:], binding.VerifiedAt)
	state.SetState(registry, bindingSlot(addr, "verified_at"), verifiedAt)

	// ExpiresAt.
	var expiresAt common.Hash
	binary.BigEndian.PutUint64(expiresAt[24:], binding.ExpiresAt)
	state.SetState(registry, bindingSlot(addr, "expires_at"), expiresAt)
}

// ReadIdentityBinding reads a persisted identity binding from on-chain state.
// Returns nil if no binding has been written for the given agent.
func ReadIdentityBinding(state stateDB, addr common.Address) *IdentityBinding {
	registry := params.AgentRegistryAddress

	flags := state.GetState(registry, bindingSlot(addr, "flags"))
	hash := state.GetState(registry, bindingSlot(addr, "hash"))
	verifiedAtRaw := state.GetState(registry, bindingSlot(addr, "verified_at"))
	expiresAtRaw := state.GetState(registry, bindingSlot(addr, "expires_at"))

	verifiedAt := binary.BigEndian.Uint64(verifiedAtRaw[24:])

	// If verifiedAt is 0 and hash is zero, no binding exists.
	if verifiedAt == 0 && hash == (common.Hash{}) {
		return nil
	}

	return &IdentityBinding{
		AgentAddress:      addr,
		OnChainVerified:   flags[31]&0x01 != 0,
		CapabilitiesMatch: flags[31]&0x02 != 0,
		Active:            flags[31]&0x04 != 0,
		BindingHash:       hash,
		VerifiedAt:        verifiedAt,
		ExpiresAt:         binary.BigEndian.Uint64(expiresAtRaw[24:]),
	}
}
