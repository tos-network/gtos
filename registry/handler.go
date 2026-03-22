package registry

import (
	"encoding/json"

	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&registryHandler{})
}

type registryHandler struct{}

func (h *registryHandler) Actions() []sysaction.ActionKind {
	return []sysaction.ActionKind{
		sysaction.ActionRegistryRegisterCap,
		sysaction.ActionRegistryDeprecateCap,
		sysaction.ActionRegistryRevokeCap,
		sysaction.ActionRegistryGrantDelegation,
		sysaction.ActionRegistryRevokeDelegation,
	}
}

func (h *registryHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionRegistryRegisterCap:
		return h.handleRegisterCap(ctx, sa)
	case sysaction.ActionRegistryDeprecateCap:
		return h.handleDeprecateCap(ctx, sa)
	case sysaction.ActionRegistryRevokeCap:
		return h.handleRevokeCap(ctx, sa)
	case sysaction.ActionRegistryGrantDelegation:
		return h.handleGrantDelegation(ctx, sa)
	case sysaction.ActionRegistryRevokeDelegation:
		return h.handleRevokeDelegation(ctx, sa)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Capability handlers
// ---------------------------------------------------------------------------

type registerCapPayload struct {
	Name        string `json:"name"`
	BitIndex    uint16 `json:"bit_index"`
	Category    uint16 `json:"category"`
	Version     uint32 `json:"version"`
	ManifestRef string `json:"manifest_ref"` // hex-encoded bytes32
}

func (h *registryHandler) handleRegisterCap(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p registerCapPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if p.Name == "" {
		return ErrInvalidCapabilityName
	}

	// Reject if already registered (packed slot is non-zero).
	existing := ReadCapability(ctx.StateDB, p.Name)
	if existing.Name != "" {
		return ErrCapabilityAlreadyRegistered
	}
	if bit, ok := capability.CapabilityBit(ctx.StateDB, p.Name); ok {
		if bit != uint8(p.BitIndex) {
			return capability.ErrCapabilityBitConflict
		}
	} else if err := capability.RegisterCapabilityNameAtBit(ctx.StateDB, p.Name, uint8(p.BitIndex)); err != nil {
		return err
	}

	rec := CapabilityRecord{
		Name:     p.Name,
		BitIndex: p.BitIndex,
		Category: p.Category,
		Version:  p.Version,
		Status:   CapActive,
	}
	if p.ManifestRef != "" {
		rec.ManifestRef = common.HexToHash(p.ManifestRef)
	}

	WriteCapability(ctx.StateDB, rec)
	return nil
}

type capNamePayload struct {
	Name string `json:"name"`
}

func (h *registryHandler) handleDeprecateCap(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p capNamePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	rec := ReadCapability(ctx.StateDB, p.Name)
	if rec.Name == "" {
		return ErrCapabilityNotFound
	}
	if rec.Status == CapRevoked {
		return ErrCapabilityAlreadyRevoked
	}

	rec.Status = CapDeprecated
	WriteCapability(ctx.StateDB, rec)
	return nil
}

func (h *registryHandler) handleRevokeCap(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p capNamePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	rec := ReadCapability(ctx.StateDB, p.Name)
	if rec.Name == "" {
		return ErrCapabilityNotFound
	}
	if rec.Status == CapRevoked {
		return ErrCapabilityAlreadyRevoked
	}

	rec.Status = CapRevoked
	WriteCapability(ctx.StateDB, rec)
	return nil
}

// ---------------------------------------------------------------------------
// Delegation handlers
// ---------------------------------------------------------------------------

type grantDelegationPayload struct {
	Principal     string `json:"principal"`      // hex address
	Delegate      string `json:"delegate"`       // hex address
	ScopeRef      string `json:"scope_ref"`      // hex bytes32
	CapabilityRef string `json:"capability_ref"` // hex bytes32
	PolicyRef     string `json:"policy_ref"`     // hex bytes32
	NotBeforeMS   uint64 `json:"not_before_ms"`
	ExpiryMS      uint64 `json:"expiry_ms"`
}

func (h *registryHandler) handleGrantDelegation(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p grantDelegationPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	principal := common.HexToAddress(p.Principal)
	delegate := common.HexToAddress(p.Delegate)
	if principal == (common.Address{}) || delegate == (common.Address{}) {
		return ErrInvalidDelegation
	}

	scopeRef := common.HexToHash(p.ScopeRef)
	capRef := common.HexToHash(p.CapabilityRef)
	policyRef := common.HexToHash(p.PolicyRef)

	rec := DelegationRecord{
		Principal:     principal,
		Delegate:      delegate,
		ScopeRef:      scopeRef,
		CapabilityRef: capRef,
		PolicyRef:     policyRef,
		NotBeforeMS:   p.NotBeforeMS,
		ExpiryMS:      p.ExpiryMS,
		Status:        DelActive,
	}

	WriteDelegation(ctx.StateDB, rec)
	return nil
}

type revokeDelegationPayload struct {
	Principal string `json:"principal"` // hex address
	Delegate  string `json:"delegate"`  // hex address
	ScopeRef  string `json:"scope_ref"` // hex bytes32
}

func (h *registryHandler) handleRevokeDelegation(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p revokeDelegationPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	principal := common.HexToAddress(p.Principal)
	delegate := common.HexToAddress(p.Delegate)
	scopeRef := common.HexToHash(p.ScopeRef)

	if !DelegationExists(ctx.StateDB, principal, delegate, scopeRef) {
		return ErrDelegationNotFound
	}

	rec := ReadDelegation(ctx.StateDB, principal, delegate, scopeRef)
	if rec.Status == DelRevoked {
		return ErrDelegationAlreadyRevoked
	}

	rec.Status = DelRevoked
	WriteDelegation(ctx.StateDB, rec)
	return nil
}
