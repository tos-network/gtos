package registry

import (
	"encoding/hex"
	"encoding/json"
	"strings"

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
	StatusRef   string `json:"status_ref,omitempty"`
}

func (h *registryHandler) handleRegisterCap(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p registerCapPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return ErrInvalidCapabilityName
	}
	if !IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedCapability
	}
	manifestRef, err := parseOptionalBytes32(p.ManifestRef)
	if err != nil {
		return ErrInvalidCapabilityName
	}
	statusRef, err := parseOptionalBytes32(p.StatusRef)
	if err != nil {
		return ErrInvalidCapabilityName
	}

	// Reject if already registered (packed slot is non-zero).
	existing := ReadCapability(ctx.StateDB, p.Name)
	if existing.Name != "" {
		return ErrCapabilityAlreadyRegistered
	}
	if bit, ok := capabilityBit(ctx.StateDB, p.Name); ok {
		if bit != uint8(p.BitIndex) {
			return errCapabilityBitConflict()
		}
	} else if err := registerCapabilityNameAtBit(ctx.StateDB, p.Name, uint8(p.BitIndex)); err != nil {
		return err
	}
	now := currentBlockU64(ctx)

	rec := CapabilityRecord{
		Owner:       ctx.From,
		Name:        p.Name,
		BitIndex:    p.BitIndex,
		Category:    p.Category,
		Version:     p.Version,
		Status:      CapActive,
		ManifestRef: manifestRef,
		CreatedAt:   now,
		UpdatedAt:   now,
		UpdatedBy:   ctx.From,
		StatusRef:   statusRef,
	}

	WriteCapability(ctx.StateDB, rec)
	return nil
}

type capNamePayload struct {
	Name      string `json:"name"`
	ReasonRef string `json:"reason_ref,omitempty"`
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
	if rec.Owner != (common.Address{}) && ctx.From != rec.Owner && !IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedCapability
	}
	if rec.Status == CapDeprecated {
		return ErrCapabilityAlreadyDeprecated
	}
	if rec.Status == CapRevoked {
		return ErrCapabilityAlreadyRevoked
	}
	if !rec.Status.CanTransitionTo(CapDeprecated) {
		return ErrCapabilityAlreadyDeprecated
	}
	reason, err := parseOptionalBytes32(p.ReasonRef)
	if err != nil {
		return ErrInvalidCapabilityName
	}
	rec.Status = CapDeprecated
	rec.UpdatedAt = currentBlockU64(ctx)
	rec.UpdatedBy = ctx.From
	rec.StatusRef = reason
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
	if rec.Owner != (common.Address{}) && ctx.From != rec.Owner && !IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedCapability
	}
	if rec.Status == CapRevoked {
		return ErrCapabilityAlreadyRevoked
	}
	if !rec.Status.CanTransitionTo(CapRevoked) {
		return ErrCapabilityAlreadyRevoked
	}
	reason, err := parseOptionalBytes32(p.ReasonRef)
	if err != nil {
		return ErrInvalidCapabilityName
	}

	rec.Status = CapRevoked
	rec.UpdatedAt = currentBlockU64(ctx)
	rec.UpdatedBy = ctx.From
	rec.StatusRef = reason
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
	StatusRef     string `json:"status_ref,omitempty"`
}

func (h *registryHandler) handleGrantDelegation(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p grantDelegationPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	principal, err := parseStrictHexAddress(p.Principal)
	if err != nil {
		return ErrInvalidDelegation
	}
	delegate, err := parseStrictHexAddress(p.Delegate)
	if err != nil {
		return ErrInvalidDelegation
	}
	if principal == (common.Address{}) || delegate == (common.Address{}) {
		return ErrInvalidDelegation
	}
	if ctx.From != principal && !IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedDelegation
	}

	scopeRef, err := parseOptionalBytes32(p.ScopeRef)
	if err != nil {
		return ErrInvalidDelegation
	}
	capRef, err := parseOptionalBytes32(p.CapabilityRef)
	if err != nil {
		return ErrInvalidDelegation
	}
	policyRef, err := parseOptionalBytes32(p.PolicyRef)
	if err != nil {
		return ErrInvalidDelegation
	}
	statusRef, err := parseOptionalBytes32(p.StatusRef)
	if err != nil {
		return ErrInvalidDelegation
	}
	if p.ExpiryMS > 0 && p.NotBeforeMS > 0 && p.ExpiryMS < p.NotBeforeMS {
		return ErrInvalidDelegationWindow
	}
	now := currentBlockU64(ctx)

	rec := DelegationRecord{
		Principal:     principal,
		Delegate:      delegate,
		ScopeRef:      scopeRef,
		CapabilityRef: capRef,
		PolicyRef:     policyRef,
		NotBeforeMS:   p.NotBeforeMS,
		ExpiryMS:      p.ExpiryMS,
		Status:        DelActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		UpdatedBy:     ctx.From,
		StatusRef:     statusRef,
	}

	WriteDelegation(ctx.StateDB, rec)
	return nil
}

type revokeDelegationPayload struct {
	Principal string `json:"principal"`            // hex address
	Delegate  string `json:"delegate"`             // hex address
	ScopeRef  string `json:"scope_ref"`            // hex bytes32
	ReasonRef string `json:"reason_ref,omitempty"` // hex bytes32
}

func (h *registryHandler) handleRevokeDelegation(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p revokeDelegationPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	principal, err := parseStrictHexAddress(p.Principal)
	if err != nil {
		return ErrInvalidDelegation
	}
	delegate, err := parseStrictHexAddress(p.Delegate)
	if err != nil {
		return ErrInvalidDelegation
	}
	scopeRef, err := parseOptionalBytes32(p.ScopeRef)
	if err != nil {
		return ErrInvalidDelegation
	}
	reason, err := parseOptionalBytes32(p.ReasonRef)
	if err != nil {
		return ErrInvalidDelegation
	}
	if ctx.From != principal && !IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedDelegation
	}

	if !DelegationExists(ctx.StateDB, principal, delegate, scopeRef) {
		return ErrDelegationNotFound
	}

	rec := ReadDelegation(ctx.StateDB, principal, delegate, scopeRef)
	if rec.Status == DelRevoked {
		return ErrDelegationAlreadyRevoked
	}

	rec.Status = DelRevoked
	rec.UpdatedAt = currentBlockU64(ctx)
	rec.UpdatedBy = ctx.From
	rec.StatusRef = reason
	WriteDelegation(ctx.StateDB, rec)
	return nil
}

func currentBlockU64(ctx *sysaction.Context) uint64 {
	if ctx == nil || ctx.BlockNumber == nil || ctx.BlockNumber.Sign() < 0 || !ctx.BlockNumber.IsUint64() {
		return 0
	}
	return ctx.BlockNumber.Uint64()
}

func parseStrictHexAddress(input string) (common.Address, error) {
	input = strings.TrimSpace(input)
	if !common.IsHexAddress(input) {
		return common.Address{}, ErrInvalidDelegation
	}
	return common.HexToAddress(input), nil
}

func parseOptionalBytes32(input string) ([32]byte, error) {
	var out [32]byte
	input = strings.TrimSpace(input)
	if input == "" {
		return out, nil
	}
	raw := input
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		raw = raw[2:]
	}
	if len(raw) != 64 {
		return out, ErrInvalidDelegation
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return out, ErrInvalidDelegation
	}
	copy(out[:], decoded)
	return out, nil
}

func capabilityBit(db capabilityStateDB, name string) (uint8, bool) {
	return capability.CapabilityBit(db, name)
}

func registerCapabilityNameAtBit(db capabilityStateDB, name string, bit uint8) error {
	return capability.RegisterCapabilityNameAtBit(db, name, bit)
}

func errCapabilityBitConflict() error {
	return capability.ErrCapabilityBitConflict
}
