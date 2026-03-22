package paypolicy

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/registry"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&handler{})
}

type handler struct{}

func (h *handler) Actions() []sysaction.ActionKind {
	return []sysaction.ActionKind{
		sysaction.ActionRegistryRegisterPayPolicy,
		sysaction.ActionRegistryDeactivatePayPolicy,
	}
}

func (h *handler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionRegistryRegisterPayPolicy:
		return h.handleRegister(ctx, sa)
	case sysaction.ActionRegistryDeactivatePayPolicy:
		return h.handleDeactivate(ctx, sa)
	default:
		return nil
	}
}

type registerPolicyPayload struct {
	PolicyID  string `json:"policy_id"`
	Kind      uint16 `json:"kind"`
	Owner     string `json:"owner"`
	Asset     string `json:"asset"`
	MaxAmount string `json:"max_amount"`
	RulesRef  string `json:"rules_ref,omitempty"`
	StatusRef string `json:"status_ref,omitempty"`
}

func (h *handler) handleRegister(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p registerPolicyPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	policyIDBytes, err := parseRequiredBytes32(p.PolicyID)
	if err != nil {
		return ErrInvalidPolicy
	}
	owner, err := parseStrictHexAddress(p.Owner)
	if err != nil {
		return ErrInvalidPolicy
	}
	amount, ok := new(big.Int).SetString(strings.TrimSpace(p.MaxAmount), 10)
	if owner == (common.Address{}) || !ok || amount.Sign() < 0 || p.Asset == "" {
		return ErrInvalidPolicy
	}
	if ctx.From != owner && !registry.IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedOwner
	}
	var policyID [32]byte
	copy(policyID[:], policyIDBytes[:])
	if existing := ReadPolicy(ctx.StateDB, policyID); existing.PolicyID != ([32]byte{}) {
		return ErrPolicyExists
	}
	rulesRef, err := parseOptionalBytes32(p.RulesRef)
	if err != nil {
		return ErrInvalidPolicy
	}
	statusRef, err := parseOptionalBytes32(p.StatusRef)
	if err != nil {
		return ErrInvalidPolicy
	}
	now := currentBlockU64(ctx)
	rec := PolicyRecord{
		PolicyID:  policyID,
		Kind:      p.Kind,
		Owner:     owner,
		Asset:     strings.ToUpper(strings.TrimSpace(p.Asset)),
		MaxAmount: amount,
		RulesRef:  rulesRef,
		Status:    PolicyActive,
		CreatedAt: now,
		UpdatedAt: now,
		UpdatedBy: ctx.From,
		StatusRef: statusRef,
	}
	WritePolicy(ctx.StateDB, rec)
	return nil
}

type deactivatePolicyPayload struct {
	PolicyID  string `json:"policy_id"`
	ReasonRef string `json:"reason_ref,omitempty"`
}

func (h *handler) handleDeactivate(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p deactivatePolicyPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	policyIDHash, err := parseRequiredBytes32(p.PolicyID)
	if err != nil {
		return ErrInvalidPolicy
	}
	var policyID [32]byte
	copy(policyID[:], policyIDHash[:])
	rec := ReadPolicy(ctx.StateDB, policyID)
	if rec.PolicyID == ([32]byte{}) {
		return ErrPolicyNotFound
	}
	if ctx.From != rec.Owner && !registry.IsGovernor(ctx.StateDB, ctx.From) {
		return ErrUnauthorizedOwner
	}
	if rec.Status == PolicyRevoked {
		return ErrPolicyAlreadyRevoked
	}
	reason, err := parseOptionalBytes32(p.ReasonRef)
	if err != nil {
		return ErrInvalidPolicy
	}
	rec.Status = PolicyRevoked
	rec.UpdatedAt = currentBlockU64(ctx)
	rec.UpdatedBy = ctx.From
	rec.StatusRef = reason
	WritePolicy(ctx.StateDB, rec)
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
		return common.Address{}, ErrInvalidPolicy
	}
	return common.HexToAddress(input), nil
}

func parseRequiredBytes32(input string) ([32]byte, error) {
	out, err := parseOptionalBytes32(input)
	if err != nil {
		return out, err
	}
	if out == ([32]byte{}) {
		return out, ErrInvalidPolicy
	}
	return out, nil
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
		return out, ErrInvalidPolicy
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return out, ErrInvalidPolicy
	}
	copy(out[:], decoded)
	return out, nil
}
