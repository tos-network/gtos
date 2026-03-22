package paypolicy

import (
	"encoding/json"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/common"
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
}

func (h *handler) handleRegister(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p registerPolicyPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	policyIDHash := common.HexToHash(p.PolicyID)
	owner := common.HexToAddress(p.Owner)
	amount, ok := new(big.Int).SetString(strings.TrimSpace(p.MaxAmount), 10)
	if policyIDHash == (common.Hash{}) || owner == (common.Address{}) || !ok || amount.Sign() < 0 || p.Asset == "" {
		return ErrInvalidPolicy
	}
	if ctx.From != owner {
		return ErrUnauthorizedOwner
	}
	var policyID [32]byte
	copy(policyID[:], policyIDHash[:])
	if existing := ReadPolicy(ctx.StateDB, policyID); existing.PolicyID != ([32]byte{}) {
		return ErrPolicyExists
	}
	rec := PolicyRecord{
		PolicyID:  policyID,
		Kind:      p.Kind,
		Owner:     owner,
		Asset:     strings.ToUpper(strings.TrimSpace(p.Asset)),
		MaxAmount: amount,
		Status:    PolicyActive,
	}
	if p.RulesRef != "" {
		ref := common.HexToHash(p.RulesRef)
		copy(rec.RulesRef[:], ref[:])
	}
	WritePolicy(ctx.StateDB, rec)
	return nil
}

type deactivatePolicyPayload struct {
	PolicyID string `json:"policy_id"`
}

func (h *handler) handleDeactivate(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p deactivatePolicyPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	policyIDHash := common.HexToHash(p.PolicyID)
	var policyID [32]byte
	copy(policyID[:], policyIDHash[:])
	rec := ReadPolicy(ctx.StateDB, policyID)
	if rec.PolicyID == ([32]byte{}) {
		return ErrPolicyNotFound
	}
	if ctx.From != rec.Owner {
		return ErrUnauthorizedOwner
	}
	rec.Status = PolicyRevoked
	WritePolicy(ctx.StateDB, rec)
	return nil
}
