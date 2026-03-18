package delegation

import (
	"encoding/json"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&delegationHandler{})
}

type delegationHandler struct{}

func (h *delegationHandler) Actions() []sysaction.ActionKind {
	return []sysaction.ActionKind{sysaction.ActionDelegationMarkUsed, sysaction.ActionDelegationRevoke}
}

func (h *delegationHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionDelegationMarkUsed:
		return h.handleMarkUsed(ctx, sa)
	case sysaction.ActionDelegationRevoke:
		return h.handleRevoke(ctx, sa)
	}
	return nil
}

type noncePayload struct {
	Principal string `json:"principal"` // hex address
	Nonce     string `json:"nonce"`     // decimal string
}

func (h *delegationHandler) handleMarkUsed(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p noncePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	principal := common.HexToAddress(p.Principal)

	// Security: only the principal can consume their own nonces.
	if ctx.From != principal {
		return ErrUnauthorizedPrincipal
	}

	nonce, ok := new(big.Int).SetString(p.Nonce, 10)
	if !ok || nonce.Sign() < 0 {
		return ErrNonceAlreadyUsed
	}

	if IsUsed(ctx.StateDB, principal, nonce) {
		return ErrNonceAlreadyUsed
	}
	MarkUsed(ctx.StateDB, principal, nonce)
	return nil
}

func (h *delegationHandler) handleRevoke(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p noncePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	principal := common.HexToAddress(p.Principal)

	// Security: only the principal can revoke their own nonces.
	if ctx.From != principal {
		return ErrUnauthorizedPrincipal
	}

	nonce, ok := new(big.Int).SetString(p.Nonce, 10)
	if !ok || nonce.Sign() < 0 {
		return ErrNonceAlreadyUsed
	}

	// Revoke is idempotent: marking an already-used nonce again is a no-op.
	Revoke(ctx.StateDB, principal, nonce)
	return nil
}
