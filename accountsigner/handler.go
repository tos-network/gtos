package accountsigner

import (
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&handler{})
}

type handler struct{}

func (h *handler) CanHandle(kind sysaction.ActionKind) bool {
	return kind == sysaction.ActionAccountSetSigner
}

func (h *handler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if ctx.Value != nil && ctx.Value.Sign() != 0 {
		return ErrNonZeroValue
	}
	var payload SetSignerPayload
	if err := sysaction.DecodePayload(sa, &payload); err != nil {
		return ErrInvalidPayload
	}
	normalizedType, _, normalizedValue, err := NormalizeSigner(payload.SignerType, payload.SignerValue)
	if err != nil {
		return ErrInvalidPayload
	}
	Set(ctx.StateDB, ctx.From, normalizedType, normalizedValue)
	return nil
}
