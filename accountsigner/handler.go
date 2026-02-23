package accountsigner

import (
	"strings"

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
	if strings.TrimSpace(payload.SignerType) == "" || strings.TrimSpace(payload.SignerValue) == "" {
		return ErrInvalidPayload
	}
	if len([]byte(payload.SignerType)) > MaxSignerTypeLen || len([]byte(payload.SignerValue)) > MaxSignerValueLen {
		return ErrInvalidPayload
	}
	Set(ctx.StateDB, ctx.From, payload.SignerType, payload.SignerValue)
	return nil
}
