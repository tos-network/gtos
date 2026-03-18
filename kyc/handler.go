package kyc

import (
	"encoding/json"

	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&kycHandler{})
}

type kycHandler struct{}

func (h *kycHandler) Actions() []sysaction.ActionKind {
	return []sysaction.ActionKind{sysaction.ActionKYCSet, sysaction.ActionKYCSuspend}
}

func (h *kycHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionKYCSet:
		return h.handleSet(ctx, sa)
	case sysaction.ActionKYCSuspend:
		return h.handleSuspend(ctx, sa)
	}
	return nil
}

type setPayload struct {
	Target string `json:"target"` // hex address
	Level  uint16 `json:"level"`
}

func (h *kycHandler) handleSet(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if !capability.HasCapability(ctx.StateDB, ctx.From, params.KYCCommitteeBit) {
		return ErrKYCNotCommittee
	}
	var p setPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if !IsValidLevel(p.Level) {
		return ErrKYCInvalidLevel
	}
	target := common.HexToAddress(p.Target)
	WriteKYC(ctx.StateDB, target, p.Level, KycActive)
	return nil
}

type suspendPayload struct {
	Target string `json:"target"` // hex address
}

func (h *kycHandler) handleSuspend(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if !capability.HasCapability(ctx.StateDB, ctx.From, params.KYCCommitteeBit) {
		return ErrKYCNotCommittee
	}
	var p suspendPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	target := common.HexToAddress(p.Target)
	level, status := readPacked(ctx.StateDB, target)
	if status != KycActive {
		return ErrKYCNotActive
	}
	writePacked(ctx.StateDB, target, level, KycSuspended)
	return nil
}
