package capability

import (
	"encoding/json"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&capabilityHandler{})
}

// registrarBit is the bit index for the "Registrar" capability (same as agent.registrarBit).
const registrarBit uint8 = 0

type capabilityHandler struct{}

func (h *capabilityHandler) CanHandle(kind sysaction.ActionKind) bool {
	switch kind {
	case sysaction.ActionCapabilityRegister,
		sysaction.ActionCapabilityGrant,
		sysaction.ActionCapabilityRevoke:
		return true
	}
	return false
}

func (h *capabilityHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionCapabilityRegister:
		return h.handleRegister(ctx, sa)
	case sysaction.ActionCapabilityGrant:
		return h.handleGrant(ctx, sa)
	case sysaction.ActionCapabilityRevoke:
		return h.handleRevoke(ctx, sa)
	}
	return nil
}

type registerPayload struct {
	Name string `json:"name"`
}

func (h *capabilityHandler) handleRegister(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	// Only Registrar-capable addresses may register new capability names.
	if !HasCapability(ctx.StateDB, ctx.From, registrarBit) {
		return ErrCapabilityRegistrar
	}
	var p registerPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	_, err := RegisterCapabilityName(ctx.StateDB, p.Name)
	return err
}

type grantRevokePayload struct {
	Target string `json:"target"` // hex address
	Bit    uint8  `json:"bit"`
}

func (h *capabilityHandler) handleGrant(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if !HasCapability(ctx.StateDB, ctx.From, registrarBit) {
		return ErrCapabilityRegistrar
	}
	var p grantRevokePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if p.Bit >= readBitCount(ctx.StateDB) {
		return ErrCapabilityBitUnregistered
	}
	target := common.HexToAddress(p.Target)
	GrantCapability(ctx.StateDB, target, p.Bit)
	return nil
}

func (h *capabilityHandler) handleRevoke(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if !HasCapability(ctx.StateDB, ctx.From, registrarBit) {
		return ErrCapabilityRegistrar
	}
	var p grantRevokePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if p.Bit >= readBitCount(ctx.StateDB) {
		return ErrCapabilityBitUnregistered
	}
	target := common.HexToAddress(p.Target)
	RevokeCapability(ctx.StateDB, target, p.Bit)
	return nil
}
