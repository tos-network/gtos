package gateway

import (
	"encoding/json"
	"math/big"

	"github.com/tos-network/gtos/agent"
	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&gatewayHandler{})
}

type gatewayHandler struct{}

func (h *gatewayHandler) CanHandle(kind sysaction.ActionKind) bool {
	switch kind {
	case sysaction.ActionGatewayRegister,
		sysaction.ActionGatewayUpdate,
		sysaction.ActionGatewayDeregister:
		return true
	}
	return false
}

func (h *gatewayHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionGatewayRegister:
		return h.handleRegister(ctx, sa)
	case sysaction.ActionGatewayUpdate:
		return h.handleUpdate(ctx, sa)
	case sysaction.ActionGatewayDeregister:
		return h.handleDeregister(ctx, sa)
	}
	return nil
}

// requireGatewayCapability verifies the caller is a registered agent with the
// GatewayRelay capability.
func requireGatewayCapability(ctx *sysaction.Context) error {
	if !agent.IsRegistered(ctx.StateDB, ctx.From) {
		return ErrNotRegisteredAgent
	}
	bit, found := capability.CapabilityBit(ctx.StateDB, CapabilityName)
	if !found || !capability.HasCapability(ctx.StateDB, ctx.From, bit) {
		return ErrNoGatewayCapability
	}
	return nil
}

func (h *gatewayHandler) handleRegister(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	// 1. Verify agent is registered and has GatewayRelay capability.
	if err := requireGatewayCapability(ctx); err != nil {
		return err
	}

	// 2. Check not already active.
	if ReadActive(ctx.StateDB, ctx.From) {
		return ErrGatewayAlreadyActive
	}

	// 3. Parse payload.
	var p RegisterGatewayPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	// 4. Validate fields.
	if p.Endpoint == "" {
		return ErrInvalidEndpoint
	}
	if len(p.Endpoint) > MaxEndpointLength {
		return ErrInvalidEndpoint
	}
	if len(p.SupportedKinds) == 0 {
		return ErrNoSupportedKinds
	}
	if len(p.SupportedKinds) > MaxSupportedKinds {
		return ErrNoSupportedKinds
	}
	for _, k := range p.SupportedKinds {
		if len(k) == 0 || len(k) > MaxKindLength {
			return ErrNoSupportedKinds
		}
	}
	if p.MaxRelayGas == 0 {
		return ErrMaxRelayGasZero
	}
	if !validFeePolicies[p.FeePolicy] {
		return ErrInvalidFeePolicy
	}
	feeAmount := big.NewInt(0)
	if p.FeeAmount != "" {
		var ok bool
		feeAmount, ok = new(big.Int).SetString(p.FeeAmount, 10)
		if !ok {
			return ErrInvalidFeeAmount
		}
	}

	// 5. Write gateway config.
	WriteEndpoint(ctx.StateDB, ctx.From, p.Endpoint)
	WriteSupportedKinds(ctx.StateDB, ctx.From, p.SupportedKinds)
	WriteMaxRelayGas(ctx.StateDB, ctx.From, p.MaxRelayGas)
	WriteFeePolicy(ctx.StateDB, ctx.From, p.FeePolicy)
	WriteFeeAmount(ctx.StateDB, ctx.From, feeAmount)
	WriteActive(ctx.StateDB, ctx.From, true)
	WriteRegisteredAt(ctx.StateDB, ctx.From, ctx.BlockNumber.Uint64())
	IncrementGatewayCount(ctx.StateDB)

	return nil
}

func (h *gatewayHandler) handleUpdate(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	// 1. Verify ownership: caller must be the gateway agent.
	if !ReadActive(ctx.StateDB, ctx.From) {
		return ErrGatewayNotFound
	}

	// 2. Parse payload.
	var p UpdateGatewayPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}

	// 3. Apply updates selectively.
	if p.Endpoint != "" {
		if len(p.Endpoint) > MaxEndpointLength {
			return ErrInvalidEndpoint
		}
		WriteEndpoint(ctx.StateDB, ctx.From, p.Endpoint)
	}
	if len(p.SupportedKinds) > 0 {
		if len(p.SupportedKinds) > MaxSupportedKinds {
			return ErrNoSupportedKinds
		}
		for _, k := range p.SupportedKinds {
			if len(k) == 0 || len(k) > MaxKindLength {
				return ErrNoSupportedKinds
			}
		}
		WriteSupportedKinds(ctx.StateDB, ctx.From, p.SupportedKinds)
	}
	if p.MaxRelayGas != 0 {
		WriteMaxRelayGas(ctx.StateDB, ctx.From, p.MaxRelayGas)
	}
	if p.FeePolicy != "" {
		if !validFeePolicies[p.FeePolicy] {
			return ErrInvalidFeePolicy
		}
		WriteFeePolicy(ctx.StateDB, ctx.From, p.FeePolicy)
	}
	if p.FeeAmount != "" {
		feeAmount, ok := new(big.Int).SetString(p.FeeAmount, 10)
		if !ok {
			return ErrInvalidFeeAmount
		}
		WriteFeeAmount(ctx.StateDB, ctx.From, feeAmount)
	}

	return nil
}

func (h *gatewayHandler) handleDeregister(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	// 1. Verify ownership: caller must be the gateway agent.
	if !ReadActive(ctx.StateDB, ctx.From) {
		return ErrGatewayNotFound
	}

	// 2. Mark inactive.
	WriteActive(ctx.StateDB, ctx.From, false)

	return nil
}
