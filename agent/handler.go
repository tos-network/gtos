package agent

import (
	"encoding/json"
	"math/big"

	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&agentHandler{})
}

// registrarBit is the well-known bit index for the "Registrar" capability.
// Agents holding bit 0 can suspend/unsuspend other agents.
const registrarBit uint8 = 0

type agentHandler struct{}

func (h *agentHandler) Actions() []sysaction.ActionKind {
	return []sysaction.ActionKind{
		sysaction.ActionAgentRegister,
		sysaction.ActionAgentUpdateProfile,
		sysaction.ActionAgentIncreaseStake,
		sysaction.ActionAgentDecreaseStake,
		sysaction.ActionAgentSuspend,
		sysaction.ActionAgentUnsuspend,
	}
}

func (h *agentHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionAgentRegister:
		return h.handleRegister(ctx, sa)
	case sysaction.ActionAgentUpdateProfile:
		return h.handleUpdateProfile(ctx, sa)
	case sysaction.ActionAgentIncreaseStake:
		return h.handleIncreaseStake(ctx, sa)
	case sysaction.ActionAgentDecreaseStake:
		return h.handleDecreaseStake(ctx, sa)
	case sysaction.ActionAgentSuspend:
		return h.handleSuspend(ctx, sa)
	case sysaction.ActionAgentUnsuspend:
		return h.handleUnsuspend(ctx, sa)
	}
	return nil
}

func (h *agentHandler) handleRegister(ctx *sysaction.Context, _ *sysaction.SysAction) error {
	// 1. Stake must meet minimum.
	if ctx.Value.Cmp(params.AgentMinStake) < 0 {
		return ErrAgentInsufficientStake
	}

	// 2. Explicit balance check (legacy txs may not check tx.Value in buyGas).
	if ctx.StateDB.GetBalance(ctx.From).Cmp(ctx.Value) < 0 {
		return ErrAgentInsufficientBalance
	}

	// 3. Reject duplicate active registration.
	if ReadStake(ctx.StateDB, ctx.From).Sign() != 0 {
		return ErrAgentAlreadyRegistered
	}

	// 4. Detect first-ever registration BEFORE any writes.
	isNew := !readRegisteredFlag(ctx.StateDB, ctx.From)

	// 5. Lock stake: sender -> agent registry account.
	ctx.StateDB.SubBalance(ctx.From, ctx.Value)
	ctx.StateDB.AddBalance(params.AgentRegistryAddress, ctx.Value)

	// 6. Write per-agent fields.
	WriteStake(ctx.StateDB, ctx.From, ctx.Value)
	WriteStatus(ctx.StateDB, ctx.From, AgentActive)
	WriteSuspended(ctx.StateDB, ctx.From, false)

	// 7. Append to list only on first-ever registration.
	if isNew {
		writeRegisteredFlag(ctx.StateDB, ctx.From)
		appendAgentToList(ctx.StateDB, ctx.From)
	}

	return nil
}

type updateProfilePayload struct {
	URI string `json:"uri"`
}

func (h *agentHandler) handleUpdateProfile(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if !IsRegistered(ctx.StateDB, ctx.From) {
		return ErrAgentNotRegistered
	}
	var p updateProfilePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if len(p.URI) > MaxURILength {
		return ErrURITooLong
	}
	WriteMetadata(ctx.StateDB, ctx.From, p.URI)
	return nil
}

func (h *agentHandler) handleIncreaseStake(ctx *sysaction.Context, _ *sysaction.SysAction) error {
	if !IsRegistered(ctx.StateDB, ctx.From) {
		return ErrAgentNotRegistered
	}
	if ReadStatus(ctx.StateDB, ctx.From) != AgentActive {
		return ErrAgentNotActive
	}
	if ctx.Value.Sign() == 0 {
		return ErrAgentInsufficientStake
	}
	if ctx.StateDB.GetBalance(ctx.From).Cmp(ctx.Value) < 0 {
		return ErrAgentInsufficientBalance
	}

	ctx.StateDB.SubBalance(ctx.From, ctx.Value)
	ctx.StateDB.AddBalance(params.AgentRegistryAddress, ctx.Value)

	current := ReadStake(ctx.StateDB, ctx.From)
	WriteStake(ctx.StateDB, ctx.From, new(big.Int).Add(current, ctx.Value))
	return nil
}

type decreaseStakePayload struct {
	Amount string `json:"amount"` // decimal string (wei)
}

func (h *agentHandler) handleDecreaseStake(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if !IsRegistered(ctx.StateDB, ctx.From) {
		return ErrAgentNotRegistered
	}
	if ReadStatus(ctx.StateDB, ctx.From) != AgentActive {
		return ErrAgentNotActive
	}

	var p decreaseStakePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	amount, ok := new(big.Int).SetString(p.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return ErrAgentInsufficientStake
	}

	current := ReadStake(ctx.StateDB, ctx.From)
	remaining := new(big.Int).Sub(current, amount)
	if remaining.Sign() < 0 {
		return ErrDecreaseExceedsStake
	}
	// After partial decrease, remaining stake must still meet minimum (or be zero = full exit).
	if remaining.Sign() > 0 && remaining.Cmp(params.AgentMinStake) < 0 {
		return ErrAgentInsufficientStake
	}

	// Registry balance guard against accounting bugs.
	if ctx.StateDB.GetBalance(params.AgentRegistryAddress).Cmp(amount) < 0 {
		return ErrRegistryBalanceBroken
	}

	ctx.StateDB.SubBalance(params.AgentRegistryAddress, amount)
	ctx.StateDB.AddBalance(ctx.From, amount)
	WriteStake(ctx.StateDB, ctx.From, remaining)
	if remaining.Sign() == 0 {
		WriteStatus(ctx.StateDB, ctx.From, AgentInactive)
	}
	return nil
}

type targetPayload struct {
	Target string `json:"target"` // hex address of agent to act on
}

func (h *agentHandler) handleSuspend(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if !capability.HasCapability(ctx.StateDB, ctx.From, registrarBit) {
		return ErrCapabilityRequired
	}
	var p targetPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	target := common.HexToAddress(p.Target)
	if target == (common.Address{}) {
		return ErrInvalidTarget
	}
	if !IsRegistered(ctx.StateDB, target) {
		return ErrAgentNotRegistered
	}
	WriteSuspended(ctx.StateDB, target, true)
	return nil
}

func (h *agentHandler) handleUnsuspend(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	if !capability.HasCapability(ctx.StateDB, ctx.From, registrarBit) {
		return ErrCapabilityRequired
	}
	var p targetPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	target := common.HexToAddress(p.Target)
	if target == (common.Address{}) {
		return ErrInvalidTarget
	}
	if !IsRegistered(ctx.StateDB, target) {
		return ErrAgentNotRegistered
	}
	WriteSuspended(ctx.StateDB, target, false)
	return nil
}
