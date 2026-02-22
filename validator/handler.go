package validator

import (
	"math/big"

	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&validatorHandler{})
}

// validatorHandler implements sysaction.Handler for DPoS validator lifecycle actions.
type validatorHandler struct{}

func (h *validatorHandler) CanHandle(kind sysaction.ActionKind) bool {
	switch kind {
	case sysaction.ActionValidatorRegister, sysaction.ActionValidatorWithdraw:
		return true
	}
	return false
}

func (h *validatorHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionValidatorRegister:
		return h.handleRegister(ctx, sa)
	case sysaction.ActionValidatorWithdraw:
		return h.handleWithdraw(ctx, sa)
	}
	return nil
}

func (h *validatorHandler) handleRegister(ctx *sysaction.Context, _ *sysaction.SysAction) error {
	// ── Validation phase (no state writes) ───────────────────────────────────

	// 1. Stake must meet minimum.
	if ctx.Value.Cmp(params.DPoSMinValidatorStake) < 0 {
		return ErrInsufficientStake
	}

	// 2. R2-C5: explicit sender balance check.
	//    For EIP-1559 txs, buyGas() already includes tx.Value in its balance check.
	//    For legacy txs (no gasFeeCap), buyGas() only checks gas*gasPrice — the value
	//    is NOT checked, so SubBalance below could make the balance negative without
	//    this guard.
	if ctx.StateDB.GetBalance(ctx.From).Cmp(ctx.Value) < 0 {
		return ErrInsufficientBalance
	}

	// 3. Reject duplicate registration.
	//    After VALIDATOR_WITHDRAW selfStake is reset to 0, so re-registration is
	//    permitted (documented known behaviour, intentional for MVP).
	if ReadSelfStake(ctx.StateDB, ctx.From).Sign() != 0 {
		return ErrAlreadyRegistered
	}

	// 4. R2-C2: detect first-ever registration BEFORE any writes.
	//    Uses the permanent "registered" flag (not selfStake) so that a re-registration
	//    after withdrawal is correctly identified as NOT new (selfStake=0 after withdraw,
	//    so using selfStake alone would incorrectly classify re-registration as new).
	isNewRegistration := !readRegisteredFlag(ctx.StateDB, ctx.From)

	// ── Mutation phase ───────────────────────────────────────────────────────

	// 5. Lock stake: sender -> validator registry account.
	ctx.StateDB.SubBalance(ctx.From, ctx.Value)
	ctx.StateDB.AddBalance(params.ValidatorRegistryAddress, ctx.Value)

	// 6. Write per-validator fields.
	writeSelfStake(ctx.StateDB, ctx.From, ctx.Value)
	WriteValidatorStatus(ctx.StateDB, ctx.From, Active)

	// 7. Append address to list only on first-ever registration.
	//    Re-registration after withdraw: address already in list (status was inactive,
	//    now active again). Do NOT append → no duplicates in the list.
	if isNewRegistration {
		writeRegisteredFlag(ctx.StateDB, ctx.From)
		appendValidatorToList(ctx.StateDB, ctx.From)
	}

	return nil
}

func (h *validatorHandler) handleWithdraw(ctx *sysaction.Context, _ *sysaction.SysAction) error {
	// ── Validation phase ─────────────────────────────────────────────────────

	if ReadValidatorStatus(ctx.StateDB, ctx.From) != Active {
		return ErrNotActive
	}
	selfStake := ReadSelfStake(ctx.StateDB, ctx.From)

	// Defensive: validator registry balance should always >= selfStake if invariant holds.
	// Guards against future bugs that could corrupt the accounting.
	if ctx.StateDB.GetBalance(params.ValidatorRegistryAddress).Cmp(selfStake) < 0 {
		return ErrValidatorRegistryBalanceBroken
	}

	// ── Mutation phase ───────────────────────────────────────────────────────

	// Refund stake: validator registry account -> sender.
	ctx.StateDB.SubBalance(params.ValidatorRegistryAddress, selfStake)
	ctx.StateDB.AddBalance(ctx.From, selfStake)

	// Clear fields. Address remains in list; status=Inactive is the tombstone.
	writeSelfStake(ctx.StateDB, ctx.From, new(big.Int))
	WriteValidatorStatus(ctx.StateDB, ctx.From, Inactive)

	// MVP: no lockup period. Funds returned immediately.
	return nil
}
