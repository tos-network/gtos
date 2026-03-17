package policywallet

import (
	"encoding/json"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/sysaction"
)

func init() {
	sysaction.DefaultRegistry.Register(&policyWalletHandler{})
}

type policyWalletHandler struct{}

func (h *policyWalletHandler) CanHandle(kind sysaction.ActionKind) bool {
	switch kind {
	case sysaction.ActionPolicySetSpendCaps,
		sysaction.ActionPolicySetAllowlist,
		sysaction.ActionPolicySetTerminalPolicy,
		sysaction.ActionPolicyAuthorizeDelegate,
		sysaction.ActionPolicyRevokeDelegate,
		sysaction.ActionPolicySetGuardian,
		sysaction.ActionPolicyInitiateRecovery,
		sysaction.ActionPolicyCancelRecovery,
		sysaction.ActionPolicyCompleteRecovery,
		sysaction.ActionPolicySuspend,
		sysaction.ActionPolicyUnsuspend:
		return true
	}
	return false
}

func (h *policyWalletHandler) Handle(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	switch sa.Action {
	case sysaction.ActionPolicySetSpendCaps:
		return h.handleSetSpendCaps(ctx, sa)
	case sysaction.ActionPolicySetAllowlist:
		return h.handleSetAllowlist(ctx, sa)
	case sysaction.ActionPolicySetTerminalPolicy:
		return h.handleSetTerminalPolicy(ctx, sa)
	case sysaction.ActionPolicyAuthorizeDelegate:
		return h.handleAuthorizeDelegate(ctx, sa)
	case sysaction.ActionPolicyRevokeDelegate:
		return h.handleRevokeDelegate(ctx, sa)
	case sysaction.ActionPolicySetGuardian:
		return h.handleSetGuardian(ctx, sa)
	case sysaction.ActionPolicyInitiateRecovery:
		return h.handleInitiateRecovery(ctx, sa)
	case sysaction.ActionPolicyCancelRecovery:
		return h.handleCancelRecovery(ctx, sa)
	case sysaction.ActionPolicyCompleteRecovery:
		return h.handleCompleteRecovery(ctx, sa)
	case sysaction.ActionPolicySuspend:
		return h.handleSuspend(ctx, sa)
	case sysaction.ActionPolicyUnsuspend:
		return h.handleUnsuspend(ctx, sa)
	}
	return nil
}

// requireOwner verifies that ctx.From is the wallet owner.
// If the wallet has no owner set, the first caller becomes the owner.
func requireOwner(ctx *sysaction.Context, wallet common.Address) error {
	if ctx.From == (common.Address{}) {
		return ErrZeroAddress
	}
	owner := ReadOwner(ctx.StateDB, wallet)
	if owner == (common.Address{}) {
		// First interaction: caller becomes owner.
		WriteOwner(ctx.StateDB, wallet, ctx.From)
		return nil
	}
	if owner != ctx.From {
		return ErrNotOwner
	}
	return nil
}

// requireNotSuspended returns an error if the wallet is suspended.
func requireNotSuspended(db stateDB, wallet common.Address) error {
	if ReadSuspended(db, wallet) {
		return ErrWalletSuspended
	}
	return nil
}

func (h *policyWalletHandler) handleSetSpendCaps(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p SetSpendCapsPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if err := requireOwner(ctx, p.Account); err != nil {
		return err
	}
	if err := requireNotSuspended(ctx.StateDB, p.Account); err != nil {
		return err
	}
	daily, ok := new(big.Int).SetString(p.DailyLimit, 10)
	if !ok {
		return ErrInvalidAmount
	}
	if daily.Sign() < 0 {
		return ErrNegativeAmount
	}
	single, ok := new(big.Int).SetString(p.SingleTxLimit, 10)
	if !ok {
		return ErrInvalidAmount
	}
	if single.Sign() < 0 {
		return ErrNegativeAmount
	}
	WriteDailyLimit(ctx.StateDB, p.Account, daily)
	WriteSingleTxLimit(ctx.StateDB, p.Account, single)
	return nil
}

func (h *policyWalletHandler) handleSetAllowlist(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p SetAllowlistPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if err := requireOwner(ctx, p.Account); err != nil {
		return err
	}
	if err := requireNotSuspended(ctx.StateDB, p.Account); err != nil {
		return err
	}
	if p.Target == (common.Address{}) {
		return ErrZeroAddress
	}
	WriteAllowlisted(ctx.StateDB, p.Account, p.Target, p.Allowed)
	return nil
}

func (h *policyWalletHandler) handleSetTerminalPolicy(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p SetTerminalPolicyPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if err := requireOwner(ctx, p.Account); err != nil {
		return err
	}
	if err := requireNotSuspended(ctx.StateDB, p.Account); err != nil {
		return err
	}
	if p.TerminalClass > TerminalAPI {
		return ErrInvalidTerminalClass
	}
	maxSingle, ok := new(big.Int).SetString(p.MaxSingle, 10)
	if !ok {
		return ErrInvalidAmount
	}
	if maxSingle.Sign() < 0 {
		return ErrNegativeAmount
	}
	maxDaily, ok := new(big.Int).SetString(p.MaxDaily, 10)
	if !ok {
		return ErrInvalidAmount
	}
	if maxDaily.Sign() < 0 {
		return ErrNegativeAmount
	}
	WriteTerminalPolicy(ctx.StateDB, p.Account, p.TerminalClass, TerminalPolicy{
		MaxSingleValue: maxSingle,
		MaxDailyValue:  maxDaily,
		MinTrustTier:   p.MinTrustTier,
		Enabled:        true,
	})
	return nil
}

func (h *policyWalletHandler) handleAuthorizeDelegate(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p AuthorizeDelegatePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if err := requireOwner(ctx, p.Account); err != nil {
		return err
	}
	if err := requireNotSuspended(ctx.StateDB, p.Account); err != nil {
		return err
	}
	if p.Delegate == (common.Address{}) {
		return ErrZeroAddress
	}
	allowance, ok := new(big.Int).SetString(p.Allowance, 10)
	if !ok {
		return ErrInvalidAmount
	}
	if allowance.Sign() < 0 {
		return ErrNegativeAmount
	}
	if allowance.Sign() == 0 {
		return ErrZeroAllowance
	}
	WriteDelegateAuth(ctx.StateDB, p.Account, DelegateAuth{
		Delegate:  p.Delegate,
		Allowance: allowance,
		Expiry:    p.Expiry,
		Active:    true,
	})
	return nil
}

func (h *policyWalletHandler) handleRevokeDelegate(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p RevokeDelegatePayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if err := requireOwner(ctx, p.Account); err != nil {
		return err
	}
	if p.Delegate == (common.Address{}) {
		return ErrZeroAddress
	}
	WriteDelegateAuth(ctx.StateDB, p.Account, DelegateAuth{
		Delegate:  p.Delegate,
		Allowance: big.NewInt(0),
		Expiry:    0,
		Active:    false,
	})
	return nil
}

func (h *policyWalletHandler) handleSetGuardian(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p SetGuardianPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	if err := requireOwner(ctx, p.Account); err != nil {
		return err
	}
	if err := requireNotSuspended(ctx.StateDB, p.Account); err != nil {
		return err
	}
	if p.Guardian == (common.Address{}) {
		return ErrZeroAddress
	}
	WriteGuardian(ctx.StateDB, p.Account, p.Guardian)
	return nil
}

func (h *policyWalletHandler) handleInitiateRecovery(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p InitiateRecoveryPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	// Only the guardian can initiate recovery.
	guardian := ReadGuardian(ctx.StateDB, p.Account)
	if guardian == (common.Address{}) {
		return ErrNoGuardianSet
	}
	if ctx.From != guardian {
		return ErrNotGuardian
	}
	// Check no recovery already in progress.
	rs := ReadRecoveryState(ctx.StateDB, p.Account)
	if rs.Active {
		return ErrRecoveryAlreadyActive
	}
	if p.NewOwner == (common.Address{}) {
		return ErrZeroAddress
	}
	WriteRecoveryState(ctx.StateDB, p.Account, RecoveryState{
		Active:      true,
		Guardian:    guardian,
		NewOwner:    p.NewOwner,
		InitiatedAt: ctx.BlockNumber.Uint64(),
		Timelock:    RecoveryTimelockBlocks,
	})
	return nil
}

func (h *policyWalletHandler) handleCancelRecovery(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p CancelRecoveryPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	// Owner can cancel a pending recovery.
	if err := requireOwner(ctx, p.Account); err != nil {
		return err
	}
	rs := ReadRecoveryState(ctx.StateDB, p.Account)
	if !rs.Active {
		return ErrRecoveryNotActive
	}
	WriteRecoveryState(ctx.StateDB, p.Account, RecoveryState{})
	return nil
}

func (h *policyWalletHandler) handleCompleteRecovery(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p CompleteRecoveryPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	rs := ReadRecoveryState(ctx.StateDB, p.Account)
	if !rs.Active {
		return ErrRecoveryNotActive
	}
	// Only the guardian that initiated recovery can complete it.
	if ctx.From != rs.Guardian {
		return ErrNotGuardian
	}
	// Verify timelock has elapsed. Guard against uint64 overflow.
	deadline := rs.InitiatedAt + rs.Timelock
	if deadline < rs.InitiatedAt {
		// Overflow: timelock can never be met.
		return ErrTimelockOverflow
	}
	if ctx.BlockNumber.Uint64() < deadline {
		return ErrRecoveryTimelockNotMet
	}
	// Transfer ownership.
	WriteOwner(ctx.StateDB, p.Account, rs.NewOwner)
	// Clear recovery state.
	WriteRecoveryState(ctx.StateDB, p.Account, RecoveryState{})
	return nil
}

func (h *policyWalletHandler) handleSuspend(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p SuspendPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	// Either owner or guardian can suspend.
	owner := ReadOwner(ctx.StateDB, p.Account)
	if owner == (common.Address{}) {
		return ErrOwnerNotSet
	}
	guardian := ReadGuardian(ctx.StateDB, p.Account)
	if ctx.From != owner && ctx.From != guardian {
		return ErrNotOwner
	}
	WriteSuspended(ctx.StateDB, p.Account, true)
	return nil
}

func (h *policyWalletHandler) handleUnsuspend(ctx *sysaction.Context, sa *sysaction.SysAction) error {
	var p SuspendPayload
	if err := json.Unmarshal(sa.Payload, &p); err != nil {
		return err
	}
	// Only the owner can unsuspend.
	if err := requireOwner(ctx, p.Account); err != nil {
		return err
	}
	if !ReadSuspended(ctx.StateDB, p.Account) {
		return ErrWalletNotSuspended
	}
	WriteSuspended(ctx.StateDB, p.Account, false)
	return nil
}
