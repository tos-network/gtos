// Package policywallet implements on-chain policy wallet primitives for the
// GTOS 2046 architecture. It provides spend caps, allowlists, terminal-class
// restrictions, guardian approval, recovery, and delegated agent authority.
package policywallet

import (
	"errors"
	"math/big"

	"github.com/tos-network/gtos/common"
)

// Terminal classes identify the originating device or channel.
const (
	TerminalApp   uint8 = 0
	TerminalCard  uint8 = 1
	TerminalPOS   uint8 = 2
	TerminalVoice uint8 = 3
	TerminalKiosk uint8 = 4
	TerminalRobot uint8 = 5
	TerminalAPI   uint8 = 6
)

// Trust tiers.
const (
	TrustUntrusted uint8 = 0
	TrustLow       uint8 = 1
	TrustMedium    uint8 = 2
	TrustHigh      uint8 = 3
	TrustFull      uint8 = 4
)

// SpendCaps holds per-wallet spend limits.
type SpendCaps struct {
	DailyLimit    *big.Int
	SingleTxLimit *big.Int
}

// TerminalPolicy holds per-terminal-class policy parameters.
type TerminalPolicy struct {
	MaxSingleValue *big.Int
	MaxDailyValue  *big.Int
	MinTrustTier   uint8
	Enabled        bool
}

// DelegateAuth holds authorisation state for a delegate address.
type DelegateAuth struct {
	Delegate  common.Address
	Allowance *big.Int
	Expiry    uint64
	Active    bool
}

// RecoveryState holds the in-progress recovery state for a wallet.
type RecoveryState struct {
	Active      bool
	Guardian    common.Address
	NewOwner    common.Address
	InitiatedAt uint64
	Timelock    uint64
}

// ---------- System action payloads (JSON) ----------

// SetSpendCapsPayload is the payload for ActionPolicySetSpendCaps.
type SetSpendCapsPayload struct {
	Account       common.Address `json:"account"`
	DailyLimit    string         `json:"daily_limit"`
	SingleTxLimit string         `json:"single_tx_limit"`
}

// SetAllowlistPayload is the payload for ActionPolicySetAllowlist.
type SetAllowlistPayload struct {
	Account common.Address `json:"account"`
	Target  common.Address `json:"target"`
	Allowed bool           `json:"allowed"`
}

// SetTerminalPolicyPayload is the payload for ActionPolicySetTerminalPolicy.
type SetTerminalPolicyPayload struct {
	Account       common.Address `json:"account"`
	TerminalClass uint8          `json:"terminal_class"`
	MaxSingle     string         `json:"max_single"`
	MaxDaily      string         `json:"max_daily"`
	MinTrustTier  uint8          `json:"min_trust_tier"`
}

// AuthorizeDelegatePayload is the payload for ActionPolicyAuthorizeDelegate.
type AuthorizeDelegatePayload struct {
	Account   common.Address `json:"account"`
	Delegate  common.Address `json:"delegate"`
	Allowance string         `json:"allowance"`
	Expiry    uint64         `json:"expiry"`
}

// RevokeDelegatePayload is the payload for ActionPolicyRevokeDelegate.
type RevokeDelegatePayload struct {
	Account  common.Address `json:"account"`
	Delegate common.Address `json:"delegate"`
}

// SetGuardianPayload is the payload for ActionPolicySetGuardian.
type SetGuardianPayload struct {
	Account  common.Address `json:"account"`
	Guardian common.Address `json:"guardian"`
}

// InitiateRecoveryPayload is the payload for ActionPolicyInitiateRecovery.
type InitiateRecoveryPayload struct {
	Account  common.Address `json:"account"`
	NewOwner common.Address `json:"new_owner"`
}

// CancelRecoveryPayload is the payload for ActionPolicyCancelRecovery.
type CancelRecoveryPayload struct {
	Account common.Address `json:"account"`
}

// CompleteRecoveryPayload is the payload for ActionPolicyCompleteRecovery.
type CompleteRecoveryPayload struct {
	Account common.Address `json:"account"`
}

// SuspendPayload is the payload for ActionPolicySuspend / ActionPolicyUnsuspend.
type SuspendPayload struct {
	Account common.Address `json:"account"`
}

// Sentinel errors returned by policy wallet handlers.
var (
	ErrNotOwner              = errors.New("policywallet: caller is not wallet owner")
	ErrNotGuardian           = errors.New("policywallet: caller is not guardian")
	ErrWalletSuspended       = errors.New("policywallet: wallet is suspended")
	ErrWalletNotSuspended    = errors.New("policywallet: wallet is not suspended")
	ErrNoGuardianSet         = errors.New("policywallet: no guardian configured")
	ErrRecoveryNotActive     = errors.New("policywallet: no active recovery")
	ErrRecoveryAlreadyActive = errors.New("policywallet: recovery already active")
	ErrRecoveryTimelockNotMet = errors.New("policywallet: recovery timelock not elapsed")
	ErrInvalidAmount         = errors.New("policywallet: invalid amount string")
	ErrInvalidTerminalClass  = errors.New("policywallet: invalid terminal class")
	ErrZeroAddress           = errors.New("policywallet: zero address not allowed")
	ErrOwnerNotSet           = errors.New("policywallet: wallet has no owner")
	ErrNegativeAmount        = errors.New("policywallet: negative amount not allowed")
	ErrTimelockOverflow      = errors.New("policywallet: timelock arithmetic overflow")
	ErrZeroAllowance         = errors.New("policywallet: zero allowance not allowed for delegate")
)

// RecoveryTimelockBlocks is the number of blocks that must pass between
// initiating and completing a recovery (approximately 24 hours at 360ms blocks).
const RecoveryTimelockBlocks uint64 = 240_000
