package policywallet

import (
	"errors"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
)

// Privacy-tier terminal policy constants.
// Privacy actions require stricter terminal rules.
const (
	PrivacyTerminalMaxTrustTier = TrustMedium // privacy actions need at least medium trust
)

// Privacy action types.
const (
	PrivacyActionShield       = "shield"
	PrivacyActionUnshield     = "unshield"
	PrivacyActionPrivTransfer = "priv_transfer"
)

// Sentinel errors for privacy terminal access.
var (
	ErrPrivTerminalTrustTooLow  = errors.New("policywallet: trust tier too low for privacy action")
	ErrPrivTerminalShieldDenied = errors.New("policywallet: shield not allowed from this terminal")
	ErrPrivTerminalUnshieldDenied = errors.New("policywallet: unshield not allowed from this terminal")
	ErrPrivTerminalTransferDenied = errors.New("policywallet: private transfer not allowed from this terminal")
	ErrPrivTerminalValueExceeded  = errors.New("policywallet: value exceeds privacy terminal limit")
	ErrPrivUnknownAction          = errors.New("policywallet: unknown privacy action type")
)

// PrivacyTerminalPolicy defines per-terminal-class restrictions for
// privacy-tier actions.
type PrivacyTerminalPolicy struct {
	TerminalClass   uint8    `json:"terminal_class"`
	MaxPrivateValue *big.Int `json:"max_private_value"` // max value for private transfers from this terminal
	AllowShield     bool     `json:"allow_shield"`      // whether shield (public->private) is allowed
	AllowUnshield   bool     `json:"allow_unshield"`    // whether unshield (private->public) is allowed
	AllowPrivTransfer bool   `json:"allow_priv_transfer"` // whether private-to-private transfer is allowed
	MinTrustTier    uint8    `json:"min_trust_tier"`      // override for privacy actions
}

// DefaultPrivacyTerminalPolicies returns sane defaults for all terminal classes.
func DefaultPrivacyTerminalPolicies() []PrivacyTerminalPolicy {
	oneThousandTOS := new(big.Int).Mul(big.NewInt(1_000), big.NewInt(1e18))
	oneHundredTOS := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))

	return []PrivacyTerminalPolicy{
		{TerminalClass: TerminalApp, MaxPrivateValue: oneThousandTOS, AllowShield: true, AllowUnshield: true, AllowPrivTransfer: true, MinTrustTier: TrustMedium},
		{TerminalClass: TerminalCard, MaxPrivateValue: oneHundredTOS, AllowShield: true, AllowUnshield: true, AllowPrivTransfer: false, MinTrustTier: TrustHigh},
		{TerminalClass: TerminalPOS, MaxPrivateValue: oneHundredTOS, AllowShield: false, AllowUnshield: true, AllowPrivTransfer: false, MinTrustTier: TrustHigh},
		{TerminalClass: TerminalVoice, MaxPrivateValue: big.NewInt(0), AllowShield: false, AllowUnshield: false, AllowPrivTransfer: false, MinTrustTier: TrustFull},
		{TerminalClass: TerminalKiosk, MaxPrivateValue: oneHundredTOS, AllowShield: false, AllowUnshield: true, AllowPrivTransfer: false, MinTrustTier: TrustHigh},
		{TerminalClass: TerminalRobot, MaxPrivateValue: oneThousandTOS, AllowShield: true, AllowUnshield: true, AllowPrivTransfer: true, MinTrustTier: TrustMedium},
		{TerminalClass: TerminalAPI, MaxPrivateValue: oneThousandTOS, AllowShield: true, AllowUnshield: true, AllowPrivTransfer: true, MinTrustTier: TrustMedium},
	}
}

// ---------- State storage ----------

// privTerminalFieldSlot returns a storage slot for a privacy terminal policy field.
func privTerminalFieldSlot(wallet common.Address, class uint8, field string) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len("privTerminal")+1+1+len(field))
	key = append(key, wallet.Bytes()...)
	key = append(key, 0x00)
	key = append(key, []byte("privTerminal")...)
	key = append(key, 0x00)
	key = append(key, class)
	key = append(key, []byte(field)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// WritePrivacyTerminalPolicy persists a privacy terminal policy to state.
func WritePrivacyTerminalPolicy(state stateDB, account common.Address, policy PrivacyTerminalPolicy) {
	// Store MaxPrivateValue.
	maxVal := policy.MaxPrivateValue
	if maxVal == nil {
		maxVal = big.NewInt(0)
	}
	state.SetState(registry, privTerminalFieldSlot(account, policy.TerminalClass, "maxVal"), common.BigToHash(maxVal))

	// Pack boolean flags and MinTrustTier into a single slot.
	var flags common.Hash
	if policy.AllowShield {
		flags[28] = 1
	}
	if policy.AllowUnshield {
		flags[29] = 1
	}
	if policy.AllowPrivTransfer {
		flags[30] = 1
	}
	flags[31] = policy.MinTrustTier
	state.SetState(registry, privTerminalFieldSlot(account, policy.TerminalClass, "flags"), flags)
}

// ReadPrivacyTerminalPolicy reads a privacy terminal policy from state.
func ReadPrivacyTerminalPolicy(state stateDB, account common.Address, terminalClass uint8) PrivacyTerminalPolicy {
	maxVal := state.GetState(registry, privTerminalFieldSlot(account, terminalClass, "maxVal"))
	flags := state.GetState(registry, privTerminalFieldSlot(account, terminalClass, "flags"))

	return PrivacyTerminalPolicy{
		TerminalClass:     terminalClass,
		MaxPrivateValue:   maxVal.Big(),
		AllowShield:       flags[28] != 0,
		AllowUnshield:     flags[29] != 0,
		AllowPrivTransfer: flags[30] != 0,
		MinTrustTier:      flags[31],
	}
}

// ValidatePrivacyTerminalAccess checks if a privacy action is allowed from
// this terminal class at the given trust tier.
func ValidatePrivacyTerminalAccess(state stateDB, account common.Address, terminalClass uint8, trustTier uint8, actionType string, value *big.Int) error {
	policy := ReadPrivacyTerminalPolicy(state, account, terminalClass)

	// Check trust tier against both the privacy-tier minimum and the policy override.
	minTrust := policy.MinTrustTier
	if minTrust < PrivacyTerminalMaxTrustTier {
		minTrust = PrivacyTerminalMaxTrustTier
	}
	if trustTier < minTrust {
		return ErrPrivTerminalTrustTooLow
	}

	// Check action permission.
	switch actionType {
	case PrivacyActionShield:
		if !policy.AllowShield {
			return ErrPrivTerminalShieldDenied
		}
	case PrivacyActionUnshield:
		if !policy.AllowUnshield {
			return ErrPrivTerminalUnshieldDenied
		}
	case PrivacyActionPrivTransfer:
		if !policy.AllowPrivTransfer {
			return ErrPrivTerminalTransferDenied
		}
	default:
		return ErrPrivUnknownAction
	}

	// Check value against MaxPrivateValue (0 means no private actions allowed from
	// this terminal).
	if policy.MaxPrivateValue != nil && policy.MaxPrivateValue.Sign() > 0 && value != nil {
		if value.Cmp(policy.MaxPrivateValue) > 0 {
			return ErrPrivTerminalValueExceeded
		}
	}

	return nil
}
