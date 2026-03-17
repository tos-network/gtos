package policywallet

import (
	"github.com/tos-network/gtos/boundary"
	"github.com/tos-network/gtos/common"
)

// SpendCapsResult is the JSON-friendly result for GetSpendCaps.
type SpendCapsResult struct {
	DailyLimit    string `json:"daily_limit"`
	SingleTxLimit string `json:"single_tx_limit"`
	DailySpent    string `json:"daily_spent"`
	SpendDay      uint64 `json:"spend_day"`
}

// TerminalPolicyResult is the JSON-friendly result for GetTerminalPolicy.
type TerminalPolicyResult struct {
	MaxSingleValue string `json:"max_single_value"`
	MaxDailyValue  string `json:"max_daily_value"`
	MinTrustTier   uint8  `json:"min_trust_tier"`
	Enabled        bool   `json:"enabled"`
}

// DelegateAuthResult is the JSON-friendly result for GetDelegateAuth.
type DelegateAuthResult struct {
	Delegate  common.Address `json:"delegate"`
	Allowance string         `json:"allowance"`
	Expiry    uint64         `json:"expiry"`
	Active    bool           `json:"active"`
}

// RecoveryStateResult is the JSON-friendly result for GetRecoveryState.
type RecoveryStateResult struct {
	Active      bool           `json:"active"`
	Guardian    common.Address `json:"guardian"`
	NewOwner    common.Address `json:"new_owner"`
	InitiatedAt uint64         `json:"initiated_at"`
	Timelock    uint64         `json:"timelock"`
}

// PublicPolicyWalletAPI provides RPC methods for querying policy wallet state.
type PublicPolicyWalletAPI struct {
	stateReader func() stateDB
}

// NewPublicPolicyWalletAPI creates a new policy wallet API instance.
func NewPublicPolicyWalletAPI(stateReader func() stateDB) *PublicPolicyWalletAPI {
	return &PublicPolicyWalletAPI{stateReader: stateReader}
}

// GetSpendCaps returns the spend caps for an account.
func (api *PublicPolicyWalletAPI) GetSpendCaps(account common.Address) (*SpendCapsResult, error) {
	db := api.stateReader()
	return &SpendCapsResult{
		DailyLimit:    ReadDailyLimit(db, account).String(),
		SingleTxLimit: ReadSingleTxLimit(db, account).String(),
		DailySpent:    ReadDailySpent(db, account).String(),
		SpendDay:      ReadSpendDay(db, account),
	}, nil
}

// GetTerminalPolicy returns terminal policy for an account and terminal class.
func (api *PublicPolicyWalletAPI) GetTerminalPolicy(account common.Address, terminalClass uint8) (*TerminalPolicyResult, error) {
	db := api.stateReader()
	tp := ReadTerminalPolicy(db, account, terminalClass)
	return &TerminalPolicyResult{
		MaxSingleValue: tp.MaxSingleValue.String(),
		MaxDailyValue:  tp.MaxDailyValue.String(),
		MinTrustTier:   tp.MinTrustTier,
		Enabled:        tp.Enabled,
	}, nil
}

// GetDelegateAuth returns delegate authorization for an account and delegate.
func (api *PublicPolicyWalletAPI) GetDelegateAuth(account common.Address, delegate common.Address) (*DelegateAuthResult, error) {
	db := api.stateReader()
	da := ReadDelegateAuth(db, account, delegate)
	return &DelegateAuthResult{
		Delegate:  da.Delegate,
		Allowance: da.Allowance.String(),
		Expiry:    da.Expiry,
		Active:    da.Active,
	}, nil
}

// GetRecoveryState returns the current recovery state for an account.
func (api *PublicPolicyWalletAPI) GetRecoveryState(account common.Address) (*RecoveryStateResult, error) {
	db := api.stateReader()
	rs := ReadRecoveryState(db, account)
	return &RecoveryStateResult{
		Active:      rs.Active,
		Guardian:    rs.Guardian,
		NewOwner:    rs.NewOwner,
		InitiatedAt: rs.InitiatedAt,
		Timelock:    rs.Timelock,
	}, nil
}

// IsSuspended returns whether an account is suspended.
func (api *PublicPolicyWalletAPI) IsSuspended(account common.Address) (bool, error) {
	db := api.stateReader()
	return ReadSuspended(db, account), nil
}

// GetOwner returns the policy wallet owner.
func (api *PublicPolicyWalletAPI) GetOwner(account common.Address) (common.Address, error) {
	db := api.stateReader()
	return ReadOwner(db, account), nil
}

// GetGuardian returns the policy wallet guardian.
func (api *PublicPolicyWalletAPI) GetGuardian(account common.Address) (common.Address, error) {
	db := api.stateReader()
	return ReadGuardian(db, account), nil
}

// GetBoundaryVersion returns the boundary schema version used by this node.
func (api *PublicPolicyWalletAPI) GetBoundaryVersion() string {
	return boundary.SchemaVersion
}

// GetSchemaVersion returns the boundary schema version and negotiation info.
// Clients can pass their own version to check compatibility.
func (api *PublicPolicyWalletAPI) GetSchemaVersion() map[string]interface{} {
	return map[string]interface{}{
		"schema_version": boundary.SchemaVersion,
		"namespace":      "policyWallet",
	}
}
