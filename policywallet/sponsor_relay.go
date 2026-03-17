package policywallet

import (
	"errors"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
)

// Sentinel errors for sponsor relay validation.
var (
	ErrSponsorNotAllowlisted   = errors.New("policywallet: sponsor not on account allowlist")
	ErrSponsorTerminalDisabled = errors.New("policywallet: terminal class not enabled for account")
	ErrSponsorTrustTooLow      = errors.New("policywallet: trust tier below terminal minimum")
	ErrSponsorValueExceeded    = errors.New("policywallet: value exceeds terminal single-tx limit")
	ErrSponsorWalletSuspended  = errors.New("policywallet: account wallet is suspended")
)

// ValidateSponsoredExecution checks that a sponsored tx complies with policy
// wallet rules. It verifies:
//   - The wallet is not suspended.
//   - The sponsor is on the account's allowlist.
//   - The terminal class is enabled and meets trust tier requirements.
//   - The value does not exceed the terminal's single-tx limit.
func ValidateSponsoredExecution(state stateDB, account common.Address, sponsor common.Address, value *big.Int, terminalClass uint8, trustTier uint8) error {
	// Check wallet suspension.
	if ReadSuspended(state, account) {
		return ErrSponsorWalletSuspended
	}

	// Check sponsor is on the account's allowlist.
	if !ReadAllowlisted(state, account, sponsor) {
		return ErrSponsorNotAllowlisted
	}

	// Check terminal policy.
	tp := ReadTerminalPolicy(state, account, terminalClass)
	if !tp.Enabled {
		return ErrSponsorTerminalDisabled
	}
	if trustTier < tp.MinTrustTier {
		return ErrSponsorTrustTooLow
	}

	// Check value against terminal single-tx limit (0 means unlimited).
	if tp.MaxSingleValue != nil && tp.MaxSingleValue.Sign() > 0 && value != nil {
		if value.Cmp(tp.MaxSingleValue) > 0 {
			return ErrSponsorValueExceeded
		}
	}

	return nil
}

// GetSponsorReceiptFields returns the sponsor attribution fields for receipt
// enrichment. Returns nil if the transaction has no sponsor.
func GetSponsorReceiptFields(tx *types.Transaction) map[string]interface{} {
	sponsor, ok := tx.SponsorFrom()
	if !ok {
		return nil
	}

	fields := map[string]interface{}{
		"sponsor": sponsor,
	}

	if signerType, ok := tx.SponsorSignerType(); ok {
		fields["sponsor_signer_type"] = signerType
	}
	if nonce, ok := tx.SponsorNonce(); ok {
		fields["sponsor_nonce"] = nonce
	}
	if expiry, ok := tx.SponsorExpiry(); ok {
		fields["sponsor_expiry"] = expiry
	}
	if policyHash, ok := tx.SponsorPolicyHash(); ok {
		fields["sponsor_policy_hash"] = policyHash
	}

	return fields
}
