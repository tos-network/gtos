package tosapi

import (
	"github.com/tos-network/gtos/common"
	corepriv "github.com/tos-network/gtos/core/priv"
)

// PrivacyRPCRestricted controls whether privacy query RPCs (tos_privGetBalance,
// tos_privGetNonce) and raw storage reads on privacy slots via eth_getStorageAt
// are blocked. Set to true in production to prevent unauthenticated privacy
// data queries that could enable activity frequency monitoring.
//
// TODO: Replace this boolean gate with proper authentication that proves
// knowledge of the account's private key before returning encrypted balances.
var PrivacyRPCRestricted bool

var privacySlots = map[common.Hash]bool{
	corepriv.CommitmentSlot: true,
	corepriv.HandleSlot:     true,
	corepriv.VersionSlot:    true,
	corepriv.NonceSlot:      true,
}

// isPrivacySlot returns true if the given storage slot hash corresponds to one
// of the privacy-reserved state slots (commitment, handle, version, nonce).
func isPrivacySlot(slot common.Hash) bool {
	return privacySlots[slot]
}
