package delegation

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// stateDB is the minimal storage interface required by this package.
// Avoids an import cycle with core/vm (which imports this package).
type stateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

// usedSlot returns the storage slot tracking whether (principal, nonce) has been consumed.
// Key = keccak256("del\x00used\x00" || principal[20] || nonce[32]).
func usedSlot(principal common.Address, nonce *big.Int) common.Hash {
	nonceBytes := make([]byte, 32)
	nonce.FillBytes(nonceBytes)
	key := append([]byte("del\x00used\x00"), principal.Bytes()...)
	key = append(key, nonceBytes...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// nonceCountSlot returns the slot storing the next nonce hint for principal.
// Key = keccak256("del\x00nonce\x00" || principal[20]).
func nonceCountSlot(principal common.Address) common.Hash {
	key := append([]byte("del\x00nonce\x00"), principal.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// IsUsed reports whether (principal, nonce) has already been consumed.
func IsUsed(db stateDB, principal common.Address, nonce *big.Int) bool {
	raw := db.GetState(params.DelegationRegistryAddress, usedSlot(principal, nonce))
	return raw[31] != 0
}

// MarkUsed marks (principal, nonce) as consumed. Advances the nonce hint if this
// nonce equals the current hint.
func MarkUsed(db stateDB, principal common.Address, nonce *big.Int) {
	var val common.Hash
	val[31] = 1
	db.SetState(params.DelegationRegistryAddress, usedSlot(principal, nonce), val)

	// Advance hint if applicable.
	hint := NextNonce(db, principal)
	if nonce.Cmp(hint) == 0 {
		db.SetState(params.DelegationRegistryAddress, nonceCountSlot(principal),
			common.BigToHash(new(big.Int).Add(hint, big.NewInt(1))))
	}
}

// Revoke marks (principal, nonce) as used, preventing future use.
// Semantically equivalent to MarkUsed but communicates revocation intent.
func Revoke(db stateDB, principal common.Address, nonce *big.Int) {
	MarkUsed(db, principal, nonce)
}

// NextNonce returns the next-nonce hint for principal (may not be the actual
// smallest available nonce if non-sequential nonces were used).
func NextNonce(db stateDB, principal common.Address) *big.Int {
	raw := db.GetState(params.DelegationRegistryAddress, nonceCountSlot(principal))
	return raw.Big()
}
