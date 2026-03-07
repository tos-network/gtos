package tns

import (
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

func nameToAddrSlot(nameHash common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(
		append([]byte("tns\x00n2a\x00"), nameHash.Bytes()...)))
}

func addrToNameSlot(addr common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(
		append([]byte("tns\x00a2n\x00"), addr.Bytes()...)))
}

// HashName returns keccak256 of the canonical (lowercase) name string.
// This is the on-chain key; callers who know the name can recompute it.
func HashName(name string) common.Hash {
	return common.BytesToHash(crypto.Keccak256([]byte(name)))
}

// Resolve returns the address registered for nameHash, or zero address if not found.
func Resolve(db stateDB, nameHash common.Hash) common.Address {
	raw := db.GetState(params.TNSRegistryAddress, nameToAddrSlot(nameHash))
	return common.BytesToAddress(raw[:])
}

// Reverse returns the name hash registered for addr, or zero hash if none.
func Reverse(db stateDB, addr common.Address) common.Hash {
	return db.GetState(params.TNSRegistryAddress, addrToNameSlot(addr))
}

// HasName returns true if addr has a registered TNS name.
func HasName(db stateDB, addr common.Address) bool {
	return Reverse(db, addr) != (common.Hash{})
}

func writeMapping(db stateDB, nameHash common.Hash, addr common.Address) {
	// name_hash → address: store address bytes in slot
	var addrVal common.Hash
	copy(addrVal[:], addr.Bytes())
	db.SetState(params.TNSRegistryAddress, nameToAddrSlot(nameHash), addrVal)
	// address → name_hash
	db.SetState(params.TNSRegistryAddress, addrToNameSlot(addr), nameHash)
}
