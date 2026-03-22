package registry

import (
	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
)

// StateReader adapts on-chain GTOS registry state into the VM registry reader
// interface used by LVM host functions.
type StateReader struct {
	db stateDB
}

func NewStateReader(db stateDB) *StateReader {
	return &StateReader{db: db}
}

func (r *StateReader) ReadCapabilityStatus(name string) (uint8, bool) {
	rec := ReadCapability(r.db, name)
	if rec.Name != "" {
		return uint8(rec.Status), true
	}
	if _, ok := capability.CapabilityBit(r.db, name); ok {
		return uint8(CapActive), true
	}
	return 0, false
}

func (r *StateReader) ReadAgentCapabilityBit(addr common.Address, name string) (bool, bool) {
	bit, ok := capability.CapabilityBit(r.db, name)
	if !ok {
		return false, false
	}
	return capability.HasCapability(r.db, addr, bit), true
}

func (r *StateReader) ReadDelegationStatus(principal, delegate common.Address, scope [32]byte) (uint8, uint64, uint64, bool) {
	if !DelegationExists(r.db, principal, delegate, scope) {
		return 0, 0, 0, false
	}
	rec := ReadDelegation(r.db, principal, delegate, scope)
	return uint8(rec.Status), rec.NotBeforeMS, rec.ExpiryMS, true
}
