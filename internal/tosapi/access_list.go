package tosapi

import (
	"math/big"
	"sort"
	"sync"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
)

// accessTracker records all (address, storageSlot) pairs touched during execution.
type accessTracker struct {
	mu    sync.Mutex
	slots map[common.Address]map[common.Hash]struct{}
}

func newAccessTracker() *accessTracker {
	return &accessTracker{slots: make(map[common.Address]map[common.Hash]struct{})}
}

func (t *accessTracker) addAddress(addr common.Address) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.slots[addr]; !ok {
		t.slots[addr] = make(map[common.Hash]struct{})
	}
}

func (t *accessTracker) addSlot(addr common.Address, slot common.Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.slots[addr]; !ok {
		t.slots[addr] = make(map[common.Hash]struct{})
	}
	t.slots[addr][slot] = struct{}{}
}

// toAccessList converts the tracker's recorded accesses into a types.AccessList.
// Addresses in excl (sender, recipient) are excluded — they are always warm.
func (t *accessTracker) toAccessList(excl ...common.Address) types.AccessList {
	t.mu.Lock()
	defer t.mu.Unlock()
	excluded := make(map[common.Address]bool, len(excl))
	for _, a := range excl {
		excluded[a] = true
	}

	var acl types.AccessList
	for addr, slotSet := range t.slots {
		if excluded[addr] {
			continue
		}
		tuple := types.AccessTuple{Address: addr}
		for slot := range slotSet {
			tuple.StorageKeys = append(tuple.StorageKeys, slot)
		}
		sort.Slice(tuple.StorageKeys, func(i, j int) bool {
			return tuple.StorageKeys[i].Hex() < tuple.StorageKeys[j].Hex()
		})
		acl = append(acl, tuple)
	}
	sort.Slice(acl, func(i, j int) bool {
		return acl[i].Address.Hex() < acl[j].Address.Hex()
	})
	return acl
}

// trackingStateDB wraps vm.StateDB to intercept GetState, SetState, GetBalance
// and record all accessed (address, slot) pairs in an accessTracker.
type trackingStateDB struct {
	vm.StateDB
	tracker *accessTracker
}

func (s *trackingStateDB) GetState(addr common.Address, slot common.Hash) common.Hash {
	s.tracker.addSlot(addr, slot)
	return s.StateDB.GetState(addr, slot)
}

func (s *trackingStateDB) SetState(addr common.Address, slot common.Hash, value common.Hash) {
	s.tracker.addSlot(addr, slot)
	s.StateDB.SetState(addr, slot, value)
}

func (s *trackingStateDB) GetBalance(addr common.Address) *big.Int {
	s.tracker.addAddress(addr)
	return s.StateDB.GetBalance(addr)
}
