package parallel

import "github.com/tos-network/gtos/common"

// AccessSet describes the storage locations a transaction reads and writes.
type AccessSet struct {
	ReadAddrs  map[common.Address]struct{}
	ReadSlots  map[common.Address]map[common.Hash]struct{}
	WriteAddrs map[common.Address]struct{}
	WriteSlots map[common.Address]map[common.Hash]struct{}
}

// Conflicts returns true if a's writes overlap b's reads or writes (or vice versa).
func (a *AccessSet) Conflicts(b *AccessSet) bool {
	// a writes addr that b reads or writes
	for addr := range a.WriteAddrs {
		if _, ok := b.ReadAddrs[addr]; ok {
			return true
		}
		if _, ok := b.WriteAddrs[addr]; ok {
			return true
		}
	}
	// b writes addr that a reads or writes
	for addr := range b.WriteAddrs {
		if _, ok := a.ReadAddrs[addr]; ok {
			return true
		}
		if _, ok := a.WriteAddrs[addr]; ok {
			return true
		}
	}
	// a writes slot that b reads or writes
	for addr, slots := range a.WriteSlots {
		for slot := range slots {
			if bSlots, ok := b.ReadSlots[addr]; ok {
				if _, ok2 := bSlots[slot]; ok2 {
					return true
				}
			}
			if bSlots, ok := b.WriteSlots[addr]; ok {
				if _, ok2 := bSlots[slot]; ok2 {
					return true
				}
			}
		}
	}
	// b writes slot that a reads or writes
	for addr, slots := range b.WriteSlots {
		for slot := range slots {
			if aSlots, ok := a.ReadSlots[addr]; ok {
				if _, ok2 := aSlots[slot]; ok2 {
					return true
				}
			}
			if aSlots, ok := a.WriteSlots[addr]; ok {
				if _, ok2 := aSlots[slot]; ok2 {
					return true
				}
			}
		}
	}
	return false
}
