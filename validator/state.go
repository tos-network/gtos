package validator

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"sort"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// addressAscending sorts common.Address slices in ascending byte order.
// Required for deterministic validator ordering.
type addressAscending []common.Address

func (a addressAscending) Len() int      { return len(a) }
func (a addressAscending) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a addressAscending) Less(i, j int) bool {
	return bytes.Compare(a[i][:], a[j][:]) < 0
}

// validatorSlot hashes (addr[20B] || 0x00 || field) for a per-validator storage slot.
// addr is always exactly 20 bytes — no length-extension ambiguity.
func validatorSlot(addr common.Address, field string) common.Hash {
	key := make([]byte, 0, 21+len(field))
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// validatorCountSlot stores the total count of ever-registered addresses (uint64).
var validatorCountSlot = common.BytesToHash(
	crypto.Keccak256([]byte("dpos\x00validatorCount")))

// validatorListSlot returns the slot for the i-th registered address (0-based).
// The list is append-only; withdrawn validators remain with status=Inactive.
func validatorListSlot(i uint64) common.Hash {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], i)
	return common.BytesToHash(
		crypto.Keccak256(append([]byte("dpos\x00validatorList\x00"), idx[:]...)))
}

func readValidatorCount(db vm.StateDB) uint64 {
	raw := db.GetState(params.ValidatorRegistryAddress, validatorCountSlot)
	return raw.Big().Uint64()
}

func writeValidatorCount(db vm.StateDB, n uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], n) // right-aligned in 32 bytes
	db.SetState(params.ValidatorRegistryAddress, validatorCountSlot, val)
}

func readValidatorAt(db vm.StateDB, i uint64) common.Address {
	raw := db.GetState(params.ValidatorRegistryAddress, validatorListSlot(i))
	return common.BytesToAddress(raw[12:]) // address is right-aligned
}

func appendValidatorToList(db vm.StateDB, addr common.Address) {
	n := readValidatorCount(db)
	slot := validatorListSlot(n)
	var val common.Hash
	copy(val[12:], addr.Bytes())
	db.SetState(params.ValidatorRegistryAddress, slot, val)
	writeValidatorCount(db, n+1)
}

func writeSelfStake(db vm.StateDB, addr common.Address, stake *big.Int) {
	db.SetState(params.ValidatorRegistryAddress, validatorSlot(addr, "selfStake"),
		common.BigToHash(stake))
}

// readRegisteredFlag returns true if addr has ever been registered (persists
// through withdrawals, unlike selfStake which is reset to 0 on withdrawal).
func readRegisteredFlag(db vm.StateDB, addr common.Address) bool {
	raw := db.GetState(params.ValidatorRegistryAddress, validatorSlot(addr, "registered"))
	return raw[31] != 0
}

// writeRegisteredFlag marks addr as ever-registered. Called once on first registration.
func writeRegisteredFlag(db vm.StateDB, addr common.Address) {
	var val common.Hash
	val[31] = 1
	db.SetState(params.ValidatorRegistryAddress, validatorSlot(addr, "registered"), val)
}

// WriteValidatorStatus writes the status for addr to TOS3.
func WriteValidatorStatus(db vm.StateDB, addr common.Address, s ValidatorStatus) {
	var val common.Hash
	val[31] = byte(s)
	db.SetState(params.ValidatorRegistryAddress, validatorSlot(addr, "status"), val)
}

// ReadSelfStake returns the locked stake for addr (0 if not registered).
func ReadSelfStake(db vm.StateDB, addr common.Address) *big.Int {
	raw := db.GetState(params.ValidatorRegistryAddress, validatorSlot(addr, "selfStake"))
	return raw.Big()
}

// ReadValidatorStatus returns the current status for addr.
func ReadValidatorStatus(db vm.StateDB, addr common.Address) ValidatorStatus {
	raw := db.GetState(params.ValidatorRegistryAddress, validatorSlot(addr, "status"))
	return ValidatorStatus(raw[31])
}

// ReadActiveValidators returns up to maxValidators active validators sorted
// by address ascending (deterministic round-robin order).
//
// Two-phase sort (R2-M2):
//
//	Phase 1 — collect all registered entries into memory (O(N) StateDB reads total).
//	Phase 2 — filter active, sort by stake desc (address asc as tiebreak), truncate.
//	Phase 3 — re-sort the truncated result by address ascending.
func ReadActiveValidators(db vm.StateDB, maxValidators uint64) []common.Address {
	count := readValidatorCount(db)

	type entry struct {
		addr  common.Address
		stake *big.Int
	}

	// Phase 1: read all entries in one pass (O(N) reads).
	entries := make([]entry, 0, count)
	for i := uint64(0); i < count; i++ {
		addr := readValidatorAt(db, i)
		if ReadValidatorStatus(db, addr) == Active {
			entries = append(entries, entry{addr, ReadSelfStake(db, addr)})
		}
	}

	// Phase 2: sort by stake descending; address ascending as tiebreak (stable).
	sort.SliceStable(entries, func(i, j int) bool {
		cmp := entries[i].stake.Cmp(entries[j].stake)
		if cmp != 0 {
			return cmp > 0 // higher stake first
		}
		return bytes.Compare(entries[i].addr[:], entries[j].addr[:]) < 0
	})
	if uint64(len(entries)) > maxValidators {
		entries = entries[:maxValidators]
	}

	// Phase 3: re-sort by address ascending on the truncated slice.
	result := make([]common.Address, len(entries))
	for i, e := range entries {
		result[i] = e.addr
	}
	sort.Sort(addressAscending(result))
	return result
}
