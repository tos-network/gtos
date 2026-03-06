package capability

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// bitmapSlot returns the storage slot for an address's capability bitmap.
// Key = keccak256("cap\x00bitmap\x00" || addr[20]).
func bitmapSlot(addr common.Address) common.Hash {
	key := append([]byte("cap\x00bitmap\x00"), addr.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// nameSlot returns the storage slot for a capability name → bit index mapping.
// Key = keccak256("cap\x00name\x00" || name).
// Value: u8 bit index; 0xFF = not registered.
func nameSlot(name string) common.Hash {
	key := append([]byte("cap\x00name\x00"), []byte(name)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// bitCountSlot stores the next available bit index (u8, 0–255).
var bitCountSlot = common.BytesToHash(crypto.Keccak256([]byte("cap\x00bitCount")))

// eligibleSlot returns the slot for the count of addresses holding a given bit.
// Key = keccak256("cap\x00eligible\x00" || [1]byte{bit}).
func eligibleSlot(bit uint8) common.Hash {
	key := append([]byte("cap\x00eligible\x00"), bit)
	return common.BytesToHash(crypto.Keccak256(key))
}

func readBitmap(db vm.StateDB, addr common.Address) *big.Int {
	raw := db.GetState(params.CapabilityRegistryAddress, bitmapSlot(addr))
	return raw.Big()
}

func writeBitmap(db vm.StateDB, addr common.Address, bitmap *big.Int) {
	db.SetState(params.CapabilityRegistryAddress, bitmapSlot(addr), common.BigToHash(bitmap))
}

func readBitCount(db vm.StateDB) uint8 {
	raw := db.GetState(params.CapabilityRegistryAddress, bitCountSlot)
	return uint8(raw.Big().Uint64())
}

func writeBitCount(db vm.StateDB, n uint8) {
	var val common.Hash
	val[31] = n
	db.SetState(params.CapabilityRegistryAddress, bitCountSlot, val)
}

func readNameBit(db vm.StateDB, name string) (uint8, bool) {
	raw := db.GetState(params.CapabilityRegistryAddress, nameSlot(name))
	v := raw[31]
	if v == 0xFF && raw == (common.Hash{31: 0xFF}) {
		return 0, false
	}
	// Check if set: if the entire slot is zero, not registered.
	// We use byte 30 as a "set" flag to distinguish bit 0 from "not set".
	if raw[30] == 0 && raw[31] == 0 {
		return 0, false
	}
	return v, true
}

func writeNameBit(db vm.StateDB, name string, bit uint8) {
	var val common.Hash
	val[30] = 1 // "set" marker
	val[31] = bit
	db.SetState(params.CapabilityRegistryAddress, nameSlot(name), val)
}

func readEligible(db vm.StateDB, bit uint8) *big.Int {
	raw := db.GetState(params.CapabilityRegistryAddress, eligibleSlot(bit))
	return raw.Big()
}

func writeEligible(db vm.StateDB, bit uint8, count *big.Int) {
	db.SetState(params.CapabilityRegistryAddress, eligibleSlot(bit), common.BigToHash(count))
}

// HasCapability returns true if addr holds the capability identified by bit.
func HasCapability(db vm.StateDB, addr common.Address, bit uint8) bool {
	bitmap := readBitmap(db, addr)
	return bitmap.Bit(int(bit)) == 1
}

// CapabilitiesOf returns the full capability bitmap for addr as a *big.Int.
func CapabilitiesOf(db vm.StateDB, addr common.Address) *big.Int {
	return readBitmap(db, addr)
}

// CapabilityBit resolves a capability name to its bit index.
// Returns (bit, true) if found, (0, false) if not registered.
func CapabilityBit(db vm.StateDB, name string) (uint8, bool) {
	return readNameBit(db, name)
}

// TotalEligible returns the count of addresses that hold a given capability bit.
func TotalEligible(db vm.StateDB, bit uint8) *big.Int {
	return readEligible(db, bit)
}

// GrantCapability sets bit in addr's capability bitmap and increments eligibleCount.
func GrantCapability(db vm.StateDB, addr common.Address, bit uint8) {
	bitmap := readBitmap(db, addr)
	if bitmap.Bit(int(bit)) == 0 {
		bitmap.SetBit(bitmap, int(bit), 1)
		writeBitmap(db, addr, bitmap)
		count := readEligible(db, bit)
		writeEligible(db, bit, new(big.Int).Add(count, big.NewInt(1)))
	}
}

// RevokeCapability clears bit in addr's capability bitmap and decrements eligibleCount.
func RevokeCapability(db vm.StateDB, addr common.Address, bit uint8) {
	bitmap := readBitmap(db, addr)
	if bitmap.Bit(int(bit)) == 1 {
		bitmap.SetBit(bitmap, int(bit), 0)
		writeBitmap(db, addr, bitmap)
		count := readEligible(db, bit)
		if count.Sign() > 0 {
			writeEligible(db, bit, new(big.Int).Sub(count, big.NewInt(1)))
		}
	}
}

// RegisterCapabilityName allocates the next available bit for a new capability name.
// Returns the allocated bit index, or an error if the name already exists or all bits are used.
func RegisterCapabilityName(db vm.StateDB, name string) (uint8, error) {
	if _, exists := readNameBit(db, name); exists {
		return 0, ErrCapabilityNameExists
	}
	next := readBitCount(db)
	// 255 is our sentinel for "not registered", so max usable bit is 254.
	if next >= 255 {
		return 0, ErrCapabilityBitFull
	}
	writeNameBit(db, name, next)
	writeBitCount(db, next+1)
	return next, nil
}
