package registry

import (
	"encoding/binary"

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

// ---------------------------------------------------------------------------
// Capability Registry — slot layout
// ---------------------------------------------------------------------------

// capSlot returns the base storage slot for a capability record keyed by name.
// Key = keccak256("reg\x00cap\x00" || name).
func capSlot(name string) common.Hash {
	key := append([]byte("reg\x00cap\x00"), []byte(name)...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// capFieldSlot returns slot+offset for a sub-field of a capability record.
// Each field occupies one 32-byte slot at base+offset.
func capFieldSlot(base common.Hash, offset uint64) common.Hash {
	// Increment the base hash by offset.
	var slot common.Hash
	copy(slot[:], base[:])
	// Add offset to the last 8 bytes (big-endian).
	val := binary.BigEndian.Uint64(slot[24:]) + offset
	binary.BigEndian.PutUint64(slot[24:], val)
	return slot
}

// Capability record field offsets from base slot:
//
//	0: bitIndex(u16) | category(u16) | version(u32) | status(u8)  (packed)
//	1: manifestRef (bytes32)
//	2: owner (address)
//	3: createdAt(u64) | updatedAt(u64)
const (
	capFieldPacked   uint64 = 0
	capFieldManifest uint64 = 1
	capFieldOwner    uint64 = 2
	capFieldMeta     uint64 = 3
)

// ReadCapability reads a capability record from state. Returns a zero record
// with empty Name if not found.
func ReadCapability(db stateDB, name string) CapabilityRecord {
	base := capSlot(name)

	// Read packed field.
	packed := db.GetState(params.CapabilityRegistryAddress, capFieldSlot(base, capFieldPacked))
	// If the packed slot is entirely zero, no record exists.
	if packed == (common.Hash{}) {
		return CapabilityRecord{}
	}

	var rec CapabilityRecord
	rec.Name = name
	rec.BitIndex = binary.BigEndian.Uint16(packed[0:2])
	rec.Category = binary.BigEndian.Uint16(packed[2:4])
	rec.Version = binary.BigEndian.Uint32(packed[4:8])
	rec.Status = CapabilityStatus(packed[8])

	// Read manifest ref.
	manifest := db.GetState(params.CapabilityRegistryAddress, capFieldSlot(base, capFieldManifest))
	copy(rec.ManifestRef[:], manifest[:])

	owner := db.GetState(params.CapabilityRegistryAddress, capFieldSlot(base, capFieldOwner))
	rec.Owner = common.BytesToAddress(owner[:])

	meta := db.GetState(params.CapabilityRegistryAddress, capFieldSlot(base, capFieldMeta))
	rec.CreatedAt = binary.BigEndian.Uint64(meta[0:8])
	rec.UpdatedAt = binary.BigEndian.Uint64(meta[8:16])

	return rec
}

// WriteCapability writes a capability record to state.
func WriteCapability(db stateDB, rec CapabilityRecord) {
	base := capSlot(rec.Name)

	// Pack fixed fields.
	var packed common.Hash
	binary.BigEndian.PutUint16(packed[0:2], rec.BitIndex)
	binary.BigEndian.PutUint16(packed[2:4], rec.Category)
	binary.BigEndian.PutUint32(packed[4:8], rec.Version)
	packed[8] = byte(rec.Status)
	db.SetState(params.CapabilityRegistryAddress, capFieldSlot(base, capFieldPacked), packed)

	// Write manifest ref.
	var manifest common.Hash
	copy(manifest[:], rec.ManifestRef[:])
	db.SetState(params.CapabilityRegistryAddress, capFieldSlot(base, capFieldManifest), manifest)

	var owner common.Hash
	copy(owner[:], rec.Owner.Bytes())
	db.SetState(params.CapabilityRegistryAddress, capFieldSlot(base, capFieldOwner), owner)

	var meta common.Hash
	binary.BigEndian.PutUint64(meta[0:8], rec.CreatedAt)
	binary.BigEndian.PutUint64(meta[8:16], rec.UpdatedAt)
	db.SetState(params.CapabilityRegistryAddress, capFieldSlot(base, capFieldMeta), meta)
}

// ---------------------------------------------------------------------------
// Delegation Registry — slot layout
// ---------------------------------------------------------------------------

// delSlot returns the base storage slot for a delegation record.
// Key = keccak256("reg\x00del\x00" || principal[20] || delegate[20] || scope[32]).
func delSlot(principal, delegate common.Address, scope [32]byte) common.Hash {
	key := make([]byte, 0, 4+20+20+32)
	key = append(key, "reg\x00del\x00"...)
	key = append(key, principal.Bytes()...)
	key = append(key, delegate.Bytes()...)
	key = append(key, scope[:]...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// delFieldSlot returns slot+offset for a sub-field of a delegation record.
func delFieldSlot(base common.Hash, offset uint64) common.Hash {
	var slot common.Hash
	copy(slot[:], base[:])
	val := binary.BigEndian.Uint64(slot[24:]) + offset
	binary.BigEndian.PutUint64(slot[24:], val)
	return slot
}

// Delegation record field offsets from base slot:
//
//	0: capabilityRef (bytes32)
//	1: policyRef (bytes32)
//	2: notBeforeMS(u64) | expiryMS(u64) | status(u8)  (packed)
//	3: createdAt(u64) | updatedAt(u64)
const (
	delFieldCapRef  uint64 = 0
	delFieldPolRef  uint64 = 1
	delFieldTimings uint64 = 2
	delFieldMeta    uint64 = 3
)

// ReadDelegation reads a delegation record from state. Returns a zero record
// with DelActive status and zero addresses if not found.
func ReadDelegation(db stateDB, principal, delegate common.Address, scope [32]byte) DelegationRecord {
	base := delSlot(principal, delegate, scope)

	// Read timings to check existence.
	timings := db.GetState(params.DelegationRegistryAddress, delFieldSlot(base, delFieldTimings))

	var rec DelegationRecord
	rec.Principal = principal
	rec.Delegate = delegate
	rec.ScopeRef = scope

	// Read capability ref.
	capRef := db.GetState(params.DelegationRegistryAddress, delFieldSlot(base, delFieldCapRef))
	copy(rec.CapabilityRef[:], capRef[:])

	// Read policy ref.
	polRef := db.GetState(params.DelegationRegistryAddress, delFieldSlot(base, delFieldPolRef))
	copy(rec.PolicyRef[:], polRef[:])

	// Unpack timings.
	rec.NotBeforeMS = binary.BigEndian.Uint64(timings[0:8])
	rec.ExpiryMS = binary.BigEndian.Uint64(timings[8:16])
	rec.Status = DelegationStatus(timings[16])

	meta := db.GetState(params.DelegationRegistryAddress, delFieldSlot(base, delFieldMeta))
	rec.CreatedAt = binary.BigEndian.Uint64(meta[0:8])
	rec.UpdatedAt = binary.BigEndian.Uint64(meta[8:16])

	return rec
}

// DelegationExists returns true if a delegation record has been written for
// the given (principal, delegate, scope) triple. It checks for any non-zero
// field in the stored slots.
func DelegationExists(db stateDB, principal, delegate common.Address, scope [32]byte) bool {
	base := delSlot(principal, delegate, scope)
	capRef := db.GetState(params.DelegationRegistryAddress, delFieldSlot(base, delFieldCapRef))
	timings := db.GetState(params.DelegationRegistryAddress, delFieldSlot(base, delFieldTimings))
	return capRef != (common.Hash{}) || timings != (common.Hash{})
}

// WriteDelegation writes a delegation record to state.
func WriteDelegation(db stateDB, rec DelegationRecord) {
	base := delSlot(rec.Principal, rec.Delegate, rec.ScopeRef)

	// Write capability ref.
	var capRef common.Hash
	copy(capRef[:], rec.CapabilityRef[:])
	db.SetState(params.DelegationRegistryAddress, delFieldSlot(base, delFieldCapRef), capRef)

	// Write policy ref.
	var polRef common.Hash
	copy(polRef[:], rec.PolicyRef[:])
	db.SetState(params.DelegationRegistryAddress, delFieldSlot(base, delFieldPolRef), polRef)

	// Pack timings.
	var timings common.Hash
	binary.BigEndian.PutUint64(timings[0:8], rec.NotBeforeMS)
	binary.BigEndian.PutUint64(timings[8:16], rec.ExpiryMS)
	timings[16] = byte(rec.Status)
	db.SetState(params.DelegationRegistryAddress, delFieldSlot(base, delFieldTimings), timings)

	var meta common.Hash
	binary.BigEndian.PutUint64(meta[0:8], rec.CreatedAt)
	binary.BigEndian.PutUint64(meta[8:16], rec.UpdatedAt)
	db.SetState(params.DelegationRegistryAddress, delFieldSlot(base, delFieldMeta), meta)
}
