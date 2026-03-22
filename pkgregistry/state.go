package pkgregistry

import (
	"encoding/binary"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// stateDB is the minimal storage interface (mirrors agent/state.go pattern).
type stateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

// addr is the system address for the package registry.
var addr = params.PackageRegistryAddress

// ---------------------------------------------------------------------------
// Slot formulas
// ---------------------------------------------------------------------------

// publisherSlot returns the base storage slot for a publisher record.
// slot = keccak256("pkg\x00pub\x00" || publisherID)
func publisherSlot(pubID [32]byte) common.Hash {
	key := append([]byte("pkg\x00pub\x00"), pubID[:]...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// packageSlot returns the base storage slot for a package record.
// slot = keccak256("pkg\x00pkg\x00" || name || version)
func packageSlot(name, version string) common.Hash {
	key := append([]byte("pkg\x00pkg\x00"), name...)
	key = append(key, version...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// hashLookupSlot returns the storage slot for a package-hash lookup.
// slot = keccak256("pkg\x00hash\x00" || packageHash)
func hashLookupSlot(pkgHash [32]byte) common.Hash {
	key := append([]byte("pkg\x00hash\x00"), pkgHash[:]...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// namespaceSlot returns the storage slot for a namespace ownership pointer.
// slot = keccak256("pkg\x00ns\x00" || namespace)
func namespaceSlot(namespace string) common.Hash {
	key := append([]byte("pkg\x00ns\x00"), namespace...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// latestLookupSlot returns the storage slot for the latest package pointer
// for a given package name and channel.
// slot = keccak256("pkg\x00latest\x00" || name || uint16(channel))
func latestLookupSlot(name string, channel ChannelKind) common.Hash {
	key := append([]byte("pkg\x00latest\x00"), name...)
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], uint16(channel))
	key = append(key, raw[:]...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// slotOffset returns base + offset as a storage key.
func slotOffset(base common.Hash, offset uint64) common.Hash {
	b := base.Big()
	b.Add(b, new(big.Int).SetUint64(offset))
	return common.BigToHash(b)
}

// ---------------------------------------------------------------------------
// Publisher read / write
// ---------------------------------------------------------------------------

// ReadPublisherByNamespace resolves the canonical publisher record for a
// claimed namespace. If no owner exists, the returned record has a zero
// Controller.
func ReadPublisherByNamespace(db stateDB, namespace string) PublisherRecord {
	var rec PublisherRecord
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return rec
	}
	raw := db.GetState(addr, namespaceSlot(namespace))
	if raw == (common.Hash{}) {
		return rec
	}
	var pubID [32]byte
	copy(pubID[:], raw[:])
	return ReadPublisher(db, pubID)
}

// ReadPublisher reads a PublisherRecord from state.
// If the publisher does not exist the returned record has a zero Controller.
func ReadPublisher(db stateDB, pubID [32]byte) PublisherRecord {
	base := publisherSlot(pubID)
	var rec PublisherRecord
	rec.PublisherID = pubID

	// slot+0: Controller (32-byte address)
	raw := db.GetState(addr, base)
	rec.Controller = common.BytesToAddress(raw[:])

	// slot+1: MetadataRef
	raw = db.GetState(addr, slotOffset(base, 1))
	copy(rec.MetadataRef[:], raw[:])

	// slot+2: Status (uint8 in last byte)
	raw = db.GetState(addr, slotOffset(base, 2))
	rec.Status = PackageStatus(raw[31])

	// slot+3: Namespace
	rec.Namespace = readString(db, base, 3)

	return rec
}

// WritePublisher writes a PublisherRecord to state.
func WritePublisher(db stateDB, rec PublisherRecord) {
	base := publisherSlot(rec.PublisherID)

	// slot+0: Controller
	var val common.Hash
	copy(val[:], rec.Controller.Bytes())
	db.SetState(addr, base, val)

	// slot+1: MetadataRef
	db.SetState(addr, slotOffset(base, 1), common.Hash(rec.MetadataRef))

	// slot+2: Status
	val = common.Hash{}
	val[31] = byte(rec.Status)
	db.SetState(addr, slotOffset(base, 2), val)

	// slot+3: Namespace
	if ns := strings.TrimSpace(rec.Namespace); ns != "" {
		writeString(db, base, 3, ns)
		writeNamespaceLookup(db, ns, rec.PublisherID)
	}
}

func writeNamespaceLookup(db stateDB, namespace string, pubID [32]byte) {
	if namespace == "" {
		return
	}
	base := namespaceSlot(namespace)
	var val common.Hash
	copy(val[:], pubID[:])
	db.SetState(addr, base, val)
}

func namespaceOwnerID(db stateDB, namespace string) [32]byte {
	var pubID [32]byte
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return pubID
	}
	raw := db.GetState(addr, namespaceSlot(namespace))
	copy(pubID[:], raw[:])
	return pubID
}

// ---------------------------------------------------------------------------
// Package read / write
// ---------------------------------------------------------------------------

// maxPackageStringLen is the maximum length for name or version strings.
const maxPackageStringLen = 128

// writeString stores a length-prefixed string starting at slot base+offset.
// Layout: slot = length (uint64 big-endian in last 8 bytes),
// then ceil(len/32) consecutive slots for data.
// Returns the total number of slots consumed (1 + data slots).
func writeString(db stateDB, base common.Hash, offset uint64, s string) uint64 {
	data := []byte(s)
	if len(data) > maxPackageStringLen {
		data = data[:maxPackageStringLen]
	}
	// Length slot
	var lenVal common.Hash
	binary.BigEndian.PutUint64(lenVal[24:], uint64(len(data)))
	db.SetState(addr, slotOffset(base, offset), lenVal)

	// Data slots
	nSlots := uint64((len(data) + 31) / 32)
	for i := uint64(0); i < nSlots; i++ {
		var chunk common.Hash
		start := int(i) * 32
		end := start + 32
		if end > len(data) {
			end = len(data)
		}
		copy(chunk[:], data[start:end])
		db.SetState(addr, slotOffset(base, offset+1+i), chunk)
	}
	return 1 + nSlots
}

// readString reads a length-prefixed string from base+offset.
func readString(db stateDB, base common.Hash, offset uint64) string {
	raw := db.GetState(addr, slotOffset(base, offset))
	length := int(binary.BigEndian.Uint64(raw[24:]))
	if length == 0 {
		return ""
	}
	if length > maxPackageStringLen {
		length = maxPackageStringLen
	}
	nSlots := (length + 31) / 32
	buf := make([]byte, 0, length)
	for i := 0; i < nSlots; i++ {
		raw = db.GetState(addr, slotOffset(base, offset+1+uint64(i)))
		remaining := length - len(buf)
		if remaining >= 32 {
			buf = append(buf, raw[:]...)
		} else {
			buf = append(buf, raw[:remaining]...)
		}
	}
	return string(buf)
}

// Package record slot layout (offsets from base):
//
//	0..N-1  : PackageName  (length + data)
//	N..M-1  : PackageVersion (length + data)
//	M       : PackageHash
//	M+1     : PublisherID
//	M+2     : ManifestHash
//	M+3     : Channel(uint16) | Status(uint8) | ContractCount(uint16) packed
//	M+4     : DiscoveryRef
//	M+5     : PublishedAt
//
// Because strings are variable-length we store them with a fixed max budget:
// maxSlots = 1 + ceil(maxPackageStringLen/32) = 5 slots each.
const stringBudget = 1 + (maxPackageStringLen+31)/32 // 5

// ReadPackage reads a PackageRecord by name and version.
func ReadPackage(db stateDB, name, version string) PackageRecord {
	base := packageSlot(name, version)
	return readPackageFromBase(db, base, name, version)
}

func readPackageFromBase(db stateDB, base common.Hash, name, version string) PackageRecord {
	var rec PackageRecord

	// Read name
	rec.PackageName = readString(db, base, 0)
	off := uint64(stringBudget) // skip name budget

	// Read version
	rec.PackageVersion = readString(db, base, off)
	off += stringBudget // skip version budget

	// PackageHash
	raw := db.GetState(addr, slotOffset(base, off))
	copy(rec.PackageHash[:], raw[:])
	off++

	// PublisherID
	raw = db.GetState(addr, slotOffset(base, off))
	copy(rec.PublisherID[:], raw[:])
	off++

	// ManifestHash
	raw = db.GetState(addr, slotOffset(base, off))
	copy(rec.ManifestHash[:], raw[:])
	off++

	// Packed: Channel(2) | Status(1) | ContractCount(2) — 5 bytes total, right-aligned
	raw = db.GetState(addr, slotOffset(base, off))
	rec.Channel = ChannelKind(binary.BigEndian.Uint16(raw[27:29]))
	rec.Status = PackageStatus(raw[29])
	rec.ContractCount = binary.BigEndian.Uint16(raw[30:32])
	off++

	// DiscoveryRef
	raw = db.GetState(addr, slotOffset(base, off))
	copy(rec.DiscoveryRef[:], raw[:])
	off++

	// PublishedAt
	raw = db.GetState(addr, slotOffset(base, off))
	rec.PublishedAt = binary.BigEndian.Uint64(raw[24:])

	return rec
}

// WritePackage writes a PackageRecord to state and creates a hash lookup entry.
func WritePackage(db stateDB, rec PackageRecord) {
	base := packageSlot(rec.PackageName, rec.PackageVersion)

	// Write name
	writeString(db, base, 0, rec.PackageName)
	off := uint64(stringBudget)

	// Write version
	writeString(db, base, off, rec.PackageVersion)
	off += stringBudget

	// PackageHash
	db.SetState(addr, slotOffset(base, off), common.Hash(rec.PackageHash))
	off++

	// PublisherID
	db.SetState(addr, slotOffset(base, off), common.Hash(rec.PublisherID))
	off++

	// ManifestHash
	db.SetState(addr, slotOffset(base, off), common.Hash(rec.ManifestHash))
	off++

	// Packed: Channel(2) | Status(1) | ContractCount(2)
	var packed common.Hash
	binary.BigEndian.PutUint16(packed[27:29], uint16(rec.Channel))
	packed[29] = byte(rec.Status)
	binary.BigEndian.PutUint16(packed[30:32], rec.ContractCount)
	db.SetState(addr, slotOffset(base, off), packed)
	off++

	// DiscoveryRef
	db.SetState(addr, slotOffset(base, off), common.Hash(rec.DiscoveryRef))
	off++

	// PublishedAt
	var tsVal common.Hash
	binary.BigEndian.PutUint64(tsVal[24:], rec.PublishedAt)
	db.SetState(addr, slotOffset(base, off), tsVal)

	// Hash lookup: store name+version so ReadPackageByHash can reconstruct.
	writeHashLookup(db, rec.PackageHash, rec.PackageName, rec.PackageVersion)

	if rec.Status == PkgActive {
		writeLatestLookup(db, rec.PackageName, rec.Channel, rec.PackageVersion)
		return
	}
	clearLatestLookupIfCurrent(db, rec.PackageName, rec.Channel, rec.PackageVersion)
}

// writeHashLookup stores name and version at the hash-lookup slot so that
// ReadPackageByHash can resolve the canonical package slot.
func writeHashLookup(db stateDB, pkgHash [32]byte, name, version string) {
	base := hashLookupSlot(pkgHash)
	writeString(db, base, 0, name)
	writeString(db, base, uint64(stringBudget), version)
}

// ReadPackageByHash looks up a PackageRecord by its content hash.
// Returns an empty record if the hash is not registered.
func ReadPackageByHash(db stateDB, pkgHash [32]byte) PackageRecord {
	base := hashLookupSlot(pkgHash)
	name := readString(db, base, 0)
	version := readString(db, base, uint64(stringBudget))
	if name == "" && version == "" {
		return PackageRecord{}
	}
	return ReadPackage(db, name, version)
}

// PackageMatchesNamespace reports whether a package name belongs to a
// claimed namespace. The namespace must be an exact prefix segment.
func PackageMatchesNamespace(packageName, namespace string) bool {
	packageName = strings.TrimSpace(packageName)
	namespace = strings.TrimSpace(namespace)
	if packageName == "" || namespace == "" {
		return namespace == ""
	}
	if packageName == namespace {
		return true
	}
	return strings.HasPrefix(packageName, namespace+".")
}

func writeLatestLookup(db stateDB, name string, channel ChannelKind, version string) {
	base := latestLookupSlot(name, channel)
	writeString(db, base, 0, version)
}

func readLatestVersion(db stateDB, name string, channel ChannelKind) string {
	base := latestLookupSlot(name, channel)
	return readString(db, base, 0)
}

func clearLatestLookupIfCurrent(db stateDB, name string, channel ChannelKind, version string) {
	if stringsEqual(readLatestVersion(db, name, channel), version) {
		writeLatestLookup(db, name, channel, "")
	}
}

// ReadLatestPackage returns the currently indexed latest active package record
// for a given package name and channel. If the index is unset or stale, it
// returns an empty record.
func ReadLatestPackage(db stateDB, name string, channel ChannelKind) PackageRecord {
	version := readLatestVersion(db, name, channel)
	if version == "" {
		return PackageRecord{}
	}
	rec := ReadPackage(db, name, version)
	if rec.PackageHash == ([32]byte{}) {
		return PackageRecord{}
	}
	if rec.Status != PkgActive || rec.Channel != channel {
		return PackageRecord{}
	}
	return rec
}

func stringsEqual(a, b string) bool { return a == b }
