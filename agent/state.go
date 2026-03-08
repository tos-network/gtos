package agent

import (
	"encoding/binary"
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

// agentSlot returns the storage slot for a per-agent field.
// Key = keccak256(addr[20] || 0x00 || field).
func agentSlot(addr common.Address, field string) common.Hash {
	key := make([]byte, 0, common.AddressLength+1+len(field))
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// agentCountSlot stores the total count of ever-registered agents (uint64).
var agentCountSlot = common.BytesToHash(crypto.Keccak256([]byte("agent\x00count")))

// agentListSlot returns the slot for the i-th registered agent address (0-based).
func agentListSlot(i uint64) common.Hash {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], i)
	return common.BytesToHash(
		crypto.Keccak256(append([]byte("agent\x00list\x00"), idx[:]...)))
}

// MaxURILength is the maximum allowed length for a metadata URI (256 bytes).
const MaxURILength = 256

// metadataSlot returns the base slot for a metadata URI for an agent.
// The URI is stored across ceil(len/32) consecutive slots starting from the base.
func metadataSlot(addr common.Address) common.Hash {
	key := append([]byte("agent\x00meta\x00"), addr.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// metadataLenSlot returns the slot that stores the URI length for an agent.
func metadataLenSlot(addr common.Address) common.Hash {
	key := append([]byte("agent\x00metalen\x00"), addr.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

func readAgentCount(db stateDB) uint64 {
	raw := db.GetState(params.AgentRegistryAddress, agentCountSlot)
	return raw.Big().Uint64()
}

func writeAgentCount(db stateDB, n uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], n)
	db.SetState(params.AgentRegistryAddress, agentCountSlot, val)
}

func readAgentAt(db stateDB, i uint64) common.Address {
	raw := db.GetState(params.AgentRegistryAddress, agentListSlot(i))
	return common.BytesToAddress(raw[:])
}

func appendAgentToList(db stateDB, addr common.Address) {
	n := readAgentCount(db)
	slot := agentListSlot(n)
	var val common.Hash
	copy(val[:], addr.Bytes())
	db.SetState(params.AgentRegistryAddress, slot, val)
	writeAgentCount(db, n+1)
}

func readRegisteredFlag(db stateDB, addr common.Address) bool {
	raw := db.GetState(params.AgentRegistryAddress, agentSlot(addr, "registered"))
	return raw[31] != 0
}

func writeRegisteredFlag(db stateDB, addr common.Address) {
	var val common.Hash
	val[31] = 1
	db.SetState(params.AgentRegistryAddress, agentSlot(addr, "registered"), val)
}

// IsRegistered returns true if addr has ever registered as an agent.
func IsRegistered(db stateDB, addr common.Address) bool {
	return readRegisteredFlag(db, addr)
}

// IsSuspended returns true if addr is currently suspended.
func IsSuspended(db stateDB, addr common.Address) bool {
	raw := db.GetState(params.AgentRegistryAddress, agentSlot(addr, "suspended"))
	return raw[31] != 0
}

// ReadStake returns the locked stake for addr (0 if not registered).
func ReadStake(db stateDB, addr common.Address) *big.Int {
	raw := db.GetState(params.AgentRegistryAddress, agentSlot(addr, "stake"))
	return raw.Big()
}

// ReadStatus returns the current status for addr.
func ReadStatus(db stateDB, addr common.Address) AgentStatus {
	raw := db.GetState(params.AgentRegistryAddress, agentSlot(addr, "status"))
	return AgentStatus(raw[31])
}

// WriteStake writes the locked stake for addr.
func WriteStake(db stateDB, addr common.Address, stake *big.Int) {
	db.SetState(params.AgentRegistryAddress, agentSlot(addr, "stake"), common.BigToHash(stake))
}

// WriteSuspended writes the suspended flag for addr.
func WriteSuspended(db stateDB, addr common.Address, suspended bool) {
	var val common.Hash
	if suspended {
		val[31] = 1
	}
	db.SetState(params.AgentRegistryAddress, agentSlot(addr, "suspended"), val)
}

// WriteStatus writes the lifecycle status for addr.
func WriteStatus(db stateDB, addr common.Address, s AgentStatus) {
	var val common.Hash
	val[31] = byte(s)
	db.SetState(params.AgentRegistryAddress, agentSlot(addr, "status"), val)
}

// MetadataOf returns the metadata URI stored for addr.
// The URI is reconstructed from multiple 32-byte storage slots.
func MetadataOf(db stateDB, addr common.Address) string {
	// Read length.
	lenRaw := db.GetState(params.AgentRegistryAddress, metadataLenSlot(addr))
	uriLen := int(binary.BigEndian.Uint64(lenRaw[24:]))
	if uriLen == 0 {
		return ""
	}
	if uriLen > MaxURILength {
		uriLen = MaxURILength
	}

	// Read data from consecutive slots.
	baseSlot := metadataSlot(addr).Big()
	buf := make([]byte, 0, uriLen)
	for i := 0; len(buf) < uriLen; i++ {
		slot := common.BigToHash(new(big.Int).Add(baseSlot, big.NewInt(int64(i))))
		raw := db.GetState(params.AgentRegistryAddress, slot)
		remaining := uriLen - len(buf)
		if remaining >= 32 {
			buf = append(buf, raw[:]...)
		} else {
			buf = append(buf, raw[:remaining]...)
		}
	}
	return string(buf)
}

// WriteMetadata stores a metadata URI for addr across multiple 32-byte slots.
func WriteMetadata(db stateDB, addr common.Address, uri string) {
	data := []byte(uri)

	// Store length.
	var lenVal common.Hash
	binary.BigEndian.PutUint64(lenVal[24:], uint64(len(data)))
	db.SetState(params.AgentRegistryAddress, metadataLenSlot(addr), lenVal)

	// Store data across consecutive slots.
	baseSlot := metadataSlot(addr).Big()
	for i := 0; i < len(data); i += 32 {
		var val common.Hash
		end := i + 32
		if end > len(data) {
			end = len(data)
		}
		copy(val[:], data[i:end])
		slot := common.BigToHash(new(big.Int).Add(baseSlot, big.NewInt(int64(i/32))))
		db.SetState(params.AgentRegistryAddress, slot, val)
	}
}
