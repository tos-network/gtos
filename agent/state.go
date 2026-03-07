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

// metadataSlot returns the slot for a metadata URI hash for an agent.
// Stores keccak256 of the URI; the raw string is emitted as an event by the caller.
func metadataSlot(addr common.Address) common.Hash {
	key := append([]byte("agent\x00meta\x00"), addr.Bytes()...)
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
// The URI is stored as-is in the slot (truncated to 32 bytes for short URIs,
// or as a hash for longer ones — callers are expected to store short CID/URL strings).
func MetadataOf(db stateDB, addr common.Address) string {
	raw := db.GetState(params.AgentRegistryAddress, metadataSlot(addr))
	// Trim trailing zero bytes.
	b := raw[:]
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	return string(b[:end])
}

// WriteMetadata stores a metadata URI for addr (first 32 bytes only).
func WriteMetadata(db stateDB, addr common.Address, uri string) {
	var val common.Hash
	copy(val[:], []byte(uri))
	db.SetState(params.AgentRegistryAddress, metadataSlot(addr), val)
}
