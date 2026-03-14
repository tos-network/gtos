// Package group implements the GTOS Group Registry system action handler.
package group

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// stateDB is the minimal storage interface required by this package.
type stateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

// Storage slot layout for GroupRegistryAddress (0x010A):
//
//	slot(groupId, "registered")        → 1 if registered, 0 otherwise
//	slot(groupId, "manifest_hash")     → manifest hash
//	slot(groupId, "treasury_address")  → treasury address
//	slot(groupId, "creator_address")   → creator address
//	slot(groupId, "members_root")      → members root hash
//	slot(groupId, "epoch")             → current epoch
//	slot(groupId, "events_root")       → events merkle root
//	slot(groupId, "treasury_balance")  → treasury balance snapshot
//	slot(groupId, "commit_count")      → number of state commitments
func groupSlot(groupId string, field string) common.Hash {
	return crypto.Keccak256Hash([]byte(groupId), []byte(field))
}

// --- registered ---

func IsGroupRegistered(db stateDB, groupId string) bool {
	val := db.GetState(params.GroupRegistryAddress, groupSlot(groupId, "registered"))
	return val.Big().Cmp(common.Big1) == 0
}

func SetGroupRegistered(db stateDB, groupId string, registered bool) {
	slot := groupSlot(groupId, "registered")
	if registered {
		db.SetState(params.GroupRegistryAddress, slot, common.BigToHash(common.Big1))
	} else {
		db.SetState(params.GroupRegistryAddress, slot, common.Hash{})
	}
}

// --- manifest_hash ---

func GetGroupManifestHash(db stateDB, groupId string) common.Hash {
	return db.GetState(params.GroupRegistryAddress, groupSlot(groupId, "manifest_hash"))
}

func SetGroupManifestHash(db stateDB, groupId string, hash common.Hash) {
	db.SetState(params.GroupRegistryAddress, groupSlot(groupId, "manifest_hash"), hash)
}

// --- treasury_address ---

func GetGroupTreasuryAddress(db stateDB, groupId string) common.Address {
	raw := db.GetState(params.GroupRegistryAddress, groupSlot(groupId, "treasury_address"))
	return common.BytesToAddress(raw.Bytes())
}

func SetGroupTreasuryAddress(db stateDB, groupId string, addr common.Address) {
	db.SetState(params.GroupRegistryAddress, groupSlot(groupId, "treasury_address"),
		common.BytesToHash(addr.Bytes()))
}

// --- creator_address ---

func GetGroupCreatorAddress(db stateDB, groupId string) common.Address {
	raw := db.GetState(params.GroupRegistryAddress, groupSlot(groupId, "creator_address"))
	return common.BytesToAddress(raw.Bytes())
}

func SetGroupCreatorAddress(db stateDB, groupId string, addr common.Address) {
	db.SetState(params.GroupRegistryAddress, groupSlot(groupId, "creator_address"),
		common.BytesToHash(addr.Bytes()))
}

// --- members_root ---

func GetGroupMembersRoot(db stateDB, groupId string) common.Hash {
	return db.GetState(params.GroupRegistryAddress, groupSlot(groupId, "members_root"))
}

func SetGroupMembersRoot(db stateDB, groupId string, hash common.Hash) {
	db.SetState(params.GroupRegistryAddress, groupSlot(groupId, "members_root"), hash)
}

// --- epoch ---

func GetGroupEpoch(db stateDB, groupId string) uint64 {
	raw := db.GetState(params.GroupRegistryAddress, groupSlot(groupId, "epoch"))
	return raw.Big().Uint64()
}

func SetGroupEpoch(db stateDB, groupId string, epoch uint64) {
	db.SetState(params.GroupRegistryAddress, groupSlot(groupId, "epoch"),
		common.BigToHash(new(big.Int).SetUint64(epoch)))
}

// --- events_root ---

func GetGroupEventsRoot(db stateDB, groupId string) common.Hash {
	return db.GetState(params.GroupRegistryAddress, groupSlot(groupId, "events_root"))
}

func SetGroupEventsRoot(db stateDB, groupId string, hash common.Hash) {
	db.SetState(params.GroupRegistryAddress, groupSlot(groupId, "events_root"), hash)
}

// --- treasury_balance ---

func GetGroupTreasuryBalance(db stateDB, groupId string) *big.Int {
	raw := db.GetState(params.GroupRegistryAddress, groupSlot(groupId, "treasury_balance"))
	return raw.Big()
}

func SetGroupTreasuryBalance(db stateDB, groupId string, balance *big.Int) {
	db.SetState(params.GroupRegistryAddress, groupSlot(groupId, "treasury_balance"),
		common.BigToHash(balance))
}

// --- commit_count ---

func GetGroupCommitCount(db stateDB, groupId string) uint64 {
	raw := db.GetState(params.GroupRegistryAddress, groupSlot(groupId, "commit_count"))
	return raw.Big().Uint64()
}

func SetGroupCommitCount(db stateDB, groupId string, count uint64) {
	db.SetState(params.GroupRegistryAddress, groupSlot(groupId, "commit_count"),
		common.BigToHash(new(big.Int).SetUint64(count)))
}
