package referral

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

func refSlot(prefix string, addr common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(
		append([]byte(prefix), addr.Bytes()...)))
}

// ReadReferrer returns the direct referrer of addr, or zero address if unbound.
func ReadReferrer(db stateDB, addr common.Address) common.Address {
	raw := db.GetState(params.ReferralRegistryAddress, refSlot("ref\x00referrer\x00", addr))
	return common.BytesToAddress(raw[:])
}

// HasReferrer returns true if addr has a bound referrer.
func HasReferrer(db stateDB, addr common.Address) bool {
	return ReadReferrer(db, addr) != (common.Address{})
}

// ReadDirectCount returns the number of direct referrals for addr.
func ReadDirectCount(db stateDB, addr common.Address) uint32 {
	raw := db.GetState(params.ReferralRegistryAddress, refSlot("ref\x00dcount\x00", addr))
	return uint32(raw.Big().Uint64())
}

// ReadTeamSize returns the cached total team size for addr.
func ReadTeamSize(db stateDB, addr common.Address) uint64 {
	raw := db.GetState(params.ReferralRegistryAddress, refSlot("ref\x00tsize\x00", addr))
	return raw.Big().Uint64()
}

// ReadTeamVolume returns the cumulative team volume for addr.
func ReadTeamVolume(db stateDB, addr common.Address) *big.Int {
	raw := db.GetState(params.ReferralRegistryAddress, refSlot("ref\x00tvol\x00", addr))
	return raw.Big()
}

// ReadDirectVolume returns the volume contributed by direct referrals of addr.
func ReadDirectVolume(db stateDB, addr common.Address) *big.Int {
	raw := db.GetState(params.ReferralRegistryAddress, refSlot("ref\x00dvol\x00", addr))
	return raw.Big()
}

func writeReferrer(db stateDB, addr, referrer common.Address) {
	var val common.Hash
	copy(val[:], referrer.Bytes())
	db.SetState(params.ReferralRegistryAddress, refSlot("ref\x00referrer\x00", addr), val)
}

func writeBoundBlock(db stateDB, addr common.Address, blockNum uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], blockNum)
	db.SetState(params.ReferralRegistryAddress, refSlot("ref\x00block\x00", addr), val)
}

func incrementDirectCount(db stateDB, addr common.Address) {
	n := ReadDirectCount(db, addr)
	var val common.Hash
	binary.BigEndian.PutUint32(val[28:], n+1)
	db.SetState(params.ReferralRegistryAddress, refSlot("ref\x00dcount\x00", addr), val)
}

func incrementTeamSize(db stateDB, addr common.Address) {
	n := ReadTeamSize(db, addr)
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], n+1)
	db.SetState(params.ReferralRegistryAddress, refSlot("ref\x00tsize\x00", addr), val)
}

// GetUplines walks the referrer chain and returns up to `levels` ancestors,
// starting with the direct referrer at index 0.
func GetUplines(db stateDB, addr common.Address, levels uint8) []common.Address {
	if levels > params.MaxReferralDepth {
		levels = params.MaxReferralDepth
	}
	result := make([]common.Address, 0, levels)
	cur := addr
	for i := uint8(0); i < levels; i++ {
		ref := ReadReferrer(db, cur)
		if ref == (common.Address{}) {
			break
		}
		result = append(result, ref)
		cur = ref
	}
	return result
}

// GetReferralDepth returns how deep addr is in the tree (0 = no referrer / root).
func GetReferralDepth(db stateDB, addr common.Address) uint8 {
	var depth uint8
	cur := addr
	for depth < params.MaxReferralDepth {
		ref := ReadReferrer(db, cur)
		if ref == (common.Address{}) {
			break
		}
		depth++
		cur = ref
	}
	return depth
}

// IsDownline checks whether descendant is within maxDepth levels below ancestor.
func IsDownline(db stateDB, ancestor, descendant common.Address, maxDepth uint8) bool {
	if maxDepth > params.MaxReferralDepth {
		maxDepth = params.MaxReferralDepth
	}
	cur := descendant
	for i := uint8(0); i < maxDepth; i++ {
		ref := ReadReferrer(db, cur)
		if ref == (common.Address{}) {
			return false
		}
		if ref == ancestor {
			return true
		}
		cur = ref
	}
	return false
}

// contractVolSlot returns a per-contract volume slot key.
// key = keccak256(prefix || contractAddr[32] || userAddr[32])
// This namespaces volume accumulation under the calling contract, so that
// different LVM contracts maintain isolated team/direct volume counters
// for the same referral tree.
func contractVolSlot(prefix string, contractAddr, userAddr common.Address) common.Hash {
	key := append([]byte(prefix), contractAddr.Bytes()...)
	key = append(key, userAddr.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// ReadTeamVolumeFor returns the team_volume accumulated by contractAddr for addr.
func ReadTeamVolumeFor(db stateDB, contractAddr, addr common.Address) *big.Int {
	raw := db.GetState(params.ReferralRegistryAddress,
		contractVolSlot("ref\x00ctvol\x00", contractAddr, addr))
	return raw.Big()
}

// ReadDirectVolumeFor returns the direct_volume accumulated by contractAddr for addr.
func ReadDirectVolumeFor(db stateDB, contractAddr, addr common.Address) *big.Int {
	raw := db.GetState(params.ReferralRegistryAddress,
		contractVolSlot("ref\x00cdvol\x00", contractAddr, addr))
	return raw.Big()
}

// AddTeamVolumeFor adds amount to the per-contract team_volume for each upline of addr
// up to `levels` hops, and to direct_volume of the immediate referrer.
// All writes are namespaced under contractAddr, so each LVM contract maintains
// independent volume counters for the same referral tree.
// Returns the number of upline levels actually updated.
func AddTeamVolumeFor(db stateDB, contractAddr, addr common.Address, amount *big.Int, levels uint8) uint8 {
	if levels > params.MaxReferralDepth {
		levels = params.MaxReferralDepth
	}
	cur := addr
	var updated uint8
	for i := uint8(0); i < levels; i++ {
		ref := ReadReferrer(db, cur)
		if ref == (common.Address{}) {
			break
		}
		slot := contractVolSlot("ref\x00ctvol\x00", contractAddr, ref)
		old := db.GetState(params.ReferralRegistryAddress, slot).Big()
		db.SetState(params.ReferralRegistryAddress, slot,
			common.BigToHash(new(big.Int).Add(old, amount)))
		if i == 0 {
			dslot := contractVolSlot("ref\x00cdvol\x00", contractAddr, ref)
			dold := db.GetState(params.ReferralRegistryAddress, dslot).Big()
			db.SetState(params.ReferralRegistryAddress, dslot,
				common.BigToHash(new(big.Int).Add(dold, amount)))
		}
		cur = ref
		updated++
	}
	return updated
}

// AddTeamVolume adds amount to team_volume for each upline up to `levels`,
// and also increments direct_volume of the immediate referrer.
// Returns the number of upline levels actually updated.
func AddTeamVolume(db stateDB, addr common.Address, amount *big.Int, levels uint8) uint8 {
	if levels > params.MaxReferralDepth {
		levels = params.MaxReferralDepth
	}
	cur := addr
	var updated uint8
	for i := uint8(0); i < levels; i++ {
		ref := ReadReferrer(db, cur)
		if ref == (common.Address{}) {
			break
		}
		// Increment team_volume.
		slot := refSlot("ref\x00tvol\x00", ref)
		old := db.GetState(params.ReferralRegistryAddress, slot).Big()
		db.SetState(params.ReferralRegistryAddress, slot,
			common.BigToHash(new(big.Int).Add(old, amount)))
		// Level 1 only: also increment direct_volume.
		if i == 0 {
			dslot := refSlot("ref\x00dvol\x00", ref)
			dold := db.GetState(params.ReferralRegistryAddress, dslot).Big()
			db.SetState(params.ReferralRegistryAddress, dslot,
				common.BigToHash(new(big.Int).Add(dold, amount)))
		}
		cur = ref
		updated++
	}
	return updated
}
