package core

import (
	"encoding/binary"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

func setCodeExpiryBucketBase(expireAt uint64) common.Hash {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], expireAt)
	buf := make([]byte, 0, len("gtos.setcode.expiry.bucket")+8)
	buf = append(buf, []byte("gtos.setcode.expiry.bucket")...)
	buf = append(buf, n[:]...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

func setCodeExpiryBucketMetaSlot(base common.Hash, field string) common.Hash {
	buf := make([]byte, 0, len(base)+1+len("bucket")+1+len(field))
	buf = append(buf, base[:]...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte("bucket")...)
	buf = append(buf, 0x00)
	buf = append(buf, field...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

func setCodeExpiryBucketOwnerSlot(base common.Hash, index uint64) common.Hash {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], index)
	buf := make([]byte, 0, len(base)+1+len("owner")+8)
	buf = append(buf, base[:]...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte("owner")...)
	buf = append(buf, idx[:]...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

func readUint64StateWord(db vm.StateDB, owner common.Address, slot common.Hash) uint64 {
	raw := db.GetState(owner, slot)
	return binary.BigEndian.Uint64(raw[24:])
}

func writeUint64StateWord(db vm.StateDB, owner common.Address, slot common.Hash, n uint64) {
	var word common.Hash
	binary.BigEndian.PutUint64(word[24:], n)
	db.SetState(owner, slot, word)
}

func writeAddressStateWord(db vm.StateDB, owner common.Address, slot common.Hash, addr common.Address) {
	var word common.Hash
	copy(word[12:], addr[:])
	db.SetState(owner, slot, word)
}

func readAddressStateWord(db vm.StateDB, owner common.Address, slot common.Hash) common.Address {
	var out common.Address
	word := db.GetState(owner, slot)
	copy(out[:], word[12:])
	return out
}

func appendSetCodeExpiryIndex(db vm.StateDB, owner common.Address, expireAt uint64) {
	indexOwner := params.SystemActionAddress
	// Keep the index owner account non-empty so Finalise(true) doesn't drop storage.
	if db.GetNonce(indexOwner) == 0 {
		db.SetNonce(indexOwner, 1)
	}
	bucket := setCodeExpiryBucketBase(expireAt)
	countSlot := setCodeExpiryBucketMetaSlot(bucket, "count")
	count := readUint64StateWord(db, indexOwner, countSlot)
	writeAddressStateWord(db, indexOwner, setCodeExpiryBucketOwnerSlot(bucket, count), owner)
	writeUint64StateWord(db, indexOwner, countSlot, count+1)
}

func pruneExpiredCodeAt(db vm.StateDB, blockNumber uint64) uint64 {
	indexOwner := params.SystemActionAddress
	bucket := setCodeExpiryBucketBase(blockNumber)
	countSlot := setCodeExpiryBucketMetaSlot(bucket, "count")
	count := readUint64StateWord(db, indexOwner, countSlot)
	if count == 0 {
		return 0
	}
	var pruned uint64
	for i := uint64(0); i < count; i++ {
		slot := setCodeExpiryBucketOwnerSlot(bucket, i)
		owner := readAddressStateWord(db, indexOwner, slot)
		db.SetState(indexOwner, slot, common.Hash{})
		if owner == (common.Address{}) {
			continue
		}
		expireAt := readUint64StateWord(db, owner, SetCodeExpireAtSlot)
		if expireAt != blockNumber {
			continue
		}
		if db.GetCodeSize(owner) == 0 {
			continue
		}
		db.SetCode(owner, nil)
		db.SetState(owner, SetCodeCreatedAtSlot, common.Hash{})
		db.SetState(owner, SetCodeExpireAtSlot, common.Hash{})
		pruned++
	}
	db.SetState(indexOwner, countSlot, common.Hash{})
	return pruned
}
