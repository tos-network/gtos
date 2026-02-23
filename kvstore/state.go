package kvstore

import (
	"encoding/binary"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

const kvValueChunkSize = 32

func slotForRecord(namespace string, key []byte) common.Hash {
	var l [8]byte
	ns := []byte(namespace)
	buf := make([]byte, 0, len("gtos.kv.record")+8+len(ns)+8+len(key))
	buf = append(buf, []byte("gtos.kv.record")...)
	binary.BigEndian.PutUint64(l[:], uint64(len(ns)))
	buf = append(buf, l[:]...)
	buf = append(buf, ns...)
	binary.BigEndian.PutUint64(l[:], uint64(len(key)))
	buf = append(buf, l[:]...)
	buf = append(buf, key...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

func metaSlot(base common.Hash, field string) common.Hash {
	buf := make([]byte, 0, len(base)+1+len(field))
	buf = append(buf, base[:]...)
	buf = append(buf, 0x00)
	buf = append(buf, field...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

func valueChunkSlot(base common.Hash, index uint64) common.Hash {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], index)
	buf := make([]byte, 0, len(base)+1+len("valueChunk")+8)
	buf = append(buf, base[:]...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte("valueChunk")...)
	buf = append(buf, idx[:]...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

func expiryBucketBase(expireAt uint64) common.Hash {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], expireAt)
	buf := make([]byte, 0, len("gtos.kv.expiry.bucket")+8)
	buf = append(buf, []byte("gtos.kv.expiry.bucket")...)
	buf = append(buf, n[:]...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

func expiryBucketMetaSlot(base common.Hash, field string) common.Hash {
	buf := make([]byte, 0, len(base)+1+len("bucket")+1+len(field))
	buf = append(buf, base[:]...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte("bucket")...)
	buf = append(buf, 0x00)
	buf = append(buf, field...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

func expiryBucketOwnerSlot(base common.Hash, index uint64) common.Hash {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], index)
	buf := make([]byte, 0, len(base)+1+len("owner")+8)
	buf = append(buf, base[:]...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte("owner")...)
	buf = append(buf, idx[:]...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

func expiryBucketRecordSlot(base common.Hash, index uint64) common.Hash {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], index)
	buf := make([]byte, 0, len(base)+1+len("record")+8)
	buf = append(buf, base[:]...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte("record")...)
	buf = append(buf, idx[:]...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

func readUint64(db vm.StateDB, owner common.Address, slot common.Hash) uint64 {
	raw := db.GetState(owner, slot)
	return binary.BigEndian.Uint64(raw[24:])
}

func writeUint64(db vm.StateDB, owner common.Address, slot common.Hash, n uint64) {
	var word common.Hash
	binary.BigEndian.PutUint64(word[24:], n)
	db.SetState(owner, slot, word)
}

func readBool(db vm.StateDB, owner common.Address, slot common.Hash) bool {
	return db.GetState(owner, slot)[31] != 0
}

func writeBool(db vm.StateDB, owner common.Address, slot common.Hash, v bool) {
	var word common.Hash
	if v {
		word[31] = 1
	}
	db.SetState(owner, slot, word)
}

func readAddress(db vm.StateDB, owner common.Address, slot common.Hash) common.Address {
	var out common.Address
	word := db.GetState(owner, slot)
	copy(out[:], word[12:])
	return out
}

func writeAddress(db vm.StateDB, owner common.Address, slot common.Hash, addr common.Address) {
	var word common.Hash
	copy(word[12:], addr[:])
	db.SetState(owner, slot, word)
}

func chunkCount(valueLen uint64) uint64 {
	if valueLen == 0 {
		return 0
	}
	return (valueLen + kvValueChunkSize - 1) / kvValueChunkSize
}

func readValue(db vm.StateDB, owner common.Address, base common.Hash, valueLen uint64) []byte {
	if valueLen == 0 {
		return []byte{}
	}
	value := make([]byte, valueLen)
	chunks := chunkCount(valueLen)
	for i := uint64(0); i < chunks; i++ {
		slot := valueChunkSlot(base, i)
		word := db.GetState(owner, slot)
		start := i * kvValueChunkSize
		end := start + kvValueChunkSize
		if end > valueLen {
			end = valueLen
		}
		copy(value[start:end], word[:end-start])
	}
	return value
}

func writeValue(db vm.StateDB, owner common.Address, base common.Hash, value []byte) {
	newChunks := chunkCount(uint64(len(value)))
	for i := uint64(0); i < newChunks; i++ {
		start := i * kvValueChunkSize
		end := start + kvValueChunkSize
		if end > uint64(len(value)) {
			end = uint64(len(value))
		}
		var word common.Hash
		copy(word[:], value[start:end])
		db.SetState(owner, valueChunkSlot(base, i), word)
	}
}

func clearValueRemainder(db vm.StateDB, owner common.Address, base common.Hash, fromLen, toLen uint64) {
	oldChunks := chunkCount(fromLen)
	newChunks := chunkCount(toLen)
	for i := newChunks; i < oldChunks; i++ {
		db.SetState(owner, valueChunkSlot(base, i), common.Hash{})
	}
}

func appendExpiryIndex(db vm.StateDB, owner common.Address, base common.Hash, expireAt uint64) {
	bucket := expiryBucketBase(expireAt)
	indexOwner := params.KVRouterAddress
	// Keep the index owner account non-empty so Finalise(true) doesn't drop storage.
	if db.GetNonce(indexOwner) == 0 {
		db.SetNonce(indexOwner, 1)
	}
	countSlot := expiryBucketMetaSlot(bucket, "count")
	count := readUint64(db, indexOwner, countSlot)
	writeAddress(db, indexOwner, expiryBucketOwnerSlot(bucket, count), owner)
	db.SetState(indexOwner, expiryBucketRecordSlot(bucket, count), base)
	writeUint64(db, indexOwner, countSlot, count+1)
}

func clearRecord(db vm.StateDB, owner common.Address, base common.Hash) {
	lenSlot := metaSlot(base, "valueLen")
	createdAtSlot := metaSlot(base, "createdAt")
	expireAtSlot := metaSlot(base, "expireAt")
	existsSlot := metaSlot(base, "exists")

	valueLen := readUint64(db, owner, lenSlot)
	for i := uint64(0); i < chunkCount(valueLen); i++ {
		db.SetState(owner, valueChunkSlot(base, i), common.Hash{})
	}
	db.SetState(owner, lenSlot, common.Hash{})
	db.SetState(owner, createdAtSlot, common.Hash{})
	db.SetState(owner, expireAtSlot, common.Hash{})
	db.SetState(owner, existsSlot, common.Hash{})
}

// Put upserts a TTL KV record and persists absolute createdAt/expireAt heights.
func Put(db vm.StateDB, owner common.Address, namespace string, key, value []byte, createdAt, expireAt uint64) {
	base := slotForRecord(namespace, key)
	lenSlot := metaSlot(base, "valueLen")
	oldLen := readUint64(db, owner, lenSlot)

	writeValue(db, owner, base, value)
	clearValueRemainder(db, owner, base, oldLen, uint64(len(value)))

	writeUint64(db, owner, lenSlot, uint64(len(value)))
	writeUint64(db, owner, metaSlot(base, "createdAt"), createdAt)
	writeUint64(db, owner, metaSlot(base, "expireAt"), expireAt)
	writeBool(db, owner, metaSlot(base, "exists"), true)
	appendExpiryIndex(db, owner, base, expireAt)
}

// Get returns value + meta for a record. found=false means no record exists.
func Get(db vm.StateDB, owner common.Address, namespace string, key []byte) ([]byte, RecordMeta, bool) {
	meta := GetMeta(db, owner, namespace, key)
	if !meta.Exists {
		return nil, meta, false
	}
	base := slotForRecord(namespace, key)
	valueLen := readUint64(db, owner, metaSlot(base, "valueLen"))
	return readValue(db, owner, base, valueLen), meta, true
}

// GetMeta returns persisted metadata for a record.
func GetMeta(db vm.StateDB, owner common.Address, namespace string, key []byte) RecordMeta {
	base := slotForRecord(namespace, key)
	exists := readBool(db, owner, metaSlot(base, "exists"))
	if !exists {
		return RecordMeta{}
	}
	return RecordMeta{
		CreatedAt: readUint64(db, owner, metaSlot(base, "createdAt")),
		ExpireAt:  readUint64(db, owner, metaSlot(base, "expireAt")),
		Exists:    true,
	}
}

// PruneExpiredAt removes records whose expireAt equals the target block.
// It returns the number of records removed.
func PruneExpiredAt(db vm.StateDB, blockNumber uint64) uint64 {
	indexOwner := params.KVRouterAddress
	bucket := expiryBucketBase(blockNumber)
	countSlot := expiryBucketMetaSlot(bucket, "count")
	count := readUint64(db, indexOwner, countSlot)
	if count == 0 {
		return 0
	}
	var pruned uint64
	for i := uint64(0); i < count; i++ {
		ownerSlot := expiryBucketOwnerSlot(bucket, i)
		recordSlot := expiryBucketRecordSlot(bucket, i)
		owner := readAddress(db, indexOwner, ownerSlot)
		base := db.GetState(indexOwner, recordSlot)
		// Always clear index entries after reading.
		db.SetState(indexOwner, ownerSlot, common.Hash{})
		db.SetState(indexOwner, recordSlot, common.Hash{})

		if owner == (common.Address{}) || base == (common.Hash{}) {
			continue
		}
		existsSlot := metaSlot(base, "exists")
		if !readBool(db, owner, existsSlot) {
			continue
		}
		expireAtSlot := metaSlot(base, "expireAt")
		expireAt := readUint64(db, owner, expireAtSlot)
		if expireAt != blockNumber {
			continue
		}
		clearRecord(db, owner, base)
		pruned++
	}
	db.SetState(indexOwner, countSlot, common.Hash{})
	return pruned
}
