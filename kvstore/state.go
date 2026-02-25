package kvstore

import (
	"encoding/binary"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
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
}

// Get returns value + meta for a record. found=false if no record exists or it
// has expired at the given currentBlock height.
func Get(db vm.StateDB, owner common.Address, namespace string, key []byte, currentBlock uint64) ([]byte, RecordMeta, bool) {
	meta := GetMeta(db, owner, namespace, key, currentBlock)
	if !meta.Exists {
		return nil, RecordMeta{}, false
	}
	base := slotForRecord(namespace, key)
	valueLen := readUint64(db, owner, metaSlot(base, "valueLen"))
	return readValue(db, owner, base, valueLen), meta, true
}

// GetMeta returns persisted metadata for a record. Exists=false if no record
// exists or its expireAt <= currentBlock (lazy expiry).
func GetMeta(db vm.StateDB, owner common.Address, namespace string, key []byte, currentBlock uint64) RecordMeta {
	base := slotForRecord(namespace, key)
	exists := readBool(db, owner, metaSlot(base, "exists"))
	if !exists {
		return RecordMeta{}
	}
	expireAt := readUint64(db, owner, metaSlot(base, "expireAt"))
	if expireAt <= currentBlock {
		return RecordMeta{}
	}
	return RecordMeta{
		CreatedAt: readUint64(db, owner, metaSlot(base, "createdAt")),
		ExpireAt:  expireAt,
		Exists:    true,
	}
}

