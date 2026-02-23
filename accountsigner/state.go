package accountsigner

import (
	"encoding/binary"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
)

const signerChunkSize = 32

var (
	signerExistsSlot    = crypto.Keccak256Hash([]byte("gtos.account.signer.exists"))
	signerTypeLenSlot   = crypto.Keccak256Hash([]byte("gtos.account.signer.typeLen"))
	signerValueLenSlot  = crypto.Keccak256Hash([]byte("gtos.account.signer.valueLen"))
	signerTypeBaseSlot  = crypto.Keccak256Hash([]byte("gtos.account.signer.type"))
	signerValueBaseSlot = crypto.Keccak256Hash([]byte("gtos.account.signer.value"))
)

func signerChunkSlot(base common.Hash, index uint64) common.Hash {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], index)
	buf := make([]byte, 0, len(base)+1+len("chunk")+8)
	buf = append(buf, base[:]...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte("chunk")...)
	buf = append(buf, idx[:]...)
	return common.BytesToHash(crypto.Keccak256(buf))
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

func readUint64(db vm.StateDB, owner common.Address, slot common.Hash) uint64 {
	raw := db.GetState(owner, slot)
	return binary.BigEndian.Uint64(raw[24:])
}

func writeUint64(db vm.StateDB, owner common.Address, slot common.Hash, n uint64) {
	var word common.Hash
	binary.BigEndian.PutUint64(word[24:], n)
	db.SetState(owner, slot, word)
}

func chunkCount(valueLen uint64) uint64 {
	if valueLen == 0 {
		return 0
	}
	return (valueLen + signerChunkSize - 1) / signerChunkSize
}

func readBytes(db vm.StateDB, owner common.Address, base common.Hash, valueLen uint64) []byte {
	if valueLen == 0 {
		return nil
	}
	value := make([]byte, valueLen)
	chunks := chunkCount(valueLen)
	for i := uint64(0); i < chunks; i++ {
		slot := signerChunkSlot(base, i)
		word := db.GetState(owner, slot)
		start := i * signerChunkSize
		end := start + signerChunkSize
		if end > valueLen {
			end = valueLen
		}
		copy(value[start:end], word[:end-start])
	}
	return value
}

func writeBytes(db vm.StateDB, owner common.Address, base common.Hash, value []byte) {
	newChunks := chunkCount(uint64(len(value)))
	for i := uint64(0); i < newChunks; i++ {
		start := i * signerChunkSize
		end := start + signerChunkSize
		if end > uint64(len(value)) {
			end = uint64(len(value))
		}
		var word common.Hash
		copy(word[:], value[start:end])
		db.SetState(owner, signerChunkSlot(base, i), word)
	}
}

func clearBytesRemainder(db vm.StateDB, owner common.Address, base common.Hash, fromLen, toLen uint64) {
	oldChunks := chunkCount(fromLen)
	newChunks := chunkCount(toLen)
	for i := newChunks; i < oldChunks; i++ {
		db.SetState(owner, signerChunkSlot(base, i), common.Hash{})
	}
}

// Set writes signer metadata for account.
func Set(db vm.StateDB, account common.Address, signerType, signerValue string) {
	oldTypeLen := readUint64(db, account, signerTypeLenSlot)
	oldValueLen := readUint64(db, account, signerValueLenSlot)
	typeBytes := []byte(signerType)
	valueBytes := []byte(signerValue)

	writeBytes(db, account, signerTypeBaseSlot, typeBytes)
	clearBytesRemainder(db, account, signerTypeBaseSlot, oldTypeLen, uint64(len(typeBytes)))
	writeBytes(db, account, signerValueBaseSlot, valueBytes)
	clearBytesRemainder(db, account, signerValueBaseSlot, oldValueLen, uint64(len(valueBytes)))

	writeUint64(db, account, signerTypeLenSlot, uint64(len(typeBytes)))
	writeUint64(db, account, signerValueLenSlot, uint64(len(valueBytes)))
	writeBool(db, account, signerExistsSlot, true)
}

// Get returns signer metadata for account. ok=false means fallback-to-address should apply.
func Get(db vm.StateDB, account common.Address) (signerType, signerValue string, ok bool) {
	if !readBool(db, account, signerExistsSlot) {
		return "", "", false
	}
	typeLen := readUint64(db, account, signerTypeLenSlot)
	valueLen := readUint64(db, account, signerValueLenSlot)
	typeBytes := readBytes(db, account, signerTypeBaseSlot, typeLen)
	valueBytes := readBytes(db, account, signerValueBaseSlot, valueLen)
	return string(typeBytes), string(valueBytes), true
}
