package dpos

import (
	"encoding/binary"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/tosdb"
)

// signedCheckpointKeyPrefix is the database key prefix for signed-checkpoint records.
// Full key: prefix + big-endian uint64(number)
// Value:    32-byte checkpoint hash
const signedCheckpointKeyPrefix = "dpos-signed-cp-"

// signedCheckpointKey returns the database key for the signed checkpoint record at number.
func signedCheckpointKey(number uint64) []byte {
	key := make([]byte, len(signedCheckpointKeyPrefix)+8)
	copy(key, signedCheckpointKeyPrefix)
	binary.BigEndian.PutUint64(key[len(signedCheckpointKeyPrefix):], number)
	return key
}

// ReadSignedCheckpoint reads the checkpoint hash that this validator durably signed at
// the given checkpoint number. Returns (hash, true) if a record exists, (zero, false)
// otherwise.
//
// This record is the double-sign guard: before signing a new checkpoint at number N,
// a validator must check this store. If a record exists with a different hash, the
// validator must not sign.
func ReadSignedCheckpoint(db tosdb.KeyValueReader, number uint64) (common.Hash, bool) {
	val, err := db.Get(signedCheckpointKey(number))
	if err != nil || len(val) != common.HashLength {
		return common.Hash{}, false
	}
	var h common.Hash
	copy(h[:], val)
	return h, true
}

// WriteSignedCheckpoint durably records that this node has signed (number, hash).
// This write MUST happen before the signed vote is gossiped to peers (§11, step 7).
//
// Once written, the validator will refuse to sign a different hash at the same
// checkpoint number, providing the core double-sign safety guarantee.
func WriteSignedCheckpoint(db tosdb.KeyValueWriter, number uint64, hash common.Hash) error {
	return db.Put(signedCheckpointKey(number), hash[:])
}

// ListUnsettledSignedCheckpoints returns all signed-checkpoint records whose number
// is strictly greater than finalizedNumber. These represent checkpoints this node has
// signed but that have not yet been finalized on-chain.
//
// On restart (§11, Restart re-gossip), the validator iterates these records and
// re-gossips the corresponding CheckpointVoteEnvelopes to peers, ensuring that a
// crash does not permanently stall a quorum that was close to forming.
//
// Returns (numbers, hashes, error). The two slices are parallel: numbers[i] and
// hashes[i] describe the same signed checkpoint.
func ListUnsettledSignedCheckpoints(db tosdb.KeyValueStore, finalizedNumber uint64) ([]uint64, []common.Hash, error) {
	prefix := []byte(signedCheckpointKeyPrefix)
	it := db.NewIterator(prefix, nil)
	defer it.Release()

	var numbers []uint64
	var hashes []common.Hash

	for it.Next() {
		key := it.Key()
		// Key layout: prefix(15B) + number(8B)
		if len(key) < len(prefix)+8 {
			continue
		}
		number := binary.BigEndian.Uint64(key[len(prefix):])
		if number <= finalizedNumber {
			continue
		}
		val := it.Value()
		if len(val) != common.HashLength {
			continue
		}
		var h common.Hash
		copy(h[:], val)
		numbers = append(numbers, number)
		hashes = append(hashes, h)
	}
	if err := it.Error(); err != nil {
		return nil, nil, err
	}
	return numbers, hashes, nil
}
