package rawdb

import (
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/log"
	"github.com/tos-network/gtos/rlp"
	"github.com/tos-network/gtos/tosdb"
)

// Proof sidecar key prefixes. Single-byte prefix "p" is reserved for proof data.
var (
	proofSidecarPrefix = []byte("ps") // proofSidecarPrefix + blockHash -> BatchProofSidecar
	provedHeadKey      = []byte("LastProved")
)

// proofSidecarKey returns the database key for a proof sidecar keyed by block hash.
func proofSidecarKey(blockHash common.Hash) []byte {
	return append(proofSidecarPrefix, blockHash.Bytes()...)
}

// ReadProofSidecar retrieves the proof sidecar associated with a block hash.
// Returns nil if no sidecar is stored.
func ReadProofSidecar(db tosdb.KeyValueReader, blockHash common.Hash) *types.BatchProofSidecar {
	data, _ := db.Get(proofSidecarKey(blockHash))
	if len(data) == 0 {
		return nil
	}
	sidecar := new(types.BatchProofSidecar)
	if err := rlp.DecodeBytes(data, sidecar); err != nil {
		log.Error("Invalid proof sidecar RLP", "blockHash", blockHash, "err", err)
		return nil
	}
	return sidecar
}

// WriteProofSidecar stores a proof sidecar keyed by block hash.
func WriteProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash, sidecar *types.BatchProofSidecar) {
	data, err := rlp.EncodeToBytes(sidecar)
	if err != nil {
		log.Crit("Failed to RLP encode proof sidecar", "err", err)
	}
	if err := db.Put(proofSidecarKey(blockHash), data); err != nil {
		log.Crit("Failed to store proof sidecar", "err", err)
	}
}

// HasProofSidecar returns true if a proof sidecar exists for the given block hash.
func HasProofSidecar(db tosdb.Reader, blockHash common.Hash) bool {
	has, _ := db.Has(proofSidecarKey(blockHash))
	return has
}

// DeleteProofSidecar removes the proof sidecar for a block hash.
// Used during chain reorganization to clean up orphaned sidecars.
func DeleteProofSidecar(db tosdb.KeyValueWriter, blockHash common.Hash) {
	if err := db.Delete(proofSidecarKey(blockHash)); err != nil {
		log.Crit("Failed to delete proof sidecar", "err", err)
	}
}

// ReadProvedHead retrieves the hash of the latest proved block.
// Returns the zero hash if no proved head has been set.
func ReadProvedHead(db tosdb.KeyValueReader) common.Hash {
	data, _ := db.Get(provedHeadKey)
	if len(data) == 0 {
		return common.Hash{}
	}
	return common.BytesToHash(data)
}

// WriteProvedHead stores the hash of the latest proved block.
func WriteProvedHead(db tosdb.KeyValueWriter, hash common.Hash) {
	if err := db.Put(provedHeadKey, hash.Bytes()); err != nil {
		log.Crit("Failed to store proved head hash", "err", err)
	}
}
