package dpos

import (
	"encoding/binary"
	"math/big"

	"github.com/tos-network/gtos/common"
	vmtypes "github.com/tos-network/gtos/core/vmtypes"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// MaliciousVoteEvidenceRecord is the on-chain summary stored for a submitted
// checkpoint malicious-vote evidence item. The full canonical evidence body is
// preserved in the submission transaction input; this record provides indexing,
// dedupe, and operator query state.
type MaliciousVoteEvidenceRecord struct {
	EvidenceHash  common.Hash                 `json:"evidenceHash"`
	Number        uint64                      `json:"number"`
	Signer        common.Address              `json:"signer"`
	SubmittedBy   common.Address              `json:"submittedBy"`
	SubmittedAt   uint64                      `json:"submittedAt"`
	Status        MaliciousVoteEvidenceStatus `json:"status"`
	AdjudicatedBy common.Address              `json:"adjudicatedBy"`
	AdjudicatedAt uint64                      `json:"adjudicatedAt"`
	SlashAmount   *big.Int                    `json:"slashAmount"`
}

type MaliciousVoteEvidenceStatus uint8

const (
	MaliciousVoteEvidenceSubmitted   MaliciousVoteEvidenceStatus = 1
	MaliciousVoteEvidenceAdjudicated MaliciousVoteEvidenceStatus = 2
)

var (
	evidenceCountSlot = crypto.Keccak256Hash([]byte("dpos.evidence.count"))
)

func evidenceExistsSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.exists"), hash[:]...))
}

func evidenceListSlot(i uint64) common.Hash {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], i)
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.list"), idx[:]...))
}

func evidenceSubmitterSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.submitter"), hash[:]...))
}

func evidenceSignerSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.signer"), hash[:]...))
}

func evidenceNumberSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.number"), hash[:]...))
}

func evidenceBlockSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.block"), hash[:]...))
}

func evidenceStatusSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.status"), hash[:]...))
}

func evidenceAdjudicatorSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.adjudicator"), hash[:]...))
}

func evidenceAdjudicatedAtSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.adjudicatedAt"), hash[:]...))
}

func evidenceSlashAmountSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.slashAmount"), hash[:]...))
}

func writeUint64Word(db vmtypes.StateDB, owner common.Address, slot common.Hash, n uint64) {
	var word common.Hash
	binary.BigEndian.PutUint64(word[24:], n)
	db.SetState(owner, slot, word)
}

func readUint64Word(db vmtypes.StateDB, owner common.Address, slot common.Hash) uint64 {
	raw := db.GetState(owner, slot)
	return binary.BigEndian.Uint64(raw[24:])
}

func readBoolWord(db vmtypes.StateDB, owner common.Address, slot common.Hash) bool {
	return db.GetState(owner, slot)[31] != 0
}

func writeBoolWord(db vmtypes.StateDB, owner common.Address, slot common.Hash, v bool) {
	var word common.Hash
	if v {
		word[31] = 1
	}
	db.SetState(owner, slot, word)
}

func readAddressWord(db vmtypes.StateDB, owner common.Address, slot common.Hash) common.Address {
	raw := db.GetState(owner, slot)
	return common.BytesToAddress(raw[:])
}

func writeAddressWord(db vmtypes.StateDB, owner common.Address, slot common.Hash, addr common.Address) {
	var word common.Hash
	copy(word[:], addr.Bytes())
	db.SetState(owner, slot, word)
}

func readHashWord(db vmtypes.StateDB, owner common.Address, slot common.Hash) common.Hash {
	return db.GetState(owner, slot)
}

func writeHashWord(db vmtypes.StateDB, owner common.Address, slot common.Hash, hash common.Hash) {
	db.SetState(owner, slot, hash)
}

func readBigWord(db vmtypes.StateDB, owner common.Address, slot common.Hash) *big.Int {
	return db.GetState(owner, slot).Big()
}

func writeBigWord(db vmtypes.StateDB, owner common.Address, slot common.Hash, n *big.Int) {
	if n == nil {
		n = new(big.Int)
	}
	db.SetState(owner, slot, common.BigToHash(n))
}

func ReadMaliciousVoteEvidenceCount(db vmtypes.StateDB) uint64 {
	return readUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceCountSlot)
}

func HasSubmittedMaliciousVoteEvidence(db vmtypes.StateDB, hash common.Hash) bool {
	return readBoolWord(db, params.CheckpointEvidenceRegistryAddress, evidenceExistsSlot(hash))
}

func ReadMaliciousVoteEvidenceRecord(db vmtypes.StateDB, hash common.Hash) (*MaliciousVoteEvidenceRecord, bool) {
	if !HasSubmittedMaliciousVoteEvidence(db, hash) {
		return nil, false
	}
	return &MaliciousVoteEvidenceRecord{
		EvidenceHash:  hash,
		Number:        readUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceNumberSlot(hash)),
		Signer:        readAddressWord(db, params.CheckpointEvidenceRegistryAddress, evidenceSignerSlot(hash)),
		SubmittedBy:   readAddressWord(db, params.CheckpointEvidenceRegistryAddress, evidenceSubmitterSlot(hash)),
		SubmittedAt:   readUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceBlockSlot(hash)),
		Status:        MaliciousVoteEvidenceStatus(readUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceStatusSlot(hash))),
		AdjudicatedBy: readAddressWord(db, params.CheckpointEvidenceRegistryAddress, evidenceAdjudicatorSlot(hash)),
		AdjudicatedAt: readUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceAdjudicatedAtSlot(hash)),
		SlashAmount:   readBigWord(db, params.CheckpointEvidenceRegistryAddress, evidenceSlashAmountSlot(hash)),
	}, true
}

func appendMaliciousVoteEvidenceRecord(db vmtypes.StateDB, hash common.Hash, number uint64, signer, submitter common.Address, blockNumber uint64) {
	count := ReadMaliciousVoteEvidenceCount(db)
	writeHashWord(db, params.CheckpointEvidenceRegistryAddress, evidenceListSlot(count), hash)
	writeUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceCountSlot, count+1)
	writeBoolWord(db, params.CheckpointEvidenceRegistryAddress, evidenceExistsSlot(hash), true)
	writeUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceNumberSlot(hash), number)
	writeAddressWord(db, params.CheckpointEvidenceRegistryAddress, evidenceSubmitterSlot(hash), submitter)
	writeAddressWord(db, params.CheckpointEvidenceRegistryAddress, evidenceSignerSlot(hash), signer)
	writeUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceBlockSlot(hash), blockNumber)
	writeUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceStatusSlot(hash), uint64(MaliciousVoteEvidenceSubmitted))
	writeAddressWord(db, params.CheckpointEvidenceRegistryAddress, evidenceAdjudicatorSlot(hash), common.Address{})
	writeUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceAdjudicatedAtSlot(hash), 0)
	writeBigWord(db, params.CheckpointEvidenceRegistryAddress, evidenceSlashAmountSlot(hash), new(big.Int))
}

func adjudicateMaliciousVoteEvidenceRecord(db vmtypes.StateDB, hash common.Hash, adjudicator common.Address, blockNumber uint64, slashAmount *big.Int) {
	writeUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceStatusSlot(hash), uint64(MaliciousVoteEvidenceAdjudicated))
	writeAddressWord(db, params.CheckpointEvidenceRegistryAddress, evidenceAdjudicatorSlot(hash), adjudicator)
	writeUint64Word(db, params.CheckpointEvidenceRegistryAddress, evidenceAdjudicatedAtSlot(hash), blockNumber)
	writeBigWord(db, params.CheckpointEvidenceRegistryAddress, evidenceSlashAmountSlot(hash), slashAmount)
}

func ReadMaliciousVoteEvidenceHashes(db vmtypes.StateDB, limit uint64) []common.Hash {
	count := ReadMaliciousVoteEvidenceCount(db)
	if limit == 0 || limit > count {
		limit = count
	}
	out := make([]common.Hash, 0, limit)
	start := count - limit
	for i := start; i < count; i++ {
		out = append(out, readHashWord(db, params.CheckpointEvidenceRegistryAddress, evidenceListSlot(i)))
	}
	return out
}
