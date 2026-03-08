package slashindicator

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
// dedupe and operator query state for the native SlashIndicator path.
type MaliciousVoteEvidenceRecord struct {
	EvidenceHash common.Hash                 `json:"evidenceHash"`
	OffenseKey   common.Hash                 `json:"offenseKey"`
	Number       uint64                      `json:"number"`
	Signer       common.Address              `json:"signer"`
	SubmittedBy  common.Address              `json:"submittedBy"`
	SubmittedAt  uint64                      `json:"submittedAt"`
	Status       MaliciousVoteEvidenceStatus `json:"status"`
}

type MaliciousVoteEvidenceStatus uint8

const (
	MaliciousVoteEvidenceSubmitted MaliciousVoteEvidenceStatus = 1
)

var (
	evidenceCountSlot = crypto.Keccak256Hash([]byte("dpos.evidence.count"))
)

func MaliciousVoteOffenseKey(signer common.Address, number uint64) common.Hash {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], number)
	buf := make([]byte, 0, len("dpos.offense.checkpoint_equivocation")+common.AddressLength+len(n))
	buf = append(buf, []byte("dpos.offense.checkpoint_equivocation")...)
	buf = append(buf, signer.Bytes()...)
	buf = append(buf, n[:]...)
	return crypto.Keccak256Hash(buf)
}

func evidenceExistsSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.exists"), hash[:]...))
}

func offenseExistsSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.offense.exists"), hash[:]...))
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

func evidenceOffenseSlot(hash common.Hash) common.Hash {
	return crypto.Keccak256Hash(append([]byte("dpos.evidence.offense"), hash[:]...))
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

func ReadMaliciousVoteEvidenceCount(db vmtypes.StateDB) uint64 {
	return readUint64Word(db, params.CheckpointSlashIndicatorAddress, evidenceCountSlot)
}

func HasSubmittedMaliciousVoteEvidence(db vmtypes.StateDB, hash common.Hash) bool {
	return readBoolWord(db, params.CheckpointSlashIndicatorAddress, evidenceExistsSlot(hash))
}

func HasRecordedMaliciousVoteOffense(db vmtypes.StateDB, offenseKey common.Hash) bool {
	return readBoolWord(db, params.CheckpointSlashIndicatorAddress, offenseExistsSlot(offenseKey))
}

func ReadMaliciousVoteEvidenceRecord(db vmtypes.StateDB, hash common.Hash) (*MaliciousVoteEvidenceRecord, bool) {
	if !HasSubmittedMaliciousVoteEvidence(db, hash) {
		return nil, false
	}
	return &MaliciousVoteEvidenceRecord{
		EvidenceHash: hash,
		OffenseKey:   readHashWord(db, params.CheckpointSlashIndicatorAddress, evidenceOffenseSlot(hash)),
		Number:       readUint64Word(db, params.CheckpointSlashIndicatorAddress, evidenceNumberSlot(hash)),
		Signer:       readAddressWord(db, params.CheckpointSlashIndicatorAddress, evidenceSignerSlot(hash)),
		SubmittedBy:  readAddressWord(db, params.CheckpointSlashIndicatorAddress, evidenceSubmitterSlot(hash)),
		SubmittedAt:  readUint64Word(db, params.CheckpointSlashIndicatorAddress, evidenceBlockSlot(hash)),
		Status:       MaliciousVoteEvidenceStatus(readUint64Word(db, params.CheckpointSlashIndicatorAddress, evidenceStatusSlot(hash))),
	}, true
}

func appendMaliciousVoteEvidenceRecord(db vmtypes.StateDB, hash, offenseKey common.Hash, number uint64, signer, submitter common.Address, blockNumber uint64) {
	count := ReadMaliciousVoteEvidenceCount(db)
	writeHashWord(db, params.CheckpointSlashIndicatorAddress, evidenceListSlot(count), hash)
	writeUint64Word(db, params.CheckpointSlashIndicatorAddress, evidenceCountSlot, count+1)
	writeBoolWord(db, params.CheckpointSlashIndicatorAddress, evidenceExistsSlot(hash), true)
	writeBoolWord(db, params.CheckpointSlashIndicatorAddress, offenseExistsSlot(offenseKey), true)
	writeHashWord(db, params.CheckpointSlashIndicatorAddress, evidenceOffenseSlot(hash), offenseKey)
	writeUint64Word(db, params.CheckpointSlashIndicatorAddress, evidenceNumberSlot(hash), number)
	writeAddressWord(db, params.CheckpointSlashIndicatorAddress, evidenceSubmitterSlot(hash), submitter)
	writeAddressWord(db, params.CheckpointSlashIndicatorAddress, evidenceSignerSlot(hash), signer)
	writeUint64Word(db, params.CheckpointSlashIndicatorAddress, evidenceBlockSlot(hash), blockNumber)
	writeUint64Word(db, params.CheckpointSlashIndicatorAddress, evidenceStatusSlot(hash), uint64(MaliciousVoteEvidenceSubmitted))
}

func ReadMaliciousVoteEvidenceHashes(db vmtypes.StateDB, limit uint64) []common.Hash {
	count := ReadMaliciousVoteEvidenceCount(db)
	if limit == 0 || limit > count {
		limit = count
	}
	out := make([]common.Hash, 0, limit)
	start := count - limit
	for i := start; i < count; i++ {
		out = append(out, readHashWord(db, params.CheckpointSlashIndicatorAddress, evidenceListSlot(i)))
	}
	return out
}
