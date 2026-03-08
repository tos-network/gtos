package dpos

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/slashindicator"
	"github.com/tos-network/gtos/core/types"
	vmtypes "github.com/tos-network/gtos/core/vmtypes"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

type MaliciousVoteEvidenceRecord = slashindicator.MaliciousVoteEvidenceRecord

type MaliciousVoteEvidenceStatus = slashindicator.MaliciousVoteEvidenceStatus

const (
	MaliciousVoteEvidenceSubmitted = slashindicator.MaliciousVoteEvidenceSubmitted
)

func MaliciousVoteOffenseKey(signer common.Address, number uint64) common.Hash {
	return slashindicator.MaliciousVoteOffenseKey(signer, number)
}

func ReadMaliciousVoteEvidenceCount(db vmtypes.StateDB) uint64 {
	return slashindicator.ReadMaliciousVoteEvidenceCount(db)
}

func HasSubmittedMaliciousVoteEvidence(db vmtypes.StateDB, hash common.Hash) bool {
	return slashindicator.HasSubmittedMaliciousVoteEvidence(db, hash)
}

func HasRecordedMaliciousVoteOffense(db vmtypes.StateDB, offenseKey common.Hash) bool {
	return slashindicator.HasRecordedMaliciousVoteOffense(db, offenseKey)
}

func ReadMaliciousVoteEvidenceRecord(db vmtypes.StateDB, hash common.Hash) (*MaliciousVoteEvidenceRecord, bool) {
	return slashindicator.ReadMaliciousVoteEvidenceRecord(db, hash)
}

func ReadMaliciousVoteEvidenceHashes(db vmtypes.StateDB, limit uint64) []common.Hash {
	return slashindicator.ReadMaliciousVoteEvidenceHashes(db, limit)
}

func PackSubmitFinalityViolationEvidence(evidence *types.MaliciousVoteEvidence) ([]byte, error) {
	return slashindicator.PackSubmitFinalityViolationEvidence(evidence)
}

func DecodeSubmitFinalityViolationEvidence(input []byte) (*types.MaliciousVoteEvidence, error) {
	return slashindicator.DecodeSubmitFinalityViolationEvidence(input)
}

func ExecuteSlashIndicator(msg sysaction.Msg, db vmtypes.StateDB, blockNumber *big.Int, chainConfig *params.ChainConfig) (uint64, error) {
	return slashindicator.Execute(msg, db, blockNumber, chainConfig)
}
