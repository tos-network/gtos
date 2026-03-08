package dpos

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/log"
)

const (
	defaultVoteJournalRetentionDays = 30
	voteJournalFilePrefix           = "vote-"
	voteJournalFileSuffix           = ".jsonl"
)

type checkpointVoteJournal struct {
	dir           string
	retentionDays int

	mu           sync.Mutex
	lastPruneDay string
	state        checkpointVoteJournalState
}

type checkpointVoteJournalState struct {
	LastEventAtUnix     int64       `json:"lastEventAtUnix,omitempty"`
	LastEventKind       string      `json:"lastEventKind,omitempty"`
	LatestFinalizedVote *voteRecord `json:"latestFinalizedVote,omitempty"`
	LatestLocalSigned   *voteRecord `json:"latestLocalSigned,omitempty"`
	LatestRebroadcast   *voteRecord `json:"latestRebroadcast,omitempty"`
	LastConflict        *voteRecord `json:"lastConflict,omitempty"`
	LastReceivedVote    *voteRecord `json:"lastReceivedVote,omitempty"`
	LastReceivedStatus  string      `json:"lastReceivedStatus,omitempty"`
	LastReceivedSource  string      `json:"lastReceivedSource,omitempty"`
	LatestCarrierHash   string      `json:"latestCarrierHash,omitempty"`
	LatestCarrierNumber uint64      `json:"latestCarrierNumber,omitempty"`
}

type checkpointVoteJournalRecord struct {
	Timestamp         string      `json:"ts"`
	Kind              string      `json:"kind"`
	Source            string      `json:"source,omitempty"`
	Status            string      `json:"status,omitempty"`
	Reason            string      `json:"reason,omitempty"`
	Vote              *voteRecord `json:"vote,omitempty"`
	PreviousVote      *voteRecord `json:"previousVote,omitempty"`
	Signer            string      `json:"signer,omitempty"`
	SignerPubKey      string      `json:"signerPubKey,omitempty"`
	Signature         string      `json:"signature,omitempty"`
	PreviousSignature string      `json:"previousSignature,omitempty"`
	PreviousHash      string      `json:"previousHash,omitempty"`
	CarrierHash       string      `json:"carrierHash,omitempty"`
	CarrierNumber     uint64      `json:"carrierNumber,omitempty"`
}

type voteRecord struct {
	ChainID          string `json:"chainId,omitempty"`
	Number           uint64 `json:"number"`
	Hash             string `json:"hash"`
	ValidatorSetHash string `json:"validatorSetHash,omitempty"`
}

func newCheckpointVoteJournal(dir string, retentionDays int) (*checkpointVoteJournal, error) {
	if dir == "" {
		return nil, nil
	}
	if retentionDays <= 0 {
		retentionDays = defaultVoteJournalRetentionDays
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	j := &checkpointVoteJournal{
		dir:           dir,
		retentionDays: retentionDays,
	}
	j.loadState()
	j.pruneOldFiles(time.Now().UTC())
	return j, nil
}

func (j *checkpointVoteJournal) RecordLocalSigned(env *types.CheckpointVoteEnvelope, signerPub []byte) {
	j.record(checkpointVoteJournalRecord{
		Kind:      "local_vote_signed",
		Source:    "local",
		Vote:      voteRecordFromVote(envVote(env)),
		Signer:    signerHex(env),
		SignerPubKey: pubHex(signerPub),
		Signature: sigHex(env),
	})
}

func (j *checkpointVoteJournal) RecordReceived(source, status string, env *types.CheckpointVoteEnvelope, signerPub []byte) {
	j.record(checkpointVoteJournalRecord{
		Kind:      "vote_received",
		Source:    source,
		Status:    status,
		Vote:      voteRecordFromVote(envVote(env)),
		Signer:    signerHex(env),
		SignerPubKey: pubHex(signerPub),
		Signature: sigHex(env),
	})
}

func (j *checkpointVoteJournal) RecordConflict(source string, previous, current *types.CheckpointVoteEnvelope, signerPub []byte) {
	j.record(checkpointVoteJournalRecord{
		Kind:              "vote_conflict",
		Source:            source,
		Vote:              voteRecordFromVote(envVote(current)),
		PreviousVote:      voteRecordFromVote(envVote(previous)),
		Signer:            signerHex(current),
		SignerPubKey:      pubHex(signerPub),
		Signature:         sigHex(current),
		PreviousSignature: sigHex(previous),
		PreviousHash:      previousHashHex(previous),
	})
}

func (j *checkpointVoteJournal) RecordConflictGuard(number uint64, chainID interface{ String() string }, signer common.Address, previousHash, attemptedHash, validatorSetHash common.Hash) {
	var chainIDStr string
	if chainID != nil {
		chainIDStr = chainID.String()
	}
	j.record(checkpointVoteJournalRecord{
		Kind:   "vote_conflict",
		Source: "local-db-guard",
		Reason: "signed_checkpoint_guard",
		Vote: &voteRecord{
			ChainID:          chainIDStr,
			Number:           number,
			Hash:             attemptedHash.Hex(),
			ValidatorSetHash: validatorSetHash.Hex(),
		},
		Signer:       signer.Hex(),
		SignerPubKey: "",
		PreviousHash: previousHash.Hex(),
	})
}

func (j *checkpointVoteJournal) RecordRebroadcast(env *types.CheckpointVoteEnvelope, signerPub []byte) {
	j.record(checkpointVoteJournalRecord{
		Kind:      "vote_rebroadcast",
		Source:    "restart-gossip",
		Vote:      voteRecordFromVote(envVote(env)),
		Signer:    signerHex(env),
		SignerPubKey: pubHex(signerPub),
		Signature: sigHex(env),
	})
}

func (j *checkpointVoteJournal) RecordFinalized(vote types.CheckpointVote, carrierNumber uint64, carrierHash common.Hash) {
	j.record(checkpointVoteJournalRecord{
		Kind:          "vote_finalized",
		Vote:          voteRecordFromVote(&vote),
		CarrierHash:   carrierHash.Hex(),
		CarrierNumber: carrierNumber,
	})
}

func (j *checkpointVoteJournal) record(rec checkpointVoteJournalRecord) {
	if j == nil {
		return
	}
	now := time.Now().UTC()
	rec.Timestamp = now.Format(time.RFC3339)

	j.mu.Lock()
	defer j.mu.Unlock()

	j.pruneOldFiles(now)
	path := filepath.Join(j.dir, voteJournalFilename(now))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Warn("Checkpoint vote journal failed to open file", "path", path, "err", err)
		return
	}
	enc := json.NewEncoder(f)
	if err := enc.Encode(rec); err != nil {
		log.Warn("Checkpoint vote journal failed to append record", "path", path, "err", err)
		_ = f.Close()
		return
	}
	if err := f.Close(); err != nil {
		log.Warn("Checkpoint vote journal failed to close file", "path", path, "err", err)
	}

	j.state.LastEventAtUnix = now.Unix()
	j.state.LastEventKind = rec.Kind
	switch rec.Kind {
	case "local_vote_signed":
		j.state.LatestLocalSigned = rec.Vote
	case "vote_received":
		j.state.LastReceivedVote = rec.Vote
		j.state.LastReceivedStatus = rec.Status
		j.state.LastReceivedSource = rec.Source
	case "vote_conflict":
		j.state.LastConflict = rec.Vote
	case "vote_rebroadcast":
		j.state.LatestRebroadcast = rec.Vote
	case "vote_finalized":
		j.state.LatestFinalizedVote = rec.Vote
		j.state.LatestCarrierHash = rec.CarrierHash
		j.state.LatestCarrierNumber = rec.CarrierNumber
	}
	j.writeStateLocked()
}

func (j *checkpointVoteJournal) loadState() {
	path := filepath.Join(j.dir, "state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var st checkpointVoteJournalState
	if err := json.Unmarshal(data, &st); err != nil {
		log.Warn("Checkpoint vote journal failed to load state", "path", path, "err", err)
		return
	}
	j.state = st
}

func (j *checkpointVoteJournal) writeStateLocked() {
	path := filepath.Join(j.dir, "state.json")
	data, err := json.MarshalIndent(j.state, "", "  ")
	if err != nil {
		log.Warn("Checkpoint vote journal failed to marshal state", "path", path, "err", err)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Warn("Checkpoint vote journal failed to write state", "path", path, "err", err)
	}
}

func (j *checkpointVoteJournal) pruneOldFiles(now time.Time) {
	if j.retentionDays <= 0 {
		return
	}
	day := now.Format("2006-01-02")
	if j.lastPruneDay == day {
		return
	}
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		log.Warn("Checkpoint vote journal failed to read directory for pruning", "dir", j.dir, "err", err)
		return
	}
	cutoff := now.AddDate(0, 0, -j.retentionDays)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, voteJournalFilePrefix) || !strings.HasSuffix(name, voteJournalFileSuffix) {
			continue
		}
		datePart := strings.TrimSuffix(strings.TrimPrefix(name, voteJournalFilePrefix), voteJournalFileSuffix)
		fileDay, err := time.Parse("2006-01-02", datePart)
		if err != nil {
			continue
		}
		if fileDay.Before(cutoff) {
			if err := os.Remove(filepath.Join(j.dir, name)); err != nil && !os.IsNotExist(err) {
				log.Warn("Checkpoint vote journal failed to prune old file", "path", filepath.Join(j.dir, name), "err", err)
			}
		}
	}
	j.lastPruneDay = day
}

func voteJournalFilename(now time.Time) string {
	return fmt.Sprintf("%s%s%s", voteJournalFilePrefix, now.Format("2006-01-02"), voteJournalFileSuffix)
}

func voteRecordFromVote(v *types.CheckpointVote) *voteRecord {
	if v == nil {
		return nil
	}
	var chainID string
	if v.ChainID != nil {
		chainID = v.ChainID.String()
	}
	return &voteRecord{
		ChainID:          chainID,
		Number:           v.Number,
		Hash:             v.Hash.Hex(),
		ValidatorSetHash: v.ValidatorSetHash.Hex(),
	}
}

func envVote(env *types.CheckpointVoteEnvelope) *types.CheckpointVote {
	if env == nil {
		return nil
	}
	return &env.Vote
}

func signerHex(env *types.CheckpointVoteEnvelope) string {
	if env == nil {
		return ""
	}
	return env.Signer.Hex()
}

func sigHex(env *types.CheckpointVoteEnvelope) string {
	if env == nil {
		return ""
	}
	return common.Bytes2Hex(env.Signature[:])
}

func pubHex(pub []byte) string {
	if len(pub) == 0 {
		return ""
	}
	return common.Bytes2Hex(pub)
}

func previousHashHex(env *types.CheckpointVoteEnvelope) string {
	if env == nil {
		return ""
	}
	return env.Vote.Hash.Hex()
}
