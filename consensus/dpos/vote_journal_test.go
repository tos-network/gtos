package dpos

import (
	"crypto/ed25519"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
)

func TestCheckpointVoteJournalLifecycle(t *testing.T) {
	dir := t.TempDir()
	journal, err := newCheckpointVoteJournal(dir, 30)
	if err != nil {
		t.Fatalf("newCheckpointVoteJournal: %v", err)
	}
	vote := types.CheckpointVote{
		Number:           50,
		Hash:             common.HexToHash("0x50"),
		ValidatorSetHash: common.HexToHash("0x99"),
	}
	envA := &types.CheckpointVoteEnvelope{
		Vote:      vote,
		Signer:    common.HexToAddress("0x100"),
		Signature: [64]byte{0xaa},
	}
	envB := &types.CheckpointVoteEnvelope{
		Vote: types.CheckpointVote{
			Number:           50,
			Hash:             common.HexToHash("0x51"),
			ValidatorSetHash: common.HexToHash("0x99"),
		},
		Signer:    common.HexToAddress("0x100"),
		Signature: [64]byte{0xbb},
	}

	journal.RecordLocalSigned(envA)
	journal.RecordReceived("p2p", "admitted", envA)
	journal.RecordConflict("p2p", envA, envB)
	journal.RecordRebroadcast(envA)
	journal.RecordFinalized(vote, 67, common.HexToHash("0x67"))

	entries := readVoteJournalFile(t, filepath.Join(dir, voteJournalFilename(time.Now().UTC())))
	wantKinds := []string{
		"local_vote_signed",
		"vote_received",
		"vote_conflict",
		"vote_rebroadcast",
		"vote_finalized",
	}
	for _, kind := range wantKinds {
		if !strings.Contains(entries, "\"kind\":\""+kind+"\"") {
			t.Fatalf("journal missing kind %q: %s", kind, entries)
		}
	}

	state := readVoteJournalState(t, filepath.Join(dir, "state.json"))
	if state.LastEventKind != "vote_finalized" {
		t.Fatalf("LastEventKind = %q, want vote_finalized", state.LastEventKind)
	}
	if state.LatestFinalizedVote == nil || state.LatestFinalizedVote.Number != 50 {
		t.Fatalf("LatestFinalizedVote = %#v, want checkpoint 50", state.LatestFinalizedVote)
	}
	if state.LatestLocalSigned == nil || state.LatestLocalSigned.Hash != vote.Hash.Hex() {
		t.Fatalf("LatestLocalSigned = %#v, want %s", state.LatestLocalSigned, vote.Hash.Hex())
	}
}

func TestCheckpointVoteJournalPrunesOldFiles(t *testing.T) {
	dir := t.TempDir()
	oldFile := filepath.Join(dir, voteJournalFilename(time.Now().UTC().AddDate(0, 0, -(defaultVoteJournalRetentionDays+2))))
	if err := os.WriteFile(oldFile, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	journal, err := newCheckpointVoteJournal(dir, defaultVoteJournalRetentionDays)
	if err != nil {
		t.Fatalf("newCheckpointVoteJournal: %v", err)
	}
	journal.RecordFinalized(types.CheckpointVote{
		Number: 1,
		Hash:   common.HexToHash("0x1"),
	}, 2, common.HexToHash("0x2"))

	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Fatalf("old journal file still present: err=%v", err)
	}
}

func TestOnCanonicalBlockWritesVoteFinalizedJournal(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	d, err := New(&params.DPoSConfig{
		Epoch:          208,
		MaxValidators:  21,
		PeriodMs:       3000,
		TurnLength:     params.DPoSTurnLength,
		SealSignerType: params.DPoSSealSignerTypeEd25519,
	}, db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.SetVoteJournalPath(t.TempDir()); err != nil {
		t.Fatalf("SetVoteJournalPath: %v", err)
	}

	pub, _, _ := testEd25519Key(0x11)
	d.chainID = params.TestChainConfig.ChainID
	finalizedHeader := &types.Header{
		Number: bigInt(10),
		Extra:  make([]byte, extraVanity+extraSealEd25519),
	}
	copy(finalizedHeader.Extra[len(finalizedHeader.Extra)-extraSealEd25519:], append(pub, make([]byte, ed25519.SignatureSize)...))
	rawdb.WriteHeader(db, finalizedHeader)

	carrier := types.NewBlockWithHeader(&types.Header{Number: bigInt(11)})
	vsHash := common.HexToHash("0xbeef")
	d.stageFinalityResult(carrier.Hash(), finalizedHeader.Number.Uint64(), finalizedHeader.Hash(), vsHash)

	d.OnCanonicalBlock(carrier)

	entries := readVoteJournalFile(t, filepath.Join(d.voteJournal.dir, voteJournalFilename(time.Now().UTC())))
	if !strings.Contains(entries, "\"kind\":\"vote_finalized\"") {
		t.Fatalf("journal missing vote_finalized entry: %s", entries)
	}
	if !strings.Contains(entries, finalizedHeader.Hash().Hex()) {
		t.Fatalf("journal missing finalized hash %s: %s", finalizedHeader.Hash().Hex(), entries)
	}
}

func TestExportMaliciousVoteEvidence(t *testing.T) {
	dir := t.TempDir()
	journal, err := newCheckpointVoteJournal(dir, 30)
	if err != nil {
		t.Fatalf("newCheckpointVoteJournal: %v", err)
	}
	voteA := types.CheckpointVote{
		ChainID:          big.NewInt(1337),
		Number:           64,
		Hash:             common.HexToHash("0xa"),
		ValidatorSetHash: common.HexToHash("0x10"),
	}
	voteB := types.CheckpointVote{
		ChainID:          big.NewInt(1337),
		Number:           64,
		Hash:             common.HexToHash("0xb"),
		ValidatorSetHash: common.HexToHash("0x10"),
	}
	envA := &types.CheckpointVoteEnvelope{
		Vote:      voteA,
		Signer:    common.HexToAddress("0x100"),
		Signature: [64]byte{0x1},
	}
	envB := &types.CheckpointVoteEnvelope{
		Vote:      voteB,
		Signer:    common.HexToAddress("0x100"),
		Signature: [64]byte{0x2},
	}
	journal.RecordConflict("p2p", envA, envB)

	evidence, err := ExportMaliciousVoteEvidence(dir, 64, envA.Signer)
	if err != nil {
		t.Fatalf("ExportMaliciousVoteEvidence: %v", err)
	}
	if err := evidence.Validate(); err != nil {
		t.Fatalf("evidence.Validate: %v", err)
	}
	if evidence.Number != 64 || evidence.Signer != envA.Signer {
		t.Fatalf("unexpected evidence header: %#v", evidence)
	}
	if evidence.First.Vote.Hash == evidence.Second.Vote.Hash {
		t.Fatalf("expected conflicting vote hashes, got identical evidence %#v", evidence)
	}
}

func TestStageMaliciousVoteEvidence(t *testing.T) {
	evidence, err := types.NewMaliciousVoteEvidence(
		&types.CheckpointVoteEnvelope{
			Vote: types.CheckpointVote{
				ChainID:          big.NewInt(1),
				Number:           10,
				Hash:             common.HexToHash("0x01"),
				ValidatorSetHash: common.HexToHash("0x11"),
			},
			Signer:    common.HexToAddress("0x100"),
			Signature: [64]byte{0x1},
		},
		&types.CheckpointVoteEnvelope{
			Vote: types.CheckpointVote{
				ChainID:          big.NewInt(1),
				Number:           10,
				Hash:             common.HexToHash("0x02"),
				ValidatorSetHash: common.HexToHash("0x11"),
			},
			Signer:    common.HexToAddress("0x100"),
			Signature: [64]byte{0x2},
		},
	)
	if err != nil {
		t.Fatalf("NewMaliciousVoteEvidence: %v", err)
	}
	outbox := t.TempDir()
	path, err := StageMaliciousVoteEvidence(evidence, outbox)
	if err != nil {
		t.Fatalf("StageMaliciousVoteEvidence: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("staged file missing: %v", err)
	}
}

func readVoteJournalFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return string(data)
}

func readVoteJournalState(t *testing.T, path string) checkpointVoteJournalState {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	var state checkpointVoteJournalState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("Unmarshal(%s): %v", path, err)
	}
	return state
}

func bigInt(v int64) *big.Int { return big.NewInt(v) }
