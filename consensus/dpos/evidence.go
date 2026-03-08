package dpos

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
)

// ExportMaliciousVoteEvidence scans a vote journal and exports the first
// canonical checkpoint equivocation evidence matching (number, signer).
func ExportMaliciousVoteEvidence(journalDir string, number uint64, signer common.Address) (*types.MaliciousVoteEvidence, error) {
	files, err := voteJournalFiles(journalDir)
	if err != nil {
		return nil, err
	}
	for _, path := range files {
		evidence, err := exportMaliciousVoteEvidenceFromFile(path, number, signer)
		if err != nil {
			return nil, err
		}
		if evidence != nil {
			return evidence, nil
		}
	}
	return nil, fmt.Errorf("dpos: no malicious vote evidence found for signer %s at checkpoint %d", signer.Hex(), number)
}

// StageMaliciousVoteEvidence validates evidence and writes it to an outbox path
// for future submission tooling.
func StageMaliciousVoteEvidence(evidence *types.MaliciousVoteEvidence, outboxDir string) (string, error) {
	if err := evidence.Validate(); err != nil {
		return "", err
	}
	if outboxDir == "" {
		return "", fmt.Errorf("dpos: evidence outbox directory is required")
	}
	if err := os.MkdirAll(outboxDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(outboxDir, fmt.Sprintf(
		"malicious-vote-%d-%s.json",
		evidence.Number,
		evidence.Hash().Hex()[2:10],
	))
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func voteJournalFiles(journalDir string) ([]string, error) {
	entries, err := os.ReadDir(journalDir)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, voteJournalFilePrefix) && strings.HasSuffix(name, voteJournalFileSuffix) {
			files = append(files, filepath.Join(journalDir, name))
		}
	}
	sort.Strings(files)
	return files, nil
}

func exportMaliciousVoteEvidenceFromFile(path string, number uint64, signer common.Address) (*types.MaliciousVoteEvidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var rec checkpointVoteJournalRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			return nil, err
		}
		if rec.Kind != "vote_conflict" {
			continue
		}
		if rec.Signer == "" || common.HexToAddress(rec.Signer) != signer {
			continue
		}
		if rec.Vote == nil || rec.Vote.Number != number || rec.PreviousVote == nil {
			continue
		}
		if rec.Signature == "" || rec.PreviousSignature == "" {
			continue
		}
		current, err := journalRecordEnvelope(rec.Vote, rec.Signer, rec.Signature)
		if err != nil {
			return nil, err
		}
		previous, err := journalRecordEnvelope(rec.PreviousVote, rec.Signer, rec.PreviousSignature)
		if err != nil {
			return nil, err
		}
		pubBytes, err := hex.DecodeString(strings.TrimPrefix(rec.SignerPubKey, "0x"))
		if err != nil {
			return nil, err
		}
		return types.NewMaliciousVoteEvidence(previous, current, "ed25519", pubBytes)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

func journalRecordEnvelope(v *voteRecord, signerHex, sigHex string) (*types.CheckpointVoteEnvelope, error) {
	chainID := new(big.Int)
	if v.ChainID != "" {
		if _, ok := chainID.SetString(v.ChainID, 10); !ok {
			return nil, fmt.Errorf("dpos: invalid chain ID %q in vote journal", v.ChainID)
		}
	} else {
		chainID = nil
	}
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil {
		return nil, err
	}
	if len(sigBytes) != len([64]byte{}) {
		return nil, fmt.Errorf("dpos: invalid vote signature length %d", len(sigBytes))
	}
	var sig [64]byte
	copy(sig[:], sigBytes)
	return &types.CheckpointVoteEnvelope{
		Vote: types.CheckpointVote{
			ChainID:          chainID,
			Number:           v.Number,
			Hash:             common.HexToHash(v.Hash),
			ValidatorSetHash: common.HexToHash(v.ValidatorSetHash),
		},
		Signer:    common.HexToAddress(signerHex),
		Signature: sig,
	}, nil
}
